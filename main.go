package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	host := flag.String("host", "127.0.0.1", "The target host or IP address to scan")
	port := flag.String("port", "443", "The target port to scan")
	jsonOutput := flag.String("json", "", "Output results in JSON format to specified file (if empty, outputs to stdout in human-readable format)")
	csvOutput := flag.String("csv", "", "Output results in CSV format to specified file")
	concurrentScans := flag.Int("j", 1, "Number of concurrent scans to run in parallel (speeds up large IP lists significantly!)")
	allPods := flag.Bool("all-pods", false, "Scan all pods in the current namespace (overrides --iplist and --host)")
	limitIPs := flag.Int("limit-ips", 0, "Limit the number of IPs to scan for testing purposes (0 = no limit)")
	flag.Parse()

	if !isNmapInstalled() {
		log.Fatal("Error: Nmap is not installed or not in the system's PATH. This program is a wrapper and requires Nmap to function.")
	}

	// Validate concurrent scans parameter
	if *concurrentScans < 1 {
		log.Fatal("Error: Number of concurrent scans must be at least 1")
	}

	var k8sClient *K8sClient
	var err error
	var allPodsInfo []PodInfo

	if *allPods {
		k8sClient, err = newK8sClient()
		if err != nil {
			log.Fatalf("Could not create kubernetes client for --all-pods: %v", err)
		}

		allPodsInfo = k8sClient.getAllPodsInfo() // get pod ip to pod name mapping

		log.Printf("Found %d pods to scan from the cluster.", len(allPodsInfo))

		// Apply IP limit if specified
		if *limitIPs > 0 {
			totalIPs := 0
			for _, pod := range allPodsInfo {
				totalIPs += len(pod.IPs)
			}

			if totalIPs > *limitIPs {
				log.Printf("Limiting scan to %d IPs (found %d total IPs)", *limitIPs, totalIPs)
				allPodsInfo = limitPodsToIPCount(allPodsInfo, *limitIPs)
				limitedTotal := 0
				for _, pod := range allPodsInfo {
					limitedTotal += len(pod.IPs)
				}
				log.Printf("After limiting: %d pods with %d total IPs", len(allPodsInfo), limitedTotal)
			}
		}
	}

	if len(allPodsInfo) > 0 {
		var scanResults ScanResults

		if *csvOutput != "" {
			scanResults = performClusterScan(allPodsInfo, *concurrentScans, k8sClient)

			// Write JSON if also requested
			if *jsonOutput != "" {
				// Convert ScanResults to JSON format
				if err := writeJSONOutput(scanResults, *jsonOutput); err != nil {
					log.Printf("Error writing JSON output: %v", err)
				} else {
					log.Printf("JSON results written to: %s", *jsonOutput)
				}
			}

			// Write CSV output
			if err := writeCSVOutput(scanResults, *csvOutput); err != nil {
				log.Printf("Error writing CSV output: %v", err)
			} else {
				log.Printf("CSV results written to: %s", *csvOutput)
			}

			// Write scan errors CSV if there are any errors
			if len(scanResults.ScanErrors) > 0 {
				errorFilename := strings.TrimSuffix(*csvOutput, filepath.Ext(*csvOutput)) + "_errors.csv"
				if err := writeScanErrorsCSV(scanResults, errorFilename); err != nil {
					log.Printf("Error writing scan errors CSV: %v", err)
				} else {
					log.Printf("Scan errors written to: %s", errorFilename)
				}
			}

			// Print to console if no output files specified
			if *jsonOutput == "" {
				printClusterResults(scanResults)
			}
		} else {
			// Console output only
			scanResults = performClusterScan(allPodsInfo, *concurrentScans, k8sClient)
			printClusterResults(scanResults)
		}

		return
	}

	log.Printf("Found Nmap. Starting scan on %s:%s...\n\n", *host, *port)

	cmd := exec.Command("nmap", "-sV", "--script", "ssl-enum-ciphers", "-p", *port, "-oX", "-", *host)

	output, err := cmd.CombinedOutput() // CombinedOutput captures both stdout and stderr.
	if err != nil {
		log.Fatalf("Error executing Nmap command. Nmap output:\n%s", string(output))
	}

	var nmapResult NmapRun
	if err := xml.Unmarshal(output, &nmapResult); err != nil {
		log.Fatalf("Error parsing Nmap XML output: %v", err)
	}

	if *jsonOutput != "" {
		if err := writeJSONOutput(nmapResult, *jsonOutput); err != nil {
			log.Fatalf("Error writing JSON output: %v", err)
		}
		log.Printf("JSON results written to %s", *jsonOutput)
	}

	if *csvOutput != "" {
		// For single host scans, try to get TLS config if k8s client is available
		var tlsConfig *TLSSecurityProfile
		if k8sClient != nil {
			if config, err := k8sClient.getTLSSecurityProfile(); err != nil {
				log.Printf("Warning: Could not collect TLS security profiles: %v", err)
			} else {
				tlsConfig = config
			}
		}

		// Convert single scan to ScanResults format for CSV
		singleResult := ScanResults{
			Timestamp:         time.Now().Format(time.RFC3339),
			TotalIPs:          1,
			ScannedIPs:        1,
			TLSSecurityConfig: tlsConfig,
			IPResults: []IPResult{{
				IP:          *host,
				Status:      "scanned",
				OpenPorts:   []int{}, // Will be extracted from nmapResult
				PortResults: []PortResult{},
			}},
		}

		// Extract port information from nmap result
		if len(nmapResult.Hosts) > 0 && len(nmapResult.Hosts[0].Ports) > 0 {
			for _, nmapPort := range nmapResult.Hosts[0].Ports {
				if port, err := strconv.Atoi(nmapPort.PortID); err == nil {
					singleResult.IPResults[0].OpenPorts = append(singleResult.IPResults[0].OpenPorts, port)
					singleResult.IPResults[0].PortResults = append(singleResult.IPResults[0].PortResults, PortResult{
						Port:     port,
						Protocol: nmapPort.Protocol,
						State:    nmapPort.State.State,
						Service:  nmapPort.Service.Name,
						NmapRun:  nmapResult,
					})
				}
			}
		}

		if err := writeCSVOutput(singleResult, *csvOutput); err != nil {
			log.Fatalf("Error writing CSV output: %v", err)
		}
		log.Printf("CSV results written to %s", *csvOutput)

		// Write scan errors CSV if there are any errors
		if len(singleResult.ScanErrors) > 0 {
			errorFilename := strings.TrimSuffix(*csvOutput, filepath.Ext(*csvOutput)) + "_errors.csv"
			if err := writeScanErrorsCSV(singleResult, errorFilename); err != nil {
				log.Printf("Error writing scan errors CSV: %v", err)
			} else {
				log.Printf("Scan errors written to: %s", errorFilename)
			}
		}
	}

	if *jsonOutput == "" && *csvOutput == "" {
		printParsedResults(nmapResult)
	}
}

func isNmapInstalled() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

func writeJSONOutput(data interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %v", err)
	}

	log.Printf("JSON output written to: %s", filename)
	return nil
}

func discoverOpenPorts(ip string) ([]int, error) {
	log.Printf("Discovering open ports for %s...", ip)

	// We scan all ports for this ip first to get the open ports
	// for constructing the final results.
	cmd := exec.Command("nmap", "-p-", "--open", "-T4", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("nmap port discovery failed: %v", err)
	}

	re := regexp.MustCompile(`^(\d+)/tcp\s+open`)
	var ports []int

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		matches := re.FindStringSubmatch(strings.TrimSpace(line))
		if len(matches) > 1 {
			if port, err := strconv.Atoi(matches[1]); err == nil {
				ports = append(ports, port)
			}
		}
	}

	log.Printf("Found %d open ports for %s: %v", len(ports), ip, ports)
	return ports, nil
}

func scanIPPort(ip string, port int, k8sClient *K8sClient, pod PodInfo, scanResults *ScanResults) (PortResult, error) {
	log.Printf("Scanning SSL ciphers on %s:%d", ip, port)

	cmd := exec.Command("nmap", "-sV", "--script", "ssl-enum-ciphers", "-p", strconv.Itoa(port), "-oX", "-", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return PortResult{
			Port:  port,
			Error: fmt.Sprintf("nmap scan failed: %v", err),
		}, nil
	}

	var nmapResult NmapRun
	if err := xml.Unmarshal(output, &nmapResult); err != nil {
		return PortResult{
			Port:  port,
			Error: fmt.Sprintf("failed to parse nmap XML: %v", err),
		}, nil
	}

	result := PortResult{
		Port:    port,
		NmapRun: nmapResult,
	}

	if len(nmapResult.Hosts) > 0 {
		for _, nmapPort := range nmapResult.Hosts[0].Ports {
			if nmapPort.PortID == strconv.Itoa(port) {
				result.Protocol = nmapPort.Protocol
				result.State = nmapPort.State.State
				result.Service = nmapPort.Service.Name
				break
			}
		}
	}

	// Check if TLS data was found before doing expensive process name detection
	hasTLSData := false
	if len(nmapResult.Hosts) > 0 {
		for _, host := range nmapResult.Hosts {
			for _, nmapPort := range host.Ports {
				for _, script := range nmapPort.Scripts {
					if script.ID == "ssl-enum-ciphers" && len(script.Tables) > 0 {
						hasTLSData = true
						break
					}
				}
				if hasTLSData {
					break
				}
			}
			if hasTLSData {
				break
			}
		}
	}

	// Only do process detection if we found TLS data
	if k8sClient != nil && hasTLSData && len(pod.Containers) > 0 {
		// Discover processes for this pod on-demand
		k8sClient.getAndCachePodProcesses(pod)

		// Look up from the now-populated cache
		k8sClient.processCacheMutex.Lock()
		if processName, ok := k8sClient.processNameMap[ip][port]; ok {
			result.ProcessName = processName
			// Since we don't know the exact container, we can leave it blank or list all
			result.ContainerName = strings.Join(pod.Containers, ",")
			log.Printf("Found process '%s' for %s:%d from cache", processName, ip, port)
		} else {
			log.Printf("Could not find process for %s:%d in cache", ip, port)
		}
		k8sClient.processCacheMutex.Unlock()
	} else if !hasTLSData {
		log.Printf("Skipping process name detection for %s:%d - no TLS data found. Nmap output: %s", ip, port, string(output))
	}

	return result, nil
}

func performClusterScan(allPodsInfo []PodInfo, concurrentScans int, k8sClient *K8sClient) ScanResults {
	startTime := time.Now()

	totalIPs := 0
	for _, pod := range allPodsInfo {
		totalIPs += len(pod.IPs)
	}

	fmt.Printf("========================================\n")
	fmt.Printf("CONCURRENT CLUSTER SCAN STARTING\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total Pods to scan: %d\n", len(allPodsInfo))
	fmt.Printf("Total IPs to scan: %d\n", totalIPs)
	fmt.Printf("Concurrent workers: %d\n", concurrentScans)
	fmt.Printf("Process detection workers: %d\n", max(2, concurrentScans/2))
	fmt.Printf("========================================\n\n")

	// Collect TLS security configuration from cluster
	var tlsConfig *TLSSecurityProfile
	if k8sClient != nil {
		if config, err := k8sClient.getTLSSecurityProfile(); err != nil {
			log.Printf("Warning: Could not collect TLS security profiles: %v", err)
		} else {
			tlsConfig = config
		}
	}

	results := ScanResults{
		Timestamp:         startTime.Format(time.RFC3339),
		TotalIPs:          totalIPs,
		IPResults:         make([]IPResult, 0, totalIPs),
		TLSSecurityConfig: tlsConfig,
	}

	// Create a channel to send PodInfo to workers
	podChan := make(chan PodInfo, len(allPodsInfo))

	// Use a WaitGroup to wait for all workers to complete
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Start worker goroutines
	for w := 0; w < concurrentScans; w++ {
		workerID := w + 1
		log.Printf("Starting WORKER %d", workerID)
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for pod := range podChan {
				log.Printf("WORKER %d: Processing Pod %s/%s", workerID, pod.Namespace, pod.Name)

				component, err := k8sClient.getOpenshiftComponentFromImage(pod.Image)
				if err != nil {
					log.Printf("Could not get openshift component for image %s: %v", pod.Image, err)
				}

				for _, ip := range pod.IPs {
					ipResult := scanIP(k8sClient, ip, pod, &results)
					ipResult.OpenshiftComponent = component // TODO add component to scan results

					mu.Lock()
					results.IPResults = append(results.IPResults, ipResult)
					results.ScannedIPs++
					mu.Unlock()
					log.Printf("WORKER %d: Completed %s (%d/%d IPs done)", workerID, ip, results.ScannedIPs, totalIPs)
				}
			}
			log.Printf("WORKER %d: FINISHED", workerID)
		}(workerID)
	}

	// Send PodInfo to workers
	for _, pod := range allPodsInfo {
		podChan <- pod
	}
	close(podChan)

	// Wait for all workers to complete
	wg.Wait()

	duration := time.Since(startTime)

	fmt.Printf("\n========================================\n")
	fmt.Printf("CONCURRENT CLUSTER SCAN COMPLETE!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total IPs processed: %d\n", results.ScannedIPs)
	fmt.Printf("Total time: %v\n", duration)
	fmt.Printf("Concurrent workers used: %d\n", concurrentScans)
	fmt.Printf("Average time per IP: %.2fs\n", duration.Seconds()/float64(results.ScannedIPs))
	fmt.Printf("========================================\n")

	return results
}

func (k *K8sClient) getAllPodsInfo() []PodInfo {
	pods, err := k.clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{}) // TODO handle error
	if err != nil {
		log.Printf("Error getting pods for info: %v", err)
		return nil
	}

	// Build pod IP to Pod mapping
	for _, pod := range pods.Items {
		if pod.Status.PodIP != "" {
			k.podIPMap[pod.Status.PodIP] = pod
		}
	}

	infos := make([]PodInfo, 0, len(pods.Items))
	for _, pod := range pods.Items {
		if pod.Status.PodIP == "" || pod.Status.Phase != v1.PodRunning {
			continue
		}

		var containerNames []string
		var image string
		if len(pod.Spec.Containers) > 0 {
			image = pod.Spec.Containers[0].Image // TODO Not sure if this matters taking the first one for now
			for _, c := range pod.Spec.Containers {
				containerNames = append(containerNames, c.Name)
			}
		}

		var ips []string
		for _, podIP := range pod.Status.PodIPs {
			ips = append(ips, podIP.IP)
		}

		if len(ips) > 0 {
			infos = append(infos, PodInfo{
				Name:       pod.Name,
				Namespace:  pod.Namespace,
				Image:      image,
				IPs:        ips,
				Containers: containerNames,
			})
		}
	}
	return infos
}

func scanIP(k8sClient *K8sClient, ip string, pod PodInfo, scanResults *ScanResults) IPResult {
	ports, err := discoverOpenPorts(ip)
	if err != nil {
		return IPResult{
			IP:     ip,
			Status: "error",
			Error:  err.Error(),
		}
	}

	ipResult := IPResult{
		IP:          ip,
		Pod:         &pod,
		Status:      "scanned",
		OpenPorts:   ports,
		PortResults: make([]PortResult, 0, len(ports)),
	}

	// Scan each open port for SSL ciphers
	for _, port := range ports {
		portResult, err := scanIPPort(ip, port, k8sClient, pod, scanResults)
		if err != nil {
			portResult = PortResult{
				Port:  port,
				Error: err.Error(),
			}
		}
		ipResult.PortResults = append(ipResult.PortResults, portResult)
	}

	return ipResult
}

// limitPodsToIPCount limits the pod list to contain at most maxIPs total IP addresses
func limitPodsToIPCount(allPodsInfo []PodInfo, maxIPs int) []PodInfo {
	if maxIPs <= 0 {
		return allPodsInfo
	}

	var limitedPods []PodInfo
	currentIPCount := 0

	for _, pod := range allPodsInfo {
		if currentIPCount >= maxIPs {
			break
		}

		// If this pod would exceed the limit, include only some of its IPs
		if currentIPCount+len(pod.IPs) > maxIPs {
			remainingIPs := maxIPs - currentIPCount
			limitedPod := pod
			limitedPod.IPs = pod.IPs[:remainingIPs]
			limitedPods = append(limitedPods, limitedPod)
			break
		}

		// Include the entire pod
		limitedPods = append(limitedPods, pod)
		currentIPCount += len(pod.IPs)
	}

	return limitedPods
}
