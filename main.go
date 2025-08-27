package main

import (
	"bufio"
	"bytes"
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
	"sync/atomic"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"
)

type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun" json:"-"`
	Hosts   []Host   `xml:"host" json:"hosts"`
}

type Host struct {
	Status Status `xml:"status" json:"status"`
	Ports  []Port `xml:"ports>port" json:"ports"`
}

type Port struct {
	PortID   string   `xml:"portid,attr" json:"portid"`
	Protocol string   `xml:"protocol,attr" json:"protocol"`
	State    State    `xml:"state" json:"state"`
	Service  Service  `xml:"service" json:"service"`
	Scripts  []Script `xml:"script" json:"scripts"`
}

type Status struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

type State struct {
	State  string `xml:"state,attr" json:"state"`
	Reason string `xml:"reason,attr" json:"reason"`
}

type Service struct {
	Name string `xml:"name,attr" json:"name"`
}

type Script struct {
	ID     string  `xml:"id,attr" json:"id"`
	Tables []Table `xml:"table" json:"tables"`
	Elems  []Elem  `xml:"elem" json:"elems"`
}

type Table struct {
	XMLName xml.Name `xml:"table" json:"-"`
	Key     string   `xml:"key,attr" json:"key"`
	Tables  []Table  `xml:"table" json:"tables"`
	Elems   []Elem   `xml:"elem" json:"elems"`
}

type Elem struct {
	Key   string `xml:"key,attr" json:"key"`
	Value string `xml:",chardata" json:"value"`
}

type ScanResults struct {
	Timestamp  string     `json:"timestamp"`
	TotalIPs   int        `json:"total_ips"`
	ScannedIPs int        `json:"scanned_ips"`
	IPResults  []IPResult `json:"ip_results"`
}

type IPResult struct {
	IP                 string              `json:"ip"`
	Status             string              `json:"status"`
	OpenPorts          []int               `json:"open_ports"`
	PortResults        []PortResult        `json:"port_results"`
	OpenshiftComponent *OpenshiftComponent `json:"openshift_component,omitempty"`
	Error              string              `json:"error,omitempty"`
}

type PortResult struct {
	Port          int     `json:"port"`
	Protocol      string  `json:"protocol"`
	State         string  `json:"state"`
	Service       string  `json:"service"`
	ProcessName   string  `json:"process_name,omitempty"`
	ContainerName string  `json:"container_name,omitempty"`
	NmapRun       NmapRun `json:"nmap_details"`
	Error         string  `json:"error,omitempty"`
}

type OpenshiftComponent struct {
	Component           string `json:"component"`
	SourceLocation      string `json:"source_location"`
	MaintainerComponent string `json:"maintainer_component"`
	IsBundle            bool   `json:"is_bundle"`
}

type K8sClient struct {
	clientset *kubernetes.Clientset
	restCfg   *rest.Config
	podIPMap  map[string]v1.Pod
	namespace string
}

func newK8sClient() (*K8sClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("Not in cluster, trying kubeconfig")
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("could not get kubernetes config: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	namespace := "default" // Or get from config
	if nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		namespace = string(nsBytes)
	}

	return &K8sClient{
		clientset: clientset,
		restCfg:   config,
		podIPMap:  make(map[string]v1.Pod),
		namespace: namespace,
	}, nil
}

func (k *K8sClient) discoverPods() error {
	log.Printf("Discovering pods in all namespaces")
	pods, err := k.clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, pod := range pods.Items {
		if pod.Status.PodIP != "" {
			k.podIPMap[pod.Status.PodIP] = pod
		}
	}
	log.Printf("Discovered %d pods with IPs across all namespaces", len(k.podIPMap))
	return nil
}

func (k *K8sClient) getOpenshiftComponentFromImage(image string) (*OpenshiftComponent, error) {
	log.Printf("Analyzing OpenShift image: %s", image)

	// Parse the image reference to extract component information
	component := k.parseOpenshiftComponentFromImageRef(image)
	if component != nil {
		log.Printf("Successfully parsed component info from image: %s -> %s", image, component.Component)
		return component, nil
	}

	// Fallback: try to get additional metadata from running pods using this image
	log.Printf("Attempting to gather component info from cluster metadata for: %s", image)
	return k.getComponentFromClusterMetadata(image)
}

func (k *K8sClient) parseOpenshiftComponentFromImageRef(image string) *OpenshiftComponent {
	// Handle OpenShift release images - similar to check-payload approach
	if strings.Contains(image, "quay.io/openshift-release-dev") {
		// Extract component from OpenShift release image path
		// Format: quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:...
		component := &OpenshiftComponent{
			SourceLocation:      "quay.io/openshift-release-dev",
			MaintainerComponent: "openshift",
			IsBundle:           false,
		}
		
		// Parse component name from image path or labels we might find
		if strings.Contains(image, "oauth-openshift") {
			component.Component = "oauth-openshift"
		} else if strings.Contains(image, "apiserver") {
			component.Component = "openshift-apiserver"
		} else if strings.Contains(image, "controller-manager") {
			component.Component = "openshift-controller-manager"
		} else {
			// Default component name from sha or extract from known patterns
			component.Component = "openshift-component"
		}
		
		return component
	}

	// Handle internal OpenShift registry images
	if strings.Contains(image, "image-registry.openshift-image-registry.svc") {
		parts := strings.Split(image, "/")
		if len(parts) >= 3 {
			return &OpenshiftComponent{
				Component:           parts[len(parts)-1], // Use image name as component
				SourceLocation:      "internal-registry",
				MaintainerComponent: "user",
				IsBundle:           false,
			}
		}
	}

	// Handle other registries (quay.io, registry.redhat.com, etc.)
	if strings.Contains(image, "quay.io") || strings.Contains(image, "registry.redhat.com") {
		return &OpenshiftComponent{
			Component:           k.extractComponentNameFromImage(image),
			SourceLocation:      k.extractRegistryFromImage(image),
			MaintainerComponent: "redhat",
			IsBundle:           false,
		}
	}

	return nil
}

func (k *K8sClient) getComponentFromClusterMetadata(image string) (*OpenshiftComponent, error) {
	// Try to find pods using this image and extract metadata
	log.Printf("Searching cluster for pods using image: %s", image)
	
	pods, err := k.clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods for image metadata: %v", err)
	}

	// Look for pods using this exact image
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.Image == image {
				// Extract component info from pod labels or annotations
				component := &OpenshiftComponent{
					Component:           k.extractComponentFromPod(pod, container),
					SourceLocation:      k.extractRegistryFromImage(image),
					MaintainerComponent: k.extractMaintainerFromPod(pod),
					IsBundle:           false,
				}
				return component, nil
			}
		}
	}

	// If no exact match found, return basic info
	return &OpenshiftComponent{
		Component:           k.extractComponentNameFromImage(image),
		SourceLocation:      "unknown",
		MaintainerComponent: "unknown", 
		IsBundle:           false,
	}, nil
}

func (k *K8sClient) extractComponentNameFromImage(image string) string {
	// Extract component name from image URL
	parts := strings.Split(image, "/")
	if len(parts) > 0 {
		// Get the last part (image name)
		imageName := parts[len(parts)-1]
		// Remove tag/sha if present
		if strings.Contains(imageName, ":") {
			imageName = strings.Split(imageName, ":")[0]
		}
		if strings.Contains(imageName, "@") {
			imageName = strings.Split(imageName, "@")[0]
		}
		return imageName
	}
	return "unknown"
}

func (k *K8sClient) extractRegistryFromImage(image string) string {
	if strings.Contains(image, "quay.io") {
		return "quay.io"
	} else if strings.Contains(image, "registry.redhat.com") {
		return "registry.redhat.com"
	} else if strings.Contains(image, "image-registry.openshift-image-registry.svc") {
		return "internal-registry"
	}
	return strings.Split(image, "/")[0]
}

func (k *K8sClient) extractComponentFromPod(pod v1.Pod, container v1.Container) string {
	// Try to extract component name from pod/container labels
	if component, exists := pod.Labels["app"]; exists {
		return component
	}
	if component, exists := pod.Labels["component"]; exists {
		return component
	}
	if component, exists := pod.Labels["app.kubernetes.io/name"]; exists {
		return component
	}
	// Fallback to container name or image name
	if container.Name != "" {
		return container.Name
	}
	return k.extractComponentNameFromImage(container.Image)
}

func (k *K8sClient) extractMaintainerFromPod(pod v1.Pod) string {
	// Determine maintainer from namespace or labels
	if strings.HasPrefix(pod.Namespace, "openshift-") {
		return "openshift"
	}
	if strings.HasPrefix(pod.Namespace, "kube-") {
		return "kubernetes"
	}
	if maintainer, exists := pod.Labels["maintainer"]; exists {
		return maintainer
	}
	return "unknown"
}

func (k *K8sClient) getProcessNameFromPod(podName, namespace, containerName string, port int) (string, error) {
	command := []string{"/bin/sh", "-c", fmt.Sprintf("lsof -i :%d -sTCP:LISTEN -P -n -F c | grep '^c' | cut -c 2- | head -n 1", port)}

	req := k.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")

	req.VersionedParams(&v1.PodExecOptions{
		Container: containerName,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(k.restCfg, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("failed to create executor: %v", err)
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	if err != nil {
		return "", fmt.Errorf("exec failed: %v, stderr: %s", err, stderr.String())
	}

	processName := strings.TrimSpace(stdout.String())
	if processName == "" {
		return "", fmt.Errorf("process not found in container %s for port %d", containerName, port)
	}

	return processName, nil
}

func main() {
	host := flag.String("host", "127.0.0.1", "The target host or IP address to scan")
	port := flag.String("port", "443", "The target port to scan")
	ipListFile := flag.String("iplist", "", "Path to file containing list of IPs to scan (one per line)")
	jsonOutput := flag.String("json", "", "Output results in JSON format to specified file (if empty, outputs to stdout in human-readable format)")
	concurrentScans := flag.Int("j", 1, "Number of concurrent scans to run in parallel (speeds up large IP lists significantly!)")
	allPods := flag.Bool("all-pods", false, "Scan all pods in the current namespace (overrides --iplist and --host)")
	flag.Parse()

	if !isNmapInstalled() {
		log.Fatal("Error: Nmap is not installed or not in the system's PATH. This program is a wrapper and requires Nmap to function.")
	}

	// Validate concurrent scans parameter
	if *concurrentScans < 1 {
		log.Fatal("Error: Number of concurrent scans must be at least 1")
	}
	if *concurrentScans > 50 {
		log.Printf("WARNING: Using %d concurrent scans might overwhelm your system. Consider using fewer workers.", *concurrentScans)
	}

	var k8sClient *K8sClient
	var err error
	var allPodsInfo []PodInfo

	if *allPods {
		k8sClient, err = newK8sClient()
		if err != nil {
			log.Fatalf("Could not create kubernetes client for --all-pods: %v", err)
		}
		// No need to call discoverPods here, getAllPodsInfo will do it.
		allPodsInfo = k8sClient.getAllPodsInfo()
		log.Printf("Found %d pods to scan from the cluster.", len(allPodsInfo))
	} else if *ipListFile != "" {
		ips, err := readIPsFromFile(*ipListFile)
		if err != nil {
			log.Fatalf("Error reading IP list file: %v", err)
		}
		// Lazily create k8s client if not already created for --all-pods
		if k8sClient == nil {
			k8sClient, err = newK8sClient()
			if err != nil {
				log.Printf("Could not create kubernetes client, will not be able to get process names from pods. Error: %v", err)
			} else {
				if err := k8sClient.discoverPods(); err != nil {
					log.Printf("Could not discover pods, will not be able to get process names. Error: %v", err)
					k8sClient = nil // disable if we can't list pods
				}
			}
		}
		allPodsInfo = buildPodInfoFromIPs(ips, k8sClient)
	}

	if len(allPodsInfo) > 0 {
		if *jsonOutput != "" {
			performClusterScanWithStreaming(allPodsInfo, *jsonOutput, *concurrentScans, k8sClient)
			log.Printf("Scan complete. Results written to: %s", *jsonOutput)
		} else {
			scanResults := performClusterScan(allPodsInfo, *concurrentScans, k8sClient)
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
	} else {
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

func printParsedResults(run NmapRun) {
	if len(run.Hosts) == 0 {
		log.Println("No hosts were scanned or host is down.")
		return
	}

	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			log.Printf("Host %s is %s.\n", os.Args[len(os.Args)-1], host.Status.State)
			continue
		}
		for _, port := range host.Ports {
			fmt.Printf("PORT    STATE SERVICE REASON\n")
			fmt.Printf("%s/%s %-5s %-7s %s\n", port.PortID, port.Protocol, port.State.State, port.Service.Name, port.State.Reason)

			for _, script := range port.Scripts {
				if script.ID == "ssl-enum-ciphers" {
					fmt.Println("| ssl-enum-ciphers:")
					printTable(script.Tables, 1)
					for _, elem := range script.Elems {
						fmt.Printf("|_  %s: %s\n", elem.Key, elem.Value)
					}
				}
			}
		}
	}
}

func printTable(tables []Table, indentLevel int) {
	indent := strings.Repeat("  ", indentLevel)
	for _, table := range tables {
		fmt.Printf("|%s %s:\n", indent, table.Key)

		if table.Key == "ciphers" {
			for _, cipherTable := range table.Tables {
				var name, kex, strength string
				for _, elem := range cipherTable.Elems {
					switch elem.Key {
					case "name":
						name = elem.Value
					case "kex_info":
						kex = elem.Value
					case "strength":
						strength = elem.Value
					}
				}
				fmt.Printf("|%s   %s (%s) - %s\n", indent, name, kex, strength)
			}
		} else {
			for _, elem := range table.Elems {
				if elem.Key != "" {
					fmt.Printf("|%s   %s: %s\n", indent, elem.Key, elem.Value)
				} else {
					fmt.Printf("|%s   - %s\n", indent, elem.Value)
				}
			}
		}

		if len(table.Tables) > 0 && table.Key != "ciphers" {
			printTable(table.Tables, indentLevel+1)
		}
	}
}

// readIPsFromFile reads IP addresses from a file, one per line
func readIPsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			ips = append(ips, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Remove duplicates
	uniqueIPs := make(map[string]bool)
	var result []string
	for _, ip := range ips {
		if !uniqueIPs[ip] {
			uniqueIPs[ip] = true
			result = append(result, ip)
		}
	}

	return result, nil
}

func discoverOpenPorts(ip string) ([]int, error) {
	log.Printf("Discovering open ports for %s...", ip)

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

func scanIPPort(ip string, port int, k8sClient *K8sClient, pod PodInfo) (PortResult, error) {
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

	if k8sClient != nil {
		// We have the pod info directly
		for _, containerName := range pod.Containers {
			processName, err := k8sClient.getProcessNameFromPod(pod.Name, pod.Namespace, containerName, port)
			if err == nil && processName != "" {
				result.ProcessName = processName
				result.ContainerName = containerName
				// Assuming one process per port, we can break after finding it.
				break
			}
		}
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
	fmt.Printf("========================================\n\n")

	results := ScanResults{
		Timestamp: startTime.Format(time.RFC3339),
		TotalIPs:  totalIPs,
		IPResults: make([]IPResult, 0, totalIPs),
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
					ipResult := scanIP(k8sClient, ip, pod)
					ipResult.OpenshiftComponent = component

					mu.Lock()
					results.IPResults = append(results.IPResults, ipResult)
					results.ScannedIPs++
					completed := results.ScannedIPs
					mu.Unlock()
					log.Printf("WORKER %d: Completed %s (%d/%d IPs done)", workerID, ip, completed, totalIPs)
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

// performClusterScanWithStreaming performs cluster scan and writes results incrementally to JSON file
func performClusterScanWithStreaming(allPodsInfo []PodInfo, outputFile string, concurrentScans int, k8sClient *K8sClient) {
	startTime := time.Now()

	totalIPs := 0
	for _, pod := range allPodsInfo {
		totalIPs += len(pod.IPs)
	}

	fmt.Printf("========================================\n")
	fmt.Printf("CONCURRENT STREAMING SCAN STARTING\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total Pods to scan: %d\n", len(allPodsInfo))
	fmt.Printf("Total IPs to scan: %d\n", totalIPs)
	fmt.Printf("Concurrent workers: %d\n", concurrentScans)
	fmt.Printf("Output file: %s\n", outputFile)
	fmt.Printf("========================================\n\n")

	// Create channels for work distribution and result collection
	podChan := make(chan PodInfo, len(allPodsInfo))
	resultChan := make(chan IPResult, totalIPs)

	var wg sync.WaitGroup
	var processedPods int64 // Atomic counter for processed pods

	// Start worker goroutines
	for w := 0; w < concurrentScans; w++ {
		workerID := w + 1
		log.Printf("Starting STREAMING WORKER %d", workerID)
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for pod := range podChan {
				currentPod := atomic.AddInt64(&processedPods, 1)
				log.Printf("STREAMING WORKER %d: Processing Pod %d/%d: %s/%s", workerID, currentPod, len(allPodsInfo), pod.Namespace, pod.Name)

				// Get OpenShift component information using Kubernetes API
				component, err := k8sClient.getOpenshiftComponentFromImage(pod.Image)
				if err != nil {
					log.Printf("Could not get openshift component for image %s: %v", pod.Image, err)
					component = nil
				}

				for _, ip := range pod.IPs {
					ipResult := scanIP(k8sClient, ip, pod)
					ipResult.OpenshiftComponent = component
					resultChan <- ipResult
				}
				log.Printf("STREAMING WORKER %d: Completed Pod %d/%d: %s/%s", workerID, currentPod, len(allPodsInfo), pod.Namespace, pod.Name)
			}
			log.Printf("STREAMING WORKER %d: FINISHED", workerID)
		}(workerID)
	}

	// Start a goroutine to collect results and write them to the file
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		results := ScanResults{
			Timestamp: startTime.Format(time.RFC3339),
			TotalIPs:  totalIPs,
			IPResults: make([]IPResult, 0, totalIPs),
		}

		file, err := os.Create(outputFile)
		if err != nil {
			log.Fatalf("Error creating output file: %v", err)
		}
		defer file.Close()

		// Write the initial structure
		file.WriteString("{\n")
		file.WriteString(fmt.Sprintf("  \"timestamp\": \"%s\",\n", results.Timestamp))
		file.WriteString(fmt.Sprintf("  \"total_ips\": %d,\n", results.TotalIPs))
		file.WriteString("  \"scanned_ips\": 0,\n")
		file.WriteString("  \"ip_results\": [\n")

		isFirstResult := true
		for i := 0; i < totalIPs; i++ {
			ipResult := <-resultChan
			results.IPResults = append(results.IPResults, ipResult)
			results.ScannedIPs++

			jsonData, err := json.MarshalIndent(ipResult, "    ", "  ")
			if err != nil {
				log.Printf("Error marshaling IP result: %v", err)
				continue
			}

			if !isFirstResult {
				file.WriteString(",\n")
			}
			file.WriteString("    " + string(jsonData))
			isFirstResult = false
		}

		// Write the final structure
		file.WriteString("\n  ]\n}\n")
	}()

	// Send PodInfo to workers
	for _, pod := range allPodsInfo {
		podChan <- pod
	}
	close(podChan)

	// Wait for all workers to complete
	wg.Wait()
	close(resultChan)

	// Wait for the collector to finish writing
	collectorWg.Wait()

	duration := time.Since(startTime)

	fmt.Printf("\n========================================\n")
	fmt.Printf("CONCURRENT STREAMING SCAN COMPLETE!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total IPs processed: %d\n", totalIPs)
	fmt.Printf("Total time: %v\n", duration)
	fmt.Printf("Concurrent workers used: %d\n", concurrentScans)
	fmt.Printf("Average time per IP: %.2fs\n", duration.Seconds()/float64(totalIPs))
	fmt.Printf("Output file: %s\n", outputFile)
	fmt.Printf("========================================\n")
}

func printClusterResults(results ScanResults) {
	fmt.Printf("=== CLUSTER SCAN RESULTS ===\n")
	fmt.Printf("Timestamp: %s\n", results.Timestamp)
	fmt.Printf("Total IPs: %d\n", results.TotalIPs)
	fmt.Printf("Successfully Scanned: %d\n", results.ScannedIPs)
	fmt.Printf("\n")

	for _, ipResult := range results.IPResults {
		fmt.Printf("-----------------------------------------------------\n")
		fmt.Printf("IP: %s\n", ipResult.IP)
		if ipResult.OpenshiftComponent != nil {
			fmt.Printf("Component: %s\n", ipResult.OpenshiftComponent.Component)
			fmt.Printf("Source Location: %s\n", ipResult.OpenshiftComponent.SourceLocation)
			fmt.Printf("Maintainer: %s\n", ipResult.OpenshiftComponent.MaintainerComponent)
			fmt.Printf("Is Bundle: %t\n", ipResult.OpenshiftComponent.IsBundle)
		}
		fmt.Printf("Status: %s\n", ipResult.Status)

		if ipResult.Error != "" {
			fmt.Printf("Error: %s\n", ipResult.Error)
			continue
		}

		if len(ipResult.OpenPorts) == 0 {
			fmt.Printf("No open ports found\n")
			continue
		}

		fmt.Printf("Open Ports: %v\n", ipResult.OpenPorts)
		fmt.Printf("\n")

		for _, portResult := range ipResult.PortResults {
			fmt.Printf("  Port %d:\n", portResult.Port)
			if portResult.Error != "" {
				fmt.Printf("    Error: %s\n", portResult.Error)
				continue
			}

			fmt.Printf("    Protocol: %s\n", portResult.Protocol)
			fmt.Printf("    State: %s\n", portResult.State)
			fmt.Printf("    Service: %s\n", portResult.Service)
			if portResult.ProcessName != "" {
				fmt.Printf("    Process Name: %s (%s)\n", portResult.ProcessName, portResult.ContainerName)
			}

			// Print SSL cipher information if available
			if len(portResult.NmapRun.Hosts) > 0 {
				for _, host := range portResult.NmapRun.Hosts {
					for _, port := range host.Ports {
						for _, script := range port.Scripts {
							if script.ID == "ssl-enum-ciphers" {
								fmt.Printf("    SSL Ciphers:\n")
								printTableWithIndent(script.Tables, 3)
							}
						}
					}
				}
			}
			fmt.Printf("\n")
		}
	}
}

func printTableWithIndent(tables []Table, indentLevel int) {
	indent := strings.Repeat("  ", indentLevel)
	for _, table := range tables {
		fmt.Printf("%s%s:\n", indent, table.Key)

		if table.Key == "ciphers" {
			for _, cipherTable := range table.Tables {
				var name, kex, strength string
				for _, elem := range cipherTable.Elems {
					switch elem.Key {
					case "name":
						name = elem.Value
					case "kex_info":
						kex = elem.Value
					case "strength":
						strength = elem.Value
					}
				}
				fmt.Printf("%s  %s (%s) - %s\n", indent, name, kex, strength)
			}
		} else {
			for _, elem := range table.Elems {
				if elem.Key != "" {
					fmt.Printf("%s  %s: %s\n", indent, elem.Key, elem.Value)
				} else {
					fmt.Printf("%s  - %s\n", indent, elem.Value)
				}
			}
		}

		if len(table.Tables) > 0 && table.Key != "ciphers" {
			printTableWithIndent(table.Tables, indentLevel+1)
		}
	}
}

// PodInfo holds information about a pod and its associated IPs
type PodInfo struct {
	Name       string   // Pod name
	Namespace  string   // Pod namespace
	Image      string   // Container image
	IPs        []string // List of IPs assigned to the pod
	Containers []string // List of container names
}

func (k *K8sClient) getAllPodsInfo() []PodInfo {
	pods, err := k.clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Printf("Error getting pods for info: %v", err)
		return nil
	}

	infos := make([]PodInfo, 0, len(pods.Items))
	for _, pod := range pods.Items {
		if pod.Status.PodIP == "" || pod.Status.Phase != v1.PodRunning {
			continue
		}

		var containerNames []string
		var image string
		if len(pod.Spec.Containers) > 0 {
			image = pod.Spec.Containers[0].Image // Taking the first one for now
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

func buildPodInfoFromIPs(ips []string, k8sClient *K8sClient) []PodInfo {
	if k8sClient == nil {
		// No k8s client, just return basic info
		infos := make([]PodInfo, len(ips))
		for i, ip := range ips {
			infos[i] = PodInfo{IPs: []string{ip}}
		}
		return infos
	}

	infos := make([]PodInfo, 0, len(ips))
	for _, ip := range ips {
		if pod, found := k8sClient.podIPMap[ip]; found {
			var containerNames []string
			var image string
			if len(pod.Spec.Containers) > 0 {
				image = pod.Spec.Containers[0].Image
				for _, c := range pod.Spec.Containers {
					containerNames = append(containerNames, c.Name)
				}
			}
			infos = append(infos, PodInfo{
				Name:       pod.Name,
				Namespace:  pod.Namespace,
				Image:      image,
				IPs:        []string{ip},
				Containers: containerNames,
			})
		} else {
			// IP not found in map, treat as external
			infos = append(infos, PodInfo{IPs: []string{ip}})
		}
	}
	return infos
}

func scanIP(k8sClient *K8sClient, ip string, pod PodInfo) IPResult {
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
		Status:      "scanned",
		OpenPorts:   ports,
		PortResults: make([]PortResult, 0, len(ports)),
	}

	// Scan each open port for SSL ciphers
	for _, port := range ports {
		portResult, err := scanIPPort(ip, port, k8sClient, pod)
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
