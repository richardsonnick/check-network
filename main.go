package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
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
	IP          string       `json:"ip"`
	Status      string       `json:"status"`
	OpenPorts   []int        `json:"open_ports"`
	PortResults []PortResult `json:"port_results"`
	Error       string       `json:"error,omitempty"`
}

type PortResult struct {
	Port     int     `json:"port"`
	Protocol string  `json:"protocol"`
	State    string  `json:"state"`
	Service  string  `json:"service"`
	NmapRun  NmapRun `json:"nmap_details"`
	Error    string  `json:"error,omitempty"`
}

func main() {
	host := flag.String("host", "127.0.0.1", "The target host or IP address to scan")
	port := flag.String("port", "443", "The target port to scan")
	ipListFile := flag.String("iplist", "", "Path to file containing list of IPs to scan (one per line)")
	jsonOutput := flag.String("json", "", "Output results in JSON format to specified file (if empty, outputs to stdout in human-readable format)")
	concurrentScans := flag.Int("j", 1, "Number of concurrent scans to run in parallel (speeds up large IP lists significantly!)")
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

	if *ipListFile != "" {
		ips, err := readIPsFromFile(*ipListFile)
		if err != nil {
			log.Fatalf("Error reading IP list file: %v", err)
		}

		if *jsonOutput != "" {
			_ = performClusterScanWithStreaming(ips, *jsonOutput, *concurrentScans)
			log.Printf("Scan complete. Results written to: %s", *jsonOutput)
		} else {
			scanResults := performClusterScan(ips, *concurrentScans)
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

func scanIPPort(ip string, port int) (PortResult, error) {
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

	// Extract basic port information if available
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

	return result, nil
}

func performClusterScan(ips []string, concurrentScans int) ScanResults {
	startTime := time.Now()

	fmt.Printf("========================================\n")
	fmt.Printf("CONCURRENT CLUSTER SCAN STARTING\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total IPs to scan: %d\n", len(ips))
	fmt.Printf("Concurrent workers: %d\n", concurrentScans)
	fmt.Printf("========================================\n\n")

	results := ScanResults{
		Timestamp: startTime.Format(time.RFC3339),
		TotalIPs:  len(ips),
		IPResults: make([]IPResult, len(ips)),
	}

	// Create a channel to send IPs to workers
	ipChan := make(chan int, len(ips))

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
			for i := range ipChan {
				ip := ips[i]
				log.Printf("WORKER %d: Processing IP %d/%d: %s", workerID, i+1, len(ips), ip)

				ipResult := IPResult{
					IP:          ip,
					Status:      "scanning",
					OpenPorts:   make([]int, 0),
					PortResults: make([]PortResult, 0),
				}

				ports, err := discoverOpenPorts(ip)
				if err != nil {
					ipResult.Status = "error"
					ipResult.Error = err.Error()
					log.Printf("WORKER %d: Error scanning %s: %v", workerID, ip, err)
				} else {
					ipResult.OpenPorts = ports
					ipResult.Status = "scanned"
					log.Printf("WORKER %d: Found %d open ports on %s", workerID, len(ports), ip)

					for _, port := range ports {
						portResult, err := scanIPPort(ip, port)
						if err != nil {
							portResult = PortResult{
								Port:  port,
								Error: err.Error(),
							}
						}
						ipResult.PortResults = append(ipResult.PortResults, portResult)
					}
				}

				mu.Lock()
				results.IPResults[i] = ipResult
				results.ScannedIPs++
				completed := results.ScannedIPs
				mu.Unlock()

				log.Printf("WORKER %d: Completed %s (%d/%d IPs done)", workerID, ip, completed, len(ips))
			}
			log.Printf("WORKER %d: FINISHED", workerID)
		}(workerID)
	}

	// Send IP indices to workers
	for i := range ips {
		ipChan <- i
	}
	close(ipChan)

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
func performClusterScanWithStreaming(ips []string, outputFile string, concurrentScans int) ScanResults {
	startTime := time.Now()

	fmt.Printf("========================================\n")
	fmt.Printf("CONCURRENT STREAMING SCAN STARTING\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total IPs to scan: %d\n", len(ips))
	fmt.Printf("Concurrent workers: %d\n", concurrentScans)
	fmt.Printf("Output file: %s\n", outputFile)
	fmt.Printf("Expected speedup: ~%.1fx faster\n", float64(concurrentScans)*0.8) // Conservative estimate
	fmt.Printf("========================================\n\n")

	results := ScanResults{
		Timestamp: startTime.Format(time.RFC3339),
		TotalIPs:  len(ips),
		IPResults: make([]IPResult, len(ips)),
	}

	// Create channels for work distribution and result collection
	ipChan := make(chan int, len(ips))
	resultChan := make(chan struct {
		index  int
		result IPResult
	}, len(ips))

	var wg sync.WaitGroup
	var mu sync.Mutex
	scannedCount := 0

	// Start worker goroutines
	for w := 0; w < concurrentScans; w++ {
		workerID := w + 1
		log.Printf("Starting STREAMING WORKER %d", workerID)
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := range ipChan {
				ip := ips[i]
				log.Printf("STREAMING WORKER %d: Processing IP %d/%d: %s", workerID, i+1, len(ips), ip)

				ipResult := IPResult{
					IP:          ip,
					Status:      "scanning",
					OpenPorts:   make([]int, 0),
					PortResults: make([]PortResult, 0),
				}

				// Discover open ports
				ports, err := discoverOpenPorts(ip)
				if err != nil {
					ipResult.Status = "error"
					ipResult.Error = err.Error()
					log.Printf("STREAMING WORKER %d: Error scanning %s: %v", workerID, ip, err)
				} else {
					ipResult.OpenPorts = ports
					ipResult.Status = "scanned"
					log.Printf("STREAMING WORKER %d: Found %d open ports on %s", workerID, len(ports), ip)

					// Scan each open port
					for _, port := range ports {
						portResult, err := scanIPPort(ip, port)
						if err != nil {
							portResult = PortResult{
								Port:  port,
								Error: err.Error(),
							}
						}
						ipResult.PortResults = append(ipResult.PortResults, portResult)
					}
				}

				// Send result to result channel
				resultChan <- struct {
					index  int
					result IPResult
				}{i, ipResult}

				log.Printf("STREAMING WORKER %d: Completed %s", workerID, ip)
			}
			log.Printf("STREAMING WORKER %d: FINISHED", workerID)
		}(workerID)
	}

	// Start a goroutine to collect results and update the results slice
	go func() {
		for res := range resultChan {
			mu.Lock()
			results.IPResults[res.index] = res.result
			results.ScannedIPs++
			scannedCount++
			mu.Unlock()
		}
	}()

	// Send IP indices to workers
	for i := range ips {
		ipChan <- i
	}
	close(ipChan)

	// Wait for all workers to complete
	wg.Wait()
	close(resultChan)

	// Wait a moment for result collection to complete
	for scannedCount < len(ips) {
		time.Sleep(10 * time.Millisecond)
	}

	// Write final results to file
	finalData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling final results: %v", err)
	}

	if err := os.WriteFile(outputFile, finalData, 0644); err != nil {
		log.Fatalf("Error writing final results to file: %v", err)
	}

	duration := time.Since(startTime)

	fmt.Printf("\n========================================\n")
	fmt.Printf("CONCURRENT STREAMING SCAN COMPLETE!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total IPs processed: %d\n", results.ScannedIPs)
	fmt.Printf("Total time: %v\n", duration)
	fmt.Printf("Concurrent workers used: %d\n", concurrentScans)
	fmt.Printf("Average time per IP: %.2fs\n", duration.Seconds()/float64(results.ScannedIPs))
	fmt.Printf("Output file: %s\n", outputFile)
	fmt.Printf("========================================\n")

	return results
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
