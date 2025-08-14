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
	"time"

	"github.com/richardsonnick/check-network/pkg/sslscan"
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
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	useSslscan := flag.Bool("sslscan", false, "Use sslscan instead of nmap for SSL scanning")
	flag.Parse()

	if !*useSslscan && !isNmapInstalled() {
		log.Fatal("Error: Nmap is not installed or not in the system's PATH. This program is a wrapper and requires Nmap to function.")
	}

	if *useSslscan {
		scanner := sslscan.NewScanner()
		if !scanner.IsInstalled() {
			log.Fatal("Error: sslscan is not installed or not in the system's PATH. Install with: brew install sslscan")
		}
	}

	if *ipListFile != "" {
		ips, err := readIPsFromFile(*ipListFile)
		if err != nil {
			log.Fatalf("Error reading IP list file: %v", err)
		}

		if *useSslscan {
			// Use sslscan for cluster scanning
			results := performSslscanClusterScan(ips, *port, *jsonOutput)
			if *jsonOutput {
				json.NewEncoder(os.Stdout).Encode(results)
			} else {
				printSslscanClusterResults(results)
			}
		} else {
			// Use nmap for cluster scanning
			scanResults := performClusterScan(ips, *jsonOutput)
			if *jsonOutput {
				json.NewEncoder(os.Stdout).Encode(scanResults)
			} else {
				printClusterResults(scanResults)
			}
		}
		return
	}

	if *useSslscan {
		if !*jsonOutput {
			log.Printf("Using sslscan. Starting scan on %s:%s...\n\n", *host, *port)
		}
		scanner := sslscan.NewScanner()
		result, err := scanner.Scan(*host, *port)
		if err != nil {
			log.Fatalf("Error scanning host with sslscan: %v", err)
		}
		sslscan.PrintResults(result, *jsonOutput)
	} else {
		if !*jsonOutput {
			log.Printf("Using nmap. Starting scan on %s:%s...\n\n", *host, *port)
		}
		result, err := scanSingleHost(*host, *port)
		if err != nil {
			log.Fatalf("Error scanning host: %v", err)
		}
		printParsedResults(result, *jsonOutput)
	}
}

func isNmapInstalled() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

func scanSingleHost(host, port string) (NmapRun, error) {
	cmd := exec.Command("nmap", "-sV", "--script", "ssl-enum-ciphers", "-p", port, "-oX", "-", host)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return NmapRun{}, fmt.Errorf("nmap command failed: %v, output: %s", err, string(output))
	}

	var nmapResult NmapRun
	if err := xml.Unmarshal(output, &nmapResult); err != nil {
		return NmapRun{}, fmt.Errorf("failed to parse nmap XML output: %v", err)
	}

	return nmapResult, nil
}

// SslscanClusterResults represents results from scanning multiple hosts with sslscan
type SslscanClusterResults struct {
	Timestamp    string           `json:"timestamp"`
	TotalHosts   int              `json:"total_hosts"`
	ScannedHosts int              `json:"scanned_hosts"`
	Port         string           `json:"port"`
	Results      []sslscan.Result `json:"results"`
}

// performSslscanClusterScan scans multiple hosts using sslscan
func performSslscanClusterScan(hosts []string, port string, jsonOutput bool) SslscanClusterResults {
	startTime := time.Now()
	if !jsonOutput {
		log.Printf("Starting sslscan cluster scan of %d hosts on port %s...", len(hosts), port)
	}

	results := SslscanClusterResults{
		Timestamp:  startTime.Format(time.RFC3339),
		TotalHosts: len(hosts),
		Port:       port,
		Results:    make([]sslscan.Result, 0, len(hosts)),
	}

	scanner := sslscan.NewScanner()

	for i, host := range hosts {
		if !jsonOutput {
			log.Printf("Scanning host %d/%d: %s", i+1, len(hosts), host)
		}

		result, err := scanner.Scan(host, port)
		if err != nil {
			if !jsonOutput {
				log.Printf("Error scanning %s: %v", host, err)
			}
			// Add error result
			errorResult := sslscan.Result{
				Host: host,
				Port: port,
			}
			results.Results = append(results.Results, errorResult)
		} else {
			results.Results = append(results.Results, result)
			results.ScannedHosts++
		}
	}

	duration := time.Since(startTime)
	if !jsonOutput {
		log.Printf("Sslscan cluster scan complete. Scanned %d/%d hosts in %v",
			results.ScannedHosts, results.TotalHosts, duration)
	}

	return results
}

// printSslscanClusterResults prints cluster scan results from sslscan
func printSslscanClusterResults(results SslscanClusterResults) {
	fmt.Printf("=== SSLSCAN CLUSTER SCAN RESULTS ===\n")
	fmt.Printf("Timestamp: %s\n", results.Timestamp)
	fmt.Printf("Port: %s\n", results.Port)
	fmt.Printf("Total Hosts: %d\n", results.TotalHosts)
	fmt.Printf("Successfully Scanned: %d\n", results.ScannedHosts)
	fmt.Printf("\n")

	for i, result := range results.Results {
		fmt.Printf("-----------------------------------------------------\n")
		fmt.Printf("Host %d/%d: %s\n", i+1, len(results.Results), result.Host)

		if len(result.Protocols) == 0 && len(result.Ciphers) == 0 {
			fmt.Printf("Status: Error or no SSL/TLS found\n")
			continue
		}

		// Print protocols
		fmt.Printf("SSL/TLS Protocols:\n")
		for _, protocol := range result.Protocols {
			fmt.Printf("  %s: %s\n", protocol.Version, protocol.Status)
		}

		// Print enabled protocols summary
		enabledProtocols := make([]string, 0)
		for _, protocol := range result.Protocols {
			if protocol.Status == "enabled" {
				enabledProtocols = append(enabledProtocols, protocol.Version)
			}
		}
		fmt.Printf("Enabled Protocols: %v\n", enabledProtocols)

		// Print cipher count by protocol
		cipherCounts := make(map[string]int)
		for _, cipher := range result.Ciphers {
			cipherCounts[cipher.Protocol]++
		}
		fmt.Printf("Cipher Counts: ")
		for proto, count := range cipherCounts {
			fmt.Printf("%s=%d ", proto, count)
		}
		fmt.Printf("\n")

		// Print weak ciphers (< 128 bits or 3DES)
		weakCiphers := make([]string, 0)
		for _, cipher := range result.Ciphers {
			if cipher.Bits == "112" || strings.Contains(cipher.Cipher, "3DES") {
				weakCiphers = append(weakCiphers, cipher.Cipher)
			}
		}
		if len(weakCiphers) > 0 {
			fmt.Printf("⚠️  Weak Ciphers Found: %v\n", weakCiphers)
		}

		// Print security test summary
		if len(result.SecurityTests) > 0 {
			vulnerabilities := make([]string, 0)
			for _, test := range result.SecurityTests {
				if strings.Contains(strings.ToLower(test.Result), "vulnerable") {
					vulnerabilities = append(vulnerabilities, test.Test)
				}
			}
			if len(vulnerabilities) > 0 {
				fmt.Printf("🔴 Vulnerabilities: %v\n", vulnerabilities)
			} else {
				fmt.Printf("✅ No known vulnerabilities\n")
			}
		}

		fmt.Printf("\n")
	}
}

func printParsedResults(run NmapRun, jsonOutput bool) {
	if len(run.Hosts) == 0 {
		if jsonOutput {
			json.NewEncoder(os.Stdout).Encode(map[string]string{"message": "No hosts were scanned or host is down."})
		} else {
			log.Println("No hosts were scanned or host is down.")
		}
		return
	}

	if jsonOutput {
		json.NewEncoder(os.Stdout).Encode(run)
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

func performClusterScan(ips []string, jsonOutput bool) ScanResults {
	startTime := time.Now()
	if !jsonOutput {
		log.Printf("Starting cluster scan of %d unique IPs...", len(ips))
	}

	results := ScanResults{
		Timestamp: startTime.Format(time.RFC3339),
		TotalIPs:  len(ips),
		IPResults: make([]IPResult, 0, len(ips)),
	}

	for i, ip := range ips {
		if !jsonOutput {
			log.Printf("Processing IP %d/%d: %s", i+1, len(ips), ip)
		}

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
		} else {
			ipResult.OpenPorts = ports
			ipResult.Status = "scanned"

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

		results.IPResults = append(results.IPResults, ipResult)
		results.ScannedIPs++
	}

	duration := time.Since(startTime)
	if !jsonOutput {
		log.Printf("Cluster scan complete. Processed %d IPs in %v", results.ScannedIPs, duration)
	}

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
