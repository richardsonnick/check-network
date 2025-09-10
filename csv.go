package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

var csvColumns = []string{
	"IP", "Port", "Pod Name", "Namespace", "Component Name", "Component Maintainer", "Process", "TLS Ciphers", "TLS Version", "TLS Configured MinVersion", "TLS Configured Ciphers",
}

// writeCSVOutput writes scan results to a CSV file with one row per IP/port combination
func writeCSVOutput(results ScanResults, filename string) error {
	log.Printf("Writing CSV output to: %s", filename)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	if err := writer.Write(csvColumns); err != nil {
		return fmt.Errorf("failed to write CSV header: %v", err)
	}

	// Collect all configured cipher suites and minimum versions from TLS security profiles
	var allConfiguredCiphers []string
	var allConfiguredMinVersions []string
	if results.TLSSecurityConfig != nil {
		if results.TLSSecurityConfig.IngressController != nil {
			allConfiguredCiphers = append(allConfiguredCiphers, results.TLSSecurityConfig.IngressController.Ciphers...)
			if results.TLSSecurityConfig.IngressController.MinTLSVersion != "" {
				allConfiguredMinVersions = append(allConfiguredMinVersions, results.TLSSecurityConfig.IngressController.MinTLSVersion)
			}
		}
		if results.TLSSecurityConfig.APIServer != nil {
			allConfiguredCiphers = append(allConfiguredCiphers, results.TLSSecurityConfig.APIServer.Ciphers...)
			if results.TLSSecurityConfig.APIServer.MinTLSVersion != "" {
				allConfiguredMinVersions = append(allConfiguredMinVersions, results.TLSSecurityConfig.APIServer.MinTLSVersion)
			}
		}
		if results.TLSSecurityConfig.KubeletConfig != nil {
			allConfiguredCiphers = append(allConfiguredCiphers, results.TLSSecurityConfig.KubeletConfig.TLSCipherSuites...)
			if results.TLSSecurityConfig.KubeletConfig.TLSMinVersion != "" {
				allConfiguredMinVersions = append(allConfiguredMinVersions, results.TLSSecurityConfig.KubeletConfig.TLSMinVersion)
			}
		}
	}
	// Remove duplicates from configured ciphers and min versions
	allConfiguredCiphers = removeDuplicates(allConfiguredCiphers)
	allConfiguredMinVersions = removeDuplicates(allConfiguredMinVersions)

	// Write data rows - one row per IP/port combination
	for _, ipResult := range results.IPResults {
		ipAddress := ipResult.IP

		// Process each port result
		for _, portResult := range ipResult.PortResults {
			targetPort := portResult.Port

			port := strconv.Itoa(targetPort)

			// Collect all detected ciphers and TLS versions for this port
			var allDetectedCiphers []string
			var tlsVersions []string

			// Extract TLS versions and ciphers from nmap script results
			for _, host := range portResult.NmapRun.Hosts {
				for _, nmapPort := range host.Ports {
					for _, script := range nmapPort.Scripts {
						if script.ID == "ssl-enum-ciphers" {
							for _, table := range script.Tables {
								tlsVersion := table.Key
								if tlsVersion != "" {
									tlsVersions = append(tlsVersions, tlsVersion)
								}

								// Find ciphers for this TLS version
								for _, subTable := range table.Tables {
									if subTable.Key == "ciphers" {
										for _, cipherTable := range subTable.Tables {
											for _, elem := range cipherTable.Elems {
												if elem.Key == "name" && elem.Value != "" {
													allDetectedCiphers = append(allDetectedCiphers, elem.Value)
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}

			// Remove duplicates
			allDetectedCiphers = removeDuplicates(allDetectedCiphers)
			tlsVersions = removeDuplicates(tlsVersions)

			// Skip processing this row if no TLS data was found - improves performance
			if len(allDetectedCiphers) == 0 && len(tlsVersions) == 0 {
				log.Printf("Skipping CSV row for %s:%s - no TLS data detected", ipAddress, port)
				continue
			}

			// Only get process name for rows with TLS data (already filtered in scanIPPort, but double-check)
			processName := stringOrNA(portResult.ProcessName)

			// Create row data
			rowData := map[string]string{
				"IP":                        ipAddress,
				"Port":                      port,
				"Pod Name":                  ipResult.Pod.Name,
				"Namespace":                 ipResult.Pod.Namespace,
				"Component Name":            ipResult.OpenshiftComponent.Component,
				"Component Maintainer":      ipResult.OpenshiftComponent.MaintainerComponent,
				"Process":                   processName,
				"TLS Ciphers":               joinOrNA(allDetectedCiphers),
				"TLS Version":               joinOrNA(tlsVersions),
				"TLS Configured MinVersion": joinOrNA(allConfiguredMinVersions),
				"TLS Configured Ciphers":    joinOrNA(allConfiguredCiphers),
			}

			row := buildCSVRow(csvColumns, rowData)
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write CSV row: %v", err)
			}
		}

	}

	return nil
}

// writeScanErrorsCSV writes scan errors to a CSV file
func writeScanErrorsCSV(results ScanResults, filename string) error {
	if len(results.ScanErrors) == 0 {
		log.Printf("No scan errors to write to CSV file")
		return nil
	}

	log.Printf("Writing scan errors to: %s", filename)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create scan errors CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"IP", "Port", "Error Type", "Error Message", "Pod Name", "Namespace", "Container"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write scan errors CSV header: %v", err)
	}

	// Write error rows
	for _, scanError := range results.ScanErrors {
		row := []string{
			scanError.IP,
			strconv.Itoa(scanError.Port),
			scanError.ErrorType,
			scanError.ErrorMsg,
			stringOrNA(scanError.PodName),
			stringOrNA(scanError.Namespace),
			stringOrNA(scanError.Container),
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write scan error row: %v", err)
		}
	}

	log.Printf("Successfully wrote %d scan error rows to CSV file", len(results.ScanErrors))
	return nil
}

// Helper function to build CSV row based on selected columns
func buildCSVRow(selectedColumns []string, data map[string]string) []string {
	row := make([]string, len(selectedColumns))
	for i, col := range selectedColumns {
		if value, exists := data[col]; exists {
			row[i] = value
		} else {
			row[i] = "N/A"
		}
	}
	return row
}

// Helper functions
func stringOrNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func joinOrNA(slice []string) string {
	if len(slice) == 0 {
		return "N/A"
	}
	return strings.Join(slice, ", ")
}

// Helper function to remove duplicates from string slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !keys[item] && item != "" {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}
