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
	"IP", "Port", "Pod Name", "Namespace", "Component Name", "Component Maintainer",
	"Process", "TLS Ciphers", "TLS Version",
	"Ingress Configured Profile", "Ingress Configured MinVersion", "Ingress Configured Ciphers",
	"API Configured Profile", "API Configured MinVersion", "API Configured Ciphers",
	"Kubelet Configured MinVersion", "Kubelet Configured Ciphers",
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

	rowCount := 0

	// Defensive checks for nil TLSSecurityConfig
	// TODO initialize these values in the results struct to avoid this mess.
	var ingressProfile, ingressMinVersion, ingressCiphers string
	var apiProfile, apiMinVersion, apiCiphers string
	var kubeletMinVersion, kubeletCiphers string

	if results.TLSSecurityConfig != nil {
		if results.TLSSecurityConfig.IngressController != nil {
			ingressProfile = stringOrNA(results.TLSSecurityConfig.IngressController.Type)
			ingressMinVersion = stringOrNA(results.TLSSecurityConfig.IngressController.MinTLSVersion)
			ingressCiphers = joinOrNA(removeDuplicates(results.TLSSecurityConfig.IngressController.Ciphers))
		} else {
			ingressProfile = "N/A"
			ingressMinVersion = "N/A"
			ingressCiphers = "N/A"
		}
		if results.TLSSecurityConfig.APIServer != nil {
			apiProfile = stringOrNA(results.TLSSecurityConfig.APIServer.Type)
			apiMinVersion = stringOrNA(results.TLSSecurityConfig.APIServer.MinTLSVersion)
			apiCiphers = joinOrNA(removeDuplicates(results.TLSSecurityConfig.APIServer.Ciphers))
		} else {
			apiProfile = "N/A"
			apiMinVersion = "N/A"
			apiCiphers = "N/A"
		}
		if results.TLSSecurityConfig.KubeletConfig != nil {
			kubeletMinVersion = stringOrNA(results.TLSSecurityConfig.KubeletConfig.TLSMinVersion)
			kubeletCiphers = joinOrNA(removeDuplicates(results.TLSSecurityConfig.KubeletConfig.TLSCipherSuites))
		} else {
			kubeletMinVersion = "N/A"
			kubeletCiphers = "N/A"
		}
	} else {
		ingressProfile = "N/A"
		ingressMinVersion = "N/A"
		ingressCiphers = "N/A"
		apiProfile = "N/A"
		apiMinVersion = "N/A"
		apiCiphers = "N/A"
		kubeletMinVersion = "N/A"
		kubeletCiphers = "N/A"
	}

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
				"IP":                            ipAddress,
				"Port":                          port,
				"Pod Name":                      ipResult.Pod.Name,
				"Namespace":                     ipResult.Pod.Namespace,
				"Component Name":                ipResult.OpenshiftComponent.Component,
				"Component Maintainer":          ipResult.OpenshiftComponent.MaintainerComponent,
				"Process":                       processName,
				"TLS Ciphers":                   joinOrNA(allDetectedCiphers),
				"TLS Version":                   joinOrNA(tlsVersions),
				"Ingress Configured Profile":    ingressProfile,
				"Ingress Configured MinVersion": ingressMinVersion,
				"Ingress Configured Ciphers":    ingressCiphers,
				"API Configured Profile":        apiProfile,
				"API Configured MinVersion":     apiMinVersion,
				"API Configured Ciphers":        apiCiphers,
				"Kubelet Configured MinVersion": kubeletMinVersion,
				"Kubelet Configured Ciphers":    kubeletCiphers,
			}

			row := buildCSVRow(csvColumns, rowData)
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write CSV row: %v", err)
			}
			rowCount++
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
