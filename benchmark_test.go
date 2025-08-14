package main

import (
	"testing"

	"github.com/richardsonnick/check-network/pkg/sslscan"
)

// BenchmarkSingleHostSSL benchmarks a single SSL scan using nmap
func BenchmarkSingleHostSSL(b *testing.B) {
	if !isNmapInstalled() {
		b.Skip("nmap not installed")
	}

	host := "google.com"
	port := "443"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanSingleHost(host, port)
		if err != nil {
			b.Errorf("scan failed: %v", err)
		}
	}
}

// BenchmarkSslscan benchmarks sslscan performance
func BenchmarkSslscan(b *testing.B) {
	scanner := sslscan.NewScanner()
	if !scanner.IsInstalled() {
		b.Skip("sslscan not installed")
	}

	host := "google.com"
	port := "443"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.Scan(host, port)
		if err != nil {
			b.Errorf("sslscan failed: %v", err)
		}
	}
}

// BenchmarkPortDiscovery benchmarks port discovery using nmap
func BenchmarkPortDiscovery(b *testing.B) {
	if !isNmapInstalled() {
		b.Skip("nmap not installed")
	}

	host := "scanme.nmap.org" // Known test target

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := discoverOpenPorts(host)
		if err != nil {
			b.Errorf("port discovery failed: %v", err)
		}
	}
}

// BenchmarkClusterScan2 benchmarks cluster scan with 2 targets
func BenchmarkClusterScan2(b *testing.B) {
	if !isNmapInstalled() {
		b.Skip("nmap not installed")
	}

	targets := []string{"google.com", "github.com"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		performClusterScan(targets, false)
	}
}
