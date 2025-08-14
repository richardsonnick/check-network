package sslscan

import (
	"encoding/json"
	"fmt"
	"os"
)

// PrintResults prints sslscan results in a format similar to nmap output
func PrintResults(result Result, jsonOutput bool) {
	if jsonOutput {
		json.NewEncoder(os.Stdout).Encode(result)
		return
	}

	// Print in a format similar to nmap
	fmt.Printf("HOST: %s PORT: %s\n", result.Host, result.Port)
	fmt.Printf("SSL/TLS PROTOCOLS:\n")
	for _, protocol := range result.Protocols {
		fmt.Printf("  %s: %s\n", protocol.Version, protocol.Status)
	}

	fmt.Printf("\nSUPPORTED CIPHERS:\n")
	for _, cipher := range result.Ciphers {
		fmt.Printf("  %s %s %s bits %s", cipher.Preference, cipher.Protocol, cipher.Bits, cipher.Cipher)
		if cipher.KeyExchange != "" {
			fmt.Printf(" (%s)", cipher.KeyExchange)
		}
		fmt.Printf("\n")
	}

	if len(result.SecurityTests) > 0 {
		fmt.Printf("\nSECURITY TESTS:\n")
		for _, test := range result.SecurityTests {
			fmt.Printf("  %s: %s\n", test.Test, test.Result)
		}
	}

	if result.Certificate.Subject != "" {
		fmt.Printf("\nCERTIFICATE INFO:\n")
		fmt.Printf("  Subject: %s\n", result.Certificate.Subject)
		if result.Certificate.Issuer != "" {
			fmt.Printf("  Issuer: %s\n", result.Certificate.Issuer)
		}
	}
}
