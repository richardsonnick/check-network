package sslscan

import (
	"fmt"
	"os/exec"
)

// Scanner performs sslscan operations
type Scanner struct{}

// NewScanner creates a new sslscan scanner
func NewScanner() *Scanner {
	return &Scanner{}
}

// IsInstalled checks if sslscan is available in the system PATH
func (s *Scanner) IsInstalled() bool {
	_, err := exec.LookPath("sslscan")
	return err == nil
}

// Scan performs an SSL scan using sslscan and returns structured data
func (s *Scanner) Scan(host, port string) (Result, error) {
	target := fmt.Sprintf("%s:%s", host, port)
	cmd := exec.Command("sslscan", "--xml=-", target)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return Result{}, fmt.Errorf("sslscan command failed: %v, output: %s", err, string(output))
	}

	result, err := ParseXMLOutput(string(output))
	if err != nil {
		return Result{}, fmt.Errorf("failed to parse sslscan XML output: %v", err)
	}

	return result, nil
}
