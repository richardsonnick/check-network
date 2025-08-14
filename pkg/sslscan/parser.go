package sslscan

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// ParseXMLOutput parses sslscan XML output into structured data
func ParseXMLOutput(xmlOutput string) (Result, error) {
	var doc Document
	err := xml.Unmarshal([]byte(xmlOutput), &doc)
	if err != nil {
		return Result{}, fmt.Errorf("failed to unmarshal XML: %v", err)
	}

	// Convert XML structure to our Result format
	result := Result{
		Host:          doc.SSLTest.Host,
		Port:          doc.SSLTest.Port,
		Protocols:     convertProtocols(doc.SSLTest.Protocols),
		Ciphers:       convertCiphers(doc.SSLTest.Ciphers),
		SecurityTests: convertSecurityTests(doc.SSLTest),
		Certificate:   convertCertificate(doc.SSLTest.Certificates.Certificate),
	}

	return result, nil
}

// convertProtocols converts XML Protocol slice to ProtocolInfo slice
func convertProtocols(protocols []Protocol) []ProtocolInfo {
	result := make([]ProtocolInfo, 0, len(protocols))

	for _, proto := range protocols {
		status := "disabled"
		if proto.Enabled == "1" {
			status = "enabled"
		}

		version := fmt.Sprintf("%sv%s", strings.ToUpper(proto.Type), proto.Version)

		result = append(result, ProtocolInfo{
			Version: version,
			Status:  status,
		})
	}

	return result
}

// convertCiphers converts XML Cipher slice to CipherInfo slice
func convertCiphers(ciphers []Cipher) []CipherInfo {
	result := make([]CipherInfo, 0, len(ciphers))

	for _, cipher := range ciphers {
		preference := "Accepted"
		if cipher.Status == "preferred" {
			preference = "Preferred"
		}

		keyExchange := ""
		if cipher.Curve != "" {
			keyExchange = fmt.Sprintf("Curve %s", cipher.Curve)
			if cipher.ECDHEBits != "" {
				keyExchange += fmt.Sprintf(" DHE %s", cipher.ECDHEBits)
			}
		}

		result = append(result, CipherInfo{
			Protocol:    cipher.SSLVersion,
			Bits:        cipher.Bits,
			Cipher:      cipher.Cipher,
			Preference:  preference,
			KeyExchange: keyExchange,
			Strength:    cipher.Strength,
		})
	}

	return result
}

// convertSecurityTests converts various security test results to SecurityTest slice
func convertSecurityTests(ssltest SSLTest) []SecurityTest {
	var tests []SecurityTest

	// Heartbleed tests
	for _, hb := range ssltest.Heartbleeds {
		status := "not vulnerable"
		if hb.Vulnerable == "1" {
			status = "vulnerable"
		}
		tests = append(tests, SecurityTest{
			Test:   "Heartbleed",
			Result: fmt.Sprintf("%s %s to heartbleed", hb.SSLVersion, status),
		})
	}

	// TLS Fallback SCSV
	if ssltest.Fallback.Supported == "1" {
		tests = append(tests, SecurityTest{
			Test:   "TLS Fallback SCSV",
			Result: "Server supports TLS Fallback SCSV",
		})
	}

	// TLS Renegotiation
	if ssltest.Renegotiation.Supported == "1" {
		secureText := "insecure"
		if ssltest.Renegotiation.Secure == "1" {
			secureText = "secure"
		}
		tests = append(tests, SecurityTest{
			Test:   "TLS renegotiation",
			Result: fmt.Sprintf("%s session renegotiation supported", strings.Title(secureText)),
		})
	}

	return tests
}

// convertCertificate converts XML Certificate to CertificateInfo
func convertCertificate(cert Certificate) CertificateInfo {
	return CertificateInfo{
		Subject:   cert.Subject,
		Issuer:    cert.Issuer,
		NotBefore: cert.NotValidBefore,
		NotAfter:  cert.NotValidAfter,
	}
}
