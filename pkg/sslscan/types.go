package sslscan

import "encoding/xml"

// Document represents the root XML structure from sslscan
type Document struct {
	XMLName xml.Name `xml:"document"`
	Title   string   `xml:"title,attr"`
	Version string   `xml:"version,attr"`
	SSLTest SSLTest  `xml:"ssltest"`
	Errors  []string `xml:"error"`
}

// SSLTest represents the main SSL test results
type SSLTest struct {
	XMLName       xml.Name      `xml:"ssltest"`
	Host          string        `xml:"host,attr"`
	SNIName       string        `xml:"sniname,attr"`
	Port          string        `xml:"port,attr"`
	Protocols     []Protocol    `xml:"protocol"`
	Ciphers       []Cipher      `xml:"cipher"`
	Heartbleeds   []Heartbleed  `xml:"heartbleed"`
	Fallback      Fallback      `xml:"fallback"`
	Renegotiation Renegotiation `xml:"renegotiation"`
	Groups        []Group       `xml:"group"`
	Certificates  Certificates  `xml:"certificates"`
}

// Protocol represents SSL/TLS protocol information
type Protocol struct {
	XMLName xml.Name `xml:"protocol"`
	Type    string   `xml:"type,attr"`
	Version string   `xml:"version,attr"`
	Enabled string   `xml:"enabled,attr"`
}

// Cipher represents cipher suite information
type Cipher struct {
	XMLName    xml.Name `xml:"cipher"`
	Status     string   `xml:"status,attr"`
	SSLVersion string   `xml:"sslversion,attr"`
	Bits       string   `xml:"bits,attr"`
	Cipher     string   `xml:"cipher,attr"`
	ID         string   `xml:"id,attr"`
	Strength   string   `xml:"strength,attr"`
	Curve      string   `xml:"curve,attr,omitempty"`
	ECDHEBits  string   `xml:"ecdhebits,attr,omitempty"`
}

// Heartbleed represents heartbleed vulnerability test results
type Heartbleed struct {
	XMLName    xml.Name `xml:"heartbleed"`
	SSLVersion string   `xml:"sslversion,attr"`
	Vulnerable string   `xml:"vulnerable,attr"`
}

// Fallback represents TLS fallback SCSV support
type Fallback struct {
	XMLName   xml.Name `xml:"fallback"`
	Supported string   `xml:"supported,attr"`
}

// Renegotiation represents TLS renegotiation support
type Renegotiation struct {
	XMLName   xml.Name `xml:"renegotiation"`
	Supported string   `xml:"supported,attr"`
	Secure    string   `xml:"secure,attr"`
}

// Group represents key exchange groups
type Group struct {
	XMLName    xml.Name `xml:"group"`
	SSLVersion string   `xml:"sslversion,attr"`
	Bits       string   `xml:"bits,attr"`
	Name       string   `xml:"name,attr"`
	ID         string   `xml:"id,attr"`
}

// Certificates contains certificate information
type Certificates struct {
	XMLName     xml.Name    `xml:"certificates"`
	Certificate Certificate `xml:"certificate"`
}

// Certificate represents SSL certificate information
type Certificate struct {
	XMLName            xml.Name `xml:"certificate"`
	Type               string   `xml:"type,attr"`
	SignatureAlgorithm string   `xml:"signature-algorithm"`
	Subject            string   `xml:"subject"`
	AltNames           string   `xml:"altnames"`
	Issuer             string   `xml:"issuer"`
	SelfSigned         string   `xml:"self-signed"`
	NotValidBefore     string   `xml:"not-valid-before"`
	NotYetValid        string   `xml:"not-yet-valid"`
	NotValidAfter      string   `xml:"not-valid-after"`
	Expired            string   `xml:"expired"`
}

// Result represents processed sslscan output for compatibility
type Result struct {
	Host          string          `json:"host"`
	Port          string          `json:"port"`
	Protocols     []ProtocolInfo  `json:"protocols"`
	Ciphers       []CipherInfo    `json:"ciphers"`
	SecurityTests []SecurityTest  `json:"security_tests"`
	Certificate   CertificateInfo `json:"certificate"`
}

// ProtocolInfo represents processed protocol information
type ProtocolInfo struct {
	Version string `json:"version"`
	Status  string `json:"status"` // enabled/disabled
}

// CipherInfo represents processed cipher suite information
type CipherInfo struct {
	Protocol    string `json:"protocol"`
	Bits        string `json:"bits"`
	Cipher      string `json:"cipher"`
	Preference  string `json:"preference"` // Preferred/Accepted
	KeyExchange string `json:"key_exchange,omitempty"`
	Strength    string `json:"strength,omitempty"`
}

// SecurityTest represents processed security test results
type SecurityTest struct {
	Test   string `json:"test"`
	Result string `json:"result"`
}

// CertificateInfo represents processed certificate information
type CertificateInfo struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}
