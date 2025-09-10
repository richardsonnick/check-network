package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
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
	Timestamp         string              `json:"timestamp"`
	TotalIPs          int                 `json:"total_ips"`
	ScannedIPs        int                 `json:"scanned_ips"`
	IPResults         []IPResult          `json:"ip_results"`
	TLSSecurityConfig *TLSSecurityProfile `json:"tls_security_config,omitempty"`
	ScanErrors        []ScanError         `json:"scan_errors,omitempty"`
}

// ScanError represents a scanning error for a specific IP:port
type ScanError struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	ErrorType string `json:"error_type"`
	ErrorMsg  string `json:"error_message"`
	PodName   string `json:"pod_name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Container string `json:"container,omitempty"`
}

type IPResult struct {
	IP                 string              `json:"ip"`
	Status             string              `json:"status"`
	OpenPorts          []int               `json:"open_ports"`
	PortResults        []PortResult        `json:"port_results"`
	OpenshiftComponent *OpenshiftComponent `json:"openshift_component,omitempty"`
	Pod                *PodInfo            `json:"pod,omitempty"`
	Services           []ServiceInfo       `json:"services,omitempty"`
	Error              string              `json:"error,omitempty"`
}

type ServiceInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	Ports     []int  `json:"ports,omitempty"`
}

type PodInfo struct {
	Name       string   // Pod name
	Namespace  string   // Pod namespace
	Image      string   // Container image
	IPs        []string // List of IPs assigned to the pod
	Containers []string // List of container names
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

// TLSSecurityProfile represents TLS configuration from OpenShift components
type TLSSecurityProfile struct {
	IngressController *IngressTLSProfile   `json:"ingress_controller,omitempty"`
	APIServer         *APIServerTLSProfile `json:"api_server,omitempty"`
	KubeletConfig     *KubeletTLSProfile   `json:"kubelet_config,omitempty"`
}

type IngressTLSProfile struct {
	Type          string   `json:"type,omitempty"`
	MinTLSVersion string   `json:"min_tls_version,omitempty"`
	Ciphers       []string `json:"ciphers,omitempty"`
	Raw           string   `json:"raw,omitempty"`
}

type APIServerTLSProfile struct {
	Type          string   `json:"type,omitempty"`
	MinTLSVersion string   `json:"min_tls_version,omitempty"`
	Ciphers       []string `json:"ciphers,omitempty"`
	Raw           string   `json:"raw,omitempty"`
}

type KubeletTLSProfile struct {
	TLSCipherSuites []string `json:"tls_cipher_suites,omitempty"`
	TLSMinVersion   string   `json:"tls_min_version,omitempty"`
	Raw             string   `json:"raw,omitempty"`
}

type K8sClient struct {
	clientset                 *kubernetes.Clientset
	restCfg                   *rest.Config
	podIPMap                  map[string]v1.Pod         // IP -> PodName
	processNameMap            map[string]map[int]string // IP -> Port -> Process Name
	processDiscoveryAttempted map[string]bool           // Pod Name -> bool
	processCacheMutex         sync.Mutex
	namespace                 string
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
		clientset:                 clientset,
		restCfg:                   config,
		podIPMap:                  make(map[string]v1.Pod),
		processNameMap:            make(map[string]map[int]string),
		processDiscoveryAttempted: make(map[string]bool),
		namespace:                 namespace,
	}, nil
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

// TODO: This is much different than how check-payload does it...
// https://github.com/openshift/check-payload/blob/1c3541964ab045305b9754305e99ab80d35da8e4/internal/podman/podman.go#L157
func (k *K8sClient) parseOpenshiftComponentFromImageRef(image string) *OpenshiftComponent {
	// Handle OpenShift release images - similar to check-payload approach
	if strings.Contains(image, "quay.io/openshift-release-dev") {
		// Extract component from OpenShift release image path
		// Format: quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:...
		component := &OpenshiftComponent{
			SourceLocation:      "quay.io/openshift-release-dev",
			MaintainerComponent: "openshift",
			IsBundle:            false,
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
				IsBundle:            false,
			}
		}
	}

	// Handle other registries (quay.io, registry.redhat.com, etc.)
	if strings.Contains(image, "quay.io") || strings.Contains(image, "registry.redhat.com") {
		return &OpenshiftComponent{
			Component:           k.extractComponentNameFromImage(image),
			SourceLocation:      k.extractRegistryFromImage(image),
			MaintainerComponent: "redhat",
			IsBundle:            false,
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
					IsBundle:            false,
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
		IsBundle:            false,
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// getProcessMapForPod executes a single lsof command to get all listening ports and processes for a pod
func (k *K8sClient) getProcessMapForPod(pod PodInfo) (map[string]map[int]string, error) {
	processMap := make(map[string]map[int]string)
	if len(pod.Containers) == 0 {
		return processMap, nil
	}

	// lsof command to get port and command name for all listening TCP ports
	command := []string{"/bin/sh", "-c", "lsof -i -sTCP:LISTEN -P -n -F cn"}

	// We only need to run this in one container, as networking is shared across the pod
	containerName := pod.Containers[0]

	req := k.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
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
		return nil, fmt.Errorf("failed to create executor for pod %s: %v", pod.Name, err)
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	if err != nil {
		return nil, fmt.Errorf("exec failed on pod %s: %v, stderr: %s", pod.Name, err, stderr.String())
	}

	// Parse the lsof output
	scanner := bufio.NewScanner(&stdout)
	var currentProcess string
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 1 {
			fieldType := line[0]
			fieldValue := line[1:]

			switch fieldType {
			case 'c':
				currentProcess = fieldValue
			case 'n':
				// Format is expected to be something like *:port or IP:port
				parts := strings.Split(fieldValue, ":")
				if len(parts) == 2 {
					portStr := parts[1]
					port, err := strconv.Atoi(portStr)
					if err == nil {
						// Map all pod IPs to this port and process
						for _, ip := range pod.IPs {
							if _, ok := processMap[ip]; !ok {
								processMap[ip] = make(map[int]string)
							}
							processMap[ip][port] = currentProcess
						}
					}
				}
			}
		}
	}

	return processMap, nil
}

func (k *K8sClient) getAndCachePodProcesses(pod PodInfo) {
	k.processCacheMutex.Lock()
	if k.processDiscoveryAttempted[pod.Name] {
		k.processCacheMutex.Unlock()
		return // Discovery already attempted for this pod
	}
	// Mark as attempted before unlocking to prevent other goroutines from trying
	k.processDiscoveryAttempted[pod.Name] = true
	k.processCacheMutex.Unlock()

	processMap, err := k.getProcessMapForPod(pod)
	if err != nil {
		log.Printf("Could not get process map for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		return
	}

	if len(processMap) > 0 {
		k.processCacheMutex.Lock()
		defer k.processCacheMutex.Unlock()
		for ip, portMap := range processMap {
			if _, ok := k.processNameMap[ip]; !ok {
				k.processNameMap[ip] = make(map[int]string)
			}
			for port, process := range portMap {
				k.processNameMap[ip][port] = process
			}
		}
	}
}

// getTLSSecurityProfile collects TLS security profile configurations from OpenShift components
func (k *K8sClient) getTLSSecurityProfile() (*TLSSecurityProfile, error) {
	log.Printf("Collecting TLS security profiles from OpenShift components...")

	profile := &TLSSecurityProfile{}

	// Collect Ingress Controller TLS configuration
	if ingressTLS, err := k.getIngressControllerTLS(); err != nil {
		log.Printf("Warning: Could not get Ingress Controller TLS config: %v", err)
	} else {
		profile.IngressController = ingressTLS
	}

	// Collect API Server TLS configuration
	if apiServerTLS, err := k.getAPIServerTLS(); err != nil {
		log.Printf("Warning: Could not get API Server TLS config: %v", err)
	} else {
		profile.APIServer = apiServerTLS
	}

	// Collect Kubelet TLS configuration
	if kubeletTLS, err := k.getKubeletTLS(); err != nil {
		log.Printf("Warning: Could not get Kubelet TLS config: %v", err)
	} else {
		profile.KubeletConfig = kubeletTLS
	}

	return profile, nil
}

// getIngressControllerTLS gets TLS configuration from Ingress Controller
func (k *K8sClient) getIngressControllerTLS() (*IngressTLSProfile, error) {
	cmd := exec.Command("oc", "describe", "IngressController", "default", "-n", "openshift-ingress-operator")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get ingress controller config: %v", err)
	}

	rawOutput := string(output)
	profile := &IngressTLSProfile{
		Raw: rawOutput,
	}

	// Parse TLS security profile information
	lines := strings.Split(rawOutput, "\n")
	inTLSSection := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Look for TLS Security Profile section
		if strings.Contains(trimmedLine, "Tls Security Profile:") {
			inTLSSection = true
			continue
		}

		if inTLSSection {
			// Stop if we hit another major section
			if strings.HasSuffix(trimmedLine, ":") && !strings.Contains(trimmedLine, "Type:") &&
				!strings.Contains(trimmedLine, "Min TLS Version:") && !strings.Contains(trimmedLine, "Ciphers:") {
				break
			}

			if strings.Contains(trimmedLine, "Type:") {
				profile.Type = strings.TrimSpace(strings.Split(trimmedLine, "Type:")[1])
			} else if strings.Contains(trimmedLine, "Min TLS Version:") {
				profile.MinTLSVersion = strings.TrimSpace(strings.Split(trimmedLine, "Min TLS Version:")[1])
			} else if strings.Contains(trimmedLine, "Ciphers:") {
				cipherLine := strings.TrimSpace(strings.Split(trimmedLine, "Ciphers:")[1])
				if cipherLine != "" {
					profile.Ciphers = strings.Split(cipherLine, ",")
					for i, cipher := range profile.Ciphers {
						profile.Ciphers[i] = strings.TrimSpace(cipher)
					}
				}
			}
		}
	}

	return profile, nil
}

// getAPIServerTLS gets TLS configuration from API Server
func (k *K8sClient) getAPIServerTLS() (*APIServerTLSProfile, error) {
	cmd := exec.Command("oc", "describe", "apiserver", "cluster")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get API server config: %v", err)
	}

	rawOutput := string(output)
	profile := &APIServerTLSProfile{
		Raw: rawOutput,
	}

	// Parse TLS security profile information
	lines := strings.Split(rawOutput, "\n")
	inTLSSection := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Look for TLS Security Profile section
		if strings.Contains(trimmedLine, "Tls Security Profile:") {
			inTLSSection = true
			continue
		}

		if inTLSSection {
			// Stop if we hit another major section
			if strings.HasSuffix(trimmedLine, ":") && !strings.Contains(trimmedLine, "Type:") &&
				!strings.Contains(trimmedLine, "Min TLS Version:") && !strings.Contains(trimmedLine, "Ciphers:") {
				break
			}

			if strings.Contains(trimmedLine, "Type:") {
				profile.Type = strings.TrimSpace(strings.Split(trimmedLine, "Type:")[1])
			} else if strings.Contains(trimmedLine, "Min TLS Version:") {
				profile.MinTLSVersion = strings.TrimSpace(strings.Split(trimmedLine, "Min TLS Version:")[1])
			} else if strings.Contains(trimmedLine, "Ciphers:") {
				cipherLine := strings.TrimSpace(strings.Split(trimmedLine, "Ciphers:")[1])
				if cipherLine != "" {
					profile.Ciphers = strings.Split(cipherLine, ",")
					for i, cipher := range profile.Ciphers {
						profile.Ciphers[i] = strings.TrimSpace(cipher)
					}
				}
			}
		}
	}

	return profile, nil
}

// getKubeletTLS gets TLS configuration from Kubelet config file
func (k *K8sClient) getKubeletTLS() (*KubeletTLSProfile, error) {
	// Since we need to access the host filesystem, we'll try to get this from a node
	// This assumes the scanner is running in a privileged pod with host access
	kubeletConfigPath := "/host/etc/kubernetes/kubelet.conf"

	// First try to read from host mount
	content, err := os.ReadFile(kubeletConfigPath)
	if err != nil {
		// Fallback: try to exec into a node or get config via API
		log.Printf("Could not read kubelet config from %s: %v, trying alternative method", kubeletConfigPath, err)
		return k.getKubeletTLSFromNode()
	}

	rawContent := string(content)
	profile := &KubeletTLSProfile{
		Raw: rawContent,
	}

	// Parse JSON-like content for TLS settings
	lines := strings.Split(rawContent, "\n")

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		if strings.Contains(trimmedLine, `"tlsCipherSuites"`) {
			// Extract cipher suites array
			if cipherStart := strings.Index(trimmedLine, "["); cipherStart != -1 {
				if cipherEnd := strings.Index(trimmedLine, "]"); cipherEnd != -1 {
					cipherStr := trimmedLine[cipherStart+1 : cipherEnd]
					ciphers := strings.Split(cipherStr, ",")
					for _, cipher := range ciphers {
						cleanCipher := strings.Trim(strings.TrimSpace(cipher), `"`)
						if cleanCipher != "" {
							profile.TLSCipherSuites = append(profile.TLSCipherSuites, cleanCipher)
						}
					}
				}
			}
		} else if strings.Contains(trimmedLine, `"tlsMinVersion"`) {
			// Extract minimum TLS version
			if colonIndex := strings.Index(trimmedLine, ":"); colonIndex != -1 {
				versionPart := strings.TrimSpace(trimmedLine[colonIndex+1:])
				profile.TLSMinVersion = strings.Trim(versionPart, `",`)
			}
		}
	}

	return profile, nil
}

// getKubeletTLSFromNode attempts to get kubelet config by executing commands on a node
func (k *K8sClient) getKubeletTLSFromNode() (*KubeletTLSProfile, error) {
	// Get a list of nodes
	nodes, err := k.clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %v", err)
	}

	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("no nodes found")
	}

	// Try to get kubelet config from the first node
	nodeName := nodes.Items[0].Name

	// Create a debug pod on the node to read the kubelet config
	cmd := exec.Command("oc", "debug", "node/"+nodeName, "--", "cat", "/host/etc/kubernetes/kubelet.conf")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to read kubelet config from node %s: %v", nodeName, err)
	}

	rawOutput := string(output)
	profile := &KubeletTLSProfile{
		Raw: rawOutput,
	}

	// Parse the kubelet config similar to the direct file read method
	lines := strings.Split(rawOutput, "\n")

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		if strings.Contains(trimmedLine, `"tlsCipherSuites"`) {
			// Extract cipher suites array
			if cipherStart := strings.Index(trimmedLine, "["); cipherStart != -1 {
				if cipherEnd := strings.Index(trimmedLine, "]"); cipherEnd != -1 {
					cipherStr := trimmedLine[cipherStart+1 : cipherEnd]
					ciphers := strings.Split(cipherStr, ",")
					for _, cipher := range ciphers {
						cleanCipher := strings.Trim(strings.TrimSpace(cipher), `"`)
						if cleanCipher != "" {
							profile.TLSCipherSuites = append(profile.TLSCipherSuites, cleanCipher)
						}
					}
				}
			}
		} else if strings.Contains(trimmedLine, `"tlsMinVersion"`) {
			// Extract minimum TLS version
			if colonIndex := strings.Index(trimmedLine, ":"); colonIndex != -1 {
				versionPart := strings.TrimSpace(trimmedLine[colonIndex+1:])
				profile.TLSMinVersion = strings.Trim(versionPart, `",`)
			}
		}
	}

	return profile, nil
}

func main() {
	host := flag.String("host", "127.0.0.1", "The target host or IP address to scan")
	port := flag.String("port", "443", "The target port to scan")
	jsonOutput := flag.String("json", "", "Output results in JSON format to specified file (if empty, outputs to stdout in human-readable format)")
	csvOutput := flag.String("csv", "", "Output results in CSV format to specified file")
	csvColumns := flag.String("csv-columns", "default", "CSV columns to include: 'all', 'default', 'minimal', or comma-separated list")
	concurrentScans := flag.Int("j", 1, "Number of concurrent scans to run in parallel (speeds up large IP lists significantly!)")
	allPods := flag.Bool("all-pods", false, "Scan all pods in the current namespace (overrides --iplist and --host)")
	limitIPs := flag.Int("limit-ips", 0, "Limit the number of IPs to scan for testing purposes (0 = no limit)")
	flag.Parse()

	if !isNmapInstalled() {
		log.Fatal("Error: Nmap is not installed or not in the system's PATH. This program is a wrapper and requires Nmap to function.")
	}

	// Validate concurrent scans parameter
	if *concurrentScans < 1 {
		log.Fatal("Error: Number of concurrent scans must be at least 1")
	}

	var k8sClient *K8sClient
	var err error
	var allPodsInfo []PodInfo

	if *allPods {
		k8sClient, err = newK8sClient()
		if err != nil {
			log.Fatalf("Could not create kubernetes client for --all-pods: %v", err)
		}

		allPodsInfo = k8sClient.getAllPodsInfo() // get pod ip to pod name mapping

		log.Printf("Found %d pods to scan from the cluster.", len(allPodsInfo))

		// Apply IP limit if specified
		if *limitIPs > 0 {
			totalIPs := 0
			for _, pod := range allPodsInfo {
				totalIPs += len(pod.IPs)
			}

			if totalIPs > *limitIPs {
				log.Printf("Limiting scan to %d IPs (found %d total IPs)", *limitIPs, totalIPs)
				allPodsInfo = limitPodsToIPCount(allPodsInfo, *limitIPs)
				limitedTotal := 0
				for _, pod := range allPodsInfo {
					limitedTotal += len(pod.IPs)
				}
				log.Printf("After limiting: %d pods with %d total IPs", len(allPodsInfo), limitedTotal)
			}
		}
	}

	if len(allPodsInfo) > 0 {
		var scanResults ScanResults

		// If CSV output is requested, we need the full results, so use regular scan
		// If only JSON is requested, use streaming for better performance
		if *csvOutput != "" {
			scanResults = performClusterScan(allPodsInfo, *concurrentScans, k8sClient)

			// Write JSON if also requested
			if *jsonOutput != "" {
				// Convert ScanResults to JSON format
				if err := writeJSONOutput(scanResults, *jsonOutput); err != nil {
					log.Printf("Error writing JSON output: %v", err)
				} else {
					log.Printf("JSON results written to: %s", *jsonOutput)
				}
			}

			// Write CSV output
			if err := writeCSVOutput(scanResults, *csvOutput, *csvColumns); err != nil {
				log.Printf("Error writing CSV output: %v", err)
			} else {
				log.Printf("CSV results written to: %s", *csvOutput)
			}

			// Write scan errors CSV if there are any errors
			if len(scanResults.ScanErrors) > 0 {
				errorFilename := strings.TrimSuffix(*csvOutput, filepath.Ext(*csvOutput)) + "_errors.csv"
				if err := writeScanErrorsCSV(scanResults, errorFilename); err != nil {
					log.Printf("Error writing scan errors CSV: %v", err)
				} else {
					log.Printf("Scan errors written to: %s", errorFilename)
				}
			}

			// Print to console if no output files specified
			if *jsonOutput == "" {
				printClusterResults(scanResults)
			}
		} else if *jsonOutput != "" {
			// JSON-only output, use streaming for performance
			performClusterScanWithStreaming(allPodsInfo, *jsonOutput, *concurrentScans, k8sClient)
			log.Printf("Scan complete. Results written to: %s", *jsonOutput)
		} else {
			// Console output only
			scanResults = performClusterScan(allPodsInfo, *concurrentScans, k8sClient)
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
		log.Printf("JSON results written to %s", *jsonOutput)
	}

	if *csvOutput != "" {
		// For single host scans, try to get TLS config if k8s client is available
		var tlsConfig *TLSSecurityProfile
		if k8sClient != nil {
			if config, err := k8sClient.getTLSSecurityProfile(); err != nil {
				log.Printf("Warning: Could not collect TLS security profiles: %v", err)
			} else {
				tlsConfig = config
			}
		}

		// Convert single scan to ScanResults format for CSV
		singleResult := ScanResults{
			Timestamp:         time.Now().Format(time.RFC3339),
			TotalIPs:          1,
			ScannedIPs:        1,
			TLSSecurityConfig: tlsConfig,
			IPResults: []IPResult{{
				IP:          *host,
				Status:      "scanned",
				OpenPorts:   []int{}, // Will be extracted from nmapResult
				PortResults: []PortResult{},
			}},
		}

		// Extract port information from nmap result
		if len(nmapResult.Hosts) > 0 && len(nmapResult.Hosts[0].Ports) > 0 {
			for _, nmapPort := range nmapResult.Hosts[0].Ports {
				if port, err := strconv.Atoi(nmapPort.PortID); err == nil {
					singleResult.IPResults[0].OpenPorts = append(singleResult.IPResults[0].OpenPorts, port)
					singleResult.IPResults[0].PortResults = append(singleResult.IPResults[0].PortResults, PortResult{
						Port:     port,
						Protocol: nmapPort.Protocol,
						State:    nmapPort.State.State,
						Service:  nmapPort.Service.Name,
						NmapRun:  nmapResult,
					})
				}
			}
		}

		if err := writeCSVOutput(singleResult, *csvOutput, *csvColumns); err != nil {
			log.Fatalf("Error writing CSV output: %v", err)
		}
		log.Printf("CSV results written to %s", *csvOutput)

		// Write scan errors CSV if there are any errors
		if len(singleResult.ScanErrors) > 0 {
			errorFilename := strings.TrimSuffix(*csvOutput, filepath.Ext(*csvOutput)) + "_errors.csv"
			if err := writeScanErrorsCSV(singleResult, errorFilename); err != nil {
				log.Printf("Error writing scan errors CSV: %v", err)
			} else {
				log.Printf("Scan errors written to: %s", errorFilename)
			}
		}
	}

	if *jsonOutput == "" && *csvOutput == "" {
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

	// We scan all ports for this ip first to get the open ports
	// for constructing the final results.
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

func scanIPPort(ip string, port int, k8sClient *K8sClient, pod PodInfo, scanResults *ScanResults) (PortResult, error) {
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

	// Check if TLS data was found before doing expensive process name detection
	hasTLSData := false
	if len(nmapResult.Hosts) > 0 {
		for _, host := range nmapResult.Hosts {
			for _, nmapPort := range host.Ports {
				for _, script := range nmapPort.Scripts {
					if script.ID == "ssl-enum-ciphers" && len(script.Tables) > 0 {
						hasTLSData = true
						break
					}
				}
				if hasTLSData {
					break
				}
			}
			if hasTLSData {
				break
			}
		}
	}

	// Only do process detection if we found TLS data
	if k8sClient != nil && hasTLSData && len(pod.Containers) > 0 {
		// Discover processes for this pod on-demand
		k8sClient.getAndCachePodProcesses(pod)

		// Look up from the now-populated cache
		k8sClient.processCacheMutex.Lock()
		if processName, ok := k8sClient.processNameMap[ip][port]; ok {
			result.ProcessName = processName
			// Since we don't know the exact container, we can leave it blank or list all
			result.ContainerName = strings.Join(pod.Containers, ",")
			log.Printf("Found process '%s' for %s:%d from cache", processName, ip, port)
		} else {
			log.Printf("Could not find process for %s:%d in cache", ip, port)
		}
		k8sClient.processCacheMutex.Unlock()
	} else if !hasTLSData {
		log.Printf("Skipping process name detection for %s:%d - no TLS data found. Nmap output: %s", ip, port, string(output))
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
	fmt.Printf("Process detection workers: %d\n", max(2, concurrentScans/2))
	fmt.Printf("========================================\n\n")

	// Collect TLS security configuration from cluster
	var tlsConfig *TLSSecurityProfile
	if k8sClient != nil {
		if config, err := k8sClient.getTLSSecurityProfile(); err != nil {
			log.Printf("Warning: Could not collect TLS security profiles: %v", err)
		} else {
			tlsConfig = config
		}
	}

	results := ScanResults{
		Timestamp:         startTime.Format(time.RFC3339),
		TotalIPs:          totalIPs,
		IPResults:         make([]IPResult, 0, totalIPs),
		TLSSecurityConfig: tlsConfig,
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
					ipResult := scanIP(k8sClient, ip, pod, &results)
					ipResult.OpenshiftComponent = component // TODO add component to scan results

					mu.Lock()
					results.IPResults = append(results.IPResults, ipResult)
					results.ScannedIPs++
					mu.Unlock()
					log.Printf("WORKER %d: Completed %s (%d/%d IPs done)", workerID, ip, results.ScannedIPs, totalIPs)
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

// TODO remove
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
					// TODO just pass the pod not each ip. this is dumb. The pod itself contains all ips for that pod. wtf
					ipResult := scanIP(k8sClient, ip, pod, nil) // Pass nil for streaming - errors won't be collected
					ipResult.OpenshiftComponent = component
					resultChan <- ipResult
				}
				log.Printf("STREAMING WORKER %d: Completed Pod %d/%d: %s/%s", workerID, currentPod, len(allPodsInfo), pod.Namespace, pod.Name)
			}
			log.Printf("STREAMING WORKER %d: FINISHED", workerID)
		}(workerID)
	}

	// Collect TLS security configuration from cluster
	var tlsConfig *TLSSecurityProfile
	if k8sClient != nil {
		if config, err := k8sClient.getTLSSecurityProfile(); err != nil {
			log.Printf("Warning: Could not collect TLS security profiles: %v", err)
		} else {
			tlsConfig = config
		}
	}

	// Start a goroutine to collect results and write them to the file
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		results := ScanResults{
			Timestamp:         startTime.Format(time.RFC3339),
			TotalIPs:          totalIPs,
			IPResults:         make([]IPResult, 0, totalIPs),
			TLSSecurityConfig: tlsConfig,
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
		if len(ipResult.Services) > 0 {
			fmt.Printf("Services:\n")
			for _, service := range ipResult.Services {
				fmt.Printf("  - %s/%s (Type: %s", service.Namespace, service.Name, service.Type)
				if len(service.Ports) > 0 {
					fmt.Printf(", Ports: %v", service.Ports)
				}
				fmt.Printf(")\n")
			}
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

func (k *K8sClient) getAllPodsInfo() []PodInfo {
	pods, err := k.clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{}) // TODO handle error
	if err != nil {
		log.Printf("Error getting pods for info: %v", err)
		return nil
	}

	// Build pod IP to Pod mapping
	for _, pod := range pods.Items {
		if pod.Status.PodIP != "" {
			k.podIPMap[pod.Status.PodIP] = pod
		}
	}

	infos := make([]PodInfo, 0, len(pods.Items))
	for _, pod := range pods.Items {
		if pod.Status.PodIP == "" || pod.Status.Phase != v1.PodRunning {
			continue
		}

		var containerNames []string
		var image string
		if len(pod.Spec.Containers) > 0 {
			image = pod.Spec.Containers[0].Image // TODO Not sure if this matters taking the first one for now
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

func scanIP(k8sClient *K8sClient, ip string, pod PodInfo, scanResults *ScanResults) IPResult {
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
		Pod:         &pod,
		Status:      "scanned",
		OpenPorts:   ports,
		PortResults: make([]PortResult, 0, len(ports)),
	}

	// Scan each open port for SSL ciphers
	for _, port := range ports {
		portResult, err := scanIPPort(ip, port, k8sClient, pod, scanResults)
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

// Helper function to extract service names for logging
func getServiceNames(services []ServiceInfo) []string {
	names := make([]string, len(services))
	for i, service := range services {
		names[i] = fmt.Sprintf("%s/%s", service.Namespace, service.Name)
	}
	return names
}

// CSVColumnInfo defines metadata for CSV columns
type CSVColumnInfo struct {
	Name        string
	Description string
}

// Predefined column sets
// TODO remove these sets. just use one set.
var csvColumnSets = map[string][]string{
	"minimal": {"IP", "Port", "TLS Version", "TLS Ciphers"},
	"default": {"IP", "Port", "Pod Name", "Namespace", "Component Name", "Component Maintainer", "Process", "TLS Ciphers", "TLS Version", "TLS Configured MinVersion", "TLS Configured Ciphers"},
	"all":     {"IP", "Port", "Pod Name", "Namespace", "Component Name", "Component Maintainer", "Process", "TLS Ciphers", "TLS Version", "TLS Configured MinVersion", "TLS Configured Ciphers", "TLS Accepted Ciphers"},
}

// parseCSVColumns parses the CSV columns specification
func parseCSVColumns(spec string) []string {
	// Check if it's a predefined column set
	if columns, exists := csvColumnSets[spec]; exists {
		return columns
	}

	// Custom column list
	if strings.Contains(spec, ",") {
		columns := strings.Split(spec, ",")
		for i, col := range columns {
			columns[i] = strings.TrimSpace(col)
		}
		return columns
	}

	// Default fallback
	return csvColumnSets["default"]
}

// writeCSVOutput writes scan results to a CSV file with one row per IP/port combination
func writeCSVOutput(results ScanResults, filename string, columnsSpec string) error {
	log.Printf("Writing CSV output to: %s", filename)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Parse column selection
	selectedColumns := parseCSVColumns(columnsSpec)
	log.Printf("Using CSV columns: %v", selectedColumns)

	// Write header
	if err := writer.Write(selectedColumns); err != nil {
		return fmt.Errorf("failed to write CSV header: %v", err)
	}

	rowCount := 0

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

			// Calculate intersection of configured and detected ciphers (accepted ciphers)
			acceptedCiphers := findCipherIntersection(allConfiguredCiphers, allDetectedCiphers)

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
				"TLS Accepted Ciphers":      joinOrNA(acceptedCiphers),
			}

			row := buildCSVRow(selectedColumns, rowData)
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write CSV row: %v", err)
			}
			rowCount++
		}

	}

	log.Printf("Successfully wrote %d rows to CSV file with columns: %v", rowCount, selectedColumns)
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

// findCipherIntersection finds ciphers that appear in both configured and detected lists
func findCipherIntersection(configured, detected []string) []string {
	if len(configured) == 0 || len(detected) == 0 {
		return []string{}
	}

	// Create a map for faster lookup
	configuredMap := make(map[string]bool)
	for _, cipher := range configured {
		configuredMap[cipher] = true
	}

	var intersection []string
	for _, cipher := range detected {
		if configuredMap[cipher] {
			intersection = append(intersection, cipher)
		}
	}

	return removeDuplicates(intersection)
}

// limitPodsToIPCount limits the pod list to contain at most maxIPs total IP addresses
func limitPodsToIPCount(allPodsInfo []PodInfo, maxIPs int) []PodInfo {
	if maxIPs <= 0 {
		return allPodsInfo
	}

	var limitedPods []PodInfo
	currentIPCount := 0

	for _, pod := range allPodsInfo {
		if currentIPCount >= maxIPs {
			break
		}

		// If this pod would exceed the limit, include only some of its IPs
		if currentIPCount+len(pod.IPs) > maxIPs {
			remainingIPs := maxIPs - currentIPCount
			limitedPod := pod
			limitedPod.IPs = pod.IPs[:remainingIPs]
			limitedPods = append(limitedPods, limitedPod)
			break
		}

		// Include the entire pod
		limitedPods = append(limitedPods, pod)
		currentIPCount += len(pod.IPs)
	}

	return limitedPods
}
