# check-network

A network security scanner for OpenShift/Kubernetes clusters that combines nmap port scanning with SSL/TLS cipher enumeration and OpenShift component analysis.

## Features

-  **Cluster-wide scanning**: Scan all pods across all namespaces in your OpenShift/Kubernetes cluster
-  **Port discovery**: Automatic detection of open ports on target IPs
-  **SSL/TLS analysis**: Deep cipher suite enumeration using nmap's `ssl-enum-ciphers` script  
-  **OpenShift integration**: Extracts component metadata from running pods
-  **TLS Security Profiles**: Captures OpenShift TLS security configurations from Ingress Controller, API Server, and Kubelet
-  **High performance**: Concurrent scanning with configurable worker pools and non-blocking TLS config collection
-  **Multiple output formats**: Human-readable console output or structured JSON/CSV
-  **Flexible targeting**: Scan individual hosts, IP lists, or entire clusters
-  **Process identification**: Identifies processes listening on discovered ports

## Prerequisites

- **nmap** - Must be installed and available in PATH
- **OpenShift/Kubernetes cluster access** - For cluster scanning features
- **Sufficient privileges** - Pod exec and cluster-reader permissions for full functionality

## Installation & Setup

### Local Usage

1. **Build the scanner:**
   ```bash
   go build -o check-network .
   ```

2. **Set up cluster access:**
   ```bash
   export KUBECONFIG=/path/to/your/kubeconfig
   # KUBECONFIG must point to the target OpenShift/Kubernetes cluster you want to scan
   ```

3. **Verify cluster connectivity:**
   ```bash
   oc get nodes  # or kubectl get nodes
   ```

### OpenShift Deployment (Recommended)

For comprehensive cluster scanning, deploy as a privileged pod:

```bash
# Set target project
oc new-project scanner-project  # or oc project <existing-project>

# Deploy scanner pod with all necessary permissions
./deploy.sh
```

The deployment script automatically:
- Creates privileged pod with cluster access
- Grants necessary RBAC permissions (cluster-reader, pod-exec)  
- Builds and deploys scanner image
- Runs CSV+Json scan with 15 concurrent workers
- Auto-generates service-to-IP mapping

## Usage

### Command Line Options

```bash
./check-network [OPTIONS]
```

**Options:**
- `-host <ip>` - Target host/IP to scan (default: 127.0.0.1)
- `-port <port>` - Target port to scan (default: 443)  
- `-iplist <file>` - File containing list of IPs to scan (one per line)
- `-all-pods` - Scan all pods in the cluster (requires cluster access)
- `-json <file>` - Output results in JSON format to specified file
- `-csv <file>` - Output results in CSV format to specified file
- `-csv-columns <spec>` - Control CSV columns: 'all', 'default', 'minimal', or comma-separated list (default: 'default')
- `-service-mapping <file>` - Generate service-to-IP mapping JSON file (auto-generated for cluster scans)
- `-j <num>` - Number of concurrent workers (default: 1, max recommended: 50)

### Usage Examples

**Scan a single host:**
```bash
./check-network -host 10.0.0.1 -port 443
```

**Scan multiple IPs from file:**
```bash
echo -e "10.0.0.1\n10.0.0.2\n10.0.0.3" > targets.txt
./check-network -iplist targets.txt -j 5
```

**Scan entire OpenShift cluster (JSON output):**
```bash
export KUBECONFIG=/path/to/cluster/config
./check-network -all-pods -json results.json -j 12
```

**CSV security scan with default columns:**
```bash
./check-network -all-pods -csv security-scan-$(date +%Y%m%d).csv -j 15
```

**Full security analysis with all columns:**
```bash  
./check-network -all-pods -csv full-scan-$(date +%Y%m%d).csv -csv-columns all -j 15
```

**Minimal TLS analysis:**
```bash
./check-network -all-pods -csv minimal-$(date +%Y%m%d).csv -csv-columns minimal -j 15
```

**Custom column selection:**
```bash
./check-network -all-pods -csv custom-$(date +%Y%m%d).csv -csv-columns "IP Address,Port,Service,TLS Version,Cipher Suites,Process Name" -j 15
```

**Json+CSV security scan (auto-generates service mapping):**
```bash
./check-network -all-pods -csv security-scan-$(date +%Y%m%d).csv -json security-scan-$(date +%Y%m%d).json -j 15
```
## Output Formats

### JSON Output (`-json` flag)
Structured format containing:
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "total_ips": 238,
  "tls_security_config": {
    "ingress_controller": {
      "type": "Intermediate",
      "min_tls_version": "VersionTLS12",
      "ciphers": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
    },
    "api_server": {
      "type": "Intermediate", 
      "min_tls_version": "VersionTLS12",
      "ciphers": ["ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256"]
    },
    "kubelet_config": {
      "tls_min_version": "VersionTLS12",
      "tls_cipher_suites": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
    }
  },
  "ip_results": [
    {
      "ip": "10.0.0.1",
      "status": "scanned", 
      "open_ports": [22, 443, 8080],
      "port_results": [...],
      "services": [
        {
          "name": "oauth-openshift",
          "namespace": "openshift-authentication",
          "type": "ClusterIP",
          "ports": [443, 6443]
        }
      ],
      "openshift_component": {
        "component": "oauth-openshift",
        "source_location": "quay.io/openshift-release-dev", 
        "maintainer_component": "openshift"
      }
    }
  ]
}
```

### CSV Output (`-csv` flag)
Streamlined security format with **one row per IP/port combination** focusing on TLS cipher analysis and OpenShift configuration compliance:

**Column Sets:**
- **`minimal`**: `IP, Port, TLS Version, TLS Ciphers` - Essential TLS scan data
- **`default`**: `IP, Port, Pod Name, Namespace, Process, TLS Ciphers, TLS Version, Ingress TLS Configured Ciphers, API Server TLS Configured Ciphers, Kubelet TLS Configured Ciphers` - Comprehensive security overview  
- **`all`**: All 10 columns with complete scan results and OpenShift TLS configurations

**All Available Columns:**
- `IP` - Target IP address
- `Port` - Specific port number  
- `Pod Name` - Kubernetes pod name
- `Namespace` - Kubernetes namespace
- `Process` - Process listening on port (from lsof)
- `TLS Ciphers` - Cipher suites detected by nmap ssl-enum-ciphers script
- `TLS Version` - TLS/SSL protocol versions detected by nmap ssl-enum-ciphers script (TLSv1.2, TLSv1.3, etc.)
- `Ingress TLS Configured Ciphers` - Ingress Controller configured cipher suites from OpenShift
- `API Server TLS Configured Ciphers` - API Server configured cipher suites from OpenShift
- `Kubelet TLS Configured Ciphers` - Kubelet configured cipher suites from OpenShift

**Key Features:**
- **Streamlined Layout**: One row per IP/port combination for focused analysis
- **Component-Specific Analysis**: Separate TLS config data for Ingress Controller, API Server, and Kubelet
- **Scan Results**: Shows actual cipher suites and TLS versions detected by nmap ssl-enum-ciphers script
- **Configuration Data**: Shows configured cipher suites from each OpenShift TLS component
- **Efficient Query**: TLS configuration queried once per scan (not per row) for optimal performance
- **Process Context**: Includes pod, namespace, and process information
- **Security Compliance**: Perfect for auditing TLS compliance across OpenShift components

**Example CSV Output (default columns):**
```csv
IP,Port,Pod Name,Namespace,Process,TLS Ciphers,TLS Version,Ingress TLS Configured Ciphers,API Server TLS Configured Ciphers,Kubelet TLS Configured Ciphers
10.128.0.87,443,oauth-openshift,openshift-authentication,oauth-openshift,"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLSv1.2, TLSv1.3","ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256","ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, ECDHE-RSA-AES128-GCM-SHA256","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
10.129.0.56,8080,my-app,default,httpd,N/A,N/A,"ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256","ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, ECDHE-RSA-AES128-GCM-SHA256","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
```

### Console Output (Default)
Human-readable format showing:
- Discovered open ports per IP
- SSL/TLS cipher suites and protocols
- Service information and mappings
- OpenShift component details
- Process and container information

## OpenShift Integration

### Component Detection
The scanner automatically identifies OpenShift components by analyzing:
- Container image references
- Pod labels and annotations  

### TLS Security Profile Discovery
The scanner automatically captures TLS security configurations from OpenShift cluster components by executing:

**Ingress Controller TLS Configuration:**
```bash
oc describe IngressController default -n openshift-ingress-operator
```

**API Server TLS Configuration:**
```bash
oc describe apiserver cluster
```

**Kubelet TLS Configuration:**
```bash
cat /etc/kubernetes/kubelet.conf
```

This provides comprehensive TLS security compliance information including:
- **Profile Types**: Old, Intermediate, Modern, or Custom TLS security profiles
- **Minimum TLS Versions**: Configured minimum TLS protocol versions  
- **Allowed Cipher Suites**: Lists of permitted cipher suites for each component
- **Raw Configuration Output**: Complete configuration details for audit purposes

**Performance Optimization:**
The TLS security profile collection runs concurrently with the main scanning operations, ensuring that:
- Worker threads start immediately without waiting for TLS config collection
- Multiple TLS components (Ingress, API Server, Kubelet) are queried in parallel
- **Single Query Per Scan**: TLS configuration is collected once per scan (not per row) for maximum efficiency
- Scanning performance is not impacted by configuration discovery
- Total scan time is minimized through intelligent thread utilization

The TLS security profile information is automatically included in both JSON and CSV outputs, enabling security compliance analysis and mapping of individual scan results to cluster-wide TLS policies.

### Required Permissions

The scanner requires these RBAC permissions:

```yaml
# Cluster-wide read access
- pods (get, list)
- pods/exec (create)

# ClusterRoles granted:
- cluster-reader
- pod-exec-reader (custom)

# SecurityContextConstraints:
- privileged (for comprehensive scanning)
```

## Configuration

### Environment Variables
- `KUBECONFIG` - **Required** - Path to kubeconfig file for target cluster
- `HOME` - User home directory for kubeconfig discovery

## Troubleshooting

### Common Issues

**"nmap not found"**
```bash
# Install nmap
brew install nmap  # macOS
sudo apt install nmap  # Ubuntu/Debian  
sudo yum install nmap  # RHEL/CentOS
```

**"Could not create kubernetes client"**
```bash
# Verify KUBECONFIG points to correct cluster
export KUBECONFIG=/path/to/correct/kubeconfig
oc whoami  # Verify authentication
```

**"Permission denied" errors**
```bash
# Ensure proper RBAC permissions
oc adm policy add-cluster-role-to-user cluster-reader $(oc whoami)
```

**Pod deployment fails**
```bash
# Check if project allows privileged pods
oc describe project $(oc project -q)
# May need cluster admin to grant privileged SCC
```

## Architecture

### Scanning Workflow
1. **Discovery**: Enumerate target IPs (single host, file, or cluster pods)
2. **Port Scanning**: Use nmap to discover open ports per IP
3. **SSL Analysis**: Run ssl-enum-ciphers on discovered SSL/TLS ports
4. **Component Analysis**: Extract OpenShift component metadata 
5. **Process Identification**: Exec into pods to identify listening processes
6. **Result Aggregation**: Combine all data into structured output