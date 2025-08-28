# check-network

A network security scanner for OpenShift/Kubernetes clusters that combines nmap port scanning with SSL/TLS cipher enumeration and OpenShift component analysis.

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
Comprehensive security format with **one row per IP/port/TLS version** and configurable columns for different analysis needs:

**Column Sets:**
- **`minimal`**: `IP Address, Port, Service, TLS Version, Cipher Suites` - Focus on TLS analysis
- **`default`**: `IP Address, Port, Service, Pod, Namespace, TLS Version, Cipher Suites, Status, Process Name, OpenShift Component` - Balanced security overview
- **`all`**: All 14 columns with complete security context including container names, component details, and service types

**All Available Columns:**
- `IP Address` - Target IP address
- `Port` - Specific port number  
- `Service` - Service name detected by nmap
- `Pod` - Associated Kubernetes service names (comma-separated)
- `Namespace` - Service namespaces (comma-separated)
- `TLS Version` - TLS/SSL protocol version (TLSv1.2, TLSv1.3, etc.)
- `Cipher Suites` - Comma-separated list of cipher suite names for this TLS version
- `Status` - Scan status (scanned/error/timeout)
- `Process Name` - Process listening on port (from lsof)
- `Container Name` - Container hosting the process
- `OpenShift Component` - Identified OpenShift component
- `Component Source` - Source location/registry  
- `Component Maintainer` - Component maintainer
- `Service Type` - Kubernetes service type (ClusterIP, NodePort, etc.)
- `Error` - Error message if scan failed

**Example CSV Output (default columns):**
```csv
IP Address,Port,Service,Pod,Namespace,TLS Version,Cipher Suites,Status,Process Name,OpenShift Component
10.128.0.87,443,ssl/https,oauth-openshift,openshift-authentication,TLSv1.2,"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",scanned,oauth-openshift,oauth-openshift
10.128.0.87,443,ssl/https,oauth-openshift,openshift-authentication,TLSv1.3,"TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384",scanned,oauth-openshift,oauth-openshift
10.129.0.56,8080,http,my-app,default,N/A,N/A,scanned,httpd,custom-app
```

## OpenShift Integration

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
`./deploy.sh` automatically sets these permissions for you.

## Configuration

### Environment Variables
- `KUBECONFIG` - **Required** - Path to kubeconfig file for target cluster
  
## Troubleshooting

### Common Issues

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


```mermaid
graph LR
    subgraph "Architecture"
        subgraph "Scanning Workflow"
            A[1. IP Discovery] --> B[2. Port Scan]
            B --> C[3. SSL Analysis]
            C --> D[4. Component Analysis]
            D --> E[5. Query Process ID]
            E --> F[6. Aggregate Results]
        end
    end
