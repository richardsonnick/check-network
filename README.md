# check-network

A network security scanner for OpenShift/Kubernetes clusters that combines nmap port scanning with SSL/TLS cipher enumeration and OpenShift component analysis.

## Features

-  **Cluster-wide scanning**: Scan all pods across all namespaces in your OpenShift/Kubernetes cluster
-  **Port discovery**: Automatic detection of open ports on target IPs
-  **SSL/TLS analysis**: Deep cipher suite enumeration using nmap's `ssl-enum-ciphers` script  
-  **OpenShift integration**: Extracts component metadata from running pods
-  **High performance**: Concurrent scanning with configurable worker pools
-  **Multiple output formats**: Human-readable console output or structured JSON
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
- Runs cluster scan with results output

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

**Scan entire OpenShift cluster:**
```bash
export KUBECONFIG=/path/to/cluster/config
./check-network -all-pods -json results.json -j 12
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
      "openshift_component": {
        "component": "oauth-openshift",
        "source_location": "quay.io/openshift-release-dev", 
        "maintainer_component": "openshift"
      }
    }
  ]
}
```

## OpenShift Integration

### Component Detection
The scanner automatically identifies OpenShift components by analyzing:
- Container image references
- Pod labels and annotations  

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