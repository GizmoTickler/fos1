# DPI Framework for Talos Linux

This repository contains a Deep Packet Inspection (DPI) Framework designed specifically for Talos Linux and Kubernetes. The framework uses Zeek for network traffic analysis and integrates with Cilium for policy enforcement, fully aligned with Talos Linux's immutable infrastructure model.

## Architecture

The DPI Framework consists of the following components:

1. **Zeek**: Deployed as a container with host networking to capture and analyze network traffic
2. **DPI Framework**: A Kubernetes deployment that processes Zeek logs and generates network policies
3. **Cilium Integration**: Network policies are applied through Cilium's Kubernetes CRDs

## Prerequisites

- Talos Linux cluster
- Kubernetes
- Cilium CNI plugin
- kubectl

## Installation

### Talos Linux Installation

#### 1. Install Talos System Extension for Zeek

```bash
kubectl apply -f deploy/talos/zeek-extension.yaml
```

This will install the necessary system extension to support Zeek's network capture capabilities on Talos Linux nodes.

#### 2. Deploy Zeek

```bash
kubectl apply -f deploy/kubernetes/zeek-deployment.yaml
```

This will deploy Zeek as a container with host networking to capture and analyze network traffic.

#### 3. Deploy the DPI Framework

```bash
kubectl apply -f deploy/kubernetes/dpi-framework-deployment.yaml
```

This will deploy the DPI Framework that processes Zeek logs and generates network policies.

### Non-Kubernetes Installation

The DPI Framework can also be run directly on a host for testing or development:

```bash
# Build the binary
go build -o dpi-framework ./cmd/dpi-framework

# Run with default configuration
./dpi-framework --config=config.yaml
```

## Configuration

### Kubernetes Configuration

The DPI Framework is configured through a ConfigMap in `deploy/kubernetes/dpi-framework-deployment.yaml`.

### Local Configuration

For non-Kubernetes deployments, use the `config.yaml` file.

### Configuration Options

You can customize the following settings:

```yaml
kubernetes:
  enabled: true  # Set to false for non-Kubernetes deployments
  namespace: "security-monitoring"

zeek:
  logsPath: "/zeek-logs/current"  # Path to Zeek logs directory
  policyPath: "/zeek-policy"     # Path to Zeek policy directory

profiles:  # Define what applications and protocols to monitor
  - name: "default-profile"
    description: "Default DPI profile"
    enabled: true
    applications:
      - "http"
      - "https"
      # Add more applications here

flows:  # Define traffic flows to monitor
  - description: "Default flow"
    enabled: true
    sourceNetwork: "0.0.0.0/0"
    destinationNetwork: "0.0.0.0/0"
    profile: "default-profile"
```

## Monitoring

The DPI Framework exposes Prometheus metrics on port 8080. You can use these metrics to monitor:

- DPI events by type and application
- Protocol statistics
- Zeek status

## Development

### Building the Container

```bash
docker build -t dpi-framework:latest .
```

### Running Locally

For development purposes, you can run the DPI Framework locally:

```bash
go run cmd/dpi-framework/main.go --config=config.yaml --kubeconfig=$HOME/.kube/config
```

## Talos Linux Integration

The DPI Framework is designed specifically for Talos Linux's immutable infrastructure model:

1. **System Extension**: Provides necessary kernel capabilities for Zeek without modifying the immutable OS
2. **Container Deployment**: All components run as containers, respecting Talos Linux's containerized approach
3. **Kubernetes Native**: Uses Kubernetes for orchestration and configuration, aligning with Talos Linux's Kubernetes-first design
4. **Cilium Integration**: Leverages Cilium for policy enforcement, which is commonly used with Talos Linux
5. **No Host Dependencies**: Doesn't require any modifications to the Talos Linux base OS
6. **ConfigMaps**: All configuration is done through Kubernetes ConfigMaps, not local files

## How It Works

### Zeek for Application Detection

Zeek provides deep protocol analysis capabilities that allow it to identify applications based on their network behavior. The DPI Framework leverages Zeek's protocol analyzers to:

1. **Identify Applications**: Detect HTTP, HTTPS, SSH, DNS, and many other protocols
2. **Extract Metadata**: Gather information about connections, including hosts, ports, and bytes transferred
3. **Detect Anomalies**: Identify suspicious behavior in network traffic

### Policy Enforcement with Cilium

The DPI Framework uses Cilium's Kubernetes CRDs to enforce network policies based on the applications detected by Zeek:

1. **Dynamic Policy Generation**: Create policies based on detected applications and threats
2. **Application-Aware Policies**: Apply policies based on the application layer, not just IP/port
3. **QoS Marking**: Apply DSCP markings for traffic prioritization

### Kubernetes Integration

The DPI Framework is fully integrated with Kubernetes:

1. **ConfigMaps**: Configuration is managed through Kubernetes ConfigMaps
2. **Prometheus Metrics**: Exposes metrics for monitoring
3. **RBAC**: Uses Kubernetes RBAC for access control
4. **CRDs**: Leverages Cilium CRDs for policy enforcement

## License

This project is licensed under the MIT License - see the LICENSE file for details.
