# Project Guidelines for Kubernetes-Based Router/Firewall

## Build/Test/Lint Commands
- `talosctl` - Talos Linux management
- `kubectl apply -f <manifest>` - Apply k8s manifests
- `kubectl -n <namespace> logs <pod>` - View pod logs
- `kubectl -n <namespace> exec -it <pod> -- <command>` - Run command in pod
- `go test ./...` - Run all Go tests
- `go test ./pkg/network/...` - Test network components
- `golangci-lint run` - Run linters on Go code
- `yamllint manifests/` - Lint YAML files

## Style Guidelines
- **Go Code**: Follow Go standard library style, use gofmt
- **YAML**: 2-space indentation for K8s manifests
- **Imports**: Group std lib, external deps, internal packages
- **Types**: Prefer strong typing, interfaces for dependencies
- **Errors**: Return errors, don't panic; use structured error types
- **Logging**: Use structured logging (JSON), consistent levels
- **Documentation**: GoDoc style comments for all exported items
- **Naming**: CamelCase for Go; kebab-case for K8s resources

## Architecture Conventions
- Container-based microservices architecture
- GitOps-driven deployment with Flux CD
- Infrastructure-as-code for all configurations
- Modular components with clear interfaces

## Project Progress Summary

### Completed Components

#### Infrastructure Setup
- [x] Git repository structure with organized directories
- [x] GitHub Actions CI/CD workflows for validation and testing
- [x] Talos Linux configuration for router/firewall deployment
- [x] Project documentation structure with guides and references

#### Network Infrastructure
- [x] Network interface and VLAN configuration system
- [x] Subnet management with IPv4/IPv6 support
- [x] DHCP/DHCPv6 service deployment (Kea)
- [x] DNS services with filtering (CoreDNS, AdGuard Home)
- [x] Router advertisements for IPv6 (RADVD)
- [x] Time synchronization service (Chrony)
- [x] Service discovery with mDNS (Avahi)
- [x] NAT and NAT66 for IPv4/IPv6 traffic

#### Security Components
- [x] Intrusion detection with Suricata and Zeek
- [x] Zone-based firewall with NFTables backend
- [x] Deep packet inspection (DPI) framework
- [x] Application-based filtering
- [x] QoS system with traffic classes and prioritization
- [x] Policy-based routing for intelligent traffic management
- [x] VPN service with WireGuard

#### Observability
- [x] Metrics collection with Prometheus
- [x] Visualization dashboards with Grafana

### Implemented Kubernetes Manifests
- Network services (DNS, DHCP, NTP, mDNS)
- Security services (Suricata, Zeek, Firewall)
- Observability stack (Prometheus, Grafana)
- VPN services (WireGuard)

### Implemented Go Packages
- Network interface management
- Firewall configuration and management
- Deep packet inspection
- Quality of Service (QoS)
- VPN configuration
- NAT/NAT66 functionality

### Documentation Created
- Network configuration guide
- Security configuration guide
- DPI integration documentation
- Implementation plans and trackers

### Kubernetes Custom Resources Defined
- Network interfaces and subnets
- Firewall zones, rules, and IP sets
- DPI profiles and flows
- QoS profiles and traffic classes
- Routing policies and tables

## Deployment Instructions
1. Set up Talos Linux VM with sufficient resources
2. Apply base Talos configuration using `talosctl apply-config`
3. Apply Kubernetes manifests with `kubectl apply -k manifests/base`
4. Configure network interfaces and security policies
5. Monitor system through Grafana dashboard