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

## Project Status Summary

This is a **conceptual framework** with placeholder code that outlines the architecture and integration patterns for a Kubernetes-based router/firewall. The code represents an architectural blueprint rather than a production-ready implementation.

### Completed Components

#### Repository Structure
- [x] Git repository structure with organized directories
- [x] Project documentation structure with guides and references

#### Architecture Design
- [x] Network architecture design
- [x] Security component design
- [x] Infrastructure configuration design
- [x] API definitions (CRDs)

### Conceptual Components (Partially Implemented)

#### Network Infrastructure
- [ ] Network interface and VLAN configuration framework
- [ ] Subnet management with IPv4/IPv6 support definitions
- [ ] Cilium-based network architecture design

#### Security Components
- [ ] IDS/IPS integration patterns with Suricata and Zeek
- [ ] DPI framework architecture
- [ ] Application-based filtering design with Cilium

#### Kubernetes Manifest Templates
- [ ] Network service templates (DNS, DHCP, NTP)
- [ ] Security service templates (Suricata, Zeek)
- [ ] Basic deployment manifests

### Go Package Frameworks
- [ ] Network interface management interfaces
- [ ] Cilium network controller interfaces
- [ ] DPI framework interfaces and connectors
- [ ] NAT/NAT66 conceptual implementation

### Documentation Created
- [x] Network configuration guide
- [x] Security configuration guide
- [x] DPI integration documentation
- [x] Routing configuration guide
- [x] Implementation plans and trackers

### Kubernetes Custom Resources Defined
- [x] Network interfaces and subnets
- [x] Firewall zones, rules, and IP sets
- [x] DPI profiles and flows
- [x] QoS profiles and traffic classes
- [x] Routing policies and tables

## Current Architecture Concept

### Unified Network Design (Concept)
- Cilium-based network stack for all networking functions
- eBPF for high-performance packet processing
- NAT/NAT66 through Cilium policies
- Inter-VLAN routing with Cilium endpoint policies

### Security Framework Concept
- Integration pattern between DPI engines and Cilium:
  - Suricata connector for IDS/IPS functionality
  - Zeek connector for protocol analysis
  - IP reputation list management
  - Dynamic policy generation from DPI events

## Implementation Status

The project is currently in the **architectural design and prototype phase**. The codebase contains:

1. Interface definitions and type structures
2. Conceptual implementations with placeholder logic
3. Example configurations rather than production code
4. Incomplete implementations with TODOs and comments

None of the components are currently production-ready or fully functional. This project serves as a blueprint for a future complete implementation.

## Next Steps for Implementation

1. Complete core network interface implementation
2. Implement Cilium client with complete YAML conversion
3. Develop fully functional DPI connectors
4. Add comprehensive test coverage
5. Implement production-ready error handling
6. Create deployable container images
7. Develop real configuration validation