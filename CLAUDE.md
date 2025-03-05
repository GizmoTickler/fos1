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

### Designed Components (With Placeholder Implementation)

#### Network Infrastructure
- [x] Network interface and VLAN configuration framework
- [x] Routing implementation design (static, dynamic, policy-based)
- [x] eBPF-based packet processing architecture
- [x] Cilium integration design for unified networking

#### Security Components
- [x] IDS/IPS integration patterns with Suricata and Zeek
- [x] DPI framework architecture with nProbe integration
- [x] Policy-based filtering with Cilium integration
- [x] Security orchestration system design
- [x] Threat intelligence system design

#### Kubernetes Manifest Templates
- [x] Network service templates (DNS - CoreDNS, AdGuard, mDNS)
- [x] Network service templates (DHCP with Kea)
- [x] Network service templates (NTP with Chrony)
- [x] Security service templates (Suricata, Zeek, DPI Manager)
- [x] Example routing, VLAN, and eBPF configurations
- [x] Filter policy CRDs and examples

### Go Package Frameworks
- [x] Network interface management interfaces (VLAN)
- [x] Routing interfaces and placeholder implementation
- [x] eBPF program and map management interfaces
- [x] DPI framework interfaces and connectors (Suricata, Zeek, nProbe)
- [x] NAT/NAT66 conceptual implementation with Cilium
- [x] Policy controller for filter policy management
- [x] DNS manager with DHCP integration
- [x] DHCP manager with dynamic DNS updates

### Documentation Created
- [x] Network configuration guide
- [x] Security configuration guide
- [x] DPI integration documentation
- [x] Routing configuration guide
- [x] VLAN implementation design
- [x] eBPF implementation design
- [x] DNS implementation design
- [x] DHCP implementation design
- [x] NTP implementation design
- [x] Implementation plans and trackers

### Kubernetes Custom Resources Defined
- [x] Network interfaces and subnets
- [x] Firewall zones, rules, and IP sets
- [x] DPI profiles and flows
- [x] QoS profiles and traffic classes
- [x] Routing policies and tables
- [x] eBPF program configurations
- [x] DNS zones and records
- [x] mDNS reflection rules
- [x] DHCPv4 and DHCPv6 services
- [x] NTP services with time source configuration

## Current Architecture Concept

### Unified Network Design
The network architecture is designed around a unified approach where all traffic flows through a consistent processing pipeline:

1. **Packet Ingress**
   - XDP programs for early packet processing and DDoS protection
   - TC ingress hooks for stateful firewall and initial processing

2. **Central Processing**
   - Cilium-based network stack for all networking functions
   - eBPF for high-performance packet processing
   - Network policy enforcement
   - Routing decisions (static, dynamic, policy-based)
   - NAT/NAT66 through Cilium policies

3. **Packet Egress**
   - TC egress hooks for QoS and traffic shaping
   - Final packet modifications

4. **Traffic Flow Path**
   - All traffic (including client to internet) flows through this pipeline
   - Ensures consistent policy enforcement and visibility
   - Leverages eBPF acceleration for optimal performance

### Key Design Components

#### VLAN Implementation
- Support for VLAN interfaces on physical, bridge, and bond interfaces
- VLAN trunking capabilities
- QoS priority handling (802.1p and DSCP)
- MTU auto-calculation

#### Routing System
- Comprehensive routing with static, dynamic, and policy-based options
- Multi-protocol support (BGP, OSPF, IS-IS, BFD, PIM)
- VRF isolation with Linux VRF and Cilium policies
- Multi-WAN with various load balancing methods
- Route filtering and aggregation

#### eBPF Framework
- Hierarchical map structure for efficient state management
- Support for all eBPF hooks (XDP, TC, sockops, cgroup)
- Cilium integration for unified networking
- Configuration-based programmability through CRDs

### Security Framework Concept
- Integration pattern between DPI engines and Cilium:
  - Suricata connector for IDS/IPS functionality
  - Zeek connector for protocol analysis
  - IP reputation list management
  - Dynamic policy generation from DPI events

## Implementation Status

The project is currently in the **architectural design and prototype phase**. The codebase contains:

1. Detailed architecture designs for core components
2. Interface definitions and type structures
3. Placeholder implementations with conceptual logic
4. Example configurations and CRD definitions
5. Comprehensive documentation of the intended architecture

Recent progress includes:
- Complete VLAN implementation design with placeholder code
- Comprehensive routing implementation design for static, dynamic and policy routing
- eBPF framework design with support for all hook types
- Cilium integration design with detailed implementation patterns
- Advanced security component designs (DPI, IDS/IPS, threat intelligence)
- Policy-based filtering system with hierarchical policies
- Integration framework for all security components
- Comprehensive DNS implementation with CoreDNS, AdGuard, and mDNS
- Cross-VLAN mDNS reflection with rule-based configuration
- Comprehensive DHCP implementation design with Kea DHCP server
- DHCP controller design for managing configurations across VLANs
- Dynamic DNS updates from DHCP leases
- DHCPv4 and DHCPv6 services with static reservations
- Domain suffix configuration per VLAN
- Complete NTP service design using Chrony with support for diverse time sources
- Security-enhanced NTP with authentication, access controls, and NTS support
- Per-VLAN NTP service configurations with appropriate access policies
- Comprehensive NTP monitoring with Prometheus and Grafana
- Example configurations demonstrating the intended usage

None of the components are currently production-ready or fully functional. This project serves as a blueprint for a future complete implementation.

## Next Steps for Implementation

1. Develop fully functional network monitoring
2. Add comprehensive test coverage
3. Implement production-ready error handling
4. Create deployable container images
5. Develop real configuration validation
6. Implement CI/CD pipeline for automated testing and deployment