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

This project implements a **Kubernetes-based router/firewall** with real, functional backends for core networking and security subsystems. The codebase has progressed from an architectural blueprint into working implementations across routing, NAT, DNS, DHCP, NTP, VPN, IDS/IPS, DPI, and authentication.

### Completed Components

#### Repository Structure
- [x] Git repository structure with organized directories
- [x] Project documentation structure with guides and references

#### Architecture Design
- [x] Network architecture design with hardware integration for Intel NICs
- [x] Security component design
- [x] Infrastructure configuration design
- [x] API definitions (CRDs)

### Implemented Components (Real Backends)

#### Routing and Network Infrastructure
- [x] Real Cilium route sync with deterministic VRF/PBR table mapping
- [x] FRR config validation via vtysh, live BGP/OSPF state from FRR JSON queries
- [x] Network interface and VLAN configuration framework
- [x] Hardware integration for Intel X540, X550, and I225 NICs
- [x] eBPF-based packet processing architecture
- [x] Multi-WAN management with failover and load balancing
- [x] Cilium integration for unified networking

#### NAT
- [x] Real SNAT/DNAT/NAT66/NAT64/port forwarding via Cilium policies
- [x] Idempotent statusful NAT controller

#### Network Services
- [x] DNS: CoreDNS zone updates, AdGuard filter/client updates, mDNS reflection wiring
- [x] DHCP: Real Kea control-socket communication (config-set, config-get, config-reload)
- [x] NTP: Real Chrony config generation with NTS support, chronyc reload

#### VPN
- [x] WireGuard: Real CRD-to-interface reconciliation with actual status from interface queries

#### Security Components
- [x] IDS/IPS: Real Suricata Unix socket + Eve log parsing, real Zeek Broker integration
- [x] DPI: Real event-to-Cilium policy pipeline with TTL expiry and cleanup
- [x] Policy-based filtering with Cilium integration
- [x] Security orchestration system
- [x] Threat intelligence system

#### Authentication
- [x] Real provider construction (local, LDAP, OAuth) via providers package

#### Kubernetes Manifest Templates
- [x] Network service templates (DNS - CoreDNS, AdGuard, mDNS)
- [x] Network service templates (DHCP with Kea)
- [x] Network service templates (NTP with Chrony)
- [x] Security service templates (Suricata, Zeek, DPI Manager)
- [x] Example routing, VLAN, and eBPF configurations
- [x] Filter policy CRDs and examples

### Go Packages
- [x] Network interface management (VLAN)
- [x] Routing with real Cilium route sync and FRR integration
- [x] eBPF program and map management interfaces
- [x] DPI framework with real connectors (Suricata, Zeek, nProbe)
- [x] NAT controller with real Cilium policy management
- [x] Policy controller for filter policy management
- [x] DNS manager with real CoreDNS/AdGuard backends
- [x] DHCP manager with real Kea control-socket integration

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

The project has progressed through **tickets 5-18**, replacing placeholder implementations with real, functional backends. The codebase now contains:

1. **Real backend integrations** for routing (Cilium + FRR), NAT (Cilium policies), DNS (CoreDNS + AdGuard), DHCP (Kea control socket), NTP (Chrony + chronyc), VPN (WireGuard interfaces), IDS/IPS (Suricata socket + Zeek Broker), DPI (event-to-policy pipeline), and auth (local/LDAP/OAuth providers)
2. **Idempotent controllers** with proper status management and reconciliation loops
3. **CRD definitions** for all managed resources
4. **Hardware integration** for Intel X540, X550, and I225 NICs with multi-queue utilization
5. **eBPF framework** with support for XDP, TC, sockops, and cgroup hooks
6. Comprehensive documentation and example configurations

### Areas still in design/placeholder state
- Network monitoring and observability pipeline
- Some eBPF program implementations (XDP DDoS, TC QoS shaping)
- Full hardware offloading integration
- On-demand packet capture system

## Next Steps

1. Expand test coverage across all implemented backends
2. Implement network monitoring and observability pipeline
3. Complete eBPF program implementations (XDP DDoS protection, TC QoS shaping)
4. Build deployable container images and Helm charts
5. Implement CI/CD pipeline for automated testing and deployment
6. Integration testing with real hardware and Cilium clusters
7. Production hardening: graceful shutdown, retry policies, circuit breakers