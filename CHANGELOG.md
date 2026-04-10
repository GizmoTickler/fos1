# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Real Cilium route sync with VRF/PBR support (ticket 5)
- Real Cilium NAT enforcement for SNAT/DNAT/NAT66/NAT64/port forwarding (tickets 6-7)
- Idempotent statusful NAT controller with spec-hash comparison (ticket 8)
- FRR config validation via vtysh --dryrun with rollback on failure (ticket 9)
- Live BGP/OSPF state queries from FRR JSON output (ticket 10)
- Real Kea DHCP control-socket reconciliation (ticket 11)
- DNS manager wired to CoreDNS zones, AdGuard filters, mDNS reflection (ticket 12)
- NTP controller with real Chrony config generation and NTS support (ticket 13)
- WireGuard CRD-to-interface reconciliation with real status (ticket 14)
- IDS manager with real Suricata Unix socket and Zeek Broker integration (ticket 16)
- DPI event-to-Cilium policy pipeline with TTL expiry and cleanup (ticket 17)
- Auth manager wired to real local/LDAP/OAuth providers (ticket 18)

### Changed
- CiliumClient interface extended with DeleteNetworkPolicy and route operations
- NAT manager now calls Cilium client instead of storing status only
- Implementation plan and backlog updated to reflect completed work

### Added (prior to tickets 5-18)
- Hardware integration design document detailing low-level interaction with network interfaces
- Support for Intel X540, X550, and I225 NICs in the hardware integration design
- eBPF-based NAT66 and NPT implementation approach using TC hooks for stateful operation
- Multi-queue utilization design for X540/X550 NICs (supporting up to 64 hardware queues)
- On-demand packet capture system with filtering capabilities
- Multi-WAN management with failover and load balancing
- Selective hardware offloading configuration (TX checksum, TSO, GRO)
- VPN implementation design with WireGuard kernel module as preferred approach
- Comprehensive Kea database backend integration design for DHCP services
- Mermaid diagram for DPI and Threat Intelligence interaction
- Comprehensive DNS implementation with CoreDNS, AdGuard, and mDNS
- DNS Manager with DHCP integration for dynamic DNS updates
- Custom CRDs for DNS zone and mDNS reflection management
- Cross-VLAN mDNS service discovery with rule-based configuration
- DHCP service implementation with IPv4 and IPv6 support
  - Kea DHCP server deployment configuration
  - DHCPv4Service and DHCPv6Service CRDs for configuration
  - Custom DHCP controller with VLAN integration
  - Dynamic DNS updates from DHCP leases
  - Static reservations support for MAC addresses and DUID/Client IDs
  - DHCP option configuration support
  - Domain suffix configuration per VLAN
  - Lease persistence design
- Advanced security system design (threat intelligence, security orchestration)
- Policy-based filtering with hierarchical policy model
- Routing configuration guide with examples
- Cilium network controller interfaces
- DPI framework architectural design
- Suricata and Zeek connector interfaces
- DPI manager interface design
- Conceptual implementation of Cilium integration
- Documentation for DPI event processing architecture

### Changed
- Updated network architecture to leverage NIC-specific capabilities
- Improved NAT implementation to use TC hooks rather than XDP for stateful operation
- Enhanced Cilium integration with hardware-aware configuration
- Updated CLAUDE.md to accurately reflect project status as conceptual framework
- Refactored project tracker to show actual implementation status
- Moved from NFTables concept to Cilium eBPF design in architecture documentation
- Reorganized code to separate deprecated concepts from current architectural approach
- Enhanced AdGuard Home configuration with upstream DNS support

### Fixed
- Corrected implementation status in all documentation to reflect conceptual nature
- Added missing import statements in various files
- Fixed incorrect implementation status in project tracker

## [0.2.0] - 2025-03-04

Architectural design update with Cilium and DPI framework concepts.

### Added
- Architectural design for DPI framework with Cilium integration
- Interface definitions for Suricata and Zeek connectors
- Conceptual design for unified networking based on Cilium eBPF
- Architecture pattern for security pipeline with DPI engines

## [0.1.0] - 2025-02-15

Initial release of the Kubernetes-based router/firewall architectural concept.

### Added
- Basic architectural design
- VLAN configuration concept
- DNS services architecture (CoreDNS, AdGuard Home)
- DHCP services design (Kea) and IPv6 router advertisements
- Initial security architecture with Suricata and Zeek
- Documentation structure