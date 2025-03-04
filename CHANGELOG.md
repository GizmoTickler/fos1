# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive DPI framework with Cilium integration
  - Suricata connector for IDS/IPS functionality
  - Zeek connector for protocol analysis
  - DPI manager for coordinating security components
  - IP reputation list management
  - Dynamic policy generation from DPI events
- Suricata IPS mode support with NFQueue integration
- Cilium Hubble for network flow visibility
- DPI manager Kubernetes deployment
- Real-time policy enforcement based on DPI events

### Changed
- Replaced NFTables-based firewall with Cilium eBPF policies
- Consolidated all networking on unified Cilium stack
- Implemented NAT/NAT66 through Cilium instead of separate component
- Enhanced inter-VLAN routing with Cilium endpoint policies
- Updated security documentation to reflect Cilium-based approach
- Improved Suricata configuration with IP list support

### Fixed
- Corrected integration between DPI engines and policy enforcement
- Fixed missing link between security event detection and mitigation

## [0.2.0] - 2025-03-04

Enhanced security release with Cilium integration and DPI capabilities.

### Added
- Comprehensive DPI framework with Cilium integration
- Suricata and Zeek integration with dynamic policy generation
- IPS capabilities with real-time enforcement
- Unified networking stack based on Cilium eBPF
- End-to-end security pipeline for threat detection and mitigation

## [0.1.0] - 2025-02-15

Initial release of the Kubernetes-based router/firewall distribution.

### Added
- Basic routing functionality
- VLAN support
- DNS services (CoreDNS, AdGuard Home)
- DHCP services (Kea) and IPv6 router advertisements
- Network Time Protocol (NTP) via Chrony
- Initial security features with Suricata and Zeek
- Multi-service DNS discovery with mDNS