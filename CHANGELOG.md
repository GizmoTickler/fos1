# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive DNS implementation with CoreDNS, AdGuard, and mDNS
- DNS Manager with DHCP integration for dynamic DNS updates
- Custom CRDs for DNS zone and mDNS reflection management
- Cross-VLAN mDNS service discovery with rule-based configuration
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