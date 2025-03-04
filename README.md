# Kubernetes-Based Router/Firewall Distribution

A modern, container-based router and firewall distribution utilizing Talos Linux as the immutable base operating system with built-in Kubernetes orchestration. This solution provides enterprise-grade networking, security, and monitoring capabilities while maintaining a declarative, infrastructure-as-code approach.

## Project Overview

This project aims to develop a network gateway solution with:

- Secure, reliable, and high-performance networking
- Container orchestration for service management
- Modern packet filtering (eBPF, XDP)
- Comprehensive network security
- Integrated monitoring and observability
- Full IPv4 and IPv6 support with advanced features

## Documentation

- [Project Scope](project-scope.md) - Detailed overview of project goals and requirements
- [Architecture Components](architecture-components.md) - Technical architecture and design
- [Implementation Plan](implementation-plan.md) - Step-by-step development plan
- [Project Tracker](project-tracker.md) - Status tracking for all components

## Project Structure

```
/
├── docs/              # Documentation files
├── manifests/         # Kubernetes manifests
│   ├── core/          # Core system components
│   ├── network/       # Network services
│   └── security/      # Security services
├── config/            # Configuration templates
├── scripts/           # Utility scripts
└── tests/             # Test framework
```

## Getting Started

*Documentation will be added as the project progresses*

## Features

- Packet routing (IPv4/IPv6)
- NAT/NAPT (including NAT66/NAT64)
- DHCPv4/v6 server and Router Advertisements
- DNS (authoritative, recursive, filtering)
- eBPF-based packet processing
- Static and dynamic routing protocols
- Multiple WAN support with failover
- VLAN support (802.1Q)
- Stateful packet filtering
- IDS/IPS through Suricata
- Network protocol analysis (Zeek)
- VPN services (WireGuard, OpenVPN)
- QoS and traffic management
- Comprehensive monitoring and logging

## License

This project is licensed under the [MIT License](LICENSE).