# Kubernetes-Based Router/Firewall Distribution

A modern, container-based router and firewall distribution utilizing Talos Linux as the immutable base operating system with built-in Kubernetes orchestration. This solution provides enterprise-grade networking, security, and monitoring capabilities while maintaining a declarative, infrastructure-as-code approach.

## Current Status

As of 2026-04-18, the repository is no longer a design-only scaffold. The main routing, NAT, DNS, DHCP, NTP, WireGuard, IDS, DPI, and authentication paths are implemented, and the current `origin/main` snapshot verifies cleanly with:

- `git rebase origin/main` -> `HEAD is up to date.`
- `go test ./...`
- `go build ./...`

The remaining work is concentrated in legacy or secondary control paths that still contain placeholder behavior, especially security policy enforcement/controller consolidation, duplicate Cilium scaffolding cleanup, observability/event-correlation follow-through, and hardware/offload hardening.

## Project Overview

This project aims to develop a network gateway solution with:

- Secure, reliable, and high-performance networking
- Container orchestration for service management
- Modern packet filtering (eBPF, XDP)
- Comprehensive network security
- Integrated monitoring and observability
- Full IPv4 and IPv6 support with advanced features

## Documentation

- [Project Scope](docs/project-scope.md) - Detailed overview of project goals and requirements
- [Architecture Components](docs/architecture-components.md) - Technical architecture and design
- [Implementation Plan](docs/implementation-plan.md) - Verified implementation baseline and next workstreams
- [Status Report](Status.md) - Current implementation status and prioritized follow-up areas
- [Project Tracker](docs/project-tracker.md) - Historical phase tracker with links to current status
- [Development Guide](docs/DEVELOPMENT.md) - Local development workflow and commands

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

Start with:

- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for local setup and workflow
- [docs/implementation-plan.md](docs/implementation-plan.md) for the verified implementation baseline
- [Status.md](Status.md) for the current status snapshot and next steps
- [docs/design/test_matrix.md](docs/design/test_matrix.md) for the current controller/package coverage map

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
