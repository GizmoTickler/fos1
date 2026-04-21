# Kubernetes-Based Router/Firewall Distribution

A modern, container-based router and firewall distribution utilizing Talos Linux as the immutable base operating system with built-in Kubernetes orchestration. This solution provides enterprise-grade networking, security, and monitoring capabilities while maintaining a declarative, infrastructure-as-code approach.

## Current Status

As of 2026-04-19, the repository is no longer a design-only scaffold. The main routing, NAT, DNS, DHCP, NTP, WireGuard, IDS, DPI, and authentication paths are implemented. The repository-owned developer and CI verification contract is now centered on:

- `make verify-mainline` for the canonical Go pre-merge gate
- `.github/workflows/ci.yml` enforcing `make verify-mainline` on pushes to `main` and PRs targeting `main`
- `.github/workflows/validate-manifests.yml` validating manifests on PRs without swallowing real `kubeconform` failures

The owned observability baseline is now the pod-annotation scrape path documented in [docs/observability-architecture.md](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/docs/observability-architecture.md): `dpi-manager` pods are expected to expose `:8080/metrics`, and `ntp-controller` pods are expected to expose `:9559/metrics`. That is a repository-owned manifest contract, not proof that a live cluster is scraping those exporters end to end.

The remaining work is concentrated in secondary runtime and ops hardening, especially event-correlation ingestion/sinks, broader observability-stack verification beyond the pod-annotation baseline, threat-intelligence depth, and hardware/platform hardening.

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

Before opening a PR, run `make verify-mainline`. If your change touches manifests or manifest-validation workflow behavior, also run the relevant manifest checks locally because CI will now enforce both the canonical Go gate and manifest validation in their respective workflows.

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
