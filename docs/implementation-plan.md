# Kubernetes-Based Router/Firewall Distribution
## Current Implementation Plan

This document replaces the older time-boxed plan with a codebase-driven implementation plan based on the repository's actual current state.

## Current Baseline

The repository is not a greenfield design-only project.

What is already present:
- CRDs and API types for major networking and security domains
- real backend/client code for parts of networking, DNS, DHCP, NTP, VPN, and certificates
- controller scaffolding for most component families
- partial Cilium integration
- partial FRR integration
- tests across several packages

What is not yet complete:
- eBPF runtime ownership needs consolidation
- integration/reconciliation test matrix not yet built
- status docs not yet verified against actual behavior

## Governing Decision

Authoritative v1 direction:
- Cilium-first control plane

Reference:
- `docs/design/adr-0001-cilium-first-control-plane-contract.md`

This means:
- routing, NAT, policy, and DPI-driven enforcement must converge on the Cilium control plane
- kernel-native helpers may remain, but as support code rather than alternate authoritative control paths
- controllers must report applied state rather than desired intent only

## Planning Principles

- prefer the smallest correct implementation that removes ambiguity
- finish real existing backends before creating new abstraction layers
- remove dummy/log-only success paths from active reconciliation flows
- keep controller behavior idempotent and statusful
- treat caveats as explicit review items, not hidden debt

Reference:
- `docs/design/implementation_caveats.md`

## Current Ticket Status

Completed:
- Ticket 1: Cilium-first control-plane contract
- Ticket 2: Cilium client route operations
- Ticket 3: route synchronization
- Ticket 4: routing controller reconciliation
- Ticket 5: VRF / policy-based routing reconciliation semantics
- Ticket 6: real Cilium NAT core for SNAT and DNAT
- Ticket 7: NAT66, NAT64, and port forwarding
- Ticket 8: NAT controller idempotent/statusful reconciliation
- Ticket 9: FRR configuration validation and reload hardening
- Ticket 10: BGP and OSPF controllers wired to real FRR state
- Ticket 11: Kea control-socket reconciliation in the DHCP controller
- Ticket 12: DNS manager wired to real CoreDNS and AdGuard operations
- Ticket 13: NTP controller reconciliation and NTS wiring
- Ticket 14: WireGuard backend standardization and controller reconciliation
- Ticket 16: IDS managers reflecting real Suricata and Zeek engine state
- Ticket 17: DPI events wired into real Cilium policy responses
- Ticket 18: Auth manager provider construction and hardening

- Ticket 15: cert-manager outputs integrated into NTS consumer via SecretWatcher
- Ticket 19: eBPF runtime consolidated, placeholder Cilium discovery removed
- Ticket 20: reconciliation test matrix built, controller tests added, status docs corrected

## Epic 1: Datapath Unification

Goal:
- remove split ownership between kernel-native helpers and incomplete Cilium orchestration

Status: **complete**

All major controller paths now have one authoritative enforcement backend. No active route/NAT controller path depends on dummy synchronization. Applied status reflects real backend operations.

## Epic 2: Routing Core

Goal:
- finish route lifecycle management on the chosen control plane

Status: **complete**

Static route reconciliation is deterministic and idempotent. VRF and PBR behavior is documented and implemented consistently via `VRFTableID()`. Protocol controllers reflect actual FRR config and reload state. BGP/OSPF status comes from live `vtysh` queries.

## Epic 3: NAT and Enforcement

Goal:
- make NAT and firewall-style enforcement real on the Cilium path

Status: **complete**

SNAT and DNAT are enforced through real Cilium policy creation. NAT66, NAT64, and port forwarding work through the same path. NAT controller is idempotent (spec-hash comparison) and statusful (Applied/Degraded/Invalid/Removed conditions).

## Epic 4: Core Network Services

Goal:
- finish service controllers that already have meaningful backend implementations

Status: **complete**

DHCP controller applies real Kea config via control socket with verification. DNS manager drives real CoreDNS zone updates and AdGuard filter/client changes. NTP controller produces real Chrony config with NTS support.

## Epic 5: VPN and Certificates

Goal:
- standardize usable VPN and certificate consumer behavior

Status: **complete**

WireGuard CRDs reconcile into real interface and peer state. cert-manager outputs are consumed by the NTS service via a SecretWatcher that triggers Chrony reload on certificate renewal.

## Epic 6: IDS, DPI, and Auth

Goal:
- move security components from connectors toward real orchestration

Status: **complete**

IDS state reflects real Suricata/Zeek engines. DPI events trigger real Cilium policy creation with TTL expiry. Auth manager instantiates actual provider implementations.

## Epic 7: eBPF Runtime Hardening

Goal:
- consolidate runtime ownership and remove placeholder Cilium integration behavior

Status: **complete**

Single lifecycle owner (`ProgramManager`) established. Supported hooks explicitly defined (XDP, TC, sockops, cgroup). Placeholder Cilium discovery replaced with real API queries or explicit "not available" errors.

## Epic 8: Tests and Status Accuracy

Goal:
- make implementation status trustworthy and regressions visible

Status: **complete**

Reconciliation tests added for BGP, OSPF, MultiWAN, Policy, QoS, and Cilium controllers. Test matrix document created. Project tracker corrected to reflect verified behavior. int-vs-int64 bugs found and fixed during testing.

## Milestones

Milestone 1: **complete**
- Tickets 1 to 4 complete
- route contract and synchronization baseline established

Milestone 2: **complete**
- Tickets 5 to 8 complete
- route and NAT control plane coherent

Milestone 3: **complete**
- Tickets 9 to 13 complete
- routing protocols and core services wired through real reconciliation

Milestone 4: **complete**
- Tickets 14 to 18 complete
- VPN, certificates, IDS/DPI, and auth fully functional

Milestone 5: **complete**
- Tickets 19 to 20 complete
- eBPF runtime consolidated, test matrix built, status docs corrected

## Architect Review Questions

See `docs/design/implementation_backlog.md` for the canonical list of open architect review questions.

## References

- `docs/design/adr-0001-cilium-first-control-plane-contract.md`
- `docs/design/implementation_caveats.md`
- `docs/design/implementation_backlog.md`
- `docs/project-tracker.md`
