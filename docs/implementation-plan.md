# Kubernetes-Based Router/Firewall Distribution
## Current Implementation Plan

This document replaces the older time-boxed plan with a codebase-driven implementation plan based on the repository's actual current state.

## Verification Snapshot

Verified contract on 2026-04-19:
- `make verify-mainline` is the canonical Go verification target
- `.github/workflows/ci.yml` enforces `make verify-mainline` on pushes to `main` and PRs targeting `main`
- `.github/workflows/validate-manifests.yml` validates rendered manifests on manifest-affecting PRs and fails on real `kubeconform` errors

Owned runtime observability proof on 2026-04-20:
- `.github/workflows/test-bootstrap.yml` now proves the Prometheus pod-annotation scrape path for node-local `dpi-manager` and `ntp-controller`
- the same harness proves a deterministic Suricata canary path into Elasticsearch plus the `fos1-log-retention-14d` ILM/template bootstrap
- the harness intentionally narrows the NTP proof slice to controller-owned resources in Kind instead of treating optional operator add-ons or the chrony daemonset as verified

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
- observability manifests now encode PVC-backed state plus a single-node Elasticsearch `14d` retention baseline, and the harness proves the owned scrape/log-ingest baseline, but broader observability runtime wiring is still not verified
- threat-intelligence and deeper event-ingestion/runtime paths remain incomplete
- hardware/NIC support still has broader capability gaps beyond the offload-statistics hardening completed in ticket 26
- CI now enforces the canonical `make verify-mainline` contract, but deployment/runtime verification still needs to be built on top of it

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
- Ticket 21: Kubernetes DPI policy controller now applies real Cilium policy responses with retryable failures
- Ticket 22: security policy controller no longer relies on fake informer/apply paths
- Ticket 23: route synchronizer placeholder mutation paths retired in favor of explicit real/error contracts
- Ticket 24: direct and Kubernetes helper clients no longer return log-only success for unsupported operations
- Ticket 25: event-correlation controller status and documentation aligned to a verified runtime contract
- Ticket 26: hardware offload statistics now use ethtool-derived behavior or explicit unsupported reporting
- Ticket 27: observability documentation reconciled to verified repository-owned behavior versus external/runtime assumptions
- Ticket 28: canonical `make verify-mainline` automation added for the mainline checks
- Ops sprint follow-through: CI now enforces `make verify-mainline`, manifest validation fails on real `kubeconform` errors, the owned exporter baseline is pod-annotation scraping for `dpi-manager` (`:8080/metrics`) and `ntp-controller` (`:9559/metrics`), and the Kind bootstrap harness proves that baseline plus the Suricata/Elasticsearch canary path

Open (Sprint 29 - runtime depth and post-baseline hardening):
- Ticket 29: land the event-correlator runtime and prove one event end to end through source -> correlator -> sink
- Ticket 30: exercise Elasticsearch retention and rollover beyond bootstrap presence
- Ticket 31: prove DPI and security-log ingestion under natural traffic, not a log-line canary
- Ticket 32: validate dashboard and alert-rule queries against live Prometheus series
- Ticket 33: translate `FilterPolicy`/`FirewallRule` CRDs into real Cilium network policies (Cilium-first, no nftables)
- Ticket 34: decide and converge on SAML / RADIUS / certificate auth providers (implement or remove; no "not implemented" factory paths)
- Ticket 35: real NIC capability reporting and packet-capture contract (follow the ticket-26 pattern)
- Ticket 36: raise reconciliation-style coverage on thin packages (`pkg/traffic/`, `pkg/security/policy/`, `pkg/hardware/wan/`, `pkg/network/ebpf/`)
- Ticket 37: truth-up status docs after Sprint 29 lands

See `docs/design/implementation_backlog.md` for the full Sprint 29 ticket definitions, critical path, and suggested parallel ownership.

Interpretation:
- Tickets 1-20 are complete for the primary implementation track that converted the main routing/NAT/service/security backends away from earlier placeholder behavior.
- Tickets 21-28 plus the ops follow-through closed out the post-ticket-20 convergence and ops sprint: Kubernetes DPI policy, security policy controller, route-sync/direct/K8s helper clients, event-correlation controller contract, hardware offload stats, observability docs, `make verify-mainline`, CI enforcement, and the owned Kind proof baseline.
- Sprint 29 moves the work from "baseline proven" to "baseline exercised": event-correlator runtime end-to-end, Elasticsearch retention under load, natural-traffic DPI proof, dashboard/alert query validation, real `FilterPolicy` enforcement, auth provider closeout, NIC/capture reporting, coverage bumps, and a post-sprint status truth-up.
- Repository-wide completion is broader than that ticket set; there are still secondary packages and legacy controller paths that need convergence before the codebase can be described as uniformly production-ready.

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

## Next Phase Workstreams

### Workstream 1: Extend Observability Proof Beyond The Current Baseline

Why this is next:
- the docs, manifests, and bootstrap harness now agree on the owned pod-annotation scrape baseline for DPI and NTP plus the single-node monitoring durability envelope
- the next observability work is no longer proving that the owned baseline exists; it is broadening proof beyond the current canary/query slice

Primary areas:
- `pkg/security/ids/correlation/`
- monitoring/logging deployment wiring and related docs

Exit criteria:
- live-cluster evidence goes beyond `up=1` and deterministic canaries into useful downstream metrics/log consumers
- live-cluster evidence exercises the Elasticsearch retention/storage baseline beyond policy/template presence
- event correlation has a deeper end-to-end runtime than controller-only reconciliation
- remaining observability non-goals and external runtime assumptions are explicit

### Workstream 2: Extend Verification Beyond The Current CI Gate

Why this is next:
- the repository now has a canonical local verification target and CI enforces it
- the next improvement is broadening operational proof beyond the current Go and manifest gates, not redefining those gates

Primary areas:
- CI/workflow configuration
- release/deployment docs
- `Makefile` only if CI-specific helpers are needed

Exit criteria:
- deployment/release workflows reference the required verification path
- additional runtime-sensitive checks are added only where they prove behavior the current gates do not cover
- observability verification steps clearly distinguish manifest rendering from runtime proof

### Workstream 3: Deepen Runtime Follow-Through

Why this is next:
- the first convergence sprint fixed controller contracts, but external runtime depth is still limited
- threat-intelligence and event-ingestion depth remain future implementation areas

Primary areas:
- `pkg/security/ids/correlation/`
- `docs/design/threat-intelligence-system.md`

Exit criteria:
- event correlation has a deeper end-to-end runtime than controller-only reconciliation
- remaining threat-intelligence non-goals are explicit

### Workstream 4: Hardware And Operational Hardening

Why this is next:
- the repository now verifies cleanly in local Go build/test, but operational surfaces still need hardening
- offload statistics are hardened, but NIC and platform support still have broader gaps

Primary areas:
- `pkg/hardware/offload/`
- `pkg/hardware/nic/`
- CI/deployment docs and automation

Exit criteria:
- hardware capability reporting is real, not placeholder
- critical operational checks beyond the current Go and manifest gates run in automation, not only locally
- docs explain platform assumptions and unsupported hardware paths clearly

## Architect Review Questions

See `docs/design/implementation_backlog.md` for the canonical list of open architect review questions.

## References

- `docs/design/adr-0001-cilium-first-control-plane-contract.md`
- `docs/design/implementation_caveats.md`
- `docs/design/implementation_backlog.md`
- `docs/project-tracker.md`
