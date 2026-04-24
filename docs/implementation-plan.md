# Kubernetes-Based Router/Firewall Distribution
## Current Implementation Plan

This document replaces the older time-boxed plan with a codebase-driven implementation plan based on the repository's actual current state.

## Verification Snapshot

Verified contract on 2026-04-23 (post-Sprint-30):
- `make verify-mainline` is the canonical Go verification target (`go test ./...` 42/42 packages pass, `go build ./...` green)
- `.github/workflows/ci.yml` enforces `make verify-mainline` on pushes to `main` and PRs targeting `main`
- `.github/workflows/validate-manifests.yml` validates rendered manifests on manifest-affecting PRs and fails on real `kubeconform` errors; Sprint 30 Ticket 42 added `scripts/ci/prove-no-cluster-admin.sh` as a CI step that blocks any `ClusterRoleBinding` to `cluster-admin` without an explicit `fos1.io/rbac-exception` annotation

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

Sprint 29 (runtime depth and post-baseline hardening) — completed:
- Ticket 29: event-correlator runtime end-to-end proof landed via `scripts/ci/prove-event-correlation-e2e.sh` (merges `31b5140`, `b06a45e`)
- Ticket 30: accelerated ILM rollover + delete proved via `scripts/ci/prove-es-retention-rollover.sh` against `fos1-ci-accelerated` policy; production `14d` envelope remains a manifest-level target (merges `12d4d47`, `729300e`)
- Ticket 31: natural-traffic DPI proof landed — signature id `9000001` drives eve.json → Elasticsearch → `sum(dpi_events_total)` end to end via `scripts/ci/prove-dpi-natural-traffic.sh` (merges `4c9895c`, `bb9b0cc`)
- Ticket 32: PromQL validator tool at `tools/prometheus-query-validator/` runs as a Kind harness step; target-architecture expressions allowlisted under `manifests/dashboards/.queries-target-architecture.txt` (merge `0929de8`)
- Ticket 33: `FilterPolicy` → `CiliumNetworkPolicy` translator wired with spec-hash idempotency and Applied/Degraded/Invalid/Removed conditions; `FirewallRule`, nftables, and `pkg/security/firewall/` removed per ADR-0001 (merges `9ad19b7`, `244128c`)
- Ticket 34: SAML/RADIUS/certificate auth stubs removed from manager factory, CRD enum, manifests, and docs; auth surface scoped to local/LDAP/OAuth (merges `92088b8`, `ac4f32e`)
- Ticket 35: real NIC + capture capability reporting via Linux ethtool/tcpdump with explicit unsupported paths (`ErrNICStatisticsNotSupported`, `ErrTCPDumpNotAvailable`, `ErrNICUnsupportedPlatform`); eBPF-based capture labelled non-goal (merges `83211d4`, `497f286`)
- Ticket 36: reconciliation-style coverage raised on thin packages — `pkg/traffic` 51.4%, `pkg/hardware/wan` 57.6%, `pkg/network/ebpf` 93.2%, `pkg/security/policy` 51.1% (merges `e5dcb3f`, `c31caf8`, `3714873`, `d2ec037`)
- Ticket 37: post-Sprint-29 status truth-up (merge `fd131de`)

Sprint 30 (critical-path production gaps) — completed:
- Ticket 38: prototype eBPF XDP program compilation + attachment via `github.com/cilium/ebpf`; `bpf/xdp_ddos_drop.c` builds through `make bpf-objects`, compiled ELF committed at `pkg/hardware/ebpf/bpf/xdp_ddos_drop.o` and embedded via `//go:embed`; Linux-only integration test skips without `CAP_BPF`/`CAP_NET_ADMIN`; non-XDP types return `ErrEBPFProgramTypeUnsupported` (feat `3a9f677`, merge `de851a6`)
- Ticket 39: TC-attached QoS shaping program + clsact qdisc bootstrap; `bpf/tc_qos_shape.c` compiles via `make bpf-objects`, loads through `pkg/hardware/ebpf/tc_loader_linux.go`, attaches via `AttachTCX` (kernel ≥ 6.6), exposes per-ifindex priority map for user-space population before attach (feat `f9f3565`)
- Ticket 40: shared CRD status writeback helper at `pkg/controllers/status/writer.go` lifts the NAT controller's `writeStatusToCRD` pattern; adopted by FilterPolicy (closes Sprint 29 Ticket 33 in-memory-only caveat), NAT, and MultiWAN controllers; round-trip unit tests verify retry-on-conflict (feat `47b8088`, merge `2a2851c`)
- Ticket 41: read-only REST API v0 under `cmd/api-server/` and `pkg/api/`; exposes `/v1/filter-policies` list+get, `/healthz`, `/readyz`, `/openapi.json` behind `tls.RequireAndVerifyClientCert` with a ConfigMap-backed Subject-CN allowlist; base manifests at `manifests/base/api/`; `pkg/api.TestMTLSEndToEnd` proves 200/403/handshake-failure cases (feat `e3bc979`, merge `9c70daf`)
- Ticket 42: RBAC minimum-privilege baseline — every ServiceAccount bound to a scoped ClusterRole, `scripts/ci/prove-no-cluster-admin.sh` blocks `cluster-admin` bindings without an explicit `fos1.io/rbac-exception` annotation; full verb/resource table at `docs/design/rbac-baseline.md` (feat `e13b91a`, merge `4af3403`; branch not pushed)
- Ticket 43: NAT policy apply performance baseline — `tools/bench/nat_apply_bench_test.go` plus baseline report at `docs/performance/baseline-2026-04.md`; regressions flagged as warnings in CI output (non-blocking) (feat `2b844d7`, merge `4ce31e8`)
- Ticket 44: URLhaus threat-intel v0 ingestion — `ThreatFeed` CRD, `cmd/threatintel-controller/`, `pkg/security/threatintel/` parses URLhaus CSV, translates into Cilium deny policies with last-seen TTL; `ThreatFeed.Status` reports last-fetch time, entry count, expiry state; MISP/STIX remain non-goals (feat `2c042a5`, merge `fb9dfb0`)
- Ticket 45: QoS enforcement via Cilium Bandwidth Manager — `QoSProfile` CR → `kubernetes.io/egress-bandwidth` pod annotation → BPF TBF rate limiter at pod admission; classful/uplink TC shaping lives on the Ticket 39 infrastructure for a future VLAN-shaper controller to consume (feat `3326f46`, merge `a04ce71`)
- Ticket 46: post-Sprint-30 status truth-up (this ticket)

See `docs/design/implementation_backlog.md` for full ticket definitions. The next phase is Sprint 31 (scope finalization out of scope for Ticket 46; a placeholder lives in `docs/design/implementation_backlog.md` §"Sprint 31 (placeholder): Post-Sprint-30 Production Hardening").

Interpretation:
- Tickets 1-20 are complete for the primary implementation track that converted the main routing/NAT/service/security backends away from earlier placeholder behavior.
- Tickets 21-28 plus the ops follow-through closed out the post-ticket-20 convergence and ops sprint: Kubernetes DPI policy, security policy controller, route-sync/direct/K8s helper clients, event-correlation controller contract, hardware offload stats, observability docs, `make verify-mainline`, CI enforcement, and the owned Kind proof baseline.
- Sprint 29 (tickets 29-37) moved the work from "baseline proven" to "baseline exercised" and closed out advertised-but-unshipped surfaces: event-correlator runtime end-to-end, accelerated Elasticsearch rollover proof, natural-traffic DPI proof, dashboard/alert query validation, `FilterPolicy` → Cilium translation, auth provider scope reduction (SAML/RADIUS/cert removed as non-goals), real NIC/capture reporting with explicit unsupported paths, coverage bumps on thin packages, and a post-sprint status truth-up.
- Sprint 30 (tickets 38-46) closed the critical-path production gaps called out as Sprint 29 non-goals: XDP + TC eBPF compile/load on Linux, shared CRD status writeback helper, read-only REST management API with mTLS, minimum-privilege RBAC with CI enforcement, NAT performance baseline, URLhaus threat-intel v0 ingestion, per-pod egress QoS via Cilium Bandwidth Manager, and a post-sprint truth-up.
- The next phase is Sprint 31 (placeholder scope in the backlog; detailed ticket definitions come in a separate planning session). Candidate focus areas are HA/clustering, write-path REST API, broader eBPF program types (sockops / cgroup), more threat feeds, performance coverage beyond one hot path, inter-controller TLS + secrets management, and ingress / VLAN-scoped TC shaping on top of the Ticket 39 loader.
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

Sprint 30 is fully merged. The next phase is **Sprint 31 (placeholder)**; candidate scope lives in `docs/design/implementation_backlog.md` §"Sprint 31 (placeholder): Post-Sprint-30 Production Hardening". Detailed ticket definitions come in a separate planning session and are intentionally not duplicated here.

Candidate Sprint 31 workstreams, distilled from the post-Sprint-30 state of `Status.md` §Critical Gaps and surviving caveats in `docs/design/implementation_caveats.md`:

- **HA / clustering** — elevate single-node Elasticsearch / Prometheus / Grafana / Alertmanager postures, add leader election and state replication for controllers. Largest residual production blocker after Sprint 30.
- **Write-path REST API** — extend Ticket 41's read-only v0 with mutating verbs (POST/PUT/PATCH/DELETE), watch/streaming endpoints, and additional resource families beyond FilterPolicy (NAT, routing, DPI, zones).
- **Broader eBPF program types** — add `sockops` and `cgroup` loaders alongside the Ticket 38 XDP + Ticket 39 TC path; unblock more hook coverage across the framework.
- **More threat feeds** — expand beyond Ticket 44's URLhaus CSV to IP-reputation feeds and, if ADR-0001 is revisited, MISP/STIX/TAXII; MISP/STIX are current non-goals.
- **Performance tuning beyond one hot path** — Ticket 43 baselined NAT policy apply. DPI event → Cilium policy, routing sync, DHCP control socket, DNS zone update remain unbenchmarked.
- **Internal TLS + secrets management for non-API components** — Ticket 41 introduced mTLS for the REST API only; inter-controller TLS and a documented secrets model remain open.
- **Ingress rate limiting + VLAN-scoped shaping** — Ticket 45 shipped per-pod egress rate limiting. Ingress enforcement and a VLAN-shaper controller on top of the Ticket-39 TC loader infrastructure are still to be scoped.

These workstreams are placeholders; ticket-level definitions (scope, primary areas, acceptance criteria) will be written into the backlog during a dedicated Sprint 31 planning session.

## Architect Review Questions

See `docs/design/implementation_backlog.md` for the canonical list of open architect review questions.

## References

- `docs/design/adr-0001-cilium-first-control-plane-contract.md`
- `docs/design/implementation_caveats.md`
- `docs/design/implementation_backlog.md`
- `docs/project-tracker.md`
