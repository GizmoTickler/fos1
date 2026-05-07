# Kubernetes-Based Router/Firewall Distribution
## Current Implementation Plan

This document replaces the older time-boxed plan with a codebase-driven implementation plan based on the repository's actual current state.

## Verification Snapshot

Verified contract on 2026-04-25 (post-Sprint-31):
- `make verify-mainline` is the canonical Go verification target (`go test ./...` 43/43 packages pass, `go build ./...` green)
- `.github/workflows/ci.yml` enforces `make verify-mainline` on pushes to `main` and PRs targeting `main`
- `.github/workflows/validate-manifests.yml` validates rendered manifests on manifest-affecting PRs and fails on real `kubeconform` errors; Sprint 30 Ticket 42 added `scripts/ci/prove-no-cluster-admin.sh` as a CI step that blocks any `ClusterRoleBinding` to `cluster-admin` without an explicit `fos1.io/rbac-exception` annotation
- Sprint 31 added `scripts/ci/prove-leader-failover.sh` (Ticket 47, leader election RTO ≤ 30s on `ids-controller`) and `scripts/ci/prove-cert-rotation.sh` (Ticket 49, `/healthz` stays 200 across `cmctl renew`) as Kind harness steps in `.github/workflows/test-bootstrap.yml`. The four-hot-path bench job (NAT apply + DPI / FilterPolicy / threat-intel translate per Tickets 43 + 54) runs as a non-blocking CI step.

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
- Ticket 46: post-Sprint-30 status truth-up (merge `7979c41`)

Sprint 31 (post-Sprint-30 production hardening) — completed:
- Ticket 47: HA / controller leader election baseline. `pkg/leaderelection` wraps `k8s.io/client-go/tools/leaderelection` for non-controller-runtime mains; api-server uses controller-runtime manager-level LE. Every owned controller runs `replicas: 2` with podAntiAffinity. Namespace-scoped `Role` + `RoleBinding` for `coordination.k8s.io/leases` (no new `ClusterRoleBinding`). RTO ≤ 30s proved by `scripts/ci/prove-leader-failover.sh` against `ids-controller` (feat `f16109a`, merge `f9188c5`).
- Ticket 48: write-path CRUD v1 REST API for FilterPolicy. POST / PUT (optimistic concurrency on `metadata.resourceVersion`) / PATCH (JSON Merge Patch + Strategic Merge Patch dispatch via `Content-Type`) / DELETE (with propagationPolicy). Server-side validation rejects malformed specs with structured 422. RBAC extended to grant create/update/patch/delete on `filterpolicies.security.fos1.io`. `pkg/api.TestMTLSEndToEnd` proves 200 / 403 / handshake / POST round-trip cases (feat `4efe669`, merge `69d3101`).
- Ticket 49: inter-controller TLS baseline. `fos1-internal-ca` ClusterIssuer (CA-typed, chained from a 10y self-signed root) mints per-controller server certs; `pkg/security/certificates.LoadTLSConfig` + `WatchAndReload` reloads cert-manager renewals in place via fsnotify. API server was mTLS-only in this ticket; other owned listeners stayed server-TLS-only until Sprint 32 Ticket 56. `scripts/ci/prove-cert-rotation.sh` asserts `/healthz` stays 200 across `cmctl renew`. External-daemon TLS (FRR / Suricata / Kea / Zeek) remained deferred to Sprint 32. See `docs/design/internal-tls-secrets.md`. Landed directly on main as `c60f906` (no merge commit).
- Ticket 50: residual nftables NAT imports removed. `pkg/network/nat/kernel.go` and `pkg/deprecated/nat/` deleted; `pkg/security/firewall/` had already been removed in Sprint 29 Ticket 33, so cleanup commit `bac62b2` then dropped the unused `github.com/google/nftables` from `go.mod` / `go.sum`. Active NAT path remains `pkg/network/nat/manager.go` (Cilium-first, ADR-0001) (feat `b6433fc`, merge `c78252f`, cleanup `bac62b2`).
- Ticket 51: eBPF sockops + cgroup program types. `bpf/sockops_redirect.c` and `bpf/cgroup_egress_counter.c` compile via `make bpf-objects`; `pkg/hardware/ebpf/sockops_loader_linux.go` + `cgroup_loader_linux.go` plus matching stubs land alongside the Sprint 30 XDP + TC loaders. `pkg/hardware/ebpf/program_manager.go` dispatch now routes XDP / TC / sockops / cgroup to real loaders on Linux; sk_msg, sk_lookup, etc. still return `ErrEBPFProgramTypeUnsupported`. Linux-only integration tests skip without unified cgroup v2 / `CAP_BPF` / `CAP_NET_ADMIN` (feat `08e6514`, merge `5d8173e`).
- Ticket 52: VLAN-scoped TC shaper controller. New `TrafficShaper` CRD drives `pkg/hardware/ebpf.TCLoader` for VLAN-scoped or uplink egress shaping on top of the Sprint 30 Ticket 39 TC infrastructure. Composes with Ticket 45's Cilium Bandwidth Manager: pod egress caps come from `QoSProfile`, uplink/VLAN shaping comes from `TrafficShaper`. Uses the Ticket 40 `pkg/controllers/status.Writer` helper for Applied/Degraded/Invalid/Removed conditions. Controller stays at `replicas: 1` because `hostNetwork: true` conflicts on the netdev (feat `2b64cdf`, merge `65e33df`).
- Ticket 53: MISP JSON threat-intel feed. `pkg/security/threatintel/misp.go` parses MISP's JSON event schema (domain/IP/URL indicators) into the same `Indicator` shape the URLhaus feed produces. `ThreatFeed.Spec.Format` now accepts `"misp-json"` alongside `"urlhaus-csv"`; MISP feeds reference a Kubernetes Secret via `spec.authSecretRef` and the controller reads the `apiKey` data key for the `Authorization` header. Missing Secret produces a clear `Invalid` condition. STIX/TAXII remains a non-goal (feat `ea29076`, merge `7684dee`).
- Ticket 54: performance baseline coverage expansion. `tools/bench/dpi_policy_bench_test.go`, `filterpolicy_translate_bench_test.go`, and `threatintel_translate_bench_test.go` join `nat_apply_bench_test.go` for four hot paths total. Each gets ops/s + alloc counters; `docs/performance/baseline-2026-04.md` records new baselines with machine specs and commit SHA. CI regression gate stays non-blocking per Ticket 43 envelope (feat `0f51278`, merge `b83f6e6`).
- Ticket 55: post-Sprint-31 status truth-up (this ticket).

Sprint 32 (mTLS mesh + external-daemon TLS) — in progress:
- Ticket 56: mTLS controller-to-controller mesh is in progress. `pkg/security/certificates.LoadMutualTLSConfig` reuses the Ticket 49 mounted material for server certs, client certs, `RootCAs`, `ClientCAs`, and rotation. Non-API owned HTTP listeners (DPI metrics, NTP metrics/API, event-correlator probes when TLS is enabled) now wrap handlers in deny-by-default Subject-CN allowlists. `scripts/ci/prove-mtls-mesh.sh` proves allowed cert success, missing-client-cert handshake failure, and unknown-CN 403 behavior.
- Ticket 57: Prometheus rekey for `fos1-internal-ca` is implemented locally. `prometheus-client-tls` provides the scrape identity, and owned DPI/NTP metrics jobs now use HTTPS with CA / client certificate files.
- Ticket 58: FRR vtysh mTLS sidecar is implemented locally. ADR-0002 selects a repo-owned sidecar over native FRR TLS; `cmd/frr-vtysh-sidecar` executes local `vtysh`, `pkg/network/routing/frr.Client` can use HTTPS transport, and the FRR manifest exposes only `vtysh-tls:9443`.
- Ticket 59: Suricata command auth/TLS is implemented locally. `cmd/suricata-command-sidecar` exposes `POST /suricata-command` over mTLS, enforces a mounted `suricata-command-auth` token, and forwards authenticated commands to Suricata's native Unix socket after version negotiation. `pkg/security/ids/suricata.Client` can use the HTTPS fallback with ids-controller client cert material. Local proof: `scripts/ci/prove-suricata-command-auth-tls.sh`.

See `docs/sprints/sprint-32-mtls-and-external-tls.md` for the active Sprint 32 scope and `docs/design/implementation_backlog.md` for historical ticket definitions.

Interpretation:
- Tickets 1-20 are complete for the primary implementation track that converted the main routing/NAT/service/security backends away from earlier placeholder behavior.
- Tickets 21-28 plus the ops follow-through closed out the post-ticket-20 convergence and ops sprint: Kubernetes DPI policy, security policy controller, route-sync/direct/K8s helper clients, event-correlation controller contract, hardware offload stats, observability docs, `make verify-mainline`, CI enforcement, and the owned Kind proof baseline.
- Sprint 29 (tickets 29-37) moved the work from "baseline proven" to "baseline exercised" and closed out advertised-but-unshipped surfaces: event-correlator runtime end-to-end, accelerated Elasticsearch rollover proof, natural-traffic DPI proof, dashboard/alert query validation, `FilterPolicy` → Cilium translation, auth provider scope reduction (SAML/RADIUS/cert removed as non-goals), real NIC/capture reporting with explicit unsupported paths, coverage bumps on thin packages, and a post-sprint status truth-up.
- Sprint 30 (tickets 38-46) closed the critical-path production gaps called out as Sprint 29 non-goals: XDP + TC eBPF compile/load on Linux, shared CRD status writeback helper, read-only REST management API with mTLS, minimum-privilege RBAC with CI enforcement, NAT performance baseline, URLhaus threat-intel v0 ingestion, per-pod egress QoS via Cilium Bandwidth Manager, and a post-sprint truth-up.
- Sprint 31 (tickets 47-55) closed the residual production-hardening blockers from Sprint 30: controller leader election with hot standby (RTO ≤ 30s, CI failover proof on `ids-controller`), CRUD v1 REST API for FilterPolicy with strategic-merge / JSON-merge patch dispatch, inter-controller TLS baseline via the `fos1-internal-ca` ClusterIssuer with cert-manager rotation reload, residual nftables imports + dependency removal, eBPF sockops + cgroup program types, a VLAN-scoped TC shaper controller (`TrafficShaper` CRD on top of Ticket 39's TC loader), MISP JSON threat-intel ingestion alongside URLhaus, four-hot-path performance baseline coverage, and this truth-up.
- Sprint 32 has started with Tickets 56-59. Remaining candidate focus areas are external-daemon TLS (Kea / Zeek / chrony), external-daemon HA, shared-state HA (Elasticsearch / Prometheus / Grafana / Alertmanager), write-path API for additional resource families (NAT, routing, DPI, zones), watch / streaming endpoints, and broader eBPF program types beyond the four owned loaders (sk_msg, sk_lookup, etc.).
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

Sprint 31 is fully merged. **Sprint 32 is in progress** with Tickets 56-59 started from the Linear backlog.

Candidate Sprint 32 workstreams, distilled from the post-Sprint-31 state of `Status.md` §Critical Gaps and surviving caveats in `docs/design/implementation_caveats.md`:

- **mTLS for controller-to-controller calls** — Ticket 56 now provides the shared mutual-TLS loader, client helper, receiver allowlist middleware, and in-code listener wiring for currently owned HTTP listeners. Ticket 57 layers Prometheus scrape compatibility on top with a `prometheus` client identity and `fos1-internal-ca` trust bundle.
- **External-daemon TLS (Kea control socket, Zeek Broker, chronyc)** — FRR vtysh now has a sidecar mTLS terminator via Ticket 58, and Suricata's command socket is fronted by the Ticket 59 mTLS/shared-secret sidecar. The remaining daemon paths still speak plaintext on in-pod loopback / Unix paths; cross-host paths need a sidecar TLS terminator or a daemon-native TLS configuration.
- **Prometheus rekey for `fos1-internal-ca`** — `manifests/base/monitoring/prometheus.yaml` now uses dedicated HTTPS pod-SD jobs for the owned DPI/NTP exporters, mounts the `prometheus-client-tls` Secret, and sets `ca_file`, `cert_file`, `key_file`, and per-target `server_name`.
- **External-daemon HA** — Ticket 47 covered controller-tier failover only. FRR / Suricata / Zeek / Kea singletons still run as single-pod / single-process; per-daemon clustering (BFD for FRR, Kea HA hooks, parallel Suricata sensors) remains open.
- **Shared-state HA (Elasticsearch / Prometheus / Grafana / Alertmanager)** — single-replica StatefulSets / Deployments hold persistent data. Multi-node clustering (ES cross-zone replication, Prometheus federation or Thanos) is a separate sprint.
- **Write-path API for additional resource families** — Ticket 48 extended FilterPolicy to full CRUD. NAT, routing, DPI, zones, and threat feeds remain read-only or `kubectl`-only.
- **Watch / streaming endpoints on the REST API** — chunked JSON-lines streaming was deferred from Ticket 48.
- **Broader eBPF program types** — Ticket 51 added sockops + cgroup; sk_msg, sk_lookup, lwt, and other program types still return `ErrEBPFProgramTypeUnsupported` from `pkg/hardware/ebpf/program_manager.go`.

These workstreams are placeholders; ticket-level definitions (scope, primary areas, acceptance criteria) will be written into the backlog during a dedicated Sprint 32 planning session.

## Architect Review Questions

See `docs/design/implementation_backlog.md` for the canonical list of open architect review questions.

## References

- `docs/design/adr-0001-cilium-first-control-plane-contract.md`
- `docs/design/implementation_caveats.md`
- `docs/design/implementation_backlog.md`
- `docs/project-tracker.md`
