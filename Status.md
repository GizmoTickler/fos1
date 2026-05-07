# Implementation Status Report
**Generated:** 2026-05-07
**Repository:** Kubernetes-Based Router/Firewall (FOS1)

## Executive Summary

This repository has progressed from an architectural blueprint to a **functional implementation** with Sprint 31 (tickets 47-55) fully merged as of 2026-04-25, on top of Sprint 30 (tickets 38-46) and Sprint 29 (tickets 29-37). Sprint 32 has started with Tickets 56-58 from Linear. `make verify-mainline` remains the canonical gate. The primary routing, NAT, DNS, DHCP, NTP, WireGuard, IDS, DPI, auth, policy-enforcement, eBPF (XDP + TC + sockops + cgroup), QoS (per-pod egress + VLAN-scoped TC shaper), threat-intel (URLhaus + MISP), CRUD-v1 REST API, controller HA, internal TLS, mTLS mesh primitives, FRR vtysh mTLS sidecar, and observability-proof pipelines are implemented or in active hardening.

Sprint 31 closed the residual production-hardening blockers from Sprint 30:
- **Controller HA via leader election (Ticket 47)** — every owned controller now wires leader election against `coordination.k8s.io/v1` Leases. `cmd/api-server/` uses `sigs.k8s.io/controller-runtime/pkg/manager` LeaderElection; the rest go through `pkg/leaderelection`, a thin wrapper over `k8s.io/client-go/tools/leaderelection` with the fos1-standard 15s/10s/2s timings. Every owned controller `Deployment` runs `replicas: 2` with `preferredDuringSchedulingIgnoredDuringExecution` podAntiAffinity. Namespace-scoped `Role` + `RoleBinding` per controller — no new `ClusterRoleBinding`. RTO ≤ 30s proved by `scripts/ci/prove-leader-failover.sh` against `ids-controller`. `trafficshaper-controller` stays single-replica because `hostNetwork: true` conflicts on the netdev.
- **CRUD v1 REST API for FilterPolicy (Ticket 48)** — `cmd/api-server/` and `pkg/api/` expose POST / PUT / PATCH / DELETE on `/v1/filter-policies/{ns}/{name}` plus the existing list+get, `/healthz`, `/readyz`, `/openapi.json` behind `tls.RequireAndVerifyClientCert` with a ConfigMap-backed Subject-CN allowlist. PATCH dispatches between `application/merge-patch+json` (JSON Merge Patch) and `application/strategic-merge-patch+json` (Strategic Merge Patch). PUT requires `metadata.resourceVersion` for optimistic concurrency. Server-side validation rejects malformed specs with structured 422 `Invalid` bodies. `pkg/api.TestMTLSEndToEnd` asserts 200 / 403 / handshake / POST round-trip cases.
- **Inter-controller TLS baseline (Ticket 49) + mTLS mesh start (Tickets 56-58)** — single `fos1-internal-ca` ClusterIssuer (CA-typed, chained from a 10y self-signed root) mints per-controller certs at `/var/run/secrets/fos1.io/tls/`. `LoadTLSConfig` + `WatchAndReload` still owns hot reload; `LoadMutualTLSConfig` now layers server certs, client certs, `RootCAs`, `ClientCAs`, and `RequireAndVerifyClientCert` on top for the controller mesh. Non-API owned listeners (NTP exporter/API, DPI metrics, correlator probes when TLS is enabled) enforce deny-by-default Subject-CN allowlists. Prometheus now mounts `prometheus-client-tls` and scrapes the owned DPI/NTP metrics jobs with `fos1-internal-ca` trust. FRR vtysh now uses a repo-owned mTLS sidecar terminator and no longer exposes the plaintext vtysh Service port. `scripts/ci/prove-cert-rotation.sh`, `scripts/ci/prove-mtls-mesh.sh`, and `scripts/ci/prove-frr-vtysh-tls.sh` cover the current proof envelope. External-daemon TLS for Suricata / Kea / Zeek / chronyc remains a Sprint 32 follow-up. See `docs/design/internal-tls-secrets.md` and `docs/design/adr-0002-frr-vtysh-tls-sidecar.md`.
- **nftables fully removed (Ticket 50)** — `pkg/network/nat/kernel.go` and `pkg/deprecated/nat/` deleted; cleanup commit `bac62b2` then dropped the unused `github.com/google/nftables` from `go.mod` and `go.sum` (`pkg/security/firewall/` had already been removed in Sprint 29 Ticket 33, so the dependency had no live consumers — Ticket 50's "live consumer" claim was wrong). Active NAT path remains `pkg/network/nat/manager.go` per ADR-0001.
- **eBPF XDP + TC + sockops + cgroup compile + load (Tickets 38, 39, 51)** — four owned BPF programs (`bpf/xdp_ddos_drop.c`, `bpf/tc_qos_shape.c`, `bpf/sockops_redirect.c`, `bpf/cgroup_egress_counter.c`) compile via `make bpf-objects` into ELFs committed at `pkg/hardware/ebpf/bpf/`, embedded through `//go:embed`, and loaded via `github.com/cilium/ebpf`. XDP (Ticket 38), TC (Ticket 39), and sockops/cgroup (Sprint 31 Ticket 51) all have Linux-only loader pairs + integration tests; tests skip without `CAP_BPF`/`CAP_NET_ADMIN`, without a BPF-capable clang, or (sockops/cgroup) without a unified cgroup v2 hierarchy. `pkg/hardware/ebpf/program_manager.go` dispatches `ProgramTypeXDP`, `ProgramTypeTCIngress`, `ProgramTypeTCEgress`, `ProgramTypeSockOps`, and `ProgramTypeCGroup` through owned loaders; sk_msg, sk_lookup, lwt, and other program types still return `ErrEBPFProgramTypeUnsupported`.
- **VLAN-scoped TC shaper (Ticket 52)** — new `TrafficShaper` CRD drives `pkg/hardware/ebpf.TCLoader` for VLAN-scoped or uplink egress shaping on top of the Sprint 30 Ticket 39 TC infrastructure. Composes with Ticket 45's Cilium Bandwidth Manager: pod egress caps come from `QoSProfile`, uplink/VLAN shaping comes from `TrafficShaper`. Uses the Ticket 40 `pkg/controllers/status.Writer` helper for Applied/Degraded/Invalid/Removed conditions.
- **MISP JSON threat-intel feed (Ticket 53)** — `ThreatFeed.Spec.Format` now accepts `"misp-json"` alongside `"urlhaus-csv"`. MISP feeds reference a Kubernetes Secret via `spec.authSecretRef`; the controller reads the `apiKey` data key for the `Authorization` header. Fake HTTP server in test harness verifies fetch-parse-translate-apply for both formats. STIX/TAXII remains a non-goal.
- **Four-hot-path performance baseline (Tickets 43 + 54)** — NAT apply, DPI event → Cilium policy, FilterPolicy translate, and threat-intel translate are all baselined in `tools/bench/` with ops/s + p50/p95/p99 latency recorded at `docs/performance/baseline-2026-04.md`; regressions flagged as warnings in CI (non-blocking) via `scripts/ci/run-bench.sh`.

Sprint 30 closed earlier critical-path production gaps:
- **Shared CRD status writeback helper** — `pkg/controllers/status/writer.go` lifts the NAT controller's `writeStatusToCRD` idiom into a reusable helper. Adopted by FilterPolicy (closes the Sprint 29 Ticket 33 in-memory-only caveat), NAT, and MultiWAN. Round-trip tests verify retry-on-conflict (Ticket 40).
- **REST API v0** — Sprint 30 Ticket 41 shipped read-only `/v1/filter-policies` list+get plus `/healthz`, `/readyz`, `/openapi.json` behind `tls.RequireAndVerifyClientCert` with a ConfigMap-backed Subject-CN allowlist. Base manifests at `manifests/base/api/`. (Sprint 31 Ticket 48 then layered the CRUD verbs on top — see above.)
- **Minimum-privilege RBAC** — every ServiceAccount bound to a scoped ClusterRole. `scripts/ci/prove-no-cluster-admin.sh` blocks any `ClusterRoleBinding` targeting `cluster-admin` without an explicit `fos1.io/rbac-exception` annotation. Per-controller verb/resource table at `docs/design/rbac-baseline.md` (Ticket 42).
- **NAT policy apply performance baseline** — `tools/bench/nat_apply_bench_test.go` plus baseline at `docs/performance/baseline-2026-04.md`; regressions flagged as warnings in CI (Ticket 43). Sprint 31 Ticket 54 expanded coverage to four hot paths.
- **URLhaus threat-intel v0** — `ThreatFeed` CRD + `cmd/threatintel-controller/` + `pkg/security/threatintel/` parses URLhaus CSV, translates into Cilium deny policies with last-seen TTL (Ticket 44). Sprint 31 Ticket 53 added MISP JSON.
- **QoS via Cilium Bandwidth Manager** — `QoSProfile` CR → `kubernetes.io/egress-bandwidth` pod annotation → BPF TBF rate limiter at pod admission via `pkg/security/qos.BandwidthManager`. Per-pod egress only in v1; Sprint 31 Ticket 52 added VLAN-scoped TC shaping via the new `TrafficShaper` CRD on top of Ticket 39's TC infrastructure (Ticket 45).

What remains for production readiness: external-daemon HA (FRR / Suricata / Kea / Zeek singletons); shared-state HA (Elasticsearch / Prometheus / Grafana / Alertmanager); external-daemon TLS (Suricata / Kea / Zeek / chronyc); write-path API for additional resource families (NAT, routing, DPI, zones); watch / streaming endpoints; broader eBPF program types beyond the four owned loaders (sk_msg, sk_lookup, etc.). See `docs/sprints/sprint-32-mtls-and-external-tls.md`.

## Verification Snapshot

Verified contract as of 2026-04-25:
- `make verify-mainline` is the canonical Go verification target and runs:
  - `go test ./...` (43/43 packages pass)
  - `go build ./...`
- `.github/workflows/ci.yml` enforces `make verify-mainline` on pushes to `main` and pull requests targeting `main`
- `.github/workflows/validate-manifests.yml` runs on manifest-affecting pull requests and fails on real `kubeconform` validation errors; post-Sprint-30 it also runs `scripts/ci/prove-no-cluster-admin.sh` (Ticket 42) to block any `ClusterRoleBinding` targeting `cluster-admin` without an explicit `fos1.io/rbac-exception` annotation
- `.github/workflows/test-bootstrap.yml` runs all four hot-path benchmarks (NAT apply — Ticket 43; DPI / FilterPolicy / ThreatIntel — Ticket 54) via `go test -bench=. ./tools/bench/...` as a non-blocking job that uploads `docs/performance/baseline-2026-04.md` as a CI artifact and flags regressions beyond a configurable threshold as warnings
- `.github/workflows/test-bootstrap.yml` additionally runs `scripts/ci/prove-leader-failover.sh` (Sprint 31 Ticket 47; kills the active `ids-controller` leader and asserts the standby takes over within ≤ 30s) and `scripts/ci/prove-cert-rotation.sh` (Sprint 31 Ticket 49; renews the API server cert via `cmctl renew` or Secret deletion fallback and asserts `/healthz` stays HTTP 200 across the rotation)

Owned observability contract as of 2026-04-25:
- `dpi-manager` runs as a node-local `DaemonSet` and its annotated `:8080/metrics` endpoint is runtime-proven through the Kind Prometheus pod-scrape path
- `ntp-controller` exposes an annotated `:9559/metrics` endpoint and that pod-scrape path is runtime-proven through the same Kind harness
- the Kind harness narrows NTP proof deployment to the repository-owned controller slice rather than pretending optional operator add-ons or the chrony daemonset are part of the verified baseline
- Prometheus, Grafana, and Alertmanager now persist state on PVC-backed storage in the base monitoring manifests
- Elasticsearch ships a single `30Gi` PVC and a repository-owned ILM bootstrap that attaches the `fos1-log-retention-14d` policy to `fos1-security-*` and `fos1-logs-*`; the `14d` wall-clock envelope is a manifest-level target and is not exercised end-to-end by CI
- the bootstrap harness proves one deterministic Suricata canary path into `fos1-security-*` plus `fos1-log-retention-14d` policy/template **attachment** through Elasticsearch APIs
- the bootstrap harness also runs [`scripts/ci/prove-es-retention-rollover.sh`](scripts/ci/prove-es-retention-rollover.sh) against a CI-only `fos1-ci-accelerated` policy targeting `fos1-ci-retention-*`, which verifies that ILM `rollover` and `delete` actions actually execute under accelerated (seconds/minutes) conditions; this is a contract proof of the policy shape, not a proof of the production `14d`/`30Gi` envelope
- the bootstrap harness additionally proves a deterministic end-to-end round-trip through the event correlator runtime ([`scripts/ci/prove-event-correlation-e2e.sh`](scripts/ci/prove-event-correlation-e2e.sh)): canary event injected into the configured file source, correlated record observed on the configured file sink, `/ready` returns HTTP 200
- the bootstrap harness now additionally proves a natural-traffic DPI path end to end (Sprint 29 Ticket 31, [`scripts/ci/prove-dpi-natural-traffic.sh`](scripts/ci/prove-dpi-natural-traffic.sh)): a repo-owned Suricata rule with reserved sid `9000001` fires on a curl-driven HTTP header, the event appears in Suricata eve.json, Fluentd ships it to `fos1-security-*`, and `sum(dpi_events_total)` on the `dpi-manager` pods advances past its pre-traffic baseline
- dashboard/alert queries are validated against live Kind series (Sprint 29 Ticket 32): [`tools/prometheus-query-validator`](tools/prometheus-query-validator/) runs as a Kind harness step, extracts every PromQL expression from owned dashboards and alert rules, classifies each against the live Prometheus, and fails CI on any non-allowlisted empty/error result; target-architecture expressions (node-exporter, kube-state-metrics, etc.) live in `manifests/dashboards/.queries-target-architecture.txt`
- Remaining gaps are broader than the owned baseline: no proof yet for PVC failover behavior, the production `14d` wall-clock deletion on `fos1-security-*`/`fos1-logs-*`, optional operator resources, Grafana dashboard rendering, or Alertmanager routing

### Key Metrics

| Metric | Value | Assessment |
|--------|-------|------------|
| Total Go Files | ~340+ (~250 non-test) | Large, complex codebase; Sprint 31 added `pkg/leaderelection/`, `pkg/hardware/ebpf/{sockops,cgroup}_loader_*.go`, `pkg/controllers/trafficshaper_controller.go`, `pkg/security/qos/traffic_shaper.go`, `pkg/security/threatintel/misp.go`, write-verb handlers in `pkg/api/`, plus three additional bench files in `tools/bench/`. Sprint 30 added `pkg/api/`, `pkg/controllers/status/`, `pkg/security/threatintel/`, `pkg/security/qos/bandwidth_manager.go`, `pkg/hardware/ebpf/{xdp,tc}_loader_*.go`, `cmd/api-server/`, `cmd/threatintel-controller/`, `tools/bench/`. |
| Lines of Go Code | ~95,000+ | Significant implementation |
| CRD Kinds Defined | 42+ | Comprehensive API coverage; Sprint 31 added `TrafficShaper` (Ticket 52). Sprint 30 added `ThreatFeed` (Ticket 44). FirewallRule CRD removed per ADR-0001; SAML/RADIUS/Cert auth configs removed |
| Primary Ticket Track | Tickets 1-55 complete; Tickets 56-58 in progress | Core path + observability proof depth + FilterPolicy enforcement + auth closeout + NIC/capture reporting + coverage bumps + eBPF compile+load (XDP+TC+sockops+cgroup) + shared status writeback helper + CRUD v1 REST API + RBAC baseline + four-hot-path perf baseline + URLhaus + MISP threat-intel + per-pod egress QoS + VLAN-scoped TC shaper + controller leader election + inter-controller TLS baseline + mTLS mesh primitives + FRR vtysh mTLS sidecar |
| Remaining Work Shape | Sprint 32 active hardening | External-daemon TLS (Suricata / Kea / Zeek / chronyc); external-daemon HA; shared-state HA (ES / Prometheus / Grafana / Alertmanager); write-path API for additional resource families (NAT, routing, DPI, zones); watch / streaming endpoints; broader eBPF program types beyond the four owned loaders (sk_msg, sk_lookup, lwt, etc.) |
| Verification Status | `make verify-mainline` green, 43/43 test packages pass; Kind harness proves event correlator E2E, accelerated ILM rollover, natural-traffic DPI, dashboard/alert PromQL validity, leader failover RTO ≤ 30s, cert rotation across `cmctl renew`; RBAC no-cluster-admin gate enforced; four-hot-path perf bench runs as non-blocking CI | Docs, manifests, and the bootstrap harness agree on the current proof envelope |
| Testing Coverage (Sprint 29 Ticket 36 measurements, still accurate post-Sprint-31) | `pkg/traffic` 51.4%, `pkg/hardware/wan` 57.6%, `pkg/network/ebpf` 93.2%, `pkg/security/policy` 51.1% | Thin packages have reconciliation-style coverage; Sprint 30's new packages (`pkg/api/`, `pkg/controllers/status/`, `pkg/security/threatintel/`, `pkg/security/qos/`) and Sprint 31's new packages (`pkg/leaderelection/`, MISP feed, sockops/cgroup loaders, TrafficShaper controller) all ship with dedicated tests |
| Documentation Files | 72 | Strong documentation; Sprint 31 added `docs/design/internal-tls-secrets.md` (Ticket 49) and `docs/design/high-availability.md` (Ticket 47). Sprint 30 added `docs/design/api-server.md`, `docs/design/rbac-baseline.md`, `docs/performance/baseline-2026-04.md`, `docs/performance/README.md` |
| Production Ready | ❌ NO (estimated ~84-89%) | Tickets 56-58 narrow the mTLS mesh, observability scrape, and FRR daemon-control TLS gaps, but residual blockers remain: external-daemon TLS/HA, shared-state HA, and API breadth |

## Priority Next Steps

Sprint 31 (tickets 47-55) is fully merged. Sprint 32 is active, with Tickets 56-58 underway.

Candidate Sprint 32 workstreams (in rough priority order):

1. **External-daemon TLS** — Ticket 58 moves FRR vtysh behind a sidecar mTLS terminator. Tickets 59-62 still need to move Suricata, Kea, Zeek, and chrony control paths off plaintext loopback/Unix socket assumptions.
2. **External-daemon HA** — Ticket 47 covered controller-tier failover only. FRR / Suricata / Zeek / Kea singletons run as single-pod / single-process; per-daemon clustering (BFD for FRR, Kea HA hooks, parallel Suricata sensors) remains open.
3. **Shared-state HA (Elasticsearch / Prometheus / Grafana / Alertmanager)** — single-replica StatefulSets / Deployments hold persistent data. Multi-node clustering (ES cross-zone replication, Prometheus federation or Thanos) is a separate sprint.
4. **Write-path API for additional resource families** — Ticket 48 extended FilterPolicy to full CRUD. NAT, routing, DPI, zones, and threat feeds remain read-only or `kubectl`-only.
5. **Watch / streaming endpoints on the REST API** — chunked JSON-lines streaming was deferred from Ticket 48.
6. **Broader eBPF program types** — Ticket 51 added sockops + cgroup; sk_msg, sk_lookup, lwt, and other program types still return `ErrEBPFProgramTypeUnsupported` from `pkg/hardware/ebpf/program_manager.go`.

---

## Component Status Matrix

### Network Components

#### ✅ Fully Implemented

| Component | Files | Lines | Status | Notes |
|-----------|-------|-------|--------|-------|
| **Network Interface Manager** | `pkg/network/manager.go` | 311 | Complete | Interface management with VLAN support |
| **VLAN Manager** | `pkg/network/vlan/manager.go` | 654 | Complete | Event-based VLAN interface creation, trunk configs, QoS, MTU calculation |

| **Routing Engine** | `pkg/network/routing/` | 618+ | Complete | Real FRR integration via vtysh validation, BGP/OSPF live state queries, Cilium route sync |
| **NAT Manager** | `pkg/network/nat/` | 400+ | Complete | Real Cilium NAT policy generation (SNAT/DNAT/NAT66/NAT64/port forwarding), idempotent statusful controller |
| **BGP/OSPF Protocol Handlers** | `pkg/controllers/bgp_controller.go`, `ospf_controller.go` | 850+ | Complete | Live FRR state queries from JSON output, real protocol status |

#### ⚠️ Partially Implemented

| Component | Files | Lines | Status | Critical Gaps |
|-----------|-------|-------|--------|---------------|
| **eBPF Framework** | `pkg/network/ebpf/`, `pkg/hardware/ebpf/`, `bpf/` | 650 + owned XDP + TC + sockops + cgroup | XDP, TC, sockops, and cgroup compile + load real on Linux (Sprint 30 Tickets 38/39 + Sprint 31 Ticket 51) | All four owned BPF programs (`bpf/xdp_ddos_drop.c`, `bpf/tc_qos_shape.c`, `bpf/sockops_redirect.c`, `bpf/cgroup_egress_counter.c`) compile via `make bpf-objects`, embed through `//go:embed`, and load via `github.com/cilium/ebpf`. XDP attaches via `link.XDPGenericMode` (test) or driver-native (production); TC attaches via `AttachTCX` against a `clsact` qdisc (bootstrap is idempotent; kernel ≥ 6.6 required for TCX) and exposes a per-ifindex priority map; sockops attaches to a cgroup v2 path; cgroup attaches as `BPF_CGROUP_INET_EGRESS`. `pkg/hardware/ebpf/program_manager.go` dispatches XDP / TC-ingress / TC-egress / sockops / cgroup through owned loaders; sk_msg, sk_lookup, lwt, and other program types still return `ErrEBPFProgramTypeUnsupported`. Linux-only integration tests skip without `CAP_BPF`/`CAP_NET_ADMIN` or (sockops/cgroup) without a unified cgroup v2 hierarchy. |

#### ❌ Not Implemented

- **Physical Interface Management** - No netlink syscalls for hardware interaction
- **Kernel Integration** - No route/interface manipulation at kernel level (for areas not covered by FRR/Cilium)
- **eBPF Program Types Beyond XDP / TC / sockops / cgroup** - sk_msg, sk_lookup, lwt, etc. return `ErrEBPFProgramTypeUnsupported` from `pkg/hardware/ebpf/program_manager.go`; Sprint 32 candidate

---

### Security Components

#### ✅ Fully Implemented

| Component | Files | Lines | Status | Notes |
|-----------|-------|-------|--------|-------|
| **DPI Framework Core** | `pkg/security/dpi/manager.go` | 825 | Complete | Profile/flow/event management, event dispatch system; natural-traffic proof via sid `9000001` (Sprint 29 Ticket 31) |
| **IDS Manager** | `pkg/security/ids/manager.go` | 200+ | Complete | IDS/IPS coordination framework |
| **Certificate Manager** | `pkg/security/certificates/manager.go` | 730 | Complete | Full cert-manager integration, lifecycle management |
| **Authentication Framework** | `pkg/security/auth/manager.go` | 751 | Complete (scope reduced per Sprint 29 Ticket 34) | Manager core with audit logging; local/LDAP/OAuth only |

| **DPI Connectors** | `pkg/security/dpi/connectors/` | 2000+ | Complete | Real Suricata stats, event-to-Cilium policy pipeline with TTL expiry and cleanup |
| **Suricata Controller** | `pkg/security/ids/suricata/` | 527+ | Complete | Real Suricata engine queries via Unix socket + Eve log parsing |
| **Zeek Controller** | `pkg/security/ids/zeek/` | 568+ | Complete | Real Zeek Broker client integration |
| **FilterPolicy Controller** | `pkg/security/policy/controller.go` | 700+ | Complete (Sprint 29 Ticket 33, Sprint 30 Ticket 40) | FilterPolicy → CiliumNetworkPolicy translation via spec-hash idempotency; Applied/Degraded/Invalid/Removed conditions; 51.1% coverage. Status subresource writeback now persists conditions via the shared `pkg/controllers/status.Writer` helper (Sprint 30 Ticket 40 closed the Sprint 29 in-memory-only caveat). |
| **Threat-Intelligence Controller** | `pkg/security/threatintel/`, `cmd/threatintel-controller/` | - | Complete (Sprint 30 Ticket 44 + Sprint 31 Ticket 53) | URLhaus CSV + MISP JSON ingestion via `ThreatFeed` CRD → Cilium deny policies with last-seen TTL. `spec.format` selects `urlhaus-csv` or `misp-json`; MISP feeds reference a Kubernetes Secret via `spec.authSecretRef` and the controller reads the `apiKey` data key for the `Authorization` header. `ThreatFeed.Status` reports last-fetch time, entry count, expiry state. Fake HTTP server in test harness verifies fetch-parse-translate-apply for both formats. STIX / IP-reputation feeds remain non-goals. |
| **Local Auth Provider** | `pkg/security/auth/providers/local.go` | 1030 | Complete | File-based auth with password hashing |
| **LDAP Auth Provider** | `pkg/security/auth/providers/ldap.go` | - | Complete | Real LDAP provider construction and authentication |
| **OAuth Auth Provider** | `pkg/security/auth/providers/oauth.go` | - | Complete | Real OAuth provider construction and authentication |
| **Event Correlation** | `pkg/security/ids/correlation/`, `cmd/event-correlator/`, `build/event-correlator/Dockerfile` | - | Complete (E2E proof in Kind harness) | Controller reconciles ConfigMap/Deployment/Service; the correlator runtime round-trip is gated by [scripts/ci/prove-event-correlation-e2e.sh](scripts/ci/prove-event-correlation-e2e.sh) in the Kind bootstrap harness (injects a canary event into the configured file source, asserts the file sink emits the correlated record, and asserts `/ready` returns HTTP 200). Live non-canary sensor ingestion and durable export sinks remain out of scope. |

#### ❌ Not Implemented / Non-goal

| Component | Status | Notes |
|-----------|--------|-------|
| **nftables Firewall** | Non-goal per ADR-0001; fully removed | Cilium is the sole enforcement backend. NAT-side nftables code (`pkg/network/nat/kernel.go`, `pkg/deprecated/nat/`) removed in Sprint 31 Ticket 50; cleanup commit `bac62b2` then dropped the unused `github.com/google/nftables` from `go.mod` and `go.sum` (`pkg/security/firewall/` had already been removed in Sprint 29 Ticket 33, so the dependency had no live consumers — the original Ticket 50 plan's "live consumer" claim was wrong). `pkg/cilium/controllers/firewall_controller.go` was removed in Sprint 29 Ticket 33. |
| **FirewallRule CRD** | Non-goal per ADR-0001 | Schema-only with no Go types; CRD manifest and controller removed in sprint 29 ticket 33. `FilterPolicy` is the authoritative policy surface. |
| **Policy Enforcement (FilterPolicy)** | ✅ Complete | `pkg/security/policy/controller.go` translates FilterPolicy → CiliumNetworkPolicy with spec-hash idempotency and Applied/Degraded/Invalid/Removed conditions (sprint 29 ticket 33). |
| **SAML/RADIUS/Certificate Auth** | Removed (non-goal) | Stubs removed 2026-04-21 per Sprint 29 Ticket 34; auth is scoped to local/LDAP/OAuth |
| **Threat Intelligence** | ✅ v1 (sprint 30 ticket 44 + sprint 31 ticket 53) | URLhaus CSV + MISP JSON ingestion via `ThreatFeed` CRD → CiliumPolicy translator with last-seen TTL. MISP auth is API-key only via `spec.authSecretRef` → Secret `apiKey` data key. STIX and certificate-auth MISP remain non-goals. |

---

### Network Services

#### ✅ Fully Implemented

| Component | Files | Lines | Status | Notes |
|-----------|-------|-------|--------|-------|
| **DNS Manager** | `pkg/dns/manager/manager.go` | 521 | Complete | Zone and record management, service coordination |
| **DHCP Config Manager** | `pkg/dhcp/kea_manager.go` | 434 | Complete | Kea configuration file generation and instance control |
| **NTP Service** | `pkg/ntp/` | - | Complete | Chrony configuration management, metrics |
| **WireGuard VPN** | `pkg/vpn/wireguard.go` | 305 | Complete | Config generation, interface management |

| **CoreDNS Integration** | `pkg/dns/coredns/` | - | Complete | Wired to real zone updates + reload |
| **AdGuard Integration** | `pkg/dns/adguard/` | - | Complete | Wired to real AdGuard API client |
| **mDNS Reflection** | `pkg/dns/mdns/` | - | Complete | Wired to real mDNS reflection controller |
| **DHCP Controller** | `pkg/dhcp/controller.go` | 579+ | Complete | Real Kea control socket reconciliation |

---

### Infrastructure & Hardware

#### ✅ Fully Implemented

| Component | Files | Lines | Status | Notes |
|-----------|-------|-------|--------|-------|
| **Cilium Client** | `pkg/cilium/client.go` | 371 | Complete | Network policy application via kubectl/API |
| **Cilium Router** | `pkg/cilium/router.go` | 352 | Complete | Route synchronization |
| **Multi-WAN Manager** | `pkg/hardware/wan/manager.go` | 636 | Complete | WAN failover and load balancing |
| **Traffic Manager** | `pkg/traffic/manager.go` | 545 | Complete | Traffic monitoring and classification |
| **Traffic Classifier** | `pkg/traffic/classifier.go` | 259 | Complete | Application-level classification |
| **eBPF Hardware Manager** | `pkg/hardware/ebpf/manager.go` | 535 | Complete | eBPF program management framework |

#### ⚠️ Partially Implemented

| Component | Files | Lines | Status | Critical Gaps |
|-----------|-------|-------|--------|---------------|
| **NIC Manager** | `pkg/hardware/nic/` | - | Real on Linux, stubbed off-Linux (Sprint 29 Ticket 35) | Real ethtool / netlink queries on Linux via a mockable `ethtoolClient` seam; `ErrNICStatisticsNotSupported` / `ErrNICFeatureNotSupported` sentinels surface when drivers expose no counters. Non-Linux builds return `ErrNICUnsupportedPlatform` for every method. Intel X540/X550/I225 driver-specific quirks are still a follow-up. Same contract shape as Sprint 28 Ticket 26 offload pattern. |
| **Packet Capture** | `pkg/hardware/capture/` | - | Real tcpdump shim on Linux, stubbed off-Linux (Sprint 29 Ticket 35) | Split into `manager_linux.go` + `manager_stub.go`; `NewManager` verifies `tcpdump` is on PATH and returns `ErrTCPDumpNotAvailable` when missing. A mockable `captureExec` seam powers unit tests. eBPF-based capture remains a non-goal. |
| **Hardware Offload** | `pkg/hardware/offload/` | - | Real on Linux, stubbed off-Linux (Ticket 26) | Real ethtool feature / statistics reporting on Linux with `ErrOffloadStatisticsNotSupported` for drivers that expose no counters. |

---

### Control Plane

#### ✅ Fully Implemented

| Component | Files | Lines | Status | Notes |
|-----------|-------|-------|--------|-------|
| **REST API Server** | `cmd/api-server/`, `pkg/api/` | - | Complete (CRUD v1 for FilterPolicy) | Sprint 31 Ticket 48 layered POST / PUT / PATCH / DELETE on top of Sprint 30 Ticket 41's read-only v0. PATCH dispatches between JSON Merge Patch and Strategic Merge Patch via `Content-Type`; PUT requires `metadata.resourceVersion` for optimistic concurrency; server-side validation returns structured 422 on bad specs. mTLS-only via `tls.RequireAndVerifyClientCert` plus a ConfigMap-backed Subject-CN allowlist. Trust anchor is the `fos1-internal-ca` ClusterIssuer (Ticket 49). `pkg/api.TestMTLSEndToEnd` proves 200 / 403 / handshake / POST round-trip cases. Watch / streaming endpoints and additional resource families (NAT, routing, DPI, zones) remain Sprint 32 candidates. |
| **Controller HA / Leader Election** | `pkg/leaderelection/`, `cmd/*/main.go` | - | Complete (controller tier) | Sprint 31 Ticket 47. Every owned controller wires leader election against `coordination.k8s.io/v1` Leases — `pkg/leaderelection` wraps `k8s.io/client-go/tools/leaderelection` with the fos1-standard 15s/10s/2s timings for non-controller-runtime mains; api-server uses controller-runtime manager-level LE. Every owned `Deployment` runs `replicas: 2` with `preferredDuringSchedulingIgnoredDuringExecution` podAntiAffinity. Namespace-scoped `Role` + `RoleBinding` for `coordination.k8s.io/leases` per controller — no new `ClusterRoleBinding`. RTO ≤ 30s proved by `scripts/ci/prove-leader-failover.sh` against `ids-controller`. `trafficshaper-controller` stays single-replica because `hostNetwork: true` conflicts on the netdev. `dpi-manager` is a DaemonSet and intentionally excluded. External-daemon and shared-state HA remain Sprint 32 candidates. See `docs/design/high-availability.md`. |
| **Internal TLS / mTLS Mesh** | `pkg/security/certificates/`, `manifests/base/certificates/cluster-issuer-internal.yaml` | - | In progress (server TLS complete, owned scrape rekey landed locally) | Sprint 31 Ticket 49 delivered hot-reloaded server TLS from `fos1-internal-ca`. Sprint 32 Ticket 56 adds `LoadMutualTLSConfig`, `NewMutualTLSHTTPClient`, and Subject-CN allowlist middleware; currently owned non-API listeners now enforce mTLS when TLS is enabled. Ticket 57 adds the Prometheus client cert and HTTPS scrape jobs for owned DPI/NTP metrics. `scripts/ci/prove-cert-rotation.sh` covers rotation and `scripts/ci/prove-mtls-mesh.sh` covers allowed cert / no cert / unknown CN behavior. External-daemon TLS remains a Sprint 32 follow-up. See `docs/design/internal-tls-secrets.md`. |
| **Performance Baseline Harness** | `tools/bench/`, `scripts/ci/run-bench.sh` | - | Complete (four hot paths) | Sprint 30 Ticket 43 + Sprint 31 Ticket 54. Four bench files measure NAT apply, DPI event → Cilium policy, FilterPolicy translate, and threat-intel translate. `docs/performance/baseline-2026-04.md` records ops/s + p50/p95/p99 latency + memory allocation per op + machine specs + commit SHA. CI regression detection is a warning, not a failure (Ticket 43 envelope). |

---

## Kubernetes Resources Status

### ✅ Custom Resource Definitions (40+ Kinds)

All CRD definitions are **complete and well-structured**. Removed surfaces are explicit non-goals per ADR-0001 / Sprint 29 closures:

**Network CRDs:**
- NetworkInterface, VLAN, Route, RouteTable, RoutingPolicy
- MultiWANConfig, WANLink, NAT, NAT66, PortForwarding
- EBPFProgram, EBPFMap, EBPFNATPolicy, EBPFNetworkPolicy, EBPFTrafficControl, EBPFContainerPolicy
- TrafficShaper (Sprint 31 Ticket 52; VLAN-scoped TC shaper on top of Ticket 39)

**Service CRDs:**
- DHCPv4Service, DHCPv6Service, StaticReservation
- DNSZone, DNSFilterList, DNSClient, PTRZone, MDNSReflection
- NTPService

**Security CRDs:**
- FilterPolicy, FilterPolicyGroup, FilterZone, IPSet — authoritative policy surface per ADR-0001
- DPIProfile, DPIFlow, DPIPolicy
- SuricataInstance, ZeekInstance, EventCorrelation
- ThreatFeed (Sprint 30 Ticket 44 URLhaus + Sprint 31 Ticket 53 MISP)
- QoSProfile (per-pod egress via Cilium Bandwidth Manager, Sprint 30 Ticket 45)
- WireGuardVPN, AuthProvider, AuthConfig
- CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy

**Removed (Sprint 29):**
- `FirewallRule` / `FirewallZone` — removed in Ticket 33 per ADR-0001 (Cilium is the sole enforcement backend).
- SAML / RADIUS / certificate config fields on `AuthProvider` — removed in Ticket 34 per auth scope reduction.

### ✅ Kubernetes Manifests

**Status:** Comprehensive template coverage (~14,277 lines of YAML)

- **Base Configurations** - Production-like templates for all services
- **Example Configurations** - Demonstrate usage patterns for all features
- **Overlays** - Dev and prod environment configurations
- **Deployment Configs** - Talos Linux and Kubernetes deployment manifests

**Gap:** Manifests, including the monitoring/logging stack resources, now encode a concrete single-node durability baseline, but they are still deployable templates rather than proof of verified runtime ownership or end-to-end operation

---

## Command-Line Applications

### 7 Application Entry Points

| Command | Size | Status | Purpose |
|---------|------|--------|---------|
| `cmd/dpi-framework` | 9.0K | ✅ Complete | Main DPI framework orchestrator |
| `cmd/dpi-manager` | 3.8K | ✅ Complete | DPI configuration manager |
| `cmd/dpi-test` | 5.9K | ✅ Complete | DPI testing utility |
| `cmd/ids-controller` | 2.1K | ⚠️ Partial | IDS controller entry point |
| `cmd/cilium-controller` | 4.8K | ⚠️ Partial | Cilium integration controller |
| `cmd/wireguard-controller` | 2.4K | ⚠️ Partial | WireGuard controller |
| `cmd/certificate-controller` | 3.2K | ✅ Complete | Certificate management controller |

---

## Controllers Status

### Kubernetes Controllers (18 Total)

| Controller | File | Lines | Status | Implementation |
|------------|------|-------|--------|----------------|
| Network Interface | `pkg/controllers/networkinterface_controller.go` | 379 | ⚠️ Partial | Reconciliation framework only |
| VLAN | `pkg/controllers/vlan_controller.go` | 487 | ✅ Complete | Full reconciliation |
| Routing | `pkg/controllers/routing_controller.go` | 6K | ✅ Complete | Full routing with Cilium route sync |
| BGP | `pkg/controllers/bgp_controller.go` | 447 | ✅ Complete | Live FRR BGP state queries |
| OSPF | `pkg/controllers/ospf_controller.go` | 411 | ✅ Complete | Live FRR OSPF state queries |
| Multi-WAN | `pkg/controllers/multiwan_controller.go` | 482 | ✅ Complete | Failover logic |
| NAT | `pkg/controllers/nat_controller.go` | 559 | ✅ Complete | Idempotent/statusful with real Cilium enforcement |
| eBPF | `pkg/controllers/ebpf_controller.go` | 522 | ⚠️ Partial | Program management without loading |
| DHCP | `pkg/controllers/dhcp_controller.go` | 579 | ⚠️ Partial | Config sync without daemon control |
| DNS | `pkg/controllers/dns_controller.go` | 428 | ⚠️ Partial | Record management |
| Filter Policy | `pkg/security/policy/controller.go` | 700+ | ✅ Complete (Sprint 29 Ticket 33) | Idempotent, statusful Cilium translation with add/update/delete/disable lifecycle; spec-hash no-op, Applied/Degraded/Invalid/Removed conditions; 51.1% test coverage (Sprint 29 Ticket 36). Status subresource persistence is in-memory only; Sprint 30 Ticket 40 targets a shared writeback helper. |
| Suricata | `pkg/security/ids/suricata/controller.go` | 527 | ⚠️ Partial | K8s integration only |
| Zeek | `pkg/security/ids/zeek/controller.go` | 568 | ⚠️ Partial | K8s integration only |
| WireGuard | `pkg/vpn/wireguard/controller.go` | - | ✅ Complete | Real CRD-to-interface reconciliation with status |
| Auth | `pkg/security/auth/controller.go` | 587 | ✅ Complete | Provider management |
| Certificate | `pkg/controllers/certificate_controller.go` | - | ✅ Complete | cert-manager integration |
| Cilium Network | `pkg/cilium/network_controller.go` | 359 | ✅ Complete | Policy application |
| Cilium Route | `pkg/cilium/router.go` | 352 | ✅ Complete | Route sync |

---

## Documentation Status

### ✅ 70 Documentation Files - Comprehensive Coverage

**Architecture & Design (16 files):**
- All major components have detailed design documents
- Architecture patterns clearly documented
- Integration patterns specified
- Mermaid diagrams for complex interactions

**How-To Guides (9 files):**
- Network, security, routing configuration guides
- eBPF CRD usage, hardware acceleration guides
- Policy-based routing, VRF configuration

**Reference Documentation:**
- `project-tracker.md` - Comprehensive status tracking
- `implementation-plan.md` - Development roadmap
- `project-scope.md` - Goals and requirements
- `observability-architecture.md` - Verified-vs-target-state observability boundaries

**Service Documentation:**
- DNS, DHCP integration guides
- DPI integration documentation
- Component-specific README files

**Status:** Documentation coverage is strong, but some files intentionally describe architecture/templates while status-sensitive docs must stay constrained to verified runtime ownership.

---

## Build & Deployment Infrastructure

### ✅ Build System

**Makefile Targets:**
- `make build` - Build all Go packages
- `make test` - Run all tests
- `make lint` - Run linters (Go + YAML)
- Component-specific builds (`build-dns`, `build-dhcp`, `build-dpi`)
- Integration test support

**Container Images (6 Dockerfiles):**
- All use multi-stage builds
- CGO disabled for portability
- Alpine/Golang base images
- Ready for container registry

**Deployment Configurations:**
- Talos Linux machine configs
- Kubernetes deployment manifests
- Zeek/Suricata system extensions

**Status:** Build infrastructure is ready, but services need implementation

---

## Testing Status

### ⚠️ Improving Test Coverage

**Test Statistics:**
- Test Packages Passing: 43/43 under `make verify-mainline`
- Test Files: 80+
- Test Functions: 250+

**Measured Coverage (post-Sprint 29 Ticket 36, still representative after Sprint 31):**
- `pkg/traffic` — 51.4%
- `pkg/hardware/wan` — 57.6%
- `pkg/network/ebpf` — 93.2%
- `pkg/security/policy` — 51.1%

Other packages retain their pre-sprint coverage; aggregate coverage across the repository was previously estimated at ~30-35% and has improved on the four packages above plus the new Sprint 30 packages (`pkg/api/`, `pkg/controllers/status/`, `pkg/security/threatintel/`, `pkg/security/qos/`) and the new Sprint 31 packages (`pkg/leaderelection/`, MISP feed, sockops/cgroup loaders, TrafficShaper controller, write-verb handlers in `pkg/api/`), each of which ships with dedicated round-trip tests. Accepted gaps for specific thin packages are tracked in `docs/design/test_matrix.md`.

**Kind-harness E2E Proofs (Sprint 29):**
- `scripts/ci/prove-event-correlation-e2e.sh` — canary → correlator → sink + `/ready` HTTP 200 (Ticket 29)
- `scripts/ci/prove-es-retention-rollover.sh` — accelerated ILM rollover + delete against `fos1-ci-accelerated` (Ticket 30)
- `scripts/ci/prove-dpi-natural-traffic.sh` — Suricata sid `9000001` → Elasticsearch → `sum(dpi_events_total)` advance (Ticket 31)
- `tools/prometheus-query-validator/` — dashboard + alert-rule PromQL validated against live series (Ticket 32)

**CI Harness Additions (Sprint 30):**
- `scripts/ci/prove-no-cluster-admin.sh` — blocks any `ClusterRoleBinding` to `cluster-admin` without an explicit `fos1.io/rbac-exception` annotation (Ticket 42)
- `scripts/ci/run-bench.sh` plus `tools/bench/nat_apply_bench_test.go` — NAT policy apply bench runs in CI, uploads `docs/performance/baseline-2026-04.md` as an artifact, flags regressions as warnings (Ticket 43)
- `pkg/api.TestMTLSEndToEnd` — real TLS listener with unauthorized/authorized/no-cert cases (Ticket 41)

**CI Harness Additions (Sprint 31):**
- `scripts/ci/prove-leader-failover.sh` — kills the active `ids-controller` leader and asserts the standby takes over within ≤ 30s lease duration (Ticket 47)
- `scripts/ci/prove-cert-rotation.sh` — renews the API server cert via `cmctl renew` (or Secret deletion fallback) and asserts `/healthz` stays HTTP 200 across the rotation (Ticket 49)
- Three additional bench files (`tools/bench/dpi_policy_bench_test.go`, `filterpolicy_translate_bench_test.go`, `threatintel_translate_bench_test.go`) extend the Ticket 43 NAT bench to four hot paths total via `scripts/ci/run-bench.sh` (Ticket 54)

**Missing:**
- Broader aggregate coverage across packages not specifically targeted
- Live-sensor event ingestion beyond the deterministic canary paths
- Performance benchmarks beyond the four current hot paths (routing sync, DHCP control socket, DNS zone update)
- Load testing

---

## Code Quality Assessment

### ✅ Strengths

1. **Excellent Architecture**
   - Clear separation of concerns
   - Interface-driven design
   - Manager pattern consistently applied
   - Context-based lifecycle management

2. **Code Organization**
   - Logical package structure
   - Clear naming conventions
   - Type definitions separated (`types.go`)
   - Kubernetes-native design

3. **Error Handling**
   - Returns errors rather than panicking
   - Formatted error messages with context
   - Structured error types

4. **Documentation**
   - GoDoc style comments on exports (inconsistent)
   - Comprehensive design docs
   - Clear README files

### ⚠️ Areas for Improvement

1. **Test Coverage** - 60+ test files across 37 verified packages; aggregate coverage still uneven. Four packages raised to 50%+ in Sprint 29 Ticket 36; others remain thinner.
2. **Placeholder Code** - TODO/FIXME comments still present in non-critical paths; Sprint 29 closed `<type> provider not implemented` strings (Ticket 34) and the FilterPolicy log-only reconcile path (Ticket 33).
3. **Incomplete Implementations** - eBPF compile+load is the largest remaining stub. Per-pod QoS enforcement (egress) landed in Sprint 30 Ticket 45 via Cilium Bandwidth Manager; classful/uplink TC shaping remains Ticket 39.
4. **Consistency** - Documentation inconsistent across packages; status-sensitive docs are truth-upped at end of each sprint (tickets 20, 27, 37).
5. **Error Messages** - Sprint 29 Tickets 33-35 added explicit, typed sentinel errors (`ErrNICStatisticsNotSupported`, `ErrTCPDumpNotAvailable`, `ErrNICUnsupportedPlatform`, etc.); other packages still have generic errors.

---

## Critical Implementation Gaps

Closed in Sprint 29:
- **FilterPolicy enforcement** — `pkg/security/policy/controller.go` reconciles FilterPolicy into real CiliumNetworkPolicy objects with spec-hash idempotency and Applied/Degraded/Invalid/Removed conditions (Ticket 33). `FirewallRule` CRD, nftables translator/zone manager, and `pkg/security/firewall/` removed per ADR-0001.
- **Auth surface finalization** — SAML/RADIUS/certificate stubs removed from manager factory, CRD enum, manifests, and docs; auth scoped to local/LDAP/OAuth (Ticket 34).
- **NIC and capture capability reporting** — real ethtool/tcpdump shims on Linux with explicit `ErrNICStatisticsNotSupported`, `ErrTCPDumpNotAvailable`, `ErrNICUnsupportedPlatform`, `ErrOffloadStatisticsNotSupported`, and `ErrNICFeatureNotSupported` sentinels off-Linux or on unsupported drivers (Ticket 35).
- **Observability proof depth** — event correlator E2E proof (Ticket 29), accelerated ILM rollover/delete proof (Ticket 30), natural-traffic DPI proof via sid `9000001` (Ticket 31), and dashboard/alert PromQL validation against live series (Ticket 32) all landed.

Closed in Sprint 30:
- **eBPF compile + load (XDP + TC)** — XDP (`bpf/xdp_ddos_drop.c`) and TC (`bpf/tc_qos_shape.c`) programs compile via `make bpf-objects`, embed through `//go:embed`, and load via `github.com/cilium/ebpf`. TC bootstraps a clsact qdisc idempotently and attaches via `AttachTCX` (kernel ≥ 6.6). Linux-only integration tests skip without `CAP_BPF`/`CAP_NET_ADMIN` (Tickets 38, 39). Sprint 31 Ticket 51 then added sockops + cgroup.
- **Shared CRD status writeback helper** — `pkg/controllers/status.Writer` lifts the NAT `writeStatusToCRD` pattern. Adopted by FilterPolicy (closes the Sprint 29 in-memory-only caveat), NAT, MultiWAN. Round-trip tests assert retry-on-conflict (Ticket 40).
- **REST API v0 (read-only)** — Sprint 30 Ticket 41 shipped read-only `/v1/filter-policies` list+get, `/healthz`, `/readyz`, `/openapi.json` behind `tls.RequireAndVerifyClientCert` with a ConfigMap-backed Subject-CN allowlist. Sprint 31 Ticket 48 then layered the CRUD verbs on top.
- **Minimum-privilege RBAC** — `scripts/ci/prove-no-cluster-admin.sh` blocks any `ClusterRoleBinding` to `cluster-admin` without an explicit `fos1.io/rbac-exception` annotation. Per-controller verb/resource table at `docs/design/rbac-baseline.md` (Ticket 42).
- **NAT policy apply performance baseline** — `tools/bench/nat_apply_bench_test.go` plus `docs/performance/baseline-2026-04.md`. Regressions flagged as warnings in CI (Ticket 43). Sprint 31 Ticket 54 expanded coverage to four hot paths.
- **Threat-intel feed ingestion v0** — URLhaus CSV → `ThreatFeed` CRD → Cilium deny policies with last-seen TTL (Ticket 44). Sprint 31 Ticket 53 added MISP JSON.
- **QoS enforcement (per-pod egress)** — `QoSProfile` → `kubernetes.io/egress-bandwidth` pod annotation → Cilium Bandwidth Manager BPF TBF at pod admission (Ticket 45). Sprint 31 Ticket 52 added VLAN-scoped TC shaping via the new `TrafficShaper` CRD.

Closed in Sprint 31:
- **Controller HA via leader election** — every owned controller now wires leader election against `coordination.k8s.io/v1` Leases. `pkg/leaderelection` wraps `k8s.io/client-go/tools/leaderelection` (15s/10s/2s timings) for non-controller-runtime mains; the api-server uses controller-runtime manager-level LE. Every owned controller `Deployment` runs `replicas: 2` with `preferredDuringSchedulingIgnoredDuringExecution` podAntiAffinity. Namespace-scoped `Role` + `RoleBinding` for `coordination.k8s.io/leases` per controller — no new `ClusterRoleBinding`. RTO ≤ 30s proved by `scripts/ci/prove-leader-failover.sh` against `ids-controller` (Ticket 47). `trafficshaper-controller` stays single-replica because `hostNetwork: true` conflicts on the netdev. `dpi-manager` is a DaemonSet and intentionally excluded.
- **CRUD v1 REST API for FilterPolicy** — `cmd/api-server/` and `pkg/api/` expose POST / PUT / PATCH / DELETE on `/v1/filter-policies/{ns}/{name}` with strategic-merge / JSON-merge patch dispatch via `Content-Type`, optimistic concurrency on PUT via `metadata.resourceVersion`, and structured 422 on validation failure. RBAC extended to grant create/update/patch/delete on `filterpolicies.security.fos1.io`. `pkg/api.TestMTLSEndToEnd` proves 200 / 403 / handshake-failure / POST round-trip cases (Ticket 48).
- **Inter-controller TLS / mTLS mesh** — single `fos1-internal-ca` ClusterIssuer (CA-typed, chained from a 10y self-signed root) mints per-controller certs at `/var/run/secrets/fos1.io/tls/`. `LoadTLSConfig` + `WatchAndReload` reload cert-manager renewals in place via fsnotify; `LoadMutualTLSConfig` now configures server/client auth and CA trust for the mesh. Currently owned listeners enforce Subject-CN allowlists when TLS is enabled. `scripts/ci/prove-cert-rotation.sh` covers rotation and `scripts/ci/prove-mtls-mesh.sh` covers mTLS behavior (Tickets 49 and 56). See `docs/design/internal-tls-secrets.md`.
- **nftables fully removed** — `pkg/network/nat/kernel.go` and `pkg/deprecated/nat/` deleted; cleanup commit `bac62b2` then dropped the unused `github.com/google/nftables` from `go.mod` and `go.sum` (`pkg/security/firewall/` had already been removed in Sprint 29 Ticket 33, so the dependency had no live consumers — Ticket 50's "live consumer" claim was wrong) (Ticket 50).
- **eBPF sockops + cgroup** — `bpf/sockops_redirect.c` + `bpf/cgroup_egress_counter.c` compile via `make bpf-objects`; `pkg/hardware/ebpf/sockops_loader_linux.go` + `cgroup_loader_linux.go` join the XDP + TC loaders. `pkg/hardware/ebpf/program_manager.go` dispatch routes XDP / TC / sockops / cgroup through owned loaders on Linux (Ticket 51).
- **VLAN-scoped TC shaper** — new `TrafficShaper` CRD drives `pkg/hardware/ebpf.TCLoader` for VLAN-scoped or uplink egress shaping on top of the Ticket 39 TC infrastructure. Composes with Ticket 45's Cilium Bandwidth Manager (Ticket 52).
- **MISP JSON threat-intel feed** — `ThreatFeed.Spec.Format` accepts `"misp-json"` alongside `"urlhaus-csv"`; MISP API key from Kubernetes Secret via `spec.authSecretRef`; missing Secret produces a clear `Invalid` condition (Ticket 53).
- **Four-hot-path performance baseline** — DPI event → Cilium policy, FilterPolicy translate, threat-intel translate join NAT apply in `tools/bench/`; `docs/performance/baseline-2026-04.md` records all four baselines with machine specs and commit SHA (Ticket 54).

Still open for Sprint 32+:

### 1. mTLS Controller-To-Controller + External-Daemon TLS ⚠️ (Sprint 32 active)

**What's Shipped (Sprint 31 Ticket 49):**
- Server-side TLS on every owned listener (API server, NTP exporter, DPI metrics, correlator probes) with cert-manager-issued certs from the `fos1-internal-ca` chain, hot-reloaded via fsnotify.
- API server is mTLS-only (`RequireAndVerifyClientCert` plus ConfigMap-backed Subject-CN allowlist).
- Sprint 32 Ticket 56 adds shared `LoadMutualTLSConfig`, `NewMutualTLSHTTPClient`, and Subject-CN allowlist middleware. NTP exporter/API, DPI metrics, and event-correlator probes now require mTLS when TLS is enabled.

**Still Missing:**
- FRR vtysh now has a sidecar mTLS terminator. Suricata's Unix socket, Zeek Broker, Kea's control socket, and chronyc still live inside the same pod as their controller and speak plaintext on a loopback / Unix path. Cross-host paths are the Sprint 32 follow-up — likely sidecar TLS terminators or daemon-native TLS.
- Trust anchor is a self-signed root, not an enterprise PKI. Production deployments that require HSM-backed signing should replace via overlay (Vault / cloud-KMS / external CA).
- No external secrets management model (sealed-secrets, external-secrets, Vault integration).

**Impact:** Same-pod traffic is unencrypted; cross-host paths between controllers and external daemons remain plaintext. Same-trust-boundary risk model documented in `docs/design/internal-tls-secrets.md`.

### 2. External-Daemon HA + Shared-State HA ⚠️ (Sprint 32 candidate)

**What's Shipped (Sprint 31 Ticket 47):** controller-tier leader election with hot standby; RTO ≤ 30s; CI failover proof.

**Still Missing:**
- Single-replica Elasticsearch, Prometheus, Grafana, Alertmanager — these hold persistent data and cannot be replicated by leader election alone. Multi-node clustering (ES cross-zone replication, Prometheus federation or Thanos) is a separate sprint.
- External daemon singletons: FRR, Suricata, Zeek, Kea remain single-pod / single-process with no in-tree HA contract. Operators must layer per-daemon clustering (BFD for FRR, Kea HA hooks, parallel Suricata sensors).
- No snapshot / restore automation for the Elasticsearch `30Gi` PVC; replicas at 0 means no replica safety on node loss.

**Impact:** Controller-tier failure is no longer a single point of failure (proven in CI). The data tier and external daemons remain single-instance — see `docs/design/high-availability.md` for the explicit scope and Sprint 32 candidates.

### 3. REST API Surface Expansion ⚠️ (Sprint 32 candidate)

**What's Shipped (Sprint 31 Ticket 48):**
- Write verbs on FilterPolicy: POST, PUT (optimistic concurrency), PATCH (JSON Merge Patch + Strategic Merge Patch), DELETE (with propagationPolicy).
- Server-side validation with structured 422 `Invalid` bodies.
- Audit-shaped klog lines for every write attempt.
- RBAC updated to grant create/update/patch/delete on `filterpolicies.security.fos1.io`.

**Still Missing:**
- Watch / streaming endpoints (chunked JSON-lines).
- Resource families beyond FilterPolicy (NAT, routing, DPI, zones, threat feeds).
- `application/apply-patch+yaml` (Server-Side Apply) and `application/json-patch+json` (RFC 6902) content types on PATCH.
- OAuth / OIDC / SPIFFE — mTLS remains the single auth model.
- No gRPC API server; no web UI backend.

**Impact:** Operators can now fully manage FilterPolicy via the API (no more `kubectl` + CRD round-trips for that resource). Watch/streaming and the other resource families are the next natural steps.

### 4. Broader eBPF Program Types ❌ (Sprint 32 candidate)

**What's Shipped (Sprint 31 Ticket 51):** sockops + cgroup loaders alongside the Sprint 30 XDP + TC loaders. `pkg/hardware/ebpf/program_manager.go` now dispatches all four through owned loaders on Linux.

**Still Missing:**
- sk_msg loader (for socket-redirect after sockops accept)
- sk_lookup loader (for explicit socket selection at bind/connect)
- LWT (lightweight tunnel) program types
- Other program types still return `ErrEBPFProgramTypeUnsupported` in `pkg/hardware/ebpf/program_manager.go`

**Impact:** XDP + TC + sockops + cgroup cover the most common datapath surfaces; the remaining types unlock additional enforcement and observability hooks.

### 5. Performance Gate Promotion ⚠️ (Sprint 32 candidate)

**What's Shipped (Sprint 31 Ticket 54):** four hot-path baselines (NAT apply, DPI event → Cilium policy, FilterPolicy translate, threat-intel translate) recorded in `docs/performance/baseline-2026-04.md` with machine specs and commit SHA.

**Still Missing:**
- Routing sync bench
- DHCP control socket bench
- DNS zone update bench
- CI regression detection is a warning, not a failure (Ticket 43 envelope). Once the signal is understood across runners, the gate can promote to blocking.
- Load testing; unknown packet processing throughput.

**Impact:** Four hot paths now have regression safety nets (warning-level); other hot paths still have no coverage.

### 7. Daemon Communication ✅ Complete

**Integrated:**
- FRRouting (FRR) vtysh integration with config validation and live state queries
- Suricata control via Unix socket + Eve log parsing
- Zeek Broker client integration
- Kea DHCP control socket reconciliation
- CoreDNS zone updates + reload
- AdGuard API client integration

**Remaining:** version compatibility is not exhaustively tested; fallback behavior when daemons are unavailable is limited.

### 8. Kernel/System Integration ⚠️ Partially Addressed

**Covered via FRR/Cilium/eBPF:**
- Route table management handled through FRR vtysh and Cilium route sync
- NAT enforcement handled through Cilium policy generation
- BGP/OSPF protocol state managed through FRR
- FilterPolicy enforcement through CiliumNetworkPolicy translation (Sprint 29 Ticket 33)
- Owned eBPF: XDP + TC compile and load via `github.com/cilium/ebpf` on Linux (Sprint 30 Tickets 38, 39)

**Explicit non-goals per ADR-0001:**
- nftables or iptables rule generation
- `FirewallRule` CRD and controller (both removed in Sprint 29 Ticket 33)

**Still Missing:**
- No netlink syscalls for direct network interface manipulation
- sk_msg / sk_lookup / lwt eBPF program types still return `ErrEBPFProgramTypeUnsupported` (Sprint 32 candidate; Sprint 31 Ticket 51 added sockops + cgroup alongside Sprint 30's XDP + TC)

**Impact:** Core routing/NAT/policy works via FRR+Cilium+eBPF; direct kernel interface manipulation is intentionally out of scope per ADR-0001 for enforcement paths.

---

## What Actually Works

### ✅ Functional Components (Can be used today with minor fixes)

1. **VLAN Management** - Complete interface and event system
2. **Network Interface Tracking** - Interface enumeration and management
3. **Cilium Integration** - Can apply Cilium network policies
4. **Multi-WAN Failover** - WAN link monitoring and failover logic
5. **Traffic Classification** - Application-level traffic identification
6. **Certificate Management** - Full cert-manager integration
7. **Authentication Framework** - User management and audit logging (local/LDAP/OAuth)
8. **DPI Event Processing** - Event dispatch and profile/flow management
9. **WireGuard Config Generation** - Can generate valid WireGuard configs
10. **DNS Zone Management** - Zone and record tracking
11. **DHCP Config Generation** - Can generate valid Kea configs

12. **Routing Engine** - Real FRR integration with vtysh validation, Cilium route sync
13. **NAT Manager** - Real Cilium NAT policy generation (SNAT/DNAT/NAT66/NAT64/port forwarding)
14. **BGP/OSPF** - Live FRR state queries from JSON output
15. **DHCP Controller** - Real Kea control socket reconciliation
16. **DNS Manager** - Wired to CoreDNS zones, AdGuard filters, mDNS reflection
17. **IDS Controllers** - Real Suricata Unix socket + Zeek Broker integration
18. **DPI Connectors** - Real event-to-Cilium policy pipeline with TTL expiry
19. **WireGuard VPN** - Real CRD-to-interface reconciliation
20. **Auth Providers** - Local, LDAP, and OAuth wired to real providers

### ⚠️ Partially Works (Needs completion)

1. **NTP Controller** - Config generation works, real Chrony integration in progress

### ⚠️ Partial / Future Work (Sprint 32 candidates)

1. **Prometheus Rekey for `fos1-internal-ca`** - Implemented locally via Ticket 57; verify in-cluster scrape behavior before marking fully shipped.
2. **External-Daemon TLS** - FRR vtysh is implemented locally via a sidecar mTLS terminator. Suricata socket, Kea control socket, Zeek Broker, and chronyc still speak plaintext on in-pod loopback / Unix paths. Cross-host paths need a sidecar TLS terminator or daemon-native TLS.
3. **External-Daemon HA** - FRR / Suricata / Zeek / Kea singletons run as single-pod / single-process; per-daemon clustering (BFD for FRR, Kea HA hooks, parallel Suricata sensors) remains open.
4. **Shared-State HA (Elasticsearch / Prometheus / Grafana / Alertmanager)** - Single-replica StatefulSets / Deployments hold persistent data. Multi-node clustering (ES cross-zone replication, Prometheus federation or Thanos) is a separate sprint.
5. **Write-Path API for Additional Resource Families** - Ticket 48 extended FilterPolicy to full CRUD. NAT, routing, DPI, zones, and threat feeds remain read-only or `kubectl`-only.
6. **Watch / Streaming Endpoints on the REST API** - Chunked JSON-lines streaming was deferred from Ticket 48.
7. **Broader eBPF Program Types** - Ticket 51 added sockops + cgroup; sk_msg, sk_lookup, lwt, and other program types still return `ErrEBPFProgramTypeUnsupported`.

### Non-goals (explicit per ADR-0001 / Sprint 29)

- `nftables` / `iptables` rule generation — Cilium is the sole enforcement backend
- `FirewallRule` CRD and controller — removed in Sprint 29 Ticket 33
- SAML / RADIUS / certificate auth providers — removed in Sprint 29 Ticket 34
- eBPF-based packet capture — remains a non-goal per Sprint 29 Ticket 35

---

## Comparison: Documentation vs Reality

| Feature | Documented | Implemented | Gap |
|---------|-----------|-------------|-----|
| VLAN Support | ✅ Detailed | ✅ Complete | None |
| Static Routing | ✅ Detailed | ✅ Complete | FRR + Cilium route sync |
| BGP/OSPF | ✅ Detailed | ✅ Complete | Live FRR state queries |
| Multi-WAN | ✅ Detailed | ✅ Complete | None |
| Firewalling | ✅ Detailed | ✅ Complete via Cilium | FilterPolicy → CiliumNetworkPolicy translator + statusful controller (ADR-0001, sprint 29 ticket 33). nftables is a non-goal. |
| DPI Framework | ✅ Detailed | ✅ Complete | Event-to-Cilium policy pipeline |
| IDS/IPS | ✅ Detailed | ✅ Complete | Real Suricata + Zeek integration |
| NAT/NAT66 | ✅ Detailed | ✅ Complete | Real Cilium NAT policy generation |
| eBPF Programs | ✅ Detailed | ⚠️ Partial | XDP + TC compile and load on Linux via `github.com/cilium/ebpf` (Sprint 30 Tickets 38, 39); sockops/cgroup loaders unsupported |
| DNS Services | ✅ Detailed | ✅ Complete | CoreDNS, AdGuard, mDNS integrated |
| DHCP Services | ✅ Detailed | ✅ Complete | Real Kea control socket |
| NTP Services | ✅ Detailed | ✅ Complete | Minor - config only |
| WireGuard VPN | ✅ Detailed | ✅ Complete | Real CRD-to-interface reconciliation |
| Authentication | ✅ Detailed | ✅ Complete (scoped) | Local, LDAP, OAuth wired; SAML/RADIUS/cert removed as non-goals (2026-04-21) |
| Certificates | ✅ Detailed | ✅ Complete | None |
| QoS/Traffic Shaping | ✅ Detailed | ✅ Complete (per-pod egress + VLAN-scoped TC shaper) | Cilium Bandwidth Manager backend per Sprint 30 Ticket 45 (`QoSProfile` CR → `kubernetes.io/egress-bandwidth` pod annotation) handles per-pod egress; Sprint 31 Ticket 52 added the `TrafficShaper` CRD on top of Sprint 30 Ticket 39's TC infrastructure for VLAN-scoped or uplink egress shaping. Composes: pod egress caps come from `QoSProfile`, uplink/VLAN shaping comes from `TrafficShaper`. Status writes use the Ticket 40 shared writeback helper. See `docs/design/qos.md` and `docs/design/ebpf-implementation.md`. |
| Hardware Offload | ✅ Detailed | ⚠️ Partial | No driver integration |

---

## Production Readiness Assessment

### ❌ Not Production Ready

**Blockers for Production Use:**

1. ~~No Daemon Control~~ - **Resolved:** FRR, Suricata, Zeek, Kea, CoreDNS, AdGuard all integrated
2. ~~Incomplete Auth~~ - **Resolved:** Local, LDAP, OAuth providers wired; SAML/RADIUS/cert removed as non-goals per Sprint 29 Ticket 34
3. ~~No Firewall~~ - **Resolved via Cilium (ADR-0001):** `FilterPolicy` translates into `CiliumNetworkPolicy` with idempotent, statusful reconciliation per Sprint 29 Ticket 33; nftables and `FirewallRule` are non-goals
4. ~~NIC / Capture Stubs~~ - **Resolved:** Real ethtool + tcpdump shims on Linux with explicit sentinels off-Linux per Sprint 29 Ticket 35
5. ~~Observability Proof Depth~~ - **Resolved:** Event correlator E2E, accelerated ILM rollover, natural-traffic DPI, and dashboard/alert PromQL validation all proved in the Kind bootstrap harness per Sprint 29 Tickets 29-32
6. ~~RBAC minimum-privilege baseline~~ - **Resolved:** Per Sprint 30 Ticket 42 — CI gate in `scripts/ci/prove-no-cluster-admin.sh` blocks `cluster-admin` bindings without explicit `fos1.io/rbac-exception` annotation; per-controller verb/resource table in `docs/design/rbac-baseline.md`
7. ~~No eBPF Loading~~ - **Resolved (XDP + TC + sockops + cgroup):** XDP compile+load landed per Sprint 30 Ticket 38; TC compile+load + clsact bootstrap per Ticket 39; sockops + cgroup loaders per Sprint 31 Ticket 51. sk_msg / sk_lookup / lwt remain Sprint 32 candidates.
8. ~~No API Server (read-only)~~ - **Resolved:** Read-only REST v0 per Sprint 30 Ticket 41 serves `/v1/filter-policies` under mTLS with a Subject-CN allowlist.
9. ~~No Performance Baseline~~ - **Resolved (one hot path):** NAT policy apply baseline per Sprint 30 Ticket 43. Broader coverage remains open.
10. ~~QoS Enforcement Stubbed~~ - **Resolved (per-pod egress):** `QoSProfile` CR → pod annotation → Cilium Bandwidth Manager enforces via BPF TBF per Sprint 30 Ticket 45. Ingress enforcement and VLAN-scoped shaping remain open.
11. ~~FilterPolicy status in-memory only~~ - **Resolved:** Shared `pkg/controllers/status.Writer` helper persists conditions via the status subresource per Sprint 30 Ticket 40; adopted by FilterPolicy, NAT, MultiWAN.
12. ~~No Threat Intelligence~~ - **Resolved (v1):** URLhaus CSV (Sprint 30 Ticket 44) + MISP JSON (Sprint 31 Ticket 53) ingestion via `ThreatFeed` CRD with last-seen TTL. STIX/TAXII remains non-goal.
13. ~~No Write-Path API~~ - **Resolved (CRUD v1 for FilterPolicy):** Sprint 31 Ticket 48 added POST / PUT / PATCH / DELETE on `/v1/filter-policies` with optimistic concurrency, JSON Merge Patch + Strategic Merge Patch dispatch, and structured 422 validation. Watch / streaming endpoints and additional resource families remain Sprint 32 candidates.
14. ~~Controller HA Single Point Of Failure~~ - **Resolved (controller tier):** Sprint 31 Ticket 47 ships controller leader election with hot standby and a CI failover proof on `ids-controller`; RTO ≤ 30s. Data tier and external-daemon singletons remain Sprint 32 candidates.
15. ~~Sockops / cgroup eBPF Program Types Unsupported~~ - **Resolved:** Sprint 31 Ticket 51 added sockops + cgroup loaders alongside Sprint 30 XDP + TC. sk_msg, sk_lookup, lwt, etc. remain Sprint 32 candidates.
16. ~~Performance Coverage One Hot Path~~ - **Resolved (four hot paths):** Sprint 31 Ticket 54 added DPI / FilterPolicy / threat-intel translate baselines alongside Ticket 43's NAT apply; routing sync, DHCP control socket, DNS zone update remain Sprint 32 candidates.
17. ~~No Inter-Controller TLS Baseline~~ - **Resolved (baseline):** Sprint 31 Ticket 49 ships the `fos1-internal-ca` ClusterIssuer + cert-manager rotation reload. Ticket 56 adds owned-listener mTLS, Ticket 57 adds the Prometheus client-cert scrape rekey, and Ticket 58 adds the FRR vtysh mTLS sidecar. External-daemon TLS for Suricata / Kea / Zeek / chronyc remains a Sprint 32 follow-up.
18. ~~VLAN-Scoped Shaping Missing~~ - **Resolved:** Sprint 31 Ticket 52 ships the `TrafficShaper` CRD on top of Ticket 39's TC infrastructure. Ingress enforcement (Bandwidth Manager limitation) remains open.
19. ~~`github.com/google/nftables` Still In go.mod~~ - **Resolved:** Sprint 31 Ticket 50 + cleanup `bac62b2` removed all references; nftables is fully gone (not just non-goal).
20. **Partial Kernel Integration** - Direct interface manipulation still missing (non-goal per ADR-0001 for enforcement paths)
21. **Uneven Test Coverage** - Four targeted packages at 50%+ (Sprint 29 Ticket 36); aggregate still uneven. Sprint 30 + Sprint 31's new packages (`pkg/api/`, `pkg/controllers/status/`, `pkg/security/threatintel/`, `pkg/security/qos/`, `pkg/leaderelection/`, `pkg/hardware/ebpf/{sockops,cgroup}_loader_*`, MISP feed, TrafficShaper controller) all ship with dedicated tests.
22. **External-Daemon HA + Shared-State HA** - FRR / Suricata / Zeek / Kea singletons and Elasticsearch / Prometheus / Grafana / Alertmanager remain single-instance — Sprint 32 candidates. See `docs/design/high-availability.md`.
23. **mTLS Controller-To-Controller + External-Daemon TLS** - Ticket 49 shipped server-side TLS only; Tickets 56-58 narrow the gap with owned-listener mTLS, Prometheus client certs, and FRR vtysh mTLS. TLS for Suricata / Kea / Zeek / chronyc remains open.
24. **Watch / Streaming + Additional Resource Families on REST API** - Watch endpoints and resource families beyond FilterPolicy (NAT, routing, DPI, zones) remain Sprint 32 candidates.
25. **Broader eBPF Program Types** - sk_msg, sk_lookup, lwt return `ErrEBPFProgramTypeUnsupported`; Sprint 32 candidate.

**Estimated Effort to Production:**
- **1-3 months** of full-time development (reduced from the prior 2-4 months: Sprint 31 closed controller HA via leader election, CRUD-v1 REST API, internal TLS baseline, sockops/cgroup eBPF, VLAN-scoped TC shaper, MISP threat feed, four-hot-path perf baseline, and the residual nftables cleanup. The remaining residual work is dominated by external-daemon and shared-state HA plus mTLS controller-to-controller and write-path API breadth, not net-new backend bring-up.)
- **2-3 experienced engineers**
- Focus areas: external-daemon and shared-state HA (largest residual), external-daemon TLS, write-path API for additional resource families, watch / streaming endpoints, broader eBPF program types

**Current Stage:** Beta
**Production Readiness:** ~82-87%

Rationale: Sprint 29 closed the "advertised but unshipped" surfaces (FilterPolicy enforcement, auth surface, NIC/capture reporting) and added meaningful observability proof depth. Sprint 30 closed the critical-path production gaps Sprint 29 had deferred (XDP + TC eBPF, read-only REST API, RBAC baseline, one-hot-path perf, URLhaus threat-intel, per-pod egress QoS, FilterPolicy status persistence). Sprint 31 closed the residual production-hardening blockers from Sprint 30: controller HA via leader election, CRUD v1 on the REST API for FilterPolicy, internal TLS baseline via `fos1-internal-ca`, sockops + cgroup eBPF, VLAN-scoped TC shaper, MISP threat feed, four-hot-path perf coverage, and the residual nftables cleanup. The percentage is raised from the prior ~75-80% to ~82-87% because three previously-blocking gaps (controller HA, read-only REST API, no internal TLS) are now closed at the controller tier. The number does not climb higher because external-daemon and shared-state HA remain the largest residual block, and external-daemon TLS plus write-path API breadth are still open.

---

## Strengths of This Repository

### 1. Excellent Architectural Design ✅
- Clear, well-thought-out component boundaries
- Interface-driven design allows for future implementations
- Kubernetes-native approach with comprehensive CRDs
- Event-driven architecture with proper lifecycle management

### 2. Comprehensive Documentation ✅
- 72 documentation files covering all aspects
- Detailed design documents for every major component
- Clear how-to guides and reference documentation
- Mermaid diagrams for complex interactions

### 3. Well-Organized Codebase ✅
- Logical package structure (16 top-level packages)
- Consistent naming conventions
- Separation of concerns (types, managers, controllers)
- Manager pattern consistently applied

### 4. Complete API Definitions ✅
- 42+ Kubernetes CRDs covering all functionality
- Well-structured API types
- Comprehensive example configurations
- Clear validation rules

### 5. Build Infrastructure Ready ✅
- Comprehensive Makefile with all targets
- Multi-stage Dockerfiles for all services
- Linting and validation configured
- Talos Linux deployment configs

### 6. Integration Framework ✅
- Cilium integration complete
- cert-manager integration complete
- Kubernetes controller patterns established
- Service coordination framework ready

---

## Weaknesses & Risks

### 1. Implementation Gaps (Narrowed after Sprint 31) ⚠️
- Sprint 29 closed FilterPolicy enforcement, auth surface scope, NIC/capture reporting, and observability proof depth
- Sprint 30 closed eBPF compile+load (XDP + TC), shared CRD status writeback, read-only REST API, RBAC baseline, one-hot-path perf baseline, URLhaus threat-intel v0, and per-pod egress QoS
- Sprint 31 closed controller HA via leader election, CRUD v1 REST API for FilterPolicy, internal TLS baseline via `fos1-internal-ca`, sockops + cgroup eBPF program types, VLAN-scoped TC shaper, MISP threat feed, four-hot-path perf coverage, and the residual nftables cleanup
- sk_msg / sk_lookup / lwt eBPF program types remain unsupported and are Sprint 32 candidates
- mTLS controller-to-controller and Prometheus rekey for the `fos1-internal-ca` chain are active Sprint 32 work; external-daemon TLS remains a Sprint 32 candidate
- External-daemon HA + shared-state HA remain Sprint 32 candidates
- Direct kernel/system integration beyond FRR+Cilium+eBPF is an explicit non-goal per ADR-0001 for enforcement paths
- nftables rule generation is fully removed (was a formal non-goal per Sprint 29 Ticket 33; the dependency itself was dropped from `go.mod`/`go.sum` by Sprint 31 cleanup commit `bac62b2`)

### 2. Test Coverage (Uneven) ⚠️
- 60+ test files; 43/43 packages pass `make verify-mainline`
- Four packages raised to 50%+ in Sprint 29 Ticket 36: `pkg/traffic` 51.4%, `pkg/hardware/wan` 57.6%, `pkg/network/ebpf` 93.2%, `pkg/security/policy` 51.1%
- Sprint 30 added new packages with dedicated tests: `pkg/api/` (mTLS handshake + handler), `pkg/controllers/status/` (round-trip retry-on-conflict), `pkg/security/threatintel/` (fake HTTP URLhaus fetch+parse+translate), `pkg/security/qos/` (BandwidthManager annotation reconcile)
- Sprint 31 added new packages and harness coverage with dedicated tests: `pkg/leaderelection/` (lease acquisition / loss callbacks), MISP feed (fake server fetch+parse+translate), `pkg/hardware/ebpf/{sockops,cgroup}_loader_*` (Linux integration tests skipping without unified cgroup v2), `pkg/controllers/trafficshaper_controller.go` (apply/update/delete with a fake TCLoader), write-verb handlers in `pkg/api/` (POST/PUT/PATCH/DELETE round-trip plus 422 validation cases)
- Aggregate coverage still uneven across other packages
- Kind-harness E2E proofs landed in Sprint 29 (correlator, ILM rollover, natural-traffic DPI, dashboard PromQL)
- Kind-harness E2E proofs landed in Sprint 31 (leader failover, cert rotation)
- Four hot-path benches in `tools/bench/` (NAT, DPI, FilterPolicy, threat-intel translate); routing sync, DHCP control socket, DNS zone update remain open
- No load tests

### 3. External Dependencies (High Risk) ⚠️
- Depends on external daemons (FRR, Suricata, Zeek, Kea)
- No fallback if daemons unavailable
- Version compatibility untested
- No daemon health monitoring
- External daemons remain single-pod / single-process with no in-tree HA contract; per-daemon clustering is a Sprint 32 candidate

### 4. Performance (Improving) ⚠️
- Four hot-path baselines measured: NAT apply (Sprint 30 Ticket 43) plus DPI event → Cilium policy, FilterPolicy translate, threat-intel translate (Sprint 31 Ticket 54).
  Regressions flagged in CI as warnings (non-blocking).
  See `docs/performance/baseline-2026-04.md` and `tools/bench/`.
- Remaining hot paths unbenchmarked: routing sync, DHCP control socket, DNS zone update.
- No load testing; unknown packet processing throughput.
- Unknown connection tracking limits.

### 5. Security Posture (Medium Risk) ⚠️
- RBAC minimum-privilege baseline implemented (Sprint 30 / Ticket 42):
  every ClusterRoleBinding targets a controller-scoped ClusterRole;
  `scripts/ci/prove-no-cluster-admin.sh` blocks any new `cluster-admin`
  binding without an explicit `fos1.io/rbac-exception` annotation.
  See `docs/design/rbac-baseline.md` for the per-controller verb/resource
  table.
- Internal TLS via `fos1-internal-ca` with cert-manager rotation
  (Sprint 31 / Ticket 49): every owned controller mounts a
  cert-manager-issued server cert at `/var/run/secrets/fos1.io/tls/`.
  The shared `pkg/security/certificates.LoadTLSConfig` helper plus
  fsnotify watcher reload renewals in place — no pod restart, no
  listener bounce. `scripts/ci/prove-cert-rotation.sh` asserts
  `/healthz` stays 200 across `cmctl renew`. Secrets model documented in
  `docs/design/internal-tls-secrets.md`.
- mTLS for controller-to-controller calls and TLS for external daemons
  (FRR / Suricata / Kea) deferred to Sprint 32.
- Secrets management not implemented
- No security audit performed

### 6. Operational Concerns (Medium Risk) ⚠️
- Controller-tier HA shipped (Sprint 31 Ticket 47: leader election with hot standby, RTO ≤ 30s, CI failover proof). External-daemon HA + shared-state HA remain Sprint 32 candidates.
- No clustering support for external daemons (FRR / Suricata / Zeek / Kea singletons) or shared-state observability (Elasticsearch / Prometheus / Grafana / Alertmanager single-replica)
- No backup/restore procedures; no Elasticsearch snapshot automation
- Limited observability beyond the verified Kind harness baseline
- No runbooks or operational docs

---

## Technology Stack

### Core Technologies
- **Language:** Go 1.23.3
- **Orchestration:** Kubernetes
- **CNI:** Cilium
- **OS:** Talos Linux
- **Container Runtime:** Kubernetes CRI

### External Services Required
- **Routing:** FRRouting (FRR)
- **IDS:** Suricata
- **Network Analysis:** Zeek
- **DHCP:** Kea DHCP Server
- **DNS:** CoreDNS, AdGuard Home
- **NTP:** Chrony
- **VPN:** WireGuard (kernel module)
- **DPI:** nProbe (commercial, optional)
- **Certificates:** cert-manager
- **Observability Templates/Dependencies:** Prometheus, Grafana, Alertmanager, Elasticsearch, Fluentd, Kibana
  Single-node baseline only: PVC-backed monitoring state plus an Elasticsearch ILM policy attached for `14d` retention on a `30Gi` volume (manifest-level target, not CI-verified at wall-clock scale); CI verifies only that ILM rollover + delete actions execute under an accelerated policy. No HA or snapshot automation yet.

### Key Go Dependencies
- `k8s.io/client-go` - Kubernetes client
- `sigs.k8s.io/controller-runtime` - Controller framework
- `github.com/cilium/cilium` - Cilium integration
- `github.com/vishvananda/netlink` - Network configuration (unused)
- `github.com/google/gopacket` - Packet processing
- `golang.org/x/crypto` - Cryptographic operations

---

## Recommendations Summary

### Immediate Actions (0-3 months)

1. **Implement Kernel Integration**
   - Add netlink syscalls for interface/route management
   - Integrate nftables for firewall rules
   - Test on real hardware

2. **Add Daemon Communication**
   - FRRouting vtysh/API integration
   - Kea DHCP control channel
   - Suricata/Zeek management

3. **Increase Test Coverage**
   - Unit tests for all packages (target 80%)
   - Integration tests for network stack
   - CI/CD pipeline with automated testing

### Short-term (3-6 months)

4. **Complete Authentication Providers**
   - LDAP integration (done)
   - OAuth2/OIDC integration (done)
   - SAML / RADIUS / cert are non-goals (removed 2026-04-21 per Sprint 29 Ticket 34)

5. **eBPF Implementation**
   - BPF program compilation
   - XDP/TC hook integration
   - Performance optimization

6. **API Server**
   - REST API for management
   - gRPC for high-performance operations
   - Authentication and RBAC

### Medium-term (6-12 months)

7. **High Availability**
   - Controller clustering
   - State synchronization
   - Failover mechanisms

8. **Performance Optimization**
   - Benchmarking
   - Load testing
   - XDP acceleration

9. **Security Hardening**
   - RBAC implementation
   - TLS for all services
   - Security audit
   - Penetration testing

### Long-term (12+ months)

10. **Advanced Features**
    - Web UI
    - Advanced threat intelligence
    - AI-powered traffic analysis
    - Advanced QoS

---

## Conclusion

This repository represents an **excellent architectural foundation** for a Kubernetes-based router/firewall, with:

✅ **Strengths:**
- Well-designed architecture
- Comprehensive documentation
- Clear API definitions
- Solid code organization
- Modern technology stack

⚠️ **Remaining Gaps:**
- ~83-88% production ready (up from ~82-87% after Sprint 31)
- External-daemon HA (FRR / Suricata / Zeek / Kea singletons) and shared-state HA (Elasticsearch / Prometheus / Grafana / Alertmanager) remain Sprint 32 candidates; controller-tier HA via leader election shipped in Sprint 31 Ticket 47.
- mTLS mesh primitives are now in progress via Ticket 56, Prometheus client-cert scrape rekey is implemented locally via Ticket 57, and FRR vtysh mTLS sidecar is implemented locally via Ticket 58.
- External-daemon TLS still open for Suricata, Kea, Zeek, and chronyc.
- Write-path API for additional resource families (NAT, routing, DPI, zones) and watch / streaming endpoints remain Sprint 32 candidates (Ticket 48 closed CRUD v1 for FilterPolicy).
- Broader eBPF program types beyond the four owned loaders (sk_msg, sk_lookup, lwt, etc.) still return `ErrEBPFProgramTypeUnsupported` (Ticket 51 added sockops + cgroup).
- Performance coverage on routing sync, DHCP control socket, DNS zone update, and load tests still open (Tickets 43 + 54 baselined four hot paths).
- Direct kernel integration (netlink) remains a non-goal for enforcement paths per ADR-0001; nftables, SAML/RADIUS/cert, eBPF-based capture, STIX/TAXII threat feeds, and `FirewallRule` are formal non-goals.

**Verdict:** This has evolved from an architectural blueprint to a **functional beta system** with real daemon integrations (FRR, Suricata, Zeek, Kea, CoreDNS, AdGuard), real Cilium policy generation via FilterPolicy translation, working authentication providers (local/LDAP/OAuth), Kind-harness E2E proofs for the event correlator, Elasticsearch rollover, natural-traffic DPI, dashboard/alert PromQL validity, leader failover RTO ≤ 30s, cert rotation across `cmctl renew`, and local mTLS mesh behavior; real eBPF XDP + TC + sockops + cgroup compile/load on Linux; a CRUD-v1 REST API behind mTLS; a minimum-privilege RBAC baseline with CI enforcement; a four-hot-path performance baseline; URLhaus + MISP threat-intel; per-pod egress QoS via Cilium Bandwidth Manager plus VLAN-scoped TC shaping via the new `TrafficShaper` CRD; controller leader election with hot standby; and an internal TLS/mTLS baseline via the `fos1-internal-ca` ClusterIssuer with cert-manager rotation. Sprint 32 has narrowed the mTLS gap and now includes a local FRR vtysh sidecar TLS proof.

**Recommendation:** The core routing, NAT, DNS, DHCP, IDS/IPS, DPI, filter-policy, eBPF, QoS, threat-intel, CRUD-v1 API, controller HA, and internal TLS/mTLS pipelines are now functional and proven in the Kind harness or focused unit tests. Continue Sprint 32 with external-daemon TLS, external-daemon and shared-state HA, write-path API for additional resource families, watch / streaming endpoints, and broader eBPF program types beyond the four owned loaders. See `docs/sprints/sprint-32-mtls-and-external-tls.md` for the active scope.

---

**Report Prepared By:** Claude Code
**Analysis Date:** 2026-04-25
**Repository Path:** `/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/`
**Commit:** `c60f906` (main @ end of Sprint 31; pre-truth-up)
