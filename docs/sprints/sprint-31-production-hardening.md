# Sprint 31 — Production Hardening

**Window:** 2026-04-23 → 2026-04-25
**State:** Complete
**Production readiness:** ~75–80% → ~82–87%
**Effort-to-production:** 2–4 months → 1–3 months

## Goal

Take the project from "primitives exist" to "primitives are operationally sound." Sprint 30 shipped real eBPF, real API, real RBAC, real perf baseline. Sprint 31 made every controller HA, gave the API write verbs and validation, replaced plaintext listeners with internal TLS rotated by cert-manager, finished the eBPF program type matrix, gave QoS a CRD-driven uplink path, added a second threat-intel feed type, and broadened the perf baseline to four hot paths.

## Baseline

Main HEAD when the sprint opened: `7979c41` (Sprint 30 Ticket 46 truth-up merge). `make verify-mainline` 42/42 packages pass.

## Tickets

| # | Theme | Key deliverable | Status | Commits |
|---|---|---|---|---|
| 47 | HA / leader election baseline | Every owned controller wires leader election via `pkg/leaderelection` (CR controllers) or controller-runtime manager (`cmd/api-server`). 9 controllers wired, 5 Deployments scaled to `replicas: 2` with podAntiAffinity. Namespace-scoped `Role` + `RoleBinding` per controller — no new `ClusterRoleBinding`. RTO ≤ 30s proved by `scripts/ci/prove-leader-failover.sh` against `ids-controller` | ✅ | feat `f16109a`, merge `f9188c5` |
| 48 | Write-path REST API (CRUD v1) | POST / PUT / PATCH / DELETE on `/v1/filter-policies/{ns}/{name}`. PATCH dispatches between JSON Merge Patch and Strategic Merge Patch. PUT requires `metadata.resourceVersion`. Server-side validation rejects invalid specs with structured 422 `Invalid` body. 33 passing subtests including mTLS POST round-trip | ✅ | feat `4efe669`, merge `69d3101` |
| 49 | Inter-controller TLS baseline | `fos1-internal-ca` ClusterIssuer (CA-typed, chained from 10y self-signed root) mints per-controller server certs. Shared `pkg/security/certificates.LoadTLSConfig` + fsnotify watcher reload renewals in place. API server stays mTLS; other listeners TLS-only. `scripts/ci/prove-cert-rotation.sh` asserts `/healthz` 200 across `cmctl renew` | ✅ | feat `c60f906` (direct on main, no merge commit) |
| 50 | Delete residual nftables Go imports | Deleted `pkg/network/nat/kernel.go` and `pkg/deprecated/nat/nat66.go`. Cleanup commit `bac62b2` then ran `go mod tidy` to drop the now-orphaned `github.com/google/nftables` dependency. (`pkg/security/firewall/` had been gone since Sprint 29 Ticket 33; Ticket 50 agent's "live consumer" claim was wrong.) | ✅ | feat `b6433fc`, merge `c78252f`, cleanup `bac62b2` |
| 51 | eBPF sockops + cgroup program types | `bpf/sockops_redirect.c` + `bpf/cgroup_egress_counter.c` plus loaders `pkg/hardware/ebpf/{sockops,cgroup}_loader_linux.go`. `program_manager.go` now dispatches XDP, TC ingress/egress, sockops, cgroup through owned loaders. sk_msg / sk_lookup / lwt remain `ErrEBPFProgramTypeUnsupported` | ✅ | feat `08e6514`, merge `5d8173e` |
| 52 | VLAN-scoped TC shaper | New `TrafficShaper` CRD drives `pkg/hardware/ebpf.TCLoader` for VLAN-scoped or uplink egress shaping on top of Sprint 30 Ticket 39's TC infrastructure. Composes orthogonally with `QoSProfile` (Ticket 45). Uses the Ticket 40 `status.Writer` for Applied/Degraded/Invalid/Removed conditions | ✅ | feat `2b64cdf`, merge `65e33df` |
| 53 | MISP threat-intel feed | `ThreatFeed.Spec.Format` accepts `"misp-json"` alongside `"urlhaus-csv"`. Authentication via Kubernetes Secret referenced through `spec.authSecretRef` reading the `apiKey` data key. Rate-limit-aware (429 + Retry-After). Fake HTTP server in test harness verifies fetch-parse-translate-apply for both formats | ✅ | feat `ea29076`, merge `7684dee` |
| 54 | Performance baseline coverage expansion | Three new bench files in `tools/bench/`: DPI event → Cilium policy, FilterPolicy translate, threat-intel translate. Baseline file at `docs/performance/baseline-2026-04.md` extended to 12 measurements (4 paths × 3 scales). CI job upgraded to "four hot paths" | ✅ | feat `0f51278`, merge `b83f6e6` |
| 55 | Post-sprint truth-up | Reconciled `Status.md`, `docs/project-tracker.md`, `docs/implementation-plan.md`, `docs/observability-architecture.md`, `docs/design/implementation_caveats.md`, `docs/design/implementation_backlog.md`. Production readiness recomputed; effort-to-production revised | ✅ | feat `03494b5`, merge `34de009` |

## Verification

By the close of Sprint 31 the Kind harness proved everything Sprint 29 + 30 did, plus:
- Leader-election failover RTO ≤ 30s on `ids-controller`
- cert-manager renewal preserves `/healthz` 200 on the API server (and by extension every controller using the shared TLS reloader)
- Four-hot-path bench (NAT apply, DPI event, FilterPolicy translate, threat-intel translate)

`make verify-mainline`: 43/43 test packages pass (42 + new `pkg/leaderelection`).

## Production-readiness delta

From ~75–80% → ~82–87%. The remaining residual block is now external-daemon and shared-state HA — both fundamentally about systems we don't own (FRR, Suricata, Kea, Zeek, chrony, Elasticsearch, Prometheus). Estimated effort-to-production revised from 2–4 months to 1–3 months.

## Caveats forwarded to Sprint 32

| From ticket | Caveat | Forwarded to |
|---|---|---|
| 47 | External-daemon HA — FRR / Suricata / Zeek / Kea singletons | Sprint 33 |
| 47 | Shared-state HA — Elasticsearch / Prometheus / Grafana / Alertmanager | Sprint 33 |
| 47 | `trafficshaper-controller` stays single-replica because `hostNetwork: true` conflicts on the netdev | Documented |
| 47 | `dpi-framework` and `cilium-controller` have no in-tree Deployment manifests | Documented |
| 47 | `leader_transitions_total` Prometheus counter not exported | Sprint 32 candidate |
| 48 | Write-path API only for FilterPolicy | Sprint 34 (additional resource families) |
| 48 | No watch / streaming endpoints | Sprint 34 |
| 49 | mTLS controller-to-controller | Sprint 32 |
| 49 | External-daemon TLS — FRR vtysh, Suricata socket, Kea control socket, Zeek Broker, chronyc | Sprint 32 |
| 49 | Prometheus rekey for `fos1-internal-ca` CA bundle | Sprint 32 |
| 49 | Trust-anchor replacement (self-signed root → enterprise PKI / KMS) | Operator overlay |
| 51 | sk_msg / sk_lookup / lwt program types | Sprint 34 |
| 52 | TrafficShaper composes with QoSProfile but per-pod ingress rate limiting is still open (Bandwidth Manager limitation) | Documented |
| 53 | STIX / TAXII feeds | Permanent non-goal without ADR |
| 54 | DHCP control socket, DNS zone update, FRR reload still unbenchmarked | Sprint 32+ |

## Plan corrections

- **Ticket 47.** Plan suggested `dpi-manager` as the failover-proof target. `dpi-manager` is a DaemonSet (one pod per node, node-local) — leader election does not apply without defeating the per-node design. Pivoted to `ids-controller` (Deployment, already in the Kind harness, scaled to 2 replicas with anti-affinity).
- **Ticket 49.** Plan called for a feat + merge pair like the rest of Sprint 31. Agent committed directly to `main` without a merge commit (`c60f906`) — the agent worktree was 50 commits stale, so it worked from the main checkout instead. Resetting `main` was denied; the commit shape was accepted.
- **Ticket 50.** Plan and Sprint 30 truth-up both claimed `pkg/security/firewall/kernel.go` was a "live consumer" of `github.com/google/nftables` and would block dependency removal. Wrong — `pkg/security/firewall/` was deleted in Sprint 29 Ticket 33, so the dependency had no live consumers. Cleanup commit `bac62b2` dropped it from `go.mod` and `go.sum`.
- **Ticket 52.** Salvage path — agent got cut off mid-execution; worktree had complete, tested work in `pkg/apis/network/v1alpha1/trafficshaper_types.go` and friends. Manually committed to a salvage branch and merged.
- **Ticket 47 (first attempt).** Spawned against a stale worktree; agent's edits across cmd/*/main.go would have lost Ticket 41 (api-server) and Ticket 44 (threatintel-controller) work. Re-spawned against current main after committing Sprint 30 plans.
