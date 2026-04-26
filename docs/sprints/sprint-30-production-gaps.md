# Sprint 30 — Critical-Path Production Gaps

**Window:** 2026-04-22 → 2026-04-23
**State:** Complete
**Production readiness:** ~60–65% → ~75–80%
**Effort-to-production:** 4–7 months → 2–4 months

## Goal

Close the largest "advertised but never built" production gaps. eBPF was a framework with no compile/loading, the project had no REST API, RBAC was loose, performance was unmeasured, threat-intel was a framework with no feeds, and QoS enforcement was a stub. Sprint 30 turned each of those into a real, verified primitive.

## Baseline

Main HEAD when the sprint opened: `fd131de` (Sprint 29 Ticket 37 truth-up merge). `make verify-mainline` 37/37 packages pass.

## Tickets

| # | Theme | Key deliverable | Status | Commits |
|---|---|---|---|---|
| 38 | eBPF XDP compile + load | `bpf/xdp_ddos_drop.c` compiles via `make bpf-objects` to ELF committed at `pkg/hardware/ebpf/bpf/`, embedded via `//go:embed`, loaded via `github.com/cilium/ebpf`, attached to `netlink.Dummy` interface in capability-gated test | ✅ | feat `3a9f677`, merge `de851a6` |
| 39 | eBPF TC QoS shaping | `bpf/tc_qos_shape.c` + `pkg/hardware/ebpf/tc_loader_linux.go`. Idempotent clsact qdisc bootstrap; AttachTCX (kernel ≥ 6.6); per-ifindex priority map exposed for user-space population | ✅ | feat `f9f3565` |
| 40 | Shared CRD status writeback helper | `pkg/controllers/status/writer.go` with retry-on-conflict. Adopted by FilterPolicy (closes Sprint 29 Ticket 33 caveat), NAT, MultiWAN | ✅ | feat `47b8088`, merge `2a2851c` |
| 41 | REST API v0 (read-only) | `cmd/api-server/` + `pkg/api/`: `/v1/filter-policies` list+get, `/healthz`, `/readyz`, `/openapi.json` behind `tls.RequireAndVerifyClientCert` with ConfigMap-backed Subject-CN allowlist. `pkg/api.TestMTLSEndToEnd` proves 200 / 403 / handshake-failure | ✅ | feat `e3bc979`, merge `9c70daf` |
| 42 | RBAC minimum-privilege baseline | Audit returned 0 `cluster-admin` bindings already. Added `scripts/ci/prove-no-cluster-admin.sh` with `fos1.io/rbac-exception` annotation override + per-controller verb/resource table at `docs/design/rbac-baseline.md` | ✅ | feat `e13b91a`, merge `4af3403` |
| 43 | NAT policy apply performance baseline | `tools/bench/nat_apply_bench_test.go` at three scales (single, 100, 1000 rules). Baseline at `docs/performance/baseline-2026-04.md`. Regressions warn (non-blocking) in CI | ✅ | feat `2b844d7`, merge `4ce31e8` |
| 44 | URLhaus threat-intel v0 | `ThreatFeed` CRD + `cmd/threatintel-controller/` + `pkg/security/threatintel/`. Parses URLhaus CSV, translates to Cilium deny policies with last-seen TTL | ✅ | feat `2c042a5`, merge `fb9dfb0` |
| 45 | QoS via Cilium Bandwidth Manager | `QoSProfile` CR → `kubernetes.io/egress-bandwidth` pod annotation → BPF TBF rate limiter at pod admission. Per-pod egress only in v1 | ✅ | feat `3326f46`, merge `a04ce71` |
| 46 | Post-sprint truth-up | Reconciled `Status.md`, `docs/project-tracker.md`, `docs/implementation-plan.md`, `docs/observability-architecture.md`, `docs/design/implementation_caveats.md`. Production readiness recomputed; effort-to-production revised | ✅ | feat `8fbed29`, merge `7979c41` |

## Verification

By close of Sprint 30 the Kind harness proved everything Sprint 29 did, plus the `tools/bench/` baseline harness ran in a non-blocking CI step uploading bench output as an artifact. `make verify-mainline`: 42/42 test packages pass (37 + new packages: `tools/bench`, `pkg/security/threatintel`, `pkg/api`, `pkg/controllers/status`, `pkg/security/qos` — net 5 new packages).

## Production-readiness delta

From ~60–65% → ~75–80%. The unshipped-but-architected surfaces (eBPF compile, REST API, RBAC, perf baseline, threat-intel, QoS enforcement) all became real primitives. Estimated effort-to-production revised from 4–7 months to 2–4 months.

## Caveats forwarded to Sprint 31

| From ticket | Caveat | Forwarded to |
|---|---|---|
| 33 (closed by 40) | FilterPolicy in-memory-only status conditions — closed by the new `pkg/controllers/status.Writer` helper | Closed |
| 38 | TC, sockops, cgroup program types still return `ErrEBPFProgramTypeUnsupported` | Sprint 31 Tickets 39 + 51 |
| 39 | Per-ifindex priority map has no CRD consumer yet | Sprint 31 Ticket 52 (`TrafficShaper` CRD) |
| 41 | API server is read-only; write paths and watch endpoints deferred | Sprint 31 Ticket 48 (write-path), Sprint 32+ (watch streams) |
| 41 | mTLS only for the REST API; other listeners plaintext | Sprint 31 Ticket 49 |
| 42 | Gate enforces no-cluster-admin only, not per-role minimality | Documented |
| 43 | Single hot path baselined | Sprint 31 Ticket 54 |
| 44 | URLhaus only; MISP, STIX, IP reputation feeds open | Sprint 31 Ticket 53 (MISP), permanent non-goal (STIX) |
| 45 | Egress only; ingress enforcement and VLAN-scoped shaping open | Sprint 31 Ticket 52 (VLAN shaper) |
| 46 | `pkg/network/nat/kernel.go` and `pkg/deprecated/nat/nat66.go` still imported `github.com/google/nftables` | Sprint 31 Ticket 50 |

## Plan corrections

- **Ticket 38.** Plan implicitly assumed every developer would have a BPF-capable clang. Reality: macOS Apple clang lacks the BPF backend, requiring Homebrew LLVM 21. Resolved by committing the pre-compiled `.o` (8344 bytes) and validating ELF magic in the loader. `make verify-mainline` does NOT invoke `make bpf-objects`, so macOS CI runners remain green.
- **Ticket 39.** Plan called for re-wiring `qos_controller.go` through the TC loader. Reality: Ticket 45 had already wired QoSProfile to the Cilium Bandwidth Manager via pod annotations; rewiring would have collapsed the pod-egress and uplink-shaping paths. Resolution: kept TC loader as orthogonal infrastructure (Ticket 39 ships `SetPriority`/`AttachIngress`/`AttachEgress`); a CRD consumer was deferred to Sprint 31 Ticket 52.
- **Ticket 40.** Agent hit the rate limit at 146 tool uses before committing. Worktree contained complete, tested work — salvaged via manual commit + merge.
- **Ticket 42.** Audit returned 0 `cluster-admin` bindings, contrary to the plan's "audit + replace" framing. Pivoted to CI enforcement + documentation.
- **Ticket 43.** Pure go-test bench directory `tools/bench/` requires a `doc.go` package stub for Go 1.26 to list it under `./...`. Bench `TestMain` silences klog (NAT manager is chatty) — without the redirect, `-count=10` ThousandRules emits ~844 MB of stderr.
- **Ticket 45.** Plan sketched the translator as `Spec.Classes → []PodAnnotationPatch{Selector, Annotations}`. Pivoted to `Spec.{PodSelector, Egress/IngressBandwidth}` because `Classes` was DSCP/HTB-specific (Ticket 39 territory). Rewrote `pkg/security/qos/manager.go` from 345 LOC tc-shelling to a 47 LOC type-shim.
- **Ticket 46.** Truth-up agent flagged that `pkg/security/firewall/kernel.go` was a "live consumer" of `github.com/google/nftables`. Wrong — the package was deleted in Sprint 29 Ticket 33. Corrected in Sprint 31's `bac62b2` cleanup commit.
