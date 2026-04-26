# Sprint 34 — API Expansion + eBPF Program Type Breadth (Proposed)

**Window:** TBD
**State:** Proposed
**Production-readiness target:** ~88–93% → ~92–95%

## Goal

Sprint 30 shipped a read-only REST API; Sprint 31 added CRUD for FilterPolicy. Most other resource families (NAT, routing, DPI, zones, threat feeds, QoS) are still kubectl-only. Sprint 31 also landed XDP, TC, sockops, and cgroup eBPF program types — but sk_msg, sk_lookup, lwt, and several others still return `ErrEBPFProgramTypeUnsupported`. Sprint 34 closes both surfaces: full CRUD for every owned CRD on the REST API, including watch/streaming, and the remaining eBPF program type matrix.

## Baseline

Main HEAD when this sprint opens: TBD. Assumes Sprint 33 (HA) is merged so write-path API failure modes can be tested under leader-election failover.

## Proposed tickets (74–82)

| # | Theme | Key deliverable | Priority |
|---|---|---|---|
| 74 | REST API — write paths for NAT + routing | Same shape as Sprint 31 Ticket 48 (POST/PUT/PATCH/DELETE with strategic-merge dispatch and optimistic concurrency) for `/v1/nats`, `/v1/routes`, `/v1/routing-policies`. Per-resource subject allowlist | P0 |
| 75 | REST API — write paths for DPI + threat feeds + QoS | Extend to `/v1/dpi-profiles`, `/v1/threat-feeds`, `/v1/qos-profiles`, `/v1/traffic-shapers`, `/v1/filter-zones`, `/v1/filter-policy-groups` | P0 |
| 76 | REST API — watch / SSE streams | Server-Sent Events (or chunked JSON-lines) endpoints `/v1/<resource>?watch=true`. Backed by the controller-runtime informer cache. Failover behavior under leader transitions tested in CI | P0 |
| 77 | OpenAPI 3.1 + generated typed client | Move from hand-authored `openapi.json` to generator-driven from CRD types. Ship a typed Go client at `pkg/api/client/` for use by `cmd/api-server` test harnesses and downstream tooling | P1 |
| 78 | eBPF sk_msg + sk_lookup program types | Two more loaders following the Sprint 30/31 pattern. `pkg/hardware/ebpf/program_manager.go` dispatch updated. `make bpf-objects` produces all six `.o` files | P1 |
| 79 | eBPF lwt + lwt_in + lwt_out + lwt_xmit | Light-weight tunnel program types. Plausibly only one is needed for v1; pick based on which the routing controller would consume | P1 |
| 80 | DHCP control socket + DNS zone update + FRR reload bench coverage | Three more hot paths in `tools/bench/`. Closes the Sprint 31 Ticket 54 caveat that ops-heavy hot paths remained unbenchmarked | P2 |
| 81 | Performance gate promotion: warning → blocking | Sprint 30 Ticket 43 made regressions warning-only; promote to blocking on `>20% median ns/op` regression. Requires the Ticket 80 expanded coverage to be stable in CI first | P2 |
| 82 | Post-sprint truth-up | Standard truth-up. Recompute production readiness. Open Sprint 35 placeholder | P2 |

## Acceptance theme

After Sprint 34, the REST API is a complete control plane for every owned CRD with watch streams. Operators can run the system without ever using `kubectl` directly. The eBPF program type matrix is complete (or each remaining unsupported type has an explicit, documented reason). Performance regression is a hard gate, not a warning.

## Critical path (draft)

`74 → 75 → 76 → 77 → (78, 79 in parallel) → 80 → 81 → 82`

REST API expansion goes first because it's the largest single surface; eBPF expansion is bounded and can finish after; bench expansion + gate promotion close the loop.

## Out of scope

- gRPC API surface — REST + watch streams cover the operator use case in v1; gRPC is a follow-up
- WebSocket — SSE / chunked JSON-lines is the watch model; WebSocket adds complexity without proportional benefit
- API versioning beyond v1 — deferred until a backward-incompatible change is actually needed
- eBPF user-space loader (libbpf-go integration) — current `cilium/ebpf` library remains the loader
