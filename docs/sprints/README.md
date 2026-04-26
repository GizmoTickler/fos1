# FOS1 Sprint Roadmap

This directory is the canonical, point-in-time view of the FOS1 sprint program — past, present, and proposed. Each sprint document is a self-contained reference: goal, tickets shipped or scoped, landed commits, production-readiness delta, and the caveats that became candidate scope for the next sprint.

For implementation-level detail, see:
- [`docs/implementation-plan.md`](../implementation-plan.md) — current ticket status and verification snapshot
- [`docs/design/implementation_backlog.md`](../design/implementation_backlog.md) — full ticket definitions with acceptance criteria
- [`docs/design/implementation_caveats.md`](../design/implementation_caveats.md) — known caveats per ticket

For high-level status, see [`Status.md`](../../Status.md).

---

## Trajectory

| Sprint | Window | Theme | Tickets | State | Production Readiness |
|---|---|---|---|---|---|
| Pre-Sprint-29 | through 2026-04-19 | Foundation: Cilium-first control plane, real backends, ops-first CI | 1–28 + ops sprint | Complete | ~55% |
| **[Sprint 29](sprint-29-runtime-depth.md)** | 2026-04-21 → 2026-04-22 | Runtime depth + post-baseline hardening | 29–37 (9) | **Complete** | ~55% → ~60–65% |
| **[Sprint 30](sprint-30-production-gaps.md)** | 2026-04-22 → 2026-04-23 | Critical-path production gaps | 38–46 (9) | **Complete** | ~60–65% → ~75–80% |
| **[Sprint 31](sprint-31-production-hardening.md)** | 2026-04-23 → 2026-04-25 | Production hardening | 47–55 (9) | **Complete** | ~75–80% → ~82–87% |
| [Sprint 32](sprint-32-mtls-and-external-tls.md) | proposed | mTLS controller mesh + external-daemon TLS | 56–64 (9) | Proposed | ~82–87% → ~85–90% |
| [Sprint 33](sprint-33-state-ha.md) | proposed | Shared-state HA (ES / Prometheus / Grafana / Alertmanager) + external-daemon HA | 65–73 (9) | Proposed | ~85–90% → ~88–93% |
| [Sprint 34](sprint-34-api-expansion-ebpf-breadth.md) | proposed | Write-path API expansion, broader eBPF coverage, watch streams | 74–82 (9) | Proposed | ~88–93% → ~92–95% |

**Cumulative shipped through Sprint 31:** 27 tickets across 3 sprints. 43 test packages green. `make verify-mainline` enforced on `main` and PRs.

---

## Verification baseline (post-Sprint-31)

- `make verify-mainline` — `go test ./...` 43/43 packages pass, `go build ./...` succeeds
- `.github/workflows/ci.yml` — enforces verify-mainline on `main` + PRs
- `.github/workflows/validate-manifests.yml` — `kubeconform` validation + `scripts/ci/prove-no-cluster-admin.sh` RBAC gate
- `.github/workflows/test-bootstrap.yml` — Kind harness proving:
  - Prometheus pod-annotation scrape (DPI manager + NTP controller)
  - Suricata canary + accelerated ILM rollover/delete in Elasticsearch
  - Event-correlator end-to-end (canary → file source → correlator → file sink + `/ready` 200)
  - Natural-traffic DPI (Suricata sid 9000001 → eve.json → Elasticsearch → Prometheus counter)
  - Dashboard/alert PromQL validity against live series
  - Leader-election failover (RTO ≤ 30s on `ids-controller`)
  - cert-manager renewal preserves `/healthz` 200
  - Four-hot-path performance bench (NAT apply, DPI event, FilterPolicy translate, threat-intel translate)

---

## Cumulative non-goals (per ADR-0001 and sprint truth-ups)

These were considered and explicitly removed from scope; they are not Sprint 32+ candidates without a new ADR:

- nftables / iptables rule generation — Cilium is the sole enforcement backend
- `FirewallRule` CRD and controller — removed in Sprint 29 Ticket 33
- SAML / RADIUS / certificate auth providers — removed in Sprint 29 Ticket 34
- eBPF-based packet capture — capture is via `tcpdump` shim per Sprint 29 Ticket 35

---

## How to read a sprint document

Each sprint document follows this layout:

1. **Goal** — one paragraph on what the sprint converged on
2. **Baseline** — main HEAD when the sprint opened
3. **Tickets** — table with status, theme, key deliverable, landed commits
4. **Verification** — what `make verify-mainline` and the Kind harness covered when the sprint closed
5. **Production-readiness delta** — moved from / to with rationale
6. **Caveats forwarded** — what each ticket explicitly left for a later sprint, mapped to candidate scope
7. **Plan corrections** — places where the sprint plan was wrong and how the agent diverged

This format is the same one used by post-sprint truth-up tickets (37, 46, 55) and is intended to make sprints reviewable in isolation.
