# Sprint 30 / Ticket 46: Post-Sprint-30 Truth-Up

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Reconcile every status claim in `Status.md`, `docs/project-tracker.md`, `docs/implementation-plan.md`, `docs/observability-architecture.md`, `docs/design/implementation_caveats.md` against what Sprint 30 actually landed. Same pattern as Ticket 37.

**Prerequisite:** Tickets 38-45 merged to `main`.

---

## File Map

- Modify: `Status.md`
- Modify: `docs/project-tracker.md`
- Modify: `docs/implementation-plan.md`
- Modify: `docs/observability-architecture.md`
- Modify: `docs/design/implementation_caveats.md`
- Modify: `docs/design/implementation_backlog.md` (mark 38-46 completed, open Sprint 31 placeholder)

---

## Tasks

### Sweep For Stale Claims

- [ ] For every factual claim, match to a merged test, manifest, or harness step. Delete or mark target-architecture otherwise.
- [ ] `grep -rn 'NewSAMLProvider\|NewRADIUSProvider\|NewCertificateProvider\|NFTFirewallRule\|nftables' docs/ pkg/` — should only return explicit non-goal language.

### Status.md Concrete Updates

- [ ] §Executive Summary: post-Sprint-30 state.
- [ ] §Component Status Matrix:
  - eBPF Framework: "Partial" → "XDP + TC compile and load real on Linux" (Tickets 38+39)
  - QoS: stub → real (Ticket 45)
  - Threat Intelligence: framework-only → "URLhaus v0 ingestion" (Ticket 44)
  - API Server: missing → "REST v0 read-only for FilterPolicy" (Ticket 41)
  - RBAC: missing → "Minimum-privilege baseline with CI enforcement" (Ticket 42)
- [ ] §Testing Status: include bench baseline from Ticket 43.
- [ ] §Critical Implementation Gaps: remove fixed items. Still open: HA/clustering, write-path API, broader eBPF (sockops, cgroup), more threat feeds, performance tuning.
- [ ] §Production Readiness Assessment: bump from ~60-65% (post-Sprint-29) to new honest number. Revise effort-to-production.

### Implementation Plan And Backlog

- [ ] Mark tickets 38-46 as complete in `docs/design/implementation_backlog.md`.
- [ ] `docs/implementation-plan.md` — Sprint 30 → completed; scope Sprint 31 placeholder (HA, performance tuning, broader API, more eBPF program types, more threat feeds).

### Observability

- [ ] `docs/observability-architecture.md` — any new harness steps from Sprint 30 (e.g. RBAC CI check, bench upload) should be documented.

---

## Verification

- [ ] Every claim in listed docs is traceable to a merged artifact.
- [ ] No broken references to removed code.
- [ ] Status.md Production Readiness number recomputed.

## Out Of Scope

- Sprint 31 scoping beyond a placeholder. Actual ticket definitions come in a separate session.

## Suggested Branch

`sprint-30/ticket-46-status-truth-up`
