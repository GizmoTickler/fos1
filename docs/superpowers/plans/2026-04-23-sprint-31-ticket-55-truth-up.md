# Sprint 31 / Ticket 55: Post-Sprint-31 Truth-Up

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Same pattern as Tickets 37 and 46. Reconcile every status claim against Sprint 31 landed artifacts. Open a Sprint 32 placeholder.

**Prerequisite:** Tickets 47-54 merged.

---

## File Map

- Modify: `Status.md`
- Modify: `docs/project-tracker.md`
- Modify: `docs/implementation-plan.md`
- Modify: `docs/observability-architecture.md`
- Modify: `docs/design/implementation_caveats.md`
- Modify: `docs/design/implementation_backlog.md`

## Tasks

### Sweep For Stale Claims

- [ ] Every claim traceable to a merged test/manifest/harness.
- [ ] `grep -rn 'github.com/google/nftables' pkg/ cmd/` — should be empty post-Ticket 50.
- [ ] `grep -rn 'ErrEBPFProgramTypeUnsupported' pkg/hardware/ebpf/` — the error should still exist for program types NOT yet supported; confirm which.

### Status.md Concrete Updates

- [ ] §Component Status Matrix:
  - HA: "Single point of failure" → "Leader election with hot standby; RTO ≤ 30s" (Ticket 47)
  - API Server: "read-only v0" → "CRUD v1 for FilterPolicy" (Ticket 48)
  - Internal TLS: new row — "Baseline via fos1-internal-ca ClusterIssuer with cert-manager rotation" (Ticket 49)
  - nftables: fully removed (Ticket 50)
  - eBPF: "XDP + TC + sockops + cgroup" (Ticket 51)
  - QoS: extended with VLAN-scoped TrafficShaper (Ticket 52)
  - Threat-intel: "URLhaus + MISP" (Ticket 53)
  - Performance: four hot paths baselined (Ticket 54)
- [ ] §Critical Gaps: remove fixed. Still open: external-daemon HA (FRR/Suricata/Kea), shared-state HA (Elasticsearch/Prometheus), write-path API for additional resource families, broader eBPF types beyond the four.
- [ ] §Production Readiness Assessment: bump from ~75-80% to new honest number. Estimated effort-to-production: revise.

### Implementation Plan + Backlog

- [ ] Mark tickets 47-55 as `completed` in `docs/design/implementation_backlog.md`.
- [ ] Move Sprint 31 from open to completed in `docs/implementation-plan.md`.
- [ ] Open Sprint 32 placeholder with candidate scope.

## Verification

- [ ] Every claim traceable.
- [ ] No broken references to removed code.
- [ ] Production-readiness number recomputed.

## Out Of Scope

- Sprint 32 ticket definitions — separate planning session.

## Suggested Branch

`sprint-31/ticket-55-truth-up`
