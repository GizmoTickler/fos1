# Sprint 31 / Ticket 50: Delete Residual `nftables` Go Imports

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Remove `github.com/google/nftables` dependency and all kernel-native nftables NAT code that contradicts ADR-0001 (Cilium-first). The Ticket 46 agent flagged this out of scope for the truth-up; this ticket closes it.

**Tech Stack:** Go, grep.

**Independence:** Fully self-contained, small scope.

---

## Grounded Facts

- `pkg/network/nat/kernel.go` — imports `github.com/google/nftables`, implements kernel-native NAT manager
- `pkg/deprecated/nat/nat66.go` — imports same, implements NAT66 helpers
- Active NAT path: `pkg/network/nat/manager.go` (Cilium-first, shipped in Sprint 29 Ticket 6/7/8)
- Ticket 46 confirmed these two files are the ONLY remaining `github.com/google/nftables` consumers

## File Map

- Delete: `pkg/network/nat/kernel.go`
- Delete: `pkg/deprecated/nat/` (whole tree if it's only nat66.go; verify first)
- Modify: `go.mod` / `go.sum` — drop `github.com/google/nftables` via `go mod tidy`
- Modify: `docs/design/implementation_caveats.md` — update the "nftables non-goal" caveat from "referenced in dead code" to "fully removed"
- Modify: `Status.md` §Non-goals — update nftables row to note full removal
- Verify: `grep -r "github.com/google/nftables" .` returns nothing

## Tasks

### Task 1: Audit + Plan

- [ ] `grep -rn "github.com/google/nftables" pkg/ cmd/` — enumerate every consumer.
- [ ] `grep -rn "nftables" pkg/ cmd/` (case-insensitive) — catch any remaining references beyond the import.
- [ ] For each consumer, confirm no active code path calls it — if one does, STOP and surface the finding; do not silently delete live code.

### Task 2: Delete

- [ ] Delete files.
- [ ] Remove stale references in `pkg/network/nat/types.go` or manager.go if any.
- [ ] `go mod tidy`; confirm `go.mod` no longer lists `github.com/google/nftables`.

### Task 3: Verify

- [ ] `go build ./...` green.
- [ ] `go test ./...` green (41+ packages pass).
- [ ] `grep -r "github.com/google/nftables" .` returns only superpowers/plans mentions (historical).

### Task 4: Docs

- [ ] `Status.md` §Non-goals: nftables row updates from "non-goal per ADR-0001" to "non-goal per ADR-0001; fully removed from `pkg/` in Sprint 31 Ticket 50".
- [ ] `docs/design/implementation_caveats.md`: close the "nftables kernel code lingers in pkg/network/nat/kernel.go and pkg/deprecated/nat/" caveat.

## Verification

- [ ] `make verify-mainline` green
- [ ] `grep -rn "github.com/google/nftables" pkg/ cmd/` returns nothing
- [ ] `go mod why github.com/google/nftables` reports "module is not needed"

## Out Of Scope

- Any reintroduction of an nftables path — permanently removed per ADR-0001.

## Suggested Branch

`sprint-31/ticket-50-nftables-cleanup`
