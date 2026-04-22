# Sprint 30 / Ticket 40: Shared CRD Status Writeback Helper

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Extract NAT's `writeStatusToCRD` pattern into a shared helper, adopt it in `pkg/security/policy/controller.go` to persist `FilterPolicy.Status.Conditions` + `LastAppliedHash` (Ticket 33 left this in-memory only), and adopt it in one more controller as a second consumer.

**Architecture:** Helper in `pkg/controllers/status/writer.go` exposes a generic `WriteStatus[T client.Object]` that handles retry-on-conflict. Existing NAT controller migrates to use the helper without behavior change.

**Tech Stack:** Go, `sigs.k8s.io/controller-runtime/pkg/client`, Go generics.

**Independence:** Self-contained. Can run anytime after Sprint 29 closes.

---

## Context

- **Ticket 33 caveat (from agent report):** "The controller mutates `FilterPolicy.Status.Conditions` on the cached object but does not yet call `UpdateStatus` on the CRD. This matches previous behavior of the stub. Lifting NAT's `writeStatusToCRD` pattern (see `pkg/controllers/nat_controller.go:558`) into this controller is documented as a follow-up in `docs/design/implementation_caveats.md`."
- NAT reference: `pkg/controllers/nat_controller.go:558` — uses `client.Status().Update(ctx, obj)` with retry-on-conflict via `retry.RetryOnConflict(retry.DefaultBackoff, ...)`.

---

## File Map

- Create: `pkg/controllers/status/writer.go`
  - `type Writer[T client.Object] struct { Client client.Client }`
  - `func (w *Writer[T]) WriteStatus(ctx context.Context, obj T, mutate func(T)) error`
  - retry-on-conflict built in; re-fetch latest, apply mutator, call `Status().Update`
- Create: `pkg/controllers/status/writer_test.go`
  - fake client; round-trip a status mutation; assert retry on synthetic conflict
- Modify: `pkg/controllers/nat_controller.go` — replace inline writeStatusToCRD with `Writer`.
- Modify: `pkg/security/policy/controller.go` — wire Writer; persist conditions after each reconcile.
- Modify: `pkg/security/policy/controller_test.go` — assert CRD status is persisted after apply, not just the cached object.
- Modify: one additional controller (candidate: `dhcp_controller.go` or `routing_controller.go`) — small adoption to prove reusability.
- Modify: `docs/design/implementation_caveats.md` — close the Sprint-29 follow-up note.

---

## Task 1: Helper Implementation

- [ ] Define `pkg/controllers/status/writer.go` with generic signature above.
- [ ] Implement retry via `k8s.io/client-go/util/retry.RetryOnConflict(retry.DefaultBackoff, ...)`.
- [ ] Each retry attempt must `Get` the latest object, run the mutator on the fresh copy, then `Status().Update`.
- [ ] Return wrapped errors including the object's GVK + namespace/name on failure.

## Task 2: Helper Tests

- [ ] `writer_test.go`:
  - `TestWriteStatus_SuccessOnFirstTry` — fake client with no conflict.
  - `TestWriteStatus_RetriesOnConflict` — fake client returns conflict once, succeeds second time.
  - `TestWriteStatus_GivesUpAfterBackoff` — conflict returned indefinitely.

## Task 3: NAT Controller Migration

- [ ] Replace inline status-update in `nat_controller.go` with `Writer.WriteStatus`.
- [ ] Behavior-preserving refactor; existing tests should still pass without modification.

## Task 4: FilterPolicy Adoption (Primary Value)

- [ ] Wire `Writer` into `pkg/security/policy/controller.go`.
- [ ] After each reconcile that changes `Status.Conditions` or `Status.LastAppliedHash`, call `Writer.WriteStatus`.
- [ ] Extend controller tests to assert fake client received `Status().Update` with expected conditions.

## Task 5: Second Adoption And Caveat Close

- [ ] Pick `routing_controller.go` or `dhcp_controller.go` and migrate one status write.
- [ ] Update `docs/design/implementation_caveats.md` to close the Ticket-33 follow-up.

---

## Verification

- [ ] `make verify-mainline` green
- [ ] `go test ./pkg/controllers/status/...` passes with retry/no-retry/give-up cases
- [ ] `FilterPolicy.Status` now survives a controller restart (verified by test)

## Out Of Scope

- Generic reconciler base class (the Writer is the contribution here)
- Conversion webhooks
- Subresource permission audits (Ticket 42 territory)

## Suggested Branch

`sprint-30/ticket-40-status-writeback-helper`
