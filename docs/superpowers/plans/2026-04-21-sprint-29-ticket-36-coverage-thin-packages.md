# Sprint 29 / Ticket 36: Raise Reconciliation-Style Coverage On Thin Packages

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add reconciliation-style tests (apply real spec → read back applied state → assert) to four historically-thin packages: `pkg/traffic/`, `pkg/security/policy/`, `pkg/hardware/wan/`, `pkg/network/ebpf/`. Target ≥ 50% coverage per package, or document explicit accepted gaps in `docs/design/test_matrix.md`.

**Architecture:** Use the existing `pkg/security/policy/controller_test.go:103-152` pattern as the template — mock the downstream dependency (Cilium client, netlink, hardware manager), drive the handler, assert both the mock's captured calls and the subject's internal state transitions. Tests stay unit-level; no Kind / root / external daemons.

**Tech Stack:** Go, `testing` stdlib, interface mocks, `testify` (if already used elsewhere in the repo).

**Independence:** Fully self-contained — no dependency on other Sprint 29 tickets.

---

## Context (Grounded In Current Code)

### Reference test pattern
`pkg/security/policy/controller_test.go:103-152` — `TestPolicyControllerAppliesUpdatesAndDisablesPoliciesThroughCilium`:
1. Mock CiliumClient (tracks `applied` and `deleted`)
2. Instantiate controller with fake K8s client + mock Cilium
3. Call `handlePolicyAdd(policy)` → assert 1 applied
4. Call `handlePolicyUpdate(modified)` → assert 2 applies + 1 delete
5. Call `handlePolicyUpdate(disabled)` → assert second delete, internal map cleared

This is the target shape.

### Package 1: `pkg/traffic/` (1,653 LOC, **no tests**)
- Files: `manager.go` (545), `classifier.go` (257), `bandwidth.go` (216), `monitor.go` (369), `types.go` (266)
- Public API: `Manager` interface with `ApplyConfiguration`, `DeleteConfiguration`, `GetStatus`, `ListConfigurations`, `GetClassStatistics`, `GetInterfaceStatistics`
- Dependencies: `Classifier`, `BandwidthAllocator` (pluggable)
- Blocker: `manager.go:51` calls `checkInterfaceExists()` via netlink / `ip` — mock this path

### Package 2: `pkg/security/policy/` (2,642 LOC, **partial tests**)
- Existing: `controller_test.go`, `translator_test.go`, `zone_manager_test.go`
- Additional gaps: edge cases not yet covered (already-applied idempotent no-op, invalid spec rejection)
- Note: if Ticket 33 lands first, it adds statusful tests. Do NOT re-add what 33 already covers. Gate this package's work on Ticket 33 merge, or scope to zone_manager + translator edge cases only.

### Package 3: `pkg/hardware/wan/` (647 LOC, **no tests**)
- File: `manager.go` (636), `factory.go` (11)
- Public API: `AddWANInterface`, `RemoveWANInterface`, `SetActiveWAN`, `GetWANStatus`, `ListWANInterfaces`, `StartMonitoring`
- Blocker: `manager.go:62` calls `netlink.LinkByName` — mock this path
- Blocker: `monitorWANInterface` spawns goroutine — tests must pass `MonitorEnabled: false`

### Package 4: `pkg/network/ebpf/` (991 LOC, **error-focused tests only**)
- Existing: `manager_test.go` (188 LOC) — error cases, lifecycle, hook validation
- Public API: `ProgramManager`, `MapManager`, `CiliumIntegration` — wraps `pkg/hardware/ebpf.Manager`
- Blocker: actual eBPF load requires kernel privileges — mock the hardware manager interface

---

## File Map

- Create: `pkg/traffic/manager_test.go`
- Create: `pkg/traffic/classifier_test.go` (optional, if classifier logic warrants isolation)
- Create: `pkg/security/policy/controller_idempotency_test.go` (ONLY if Ticket 33 does not cover; otherwise skip)
- Create: `pkg/hardware/wan/manager_test.go`
- Modify: `pkg/network/ebpf/manager_test.go` — add reconciliation-shape cases alongside the existing error cases
- Modify: `docs/design/test_matrix.md`
  - document which packages now have reconciliation-style coverage
  - record any explicit accepted gaps with reason

---

## Task 1: `pkg/traffic/` — Apply/Read/Delete Reconciliation

**Files:**
- Create: `pkg/traffic/manager_test.go`

- [ ] **Step 1:** Introduce a test-only seam for the netlink / `checkInterfaceExists` call. Either add an interface + injection point, or use a build-tag helper. Keep the production default behavior identical.
- [ ] **Step 2:** Write `fakeClassifier` and `fakeBandwidthAllocator` implementing the existing interfaces, recording inputs.
- [ ] **Step 3:** `TestManagerApplyConfigurationPopulatesStatus`:
  - build Configuration with 2 traffic classes + bandwidth limits
  - call `ApplyConfiguration(ctx, config)` → expect no error
  - call `GetStatus(ctx, config.Name)` → assert `UploadBandwidth`, `DownloadBandwidth`, `ClassStatistics` reflect config
  - assert fakeClassifier + fakeBandwidthAllocator received expected calls
- [ ] **Step 4:** `TestManagerDeleteConfigurationClearsState`:
  - apply then delete → assert `ListConfigurations` is empty and `GetStatus` returns not-found error
- [ ] **Step 5:** `TestManagerRejectsConfigOnMissingInterface`:
  - seam returns "interface not found" → assert wrapped error with interface name
- [ ] **Step 6:** `TestManagerIsIdempotentOnReapply`:
  - apply same config twice → fakeBandwidthAllocator sees the spec hash compared / no duplicate allocation

Target: these 4 tests should push `pkg/traffic/` to ≥ 50% coverage.

---

## Task 2: `pkg/hardware/wan/` — Add/Remove/SetActive Reconciliation

**Files:**
- Create: `pkg/hardware/wan/manager_test.go`

- [ ] **Step 1:** Introduce a test-only seam for `netlink.LinkByName`. Add a `netlinkClient` interface and an injection option on the `Manager` constructor.
- [ ] **Step 2:** `fakeNetlinkClient` returns preconfigured links.
- [ ] **Step 3:** `TestAddWANInterfaceRegistersAndActivatesFirst`:
  - add single interface with `MonitorEnabled: false`
  - `GetWANStatus` returns it, State = "active"
- [ ] **Step 4:** `TestAddWANInterfaceSelectsActiveByWeight`:
  - add 3 with weights 5/10/20 → activeWAN should be the highest-weight one
- [ ] **Step 5:** `TestSetActiveWANUpdatesStateAndEmitsEvent`:
  - add 2; switch active; assert GetWANStatus reflects the switch
- [ ] **Step 6:** `TestRemoveWANInterfaceCleansUp`:
  - add + remove; assert `ListWANInterfaces` excludes it
- [ ] **Step 7:** `TestAddWANInterfaceErrorsOnMissingLink`:
  - netlink fake returns `LinkNotFoundError`; assert wrapped error
- [ ] **Step 8:** No goroutines spawned — all tests use `MonitorEnabled: false`. If the `StartMonitoring` goroutine is load-bearing, add a single test with a channel-based fake monitor.

Target: ≥ 50% coverage on `pkg/hardware/wan/`.

---

## Task 3: `pkg/network/ebpf/` — Extend Existing Tests With Lifecycle

**Files:**
- Modify: `pkg/network/ebpf/manager_test.go`

- [ ] **Step 1:** Ensure a `fakeHardwareManager` implements the `hardware/ebpf.Manager` interface the wrapper depends on. Track load/attach/detach calls.
- [ ] **Step 2:** Add `TestProgramLifecycleLoadAttachDetachUnload`:
  - `LoadProgram(prog)` → assert hwManager received load call, state = Loaded
  - `AttachProgram(prog.Name, "xdp")` → state = Attached
  - `GetProgram(prog.Name)` → returns state reflecting both
  - `DetachProgram(prog.Name)` → state = Loaded (not attached)
  - `UnloadProgram(prog.Name)` → removed
- [ ] **Step 3:** Add `TestUnloadBeforeDetachReturnsError`: unload without detach should error with a clear message, not silently succeed.
- [ ] **Step 4:** Add `TestMapCRUDPersistsThroughProgramLifecycle`: create map, load program, unload program, map should persist (or not, depending on design — assert the chosen behavior).
- [ ] **Step 5:** Keep all existing error-focused tests intact.

Target: ≥ 50% coverage on `pkg/network/ebpf/`.

---

## Task 4: `pkg/security/policy/` — Gap Check Relative To Ticket 33

**Files:**
- Create (only if needed): `pkg/security/policy/controller_idempotency_test.go`

- [ ] **Step 1:** After Ticket 33 merges, run `go test -cover ./pkg/security/policy/...` to see the new coverage baseline.
- [ ] **Step 2:** If coverage is < 50%, add tests for uncovered branches — typically: invalid spec rejection, translator failure, mixed add/remove sets in a single reconcile.
- [ ] **Step 3:** If coverage is ≥ 50%, skip this package and note in `test_matrix.md` that Ticket 33 landed the reconciliation-style coverage.

---

## Task 5: Update `docs/design/test_matrix.md`

**Files:**
- Modify: `docs/design/test_matrix.md`

- [ ] **Step 1:** Add four rows (or extend existing ones) for `pkg/traffic/`, `pkg/hardware/wan/`, `pkg/network/ebpf/`, `pkg/security/policy/` with:
  - added-in-sprint: Sprint 29 / Ticket 36
  - test style: reconciliation (apply → readback → assert)
  - coverage achieved (from `go test -cover`)
- [ ] **Step 2:** For any package still under 50%, add an "Accepted Gap" row with the reason (e.g. "kernel-privileged eBPF paths cannot be unit-tested; covered by future integration harness").

---

## Verification

- [ ] `make verify-mainline` passes
- [ ] `go test -cover ./pkg/traffic/... ./pkg/hardware/wan/... ./pkg/network/ebpf/... ./pkg/security/policy/...` reports:
  - `pkg/traffic/` ≥ 50%
  - `pkg/hardware/wan/` ≥ 50%
  - `pkg/network/ebpf/` ≥ 50% (or documented accepted gap)
  - `pkg/security/policy/` ≥ 50%
- [ ] Test matrix doc updated with new rows and any accepted gaps
- [ ] No test requires root, kernel privileges, or an external daemon

---

## Out Of Scope

- End-to-end tests (reconciliation-level only)
- Performance benchmarks
- Kernel eBPF load verification (covered by accepted gap if applicable)
- Refactoring the production code for testability beyond minimal seam injection

---

## Suggested Branch Name

`sprint-29/ticket-36-coverage-thin-packages`
