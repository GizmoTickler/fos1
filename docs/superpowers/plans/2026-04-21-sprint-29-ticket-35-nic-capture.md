# Sprint 29 / Ticket 35: Real NIC Capability Reporting And Packet-Capture Contract

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace placeholder / interface-only behavior in `pkg/hardware/nic/` and `pkg/hardware/capture/` with real ethtool / tcpdump / AF_PACKET queries (where the running kernel/driver exposes them) or explicit "unsupported on this driver/kernel/platform" errors. Follow the ticket-26 pattern that already did this for `pkg/hardware/offload/`.

**Architecture:** Linux-only real paths behind `//go:build linux` build tags; non-Linux stubs in `manager_stub.go` returning explicit unsupported errors. Real paths use `github.com/safchain/ethtool v0.5.10` (already a dependency) and `github.com/vishvananda/netlink`. Capture path gains a stub file and explicit unsupported errors when `tcpdump` is not available.

**Tech Stack:** Go, `safchain/ethtool`, `vishvananda/netlink`, `tcpdump` shim, Go unit tests with interface mocks.

**Independence:** Fully self-contained — no dependency on other Sprint 29 tickets.

---

## Context (Grounded In Current Code)

### Reference pattern (ticket 26, already landed): `pkg/hardware/offload/`
- `manager.go` build-tag `//go:build linux` at line 1
- `ethtoolClient` interface at lines 15-36 — mockable seam
- `NewManager()` at line 129-138 — directly calls `ethtool.NewEthtool()`; returns explicit error on failure
- `ErrOffloadStatisticsNotSupported` defined at line 19
- `GetOffloadStatistics()` at lines 262-294 — returns `ErrOffloadStatisticsNotSupported` when zero stat descriptors match (line 287)
- `manager_stub.go` — all public methods return `fmt.Errorf("hardware offload management is only supported on linux")`
- `manager_test.go` at lines 1-108:
  - mock `ethtoolClient` (15-36)
  - real-path test (38-71)
  - unsupported-path test (73-90)
  - error-propagation test (92-107)

This is the exact shape both NIC and capture paths need to adopt.

### Current NIC state
- `pkg/hardware/nic/manager.go` — `//go:build linux` at line 1; methods 64-265 use ethtool + netlink
- `pkg/hardware/nic/manager_stub.go` — empty stubs returning `"NIC management is only supported on linux"`
- `pkg/hardware/types/nic_types.go` — `NICManager` interface (lines 8-29), `NICInfo` (32-62), `NICStatistics` (64-95)
- **No tests exist** for NIC manager
- Statistics + feature reporting paths likely return zero-value success on unsupported drivers — verify and fix

### Current capture state
- `pkg/hardware/capture/manager.go` — shells out to `tcpdump` (checked at line 66, executed at line 146)
- **No `manager_stub.go` and no build-tag split**
- **No tests exist**
- `pkg/hardware/types/types.go` — `CaptureManager` interface (lines 8-30), `CaptureConfig` (32-48), `CaptureStatus` (50-78)
- Does not detect tcpdump absence gracefully

### Design doc claims to reconcile
- `docs/design/hardware-integration.md:93-167` — NIC claims
- `docs/design/hardware-integration.md:240-286` — offload (already accurate post-ticket-26)
- `docs/design/hardware-integration.md:289-377` — capture claims (says eBPF+pcap; reality is tcpdump shim)

### Modules available
- `github.com/safchain/ethtool v0.5.10` (go.mod:14)
- `github.com/vishvananda/netlink` (go.mod:16)
- `github.com/google/uuid` (for capture session IDs)

---

## File Map

### NIC
- Modify: `pkg/hardware/nic/manager.go`
  - add mockable `ethtoolClient` interface (copy from offload pattern)
  - add explicit `ErrNICStatisticsNotSupported`, `ErrNICFeatureNotSupported` sentinel errors
  - replace any placeholder zero-value returns in `GetStatistics()` / capability reporting with real ethtool calls or sentinel errors
- Modify: `pkg/hardware/nic/manager_stub.go`
  - unchanged in shape, but ensure every interface method returns the platform-unsupported error (not zero-value success)
- Create: `pkg/hardware/nic/manager_test.go`
  - mirror `pkg/hardware/offload/manager_test.go:1-108`:
    - mock ethtool interface
    - real-path test with populated stats
    - unsupported-path test asserting sentinel error
    - error-propagation test
- Modify: `pkg/hardware/types/nic_types.go`
  - add any new error-return shapes the interface needs (keep backwards-compatible signatures)

### Capture
- Modify: `pkg/hardware/capture/manager.go`
  - rename to `pkg/hardware/capture/manager_linux.go` with `//go:build linux`
  - detect `tcpdump` availability at `NewManager()`; return explicit error if absent
  - define `ErrTCPDumpNotAvailable`, `ErrCaptureUnsupported` sentinels
  - wrap exec failures with actionable error context
- Create: `pkg/hardware/capture/manager_stub.go`
  - `//go:build !linux`
  - every interface method returns `fmt.Errorf("packet capture is only supported on linux")`
- Create: `pkg/hardware/capture/manager_test.go`
  - mock `exec.Command` seam (factor tcpdump exec through an interface if needed)
  - supported-path test
  - tcpdump-not-available test asserting `ErrTCPDumpNotAvailable`
  - running-capture cleanup test

### Docs
- Modify: `docs/design/hardware-integration.md`
  - §NIC: describe the ethtool-driven real path + explicit unsupported conditions
  - §Capture: replace eBPF+pcap architecture claim with the real tcpdump shim OR mark the eBPF design as a clearly-labelled future direction
- Modify: `Status.md`
  - update Hardware row: NIC + capture now report real capabilities or explicit unsupported, matching the offload pattern

---

## Task 1: Wrap NIC Manager In A Mockable Ethtool Interface

**Files:**
- Modify: `pkg/hardware/nic/manager.go`

- [ ] **Step 1:** Copy the `ethtoolClient` interface pattern from `pkg/hardware/offload/manager.go:15-36`. Ensure it exposes `FeatureNames`, `Features`, `Stats`, etc. — whatever the NIC manager actually uses.
- [ ] **Step 2:** Change `NewManager()` to accept an optional `ethtoolClient` (constructor overload or options-struct). Default to real `ethtool.NewEthtool()`.
- [ ] **Step 3:** Define sentinel errors:
  ```go
  var (
      ErrNICStatisticsNotSupported = errors.New("NIC statistics not exposed by driver")
      ErrNICFeatureNotSupported    = errors.New("NIC feature not supported by driver")
  )
  ```
- [ ] **Step 4:** Audit every method that currently returns a zero-value `NICStatistics{}` or `NICInfo{}` with no error — it should either return a populated struct or wrap a sentinel error with context (e.g. `fmt.Errorf("get stats for %s: %w", iface, ErrNICStatisticsNotSupported)`).

---

## Task 2: Add NIC Unit Tests Mirroring Offload

**Files:**
- Create: `pkg/hardware/nic/manager_test.go`

- [ ] **Step 1:** Create a `fakeEthtoolClient` struct implementing `ethtoolClient`, capturing inputs and returning configurable outputs.
- [ ] **Step 2:** Write `TestGetStatisticsPopulatesRealFields`: fake returns a non-empty stats map; assert fields populated, no error.
- [ ] **Step 3:** Write `TestGetStatisticsReturnsSentinelWhenUnsupported`: fake returns empty map; assert `errors.Is(err, ErrNICStatisticsNotSupported)`.
- [ ] **Step 4:** Write `TestGetStatisticsPropagatesEthtoolError`: fake returns error; assert error wraps with interface name context.
- [ ] **Step 5:** Ensure tests are in the linux build (or make the fake compile cross-platform via interface injection so CI runs them on non-Linux macOS dev envs too).

---

## Task 3: Split Capture Manager Into Linux + Stub

**Files:**
- Create: `pkg/hardware/capture/manager_stub.go`
- Modify/rename: `pkg/hardware/capture/manager.go` → `manager_linux.go`

- [ ] **Step 1:** Add `//go:build linux` at the top of `manager.go` and rename to `manager_linux.go`.
- [ ] **Step 2:** Create `manager_stub.go` with `//go:build !linux`. Return `fmt.Errorf("packet capture is only supported on linux")` for every public method. Keep struct shape minimal.
- [ ] **Step 3:** Define sentinels in a platform-neutral file (e.g. `errors.go`):
  ```go
  var (
      ErrTCPDumpNotAvailable = errors.New("tcpdump binary not found in PATH")
      ErrCaptureUnsupported  = errors.New("packet capture not supported on this platform")
  )
  ```
- [ ] **Step 4:** In `manager_linux.go`, factor the `tcpdump` exec through a seam interface:
  ```go
  type captureExec interface {
      LookPath(name string) (string, error)
      Start(cmd *exec.Cmd) error
      Kill(pid int) error
  }
  ```
  This seam lets tests verify unsupported paths without requiring a real missing-tcpdump environment.
- [ ] **Step 5:** `NewManager()` calls `exec.LookPath("tcpdump")`; on error, returns `ErrTCPDumpNotAvailable` wrapped with context.
- [ ] **Step 6:** Every `StartCapture()` / `StopCapture()` / `GetCaptureStatus()` error returns includes the session ID + interface for diagnostics.

---

## Task 4: Add Capture Unit Tests

**Files:**
- Create: `pkg/hardware/capture/manager_test.go`

- [ ] **Step 1:** `fakeCaptureExec` implements the seam, controllable outcomes.
- [ ] **Step 2:** `TestNewManagerReturnsErrorWhenTCPDumpMissing`: seam returns `exec.ErrNotFound`; assert `errors.Is(err, ErrTCPDumpNotAvailable)`.
- [ ] **Step 3:** `TestStartCaptureLaunchesTCPDump`: seam accepts start; assert status transitions to `Running`.
- [ ] **Step 4:** `TestStopCaptureKillsProcessAndCleansUp`: start then stop; assert process killed, status transitions.
- [ ] **Step 5:** `TestListCapturesReturnsActiveSessions`.

---

## Task 5: Docs Truth-Up

**Files:**
- Modify: `docs/design/hardware-integration.md`
- Modify: `Status.md`
- Modify: `docs/project-tracker.md`

- [ ] **Step 1:** In `hardware-integration.md` §NIC: add "Real ethtool-derived capability and statistics reporting on Linux; explicit unsupported errors when driver or kernel does not expose counters. Matches the pattern established by `pkg/hardware/offload/` in ticket 26."
- [ ] **Step 2:** §Capture: replace the eBPF+pcap architecture narrative with "Current implementation: `tcpdump` shim with explicit `ErrTCPDumpNotAvailable` when the binary is absent. eBPF-based capture remains a future direction and is not implemented."
- [ ] **Step 3:** `Status.md` Hardware rows: NIC → "Real ethtool / netlink queries on Linux; explicit unsupported errors on non-Linux or missing-driver paths." Capture → "Real tcpdump shim on Linux with explicit unsupported errors; eBPF capture remains a non-goal."

---

## Verification

- [ ] `make verify-mainline` passes on macOS (stubs compile cleanly)
- [ ] `go test ./pkg/hardware/nic/...` passes with new tests
- [ ] `go test ./pkg/hardware/capture/...` passes with new tests
- [ ] `grep -rn 'return NICStatistics{}\|return NICInfo{}' pkg/hardware/nic/` returns no placeholder-zero paths
- [ ] Docs no longer claim eBPF-based capture without labelling it a non-goal

---

## Out Of Scope

- Actually implementing eBPF-based packet capture (clearly labelled non-goal)
- NIC driver-specific feature integration (Intel X540/X550/I225 driver quirks) — follow-up if needed
- Hardware offload changes (already covered by ticket 26)
- Cross-platform (BSD, macOS Darwin kernel) real paths beyond build-tag stubs

---

## Suggested Branch Name

`sprint-29/ticket-35-nic-capture-real-reporting`
