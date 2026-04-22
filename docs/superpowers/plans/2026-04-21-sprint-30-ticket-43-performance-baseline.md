# Sprint 30 / Ticket 43: Performance Baseline Harness For One Hot Path

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Add a `go test -bench` harness that measures one hot path (recommended: NAT policy apply, or DPI event → Cilium policy creation). Produce a dated baseline report. Wire into CI as non-blocking with an uploaded artifact. Regressions beyond a configurable threshold print a warning (not failure) in v0.

**Tech Stack:** Go testing/bench, shell, GitHub Actions.

**Independence:** Fully self-contained.

---

## Context

- **Status.md** §Weaknesses lists "Performance Unknown (High Risk)".
- No benchmarks exist in the repo today. Zero baseline.

---

## File Map

- Create: `tools/bench/`:
  - `nat_apply_bench_test.go` (or `dpi_event_bench_test.go` — pick one)
  - `README.md` — what's measured, how to run, how to interpret
- Create: `docs/performance/baseline-2026-YY.md` — initial baseline report with ops/s, p50/p95/p99, allocations.
- Create: `scripts/ci/run-bench.sh` — invokes `go test -bench`, parses output, compares against `baseline-2026-YY.md`.
- Modify: `.github/workflows/test-bootstrap.yml` — non-blocking bench step, uploads report artifact.
- Modify: `Status.md` — §Performance: "Baseline measured for NAT policy apply; regressions flagged in CI as warning."

---

## Task 1: Pick Hot Path And Scaffold Bench

- [ ] Choose: NAT policy apply OR DPI event → Cilium policy creation.
- [ ] Rationale: NAT has the cleanest apply contract (single CR → single apply call via `pkg/network/nat/manager.go`). Recommend starting there.
- [ ] Author `nat_apply_bench_test.go` with:
  - `BenchmarkNATApply_SingleRule`
  - `BenchmarkNATApply_HundredRules`
  - `BenchmarkNATApply_ThousandRules`
- [ ] Use fake Cilium client to isolate apply-logic cost from Kubernetes API RTT.

## Task 2: Run And Record Baseline

- [ ] Execute `go test -bench=. -benchmem ./tools/bench/... -count=10` locally.
- [ ] Capture ops/s, ns/op, B/op, allocs/op.
- [ ] Write `docs/performance/baseline-2026-YY.md` with:
  - date, commit SHA, machine specs
  - per-benchmark: mean + stddev of ns/op
  - p50/p95/p99 derived via `benchstat` if available

## Task 3: CI Integration

- [ ] `scripts/ci/run-bench.sh` runs the bench, uploads result as artifact.
- [ ] Parses against `docs/performance/baseline-<latest>.md`; warns (not fails) on >20% regression.
- [ ] Add to `test-bootstrap.yml` as a non-blocking step (`continue-on-error: true`).

## Task 4: Docs

- [ ] `docs/performance/` gets a README explaining baseline philosophy, regression thresholds, how to update baselines intentionally.
- [ ] Status.md updated with what was measured + what was NOT (most hot paths — explicit v0 scope).

---

## Verification

- [ ] `go test -bench=. ./tools/bench/...` runs locally in <5min
- [ ] CI non-blocking step runs green on current tree
- [ ] `docs/performance/baseline-2026-YY.md` exists with real numbers
- [ ] `make verify-mainline` unaffected

## Out Of Scope

- Coverage for all hot paths
- Production load simulation
- Kubernetes API RTT measurement

## Suggested Branch

`sprint-30/ticket-43-performance-baseline`
