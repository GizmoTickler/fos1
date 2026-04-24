# Sprint 31 / Ticket 54: Performance Baseline Coverage Expansion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Ticket 43 shipped a NAT apply baseline only. This ticket adds three more hot-path benchmarks: DPI event → Cilium policy, FilterPolicy translate, Threat-intel indicator → CiliumPolicy. Update `docs/performance/baseline-2026-MM.md` with the new numbers.

**Tech Stack:** Go `testing` + `testing/bench`, fake clients, `tools/bench/` extension.

**Prerequisite:** Ticket 43 merged (it is — Sprint 30).

---

## File Map

- Create: `tools/bench/dpi_policy_bench_test.go` — benchmark `pkg/security/dpi/policy_pipeline.go` hot path
- Create: `tools/bench/filterpolicy_translate_bench_test.go` — benchmark `pkg/security/policy/translator.go`
- Create: `tools/bench/threatintel_translate_bench_test.go` — benchmark `pkg/security/threatintel/translator.go`
- Modify: `tools/bench/doc.go` — expand package comment
- Modify: `scripts/ci/run-bench.sh` — run all four harnesses, not just NAT
- Create: `docs/performance/baseline-2026-04-expanded.md` (or extend existing `baseline-2026-04.md`) — new numbers for 4 total benchmarks
- Modify: `.github/workflows/test-bootstrap.yml` — the existing perf job already runs; verify it picks up the new bench files automatically
- Modify: `Status.md` §Performance: "NAT apply + DPI event + FilterPolicy translate + threat-intel translate all baselined"

## Benchmark Variants

For each of the three new paths, emit ops/s and allocs at three scales:

### DPI event → Cilium policy
- `BenchmarkDPIEventSingle` — one event through the pipeline
- `BenchmarkDPIEventBurst100` — 100 events in one reconcile
- `BenchmarkDPIEventBurst1000`

### FilterPolicy translate
- `BenchmarkFilterPolicyTranslateSingleRule`
- `BenchmarkFilterPolicyTranslateHundredRules`
- `BenchmarkFilterPolicyTranslateThousandRules`

### Threat-intel translate
- `BenchmarkThreatIntelTranslateSingleIndicator`
- `BenchmarkThreatIntelTranslateHundredIndicators`
- `BenchmarkThreatIntelTranslateThousandIndicators`

## Tasks

### Task 1: Bench Scaffolding

- [ ] For each new bench, mirror `nat_apply_bench_test.go` shape:
  - fake Cilium client that captures applied policies
  - `TestMain` silences klog (Ticket 43 convention)
  - helper functions to build synthetic input at scale

### Task 2: Run + Record

- [ ] Run `go test -bench=. -benchmem ./tools/bench/... -count=10` locally.
- [ ] Extend `docs/performance/baseline-2026-04.md` with the new tables:
  - one §per benchmark family
  - include median ns/op, p50/p95/p99 if benchstat available, B/op, allocs/op
  - note the machine specs

### Task 3: CI

- [ ] Verify `.github/workflows/test-bootstrap.yml`'s perf-baseline job runs all four (it should via `go test -bench=. ./tools/bench/...`).
- [ ] Extend `scripts/ci/run-bench.sh` regression logic to handle all four baselines.

### Task 4: Docs + Status

- [ ] `Status.md` §Performance row updated.
- [ ] `docs/performance/README.md` mentions the 4-way coverage and what's still unbenchmarked.

## Verification

- [ ] `make verify-mainline` green
- [ ] `go test -bench=. ./tools/bench/...` runs all four in under 10min
- [ ] Baseline file captures real numbers

## Out Of Scope

- DHCP control socket, DNS zone update, FRR reload — Sprint 32 candidates
- End-to-end latency under load (envtest or Kind harness)
- Memory leak detection over long-running benches

## Suggested Branch

`sprint-31/ticket-54-perf-expansion`
