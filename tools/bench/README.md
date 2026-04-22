# tools/bench

Go benchmarks for FOS1 hot paths. See
`docs/performance/README.md` for the overall baseline philosophy and
regression policy; this README covers what this package does and how
to add a new benchmark.

## What's measured today

- `BenchmarkNATApply_SingleRule` — one DNAT port mapping per apply.
  Baseline for the minimum per-call overhead.
- `BenchmarkNATApply_HundredRules` — 100 port mappings per apply.
  Shape check for the per-rule apply loop at moderate size.
- `BenchmarkNATApply_ThousandRules` — 1,000 port mappings per apply.
  Confirms the apply loop stays linear at large size.

All three exercise `pkg/network/nat.manager.ApplyNATPolicy` with a
fake `cilium.Client` that returns `nil` for every call. That means
the numbers measure the manager's logic — validation, spec hashing,
condition bookkeeping, per-type dispatch, and the per-mapping call
loop in `applyDNAT` — not Kubernetes API RTT and not real Cilium
writes.

## How to run

Simplest form:

    go test -bench=. -benchmem ./tools/bench/...

The CI-equivalent form (what `scripts/ci/run-bench.sh` runs):

    go test -bench=. -benchmem -count=10 -run '^$' ./tools/bench/...

- `-run '^$'` skips the non-existent unit tests (the package has no
  `Test*` functions by design) and makes the invocation
  deterministic.
- `-count=10` gives `benchstat` enough samples to compute a stable
  median.
- `-benchmem` reports B/op and allocs/op.

Expected wall-clock: <5 minutes on a modern laptop. ~42s on an
Apple M3 Pro.

## How to interpret output

Raw Go bench output looks like:

    BenchmarkNATApply_SingleRule-11   517938   2318 ns/op   2624 B/op   38 allocs/op

Columns: `iterations`, `ns/op`, `bytes/op`, `allocs/op`. The
iteration count is chosen by the Go testing framework to produce a
stable measurement and is not a number to reason about directly.

To compare runs, prefer `benchstat`:

    go install golang.org/x/perf/cmd/benchstat@latest
    go test -bench=. -benchmem -count=10 -run '^$' ./tools/bench/... \
      | grep ^Benchmark > new.txt
    benchstat old.txt new.txt

## Conventions for new benchmarks

- **One package, many files.** Put each hot path's benchmark in its
  own `*_bench_test.go` file in this directory.
- **Silence `klog`.** The NAT manager (and other FOS1 packages) log
  at Info level per call; `TestMain` in `nat_apply_bench_test.go`
  wires klog to `io.Discard` for the whole package. Add any new
  logger silencing there so every benchmark benefits.
- **No shared Kubernetes fakes.** Keep any fake clients local to the
  benchmark file (like `fakeCiliumClient`). The bench package should
  not import `testing` helpers from production packages because
  those helpers can drift under us.
- **Unique keys per iteration.** The NAT manager treats `(namespace,
  name)` as a cache key and skips Cilium calls on hash-match. Use
  `fmt.Sprintf(..., i)` for the name in each iteration so the bench
  measures real apply work.
- **Update `docs/performance/baseline-YYYY-MM.md`** when adding a new
  benchmark so `run-bench.sh` has a number to compare against.

## Why only `_test.go` + `doc.go`?

Go requires at least one non-test `.go` file for a package to be
listed under `./...`. `doc.go` satisfies that with a package comment
and no runtime code, so the bench package does not ship any code to
production binaries.
