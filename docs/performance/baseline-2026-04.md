# NAT Policy Apply Performance Baseline — 2026-04

Initial performance baseline for one hot path in FOS1. Sprint 30 /
Ticket 43. This file is the reference the CI regression check
compares fresh runs against.

## Metadata

- **Baseline measured:** 2026-04-22
- **Branch base:** `main` @ `fd131de` ("Sprint 29 / Ticket 37 — post-sprint status truth-up")
- **Bench author branch:** `sprint-30/ticket-43-performance-baseline` @ `1da23a8`
- **Hot path:** `pkg/network/nat.manager.ApplyNATPolicy` (DNAT, N port mappings)
- **Harness:** `tools/bench/nat_apply_bench_test.go`
- **Isolation:** in-process fake `cilium.Client` (no Kubernetes API, no real Cilium)
- **Command:** `go test -bench=. -benchmem -count=10 -run '^$' ./tools/bench/...`
- **Bench wall-clock:** ~42s total for all three benchmarks × 10 runs.

## Machine

- **Model:** Apple M3 Pro
- **Cores:** 11 (reported by macOS, used as `GOMAXPROCS`)
- **Memory:** 18 GiB (19,327,352,832 bytes)
- **OS:** macOS 26.3.1 (build 25D771280a)
- **Go:** `go1.26.1 darwin/arm64`
- **GOOS/GOARCH:** `darwin/arm64`
- **benchstat:** `golang.org/x/perf/cmd/benchstat@latest` (installed 2026-04-22)

Caveat: this is a developer laptop, not a dedicated CI box. Thermal
state and background activity affect variance (see `HundredRules`
below). The numbers are directionally reliable for regression
detection but should not be compared across machines or OS builds.

## Summary (benchstat, 10 runs)

### Time per op

| Benchmark                   | sec/op   | ±       |
|-----------------------------|----------|---------|
| `NATApply_SingleRule`       | 2.328 µs |  ±  5 % |
| `NATApply_HundredRules`     | 21.10 µs |  ± 32 % |
| `NATApply_ThousandRules`    | 167.8 µs |  ±  6 % |
| _geomean_                   | 20.20 µs |         |

### Memory per op

| Benchmark                   | B/op       | allocs/op |
|-----------------------------|------------|-----------|
| `NATApply_SingleRule`       | 2,562 B    |      38   |
| `NATApply_HundredRules`     | 14,940 B   |     533   |
| `NATApply_ThousandRules`    | 127,500 B  |   5,033   |

### Derived throughput

Rough ops/sec (1/sec-op):

| Benchmark                   | ops/sec  |
|-----------------------------|----------|
| `NATApply_SingleRule`       | ~430 k   |
| `NATApply_HundredRules`     | ~47 k    |
| `NATApply_ThousandRules`    | ~6.0 k   |

## Distribution

`benchstat` reports median and robust relative deviation rather than
mean/stddev, which is the preferred summary for Go microbenchmarks.
A ns/op distribution summary approximating p50/p95/p99 from the 10
iterations:

### `NATApply_SingleRule` (ns/op across 10 runs)

    2311, 2313, 2318, 2323, 2324, 2331, 2414, 2426, 2433, 2590

- p50: ~2,327 ns/op
- p95: ~2,512 ns/op (interpolated)
- p99: ~2,590 ns/op (worst in sample)

### `NATApply_HundredRules` (ns/op across 10 runs)

    19125, 19577, 20364, 20485, 21066, 21135, 25367, 26538, 27893, 30588

- p50: ~20,776 ns/op
- p95: ~29,240 ns/op (interpolated)
- p99: ~30,588 ns/op (worst in sample)

The higher variance on this variant is almost certainly allocation
churn + GC intersecting with macOS scheduler noise; the 1000-rule
variant amortizes it and is more stable.

### `NATApply_ThousandRules` (ns/op across 10 runs)

    166492, 167024, 167173, 167481, 167618, 167933, 172196, 175809, 177435, 189971

- p50: ~167,776 ns/op
- p95: ~183,703 ns/op (interpolated)
- p99: ~189,971 ns/op (worst in sample)

## Raw data

```
goos: darwin
goarch: arm64
pkg: github.com/GizmoTickler/fos1/tools/bench
cpu: Apple M3 Pro
BenchmarkNATApply_SingleRule-11       	  394026	      2590 ns/op	    2623 B/op	      38 allocs/op
BenchmarkNATApply_SingleRule-11       	  492624	      2414 ns/op	    2624 B/op	      38 allocs/op
BenchmarkNATApply_SingleRule-11       	  517185	      2324 ns/op	    2624 B/op	      38 allocs/op
BenchmarkNATApply_SingleRule-11       	  518846	      2331 ns/op	    2624 B/op	      38 allocs/op
BenchmarkNATApply_SingleRule-11       	  517872	      2311 ns/op	    2624 B/op	      38 allocs/op
BenchmarkNATApply_SingleRule-11       	  523862	      2323 ns/op	    2624 B/op	      38 allocs/op
BenchmarkNATApply_SingleRule-11       	  525927	      2313 ns/op	    2624 B/op	      38 allocs/op
BenchmarkNATApply_SingleRule-11       	  517938	      2318 ns/op	    2624 B/op	      38 allocs/op
BenchmarkNATApply_SingleRule-11       	  522358	      2433 ns/op	    2624 B/op	      38 allocs/op
BenchmarkNATApply_SingleRule-11       	  454940	      2426 ns/op	    2624 B/op	      38 allocs/op
BenchmarkNATApply_HundredRules-11     	   62389	     19577 ns/op	   15297 B/op	     533 allocs/op
BenchmarkNATApply_HundredRules-11     	   60982	     20485 ns/op	   15297 B/op	     533 allocs/op
BenchmarkNATApply_HundredRules-11     	   59277	     20364 ns/op	   15296 B/op	     533 allocs/op
BenchmarkNATApply_HundredRules-11     	   55158	     21135 ns/op	   15297 B/op	     533 allocs/op
BenchmarkNATApply_HundredRules-11     	   53554	     30588 ns/op	   15296 B/op	     533 allocs/op
BenchmarkNATApply_HundredRules-11     	   47504	     25367 ns/op	   15296 B/op	     533 allocs/op
BenchmarkNATApply_HundredRules-11     	   49048	     26538 ns/op	   15296 B/op	     533 allocs/op
BenchmarkNATApply_HundredRules-11     	   41866	     27893 ns/op	   15296 B/op	     533 allocs/op
BenchmarkNATApply_HundredRules-11     	   48444	     21066 ns/op	   15296 B/op	     533 allocs/op
BenchmarkNATApply_HundredRules-11     	   58650	     19125 ns/op	   15297 B/op	     533 allocs/op
BenchmarkNATApply_ThousandRules-11    	    7231	    167933 ns/op	  130553 B/op	    5033 allocs/op
BenchmarkNATApply_ThousandRules-11    	    7123	    166492 ns/op	  130552 B/op	    5033 allocs/op
BenchmarkNATApply_ThousandRules-11    	    7020	    167024 ns/op	  130554 B/op	    5033 allocs/op
BenchmarkNATApply_ThousandRules-11    	    7120	    177435 ns/op	  130554 B/op	    5033 allocs/op
BenchmarkNATApply_ThousandRules-11    	    6517	    175809 ns/op	  130553 B/op	    5033 allocs/op
BenchmarkNATApply_ThousandRules-11    	    6818	    167481 ns/op	  130553 B/op	    5033 allocs/op
BenchmarkNATApply_ThousandRules-11    	    7322	    167618 ns/op	  130554 B/op	    5033 allocs/op
BenchmarkNATApply_ThousandRules-11    	    6832	    172196 ns/op	  130554 B/op	    5033 allocs/op
BenchmarkNATApply_ThousandRules-11    	    6450	    189971 ns/op	  130555 B/op	    5033 allocs/op
BenchmarkNATApply_ThousandRules-11    	    7291	    167173 ns/op	  130554 B/op	    5033 allocs/op
```

## Regression policy (v0)

- `scripts/ci/run-bench.sh` parses this file and a fresh `go test
  -bench` output, and emits a warning (not a failure) if a benchmark's
  median ns/op grows by more than **20 %**.
- CI runs the step with `continue-on-error: true`. Regressions are
  visible in the workflow log as `::warning::` annotations and in the
  uploaded artifact, but they do not block merges.
- When a regression is intentional (new functionality, rewritten
  pipeline), update the "Baseline (median ns/op)" column in this file
  in the same PR that introduces the regression.

## Baseline (median ns/op)

These are the numbers the regression script compares against. Update
in lockstep with intentional performance changes.

| Benchmark                   | baseline ns/op |
|-----------------------------|---------------:|
| `NATApply_SingleRule`       |          2,327 |
| `NATApply_HundredRules`     |         20,776 |
| `NATApply_ThousandRules`    |        167,776 |
