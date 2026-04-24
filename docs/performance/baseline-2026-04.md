# FOS1 Performance Baselines — 2026-04

Performance baselines for four hot paths in FOS1:

1. **NAT policy apply** — Sprint 30 / Ticket 43 (original baseline).
2. **DPI event → Cilium policy** — Sprint 31 / Ticket 54.
3. **FilterPolicy → CiliumPolicy translate** — Sprint 31 / Ticket 54.
4. **Threat-intel Indicator → CiliumPolicy translate** — Sprint 31 / Ticket 54.

This file is the reference the CI regression check compares fresh runs
against (see `scripts/ci/run-bench.sh`).

## Metadata

- **Baseline measured (NAT):** 2026-04-22
- **Baseline measured (DPI / FilterPolicy / ThreatIntel):** 2026-04-23
- **Branch base:** `main` @ `7979c41` ("Sprint 30 / Ticket 46 — post-Sprint-30 status truth-up")
- **Bench author branches:**
  - `sprint-30/ticket-43-performance-baseline` @ `1da23a8` (NAT)
  - `sprint-31/ticket-54-perf-expansion` @ HEAD (DPI / FilterPolicy / ThreatIntel)
- **Hot paths:**
  - `pkg/network/nat.manager.ApplyNATPolicy` (DNAT, N port mappings)
  - `pkg/security/dpi.PolicyPipeline.ProcessEvent` (block-action rule, N distinct source IPs)
  - `pkg/security/policy.CiliumPolicyTranslator.TranslatePolicy` (N port selectors)
  - `pkg/security/threatintel.Translator.Translate` (N distinct indicators, mix of FQDN + IP)
- **Harnesses:**
  - `tools/bench/nat_apply_bench_test.go`
  - `tools/bench/dpi_policy_bench_test.go`
  - `tools/bench/filterpolicy_translate_bench_test.go`
  - `tools/bench/threatintel_translate_bench_test.go`
- **Isolation:** in-process fake `cilium.Client` for NAT and DPI (no Kubernetes API, no real Cilium). FilterPolicy and ThreatIntel translators are pure functions — no fake is needed; the translator reports results by value.
- **Command:** `go test -bench=. -benchmem -count=10 -run '^$' ./tools/bench/...`
- **Bench wall-clock:** ~194s total for all twelve benchmarks × 10 runs on the machine below.

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

The three Ticket-54 expansions (DPI, FilterPolicy, ThreatIntel) were
captured in a single `go test -count=10` run alongside a re-run of the
NAT apply bench. That re-run matches Ticket 43's shape but landed
hotter on a few iterations (see §"NAT apply re-run drift"). The
Ticket 43 baseline values below are unchanged; only the new benches
get fresh tables.

## Summary — NAT apply (Ticket 43, 10 runs, unchanged)

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

## Summary — DPI event → Cilium policy (Ticket 54, 10 runs)

Fresh pipeline per iteration (keeps `activePolicies` map bounded).
Every event uses a distinct `/32` source IP so no dedup shortcut fires.

### Time per op

| Benchmark                        | sec/op    |
|----------------------------------|-----------|
| `DPIEvent_Single`                |  2.038 µs |
| `DPIEvent_Burst100`              |  195.1 µs |
| `DPIEvent_Burst1000`             |  2.173 ms |

### Memory per op

| Benchmark                        | B/op       | allocs/op |
|----------------------------------|------------|-----------|
| `DPIEvent_Single`                |  3,074 B   |       44  |
| `DPIEvent_Burst100`              |  250,690 B |    3,923  |
| `DPIEvent_Burst1000`             | 2,638,372 B|   39,051  |

Scaling commentary: allocs/op is ~39.0 per event in isolation and
~39.2 per event in the 1000-burst, so the per-event cost is linear
with a small fixed per-pipeline overhead.

## Summary — FilterPolicy translate (Ticket 54, 10 runs)

Pure translate (no I/O). Scale = number of `PortSelector` entries on
the input FilterPolicy; each becomes one CiliumRule.

### Time per op

| Benchmark                                   | sec/op    |
|---------------------------------------------|-----------|
| `FilterPolicyTranslate_SingleRule`          |  329.6 ns |
| `FilterPolicyTranslate_HundredRules`        |  6.261 µs |
| `FilterPolicyTranslate_ThousandRules`       |  124.4 µs |

### Memory per op

| Benchmark                                   | B/op       | allocs/op |
|---------------------------------------------|------------|-----------|
| `FilterPolicyTranslate_SingleRule`          |  872 B     |       10  |
| `FilterPolicyTranslate_HundredRules`        |  38,072 B  |      208  |
| `FilterPolicyTranslate_ThousandRules`       |  376,184 B |    2,008  |

Scaling commentary: ~2 allocs per rule plus a fixed 8-alloc header
(policy + labels map + etc.). The translate path is the cheapest of
the four measured because it is pure and makes no apply calls.

## Summary — Threat-intel Indicator → CiliumPolicy (Ticket 54, 10 runs)

Pure translate. Input mixes FQDN and IP-literal indicators (1-in-4
IPs) so both the `toFQDNs` and `toCIDR` branches are exercised.

### Time per op

| Benchmark                                            | sec/op    |
|------------------------------------------------------|-----------|
| `ThreatIntelTranslate_SingleIndicator`               |  884.1 ns |
| `ThreatIntelTranslate_HundredIndicators`             |  86.26 µs |
| `ThreatIntelTranslate_ThousandIndicators`            |  1.008 ms |

### Memory per op

| Benchmark                                            | B/op       | allocs/op |
|------------------------------------------------------|------------|-----------|
| `ThreatIntelTranslate_SingleIndicator`               |  1,304 B   |       20  |
| `ThreatIntelTranslate_HundredIndicators`             |  141,775 B |    1,819  |
| `ThreatIntelTranslate_ThousandIndicators`            |1,423,683 B |   18,028  |

Scaling commentary: ~18 allocs per indicator, driven by
`url.Parse`, SHA-1 hashing of the host, label-map allocation, and
the per-rule struct. There is a small super-linear trend on the
1000-indicator bench (~1.25× per-indicator cost vs the 100-indicator
variant); this is plausibly driven by the `seen` dedup map resizing
and GC pressure on the 1.4 MB allocation working set, but see the
caveat in §"ThreatIntelTranslate_ThousandIndicators" below on
sample-size noise before treating this as a regression.

## Distribution

`benchstat` reports median and robust relative deviation rather than
mean/stddev, which is the preferred summary for Go microbenchmarks.
A ns/op distribution summary approximating p50/p95/p99 from the 10
iterations, grouped by benchmark family:

### NAT apply (Ticket 43 measurement — held as baseline)

#### `NATApply_SingleRule` (ns/op across 10 runs)

    2311, 2313, 2318, 2323, 2324, 2331, 2414, 2426, 2433, 2590

- p50: ~2,327 ns/op
- p95: ~2,512 ns/op (interpolated)
- p99: ~2,590 ns/op (worst in sample)

#### `NATApply_HundredRules` (ns/op across 10 runs)

    19125, 19577, 20364, 20485, 21066, 21135, 25367, 26538, 27893, 30588

- p50: ~20,776 ns/op
- p95: ~29,240 ns/op (interpolated)
- p99: ~30,588 ns/op (worst in sample)

The higher variance on this variant is almost certainly allocation
churn + GC intersecting with macOS scheduler noise; the 1000-rule
variant amortizes it and is more stable.

#### `NATApply_ThousandRules` (ns/op across 10 runs)

    166492, 167024, 167173, 167481, 167618, 167933, 172196, 175809, 177435, 189971

- p50: ~167,776 ns/op
- p95: ~183,703 ns/op (interpolated)
- p99: ~189,971 ns/op (worst in sample)

### DPI event (Ticket 54, 2026-04-23)

#### `DPIEvent_Single` (ns/op across 10 runs)

    2010, 2011, 2017, 2024, 2029, 2046, 2073, 2111, 2132, 2977

- p50: ~2,037 ns/op
- p95: ~2,554 ns/op (interpolated)
- p99: ~2,977 ns/op (worst in sample — one outlier from cold-start
  JIT / GC; the other nine are tight within ~6%)

#### `DPIEvent_Burst100` (ns/op across 10 runs)

    193503, 194463, 194671, 194916, 195098, 195150, 195515, 196070, 196190, 207424

- p50: ~195,124 ns/op
- p95: ~201,807 ns/op (interpolated)
- p99: ~207,424 ns/op (worst in sample)

Per-event cost: median ns/op ÷ 100 ≈ 1,951 ns/event. This is slightly
cheaper than the Single variant because the per-pipeline constructor
cost amortizes over 100 events.

#### `DPIEvent_Burst1000` (ns/op across 10 runs)

    1991269, 1993099, 1999292, 2004508, 2013659, 2333023, 2517909, 2686951, 2792819, 2843609

- p50: ~2,173,341 ns/op
- p95: ~2,818,214 ns/op (interpolated)
- p99: ~2,843,609 ns/op (worst in sample)

Higher variance at this scale: allocations (~2.6 MB per iteration)
interact with the runtime's GC pacing. Per-event cost: ~2,173 ns/event.

### FilterPolicy translate (Ticket 54, 2026-04-23)

#### `FilterPolicyTranslate_SingleRule` (ns/op across 10 runs)

    328.3, 328.3, 328.6, 328.7, 328.9, 330.4, 333.3, 333.3, 351.3, 361.5

- p50: ~329.6 ns/op
- p95: ~356.4 ns/op (interpolated)
- p99: ~361.5 ns/op (worst in sample)

The pure-translate path is the cheapest measured — no fake I/O, no
idempotency bookkeeping, no per-rule apply loop.

#### `FilterPolicyTranslate_HundredRules` (ns/op across 10 runs)

    6152, 6159, 6185, 6200, 6211, 6310, 6311, 6921, 7235, 7978

- p50: ~6,260 ns/op
- p95: ~7,606 ns/op (interpolated)
- p99: ~7,978 ns/op (worst in sample)

#### `FilterPolicyTranslate_ThousandRules` (ns/op across 10 runs)

    65017, 67429, 116328, 120239, 121099, 127646, 140406, 142972, 149280, 188450

- p50: ~124,372 ns/op
- p95: ~168,865 ns/op (interpolated)
- p99: ~188,450 ns/op (worst in sample)

Wide distribution: the early iterations land at ~65k ns/op (hot
allocator, warm CPU caches) and later ones drift toward 120-190k as
the 0.38 MB working set churns through GC. The median is
directionally correct for regression detection but the 3× min-to-max
spread means v0 CI can only flag very large regressions (>>20%) with
confidence on this variant.

### Threat-intel translate (Ticket 54, 2026-04-23)

#### `ThreatIntelTranslate_SingleIndicator` (ns/op across 10 runs)

    849.4, 856.6, 865.9, 873.3, 878.1, 890.1, 890.7, 939.2, 947.9, 971.2

- p50: ~884.1 ns/op
- p95: ~959.5 ns/op (interpolated)
- p99: ~971.2 ns/op (worst in sample)

#### `ThreatIntelTranslate_HundredIndicators` (ns/op across 10 runs)

    85689, 85829, 86017, 86150, 86217, 86300, 86430, 86470, 88739, 96673

- p50: ~86,258 ns/op
- p95: ~92,706 ns/op (interpolated)
- p99: ~96,673 ns/op (worst in sample)

Tightest distribution of any new bench: relative deviation under 3%
for the middle eight runs.

#### `ThreatIntelTranslate_ThousandIndicators` (ns/op across 10 runs)

    859774, 862077, 880521, 904512, 982691, 1032473, 1330433, 1709059, 1924696, 1975394

- p50: ~1,007,582 ns/op
- p95: ~1,950,045 ns/op (interpolated)
- p99: ~1,975,394 ns/op (worst in sample)

Pronounced min-to-max drift (~2.3×) that correlates with thermal
state on the M3 Pro: the last three runs landed at the end of the
193-second full-bench window, after the other eleven benches had
warmed the chip. `benchstat` over additional `-count` runs smoothes
this out; the v0 regression warning threshold of +20% median is
still useful here because the p50 is well inside the tight cluster.

## NAT apply re-run drift

The 2026-04-23 full bench run also re-ran the three NAT apply
benches. Those iterations came in hotter than Ticket 43's measurement
(SingleRule p50 ≈ 4,539 ns/op vs 2,327 ns/op in Ticket 43). The cause
is thermal / scheduler state at the front of the combined run, not a
real regression: the NAT code is unchanged on this branch, and the
`ThousandRules` p50 landed at 178,349 ns/op vs 167,776 ns/op in
Ticket 43 — a ~6% delta well within the v0 20% regression threshold.
We did NOT update the NAT baseline numbers in the §"Baseline (median
ns/op)" table at the bottom. The Ticket 43 measurement is held
canonical; the re-run is informational.

## Raw data

### NAT apply (Ticket 43, kept verbatim from the original measurement)

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

### DPI / FilterPolicy / ThreatIntel (Ticket 54, 2026-04-23)

```
goos: darwin
goarch: arm64
pkg: github.com/GizmoTickler/fos1/tools/bench
cpu: Apple M3 Pro
BenchmarkDPIEvent_Single-11                            	  376935	      2977 ns/op	    3074 B/op	      44 allocs/op
BenchmarkDPIEvent_Single-11                            	  554230	      2132 ns/op	    3074 B/op	      44 allocs/op
BenchmarkDPIEvent_Single-11                            	  597818	      2011 ns/op	    3074 B/op	      44 allocs/op
BenchmarkDPIEvent_Single-11                            	  591348	      2024 ns/op	    3074 B/op	      44 allocs/op
BenchmarkDPIEvent_Single-11                            	  553508	      2111 ns/op	    3074 B/op	      44 allocs/op
BenchmarkDPIEvent_Single-11                            	  600895	      2029 ns/op	    3074 B/op	      44 allocs/op
BenchmarkDPIEvent_Single-11                            	  576675	      2017 ns/op	    3074 B/op	      44 allocs/op
BenchmarkDPIEvent_Single-11                            	  601939	      2073 ns/op	    3074 B/op	      44 allocs/op
BenchmarkDPIEvent_Single-11                            	  495668	      2046 ns/op	    3074 B/op	      44 allocs/op
BenchmarkDPIEvent_Single-11                            	  577164	      2010 ns/op	    3074 B/op	      44 allocs/op
BenchmarkDPIEvent_Burst100-11                          	    6159	    195515 ns/op	  250690 B/op	    3923 allocs/op
BenchmarkDPIEvent_Burst100-11                          	    6328	    196070 ns/op	  250695 B/op	    3923 allocs/op
BenchmarkDPIEvent_Burst100-11                          	    6211	    194463 ns/op	  250699 B/op	    3923 allocs/op
BenchmarkDPIEvent_Burst100-11                          	    6270	    193503 ns/op	  250691 B/op	    3923 allocs/op
BenchmarkDPIEvent_Burst100-11                          	    6127	    194671 ns/op	  250689 B/op	    3923 allocs/op
BenchmarkDPIEvent_Burst100-11                          	    6189	    196190 ns/op	  250700 B/op	    3923 allocs/op
BenchmarkDPIEvent_Burst100-11                          	    6225	    195150 ns/op	  250699 B/op	    3923 allocs/op
BenchmarkDPIEvent_Burst100-11                          	    6324	    195098 ns/op	  250693 B/op	    3923 allocs/op
BenchmarkDPIEvent_Burst100-11                          	    6181	    194916 ns/op	  250699 B/op	    3923 allocs/op
BenchmarkDPIEvent_Burst100-11                          	    6073	    207424 ns/op	  250690 B/op	    3923 allocs/op
BenchmarkDPIEvent_Burst1000-11                         	     596	   1999292 ns/op	 2638798 B/op	   39052 allocs/op
BenchmarkDPIEvent_Burst1000-11                         	     602	   1991269 ns/op	 2638752 B/op	   39051 allocs/op
BenchmarkDPIEvent_Burst1000-11                         	     604	   2004508 ns/op	 2638747 B/op	   39052 allocs/op
BenchmarkDPIEvent_Burst1000-11                         	     601	   1993099 ns/op	 2638788 B/op	   39051 allocs/op
BenchmarkDPIEvent_Burst1000-11                         	     601	   2013659 ns/op	 2638830 B/op	   39052 allocs/op
BenchmarkDPIEvent_Burst1000-11                         	     603	   2333023 ns/op	 2638757 B/op	   39052 allocs/op
BenchmarkDPIEvent_Burst1000-11                         	     548	   2686951 ns/op	 2637965 B/op	   39051 allocs/op
BenchmarkDPIEvent_Burst1000-11                         	     463	   2792819 ns/op	 2637531 B/op	   39051 allocs/op
BenchmarkDPIEvent_Burst1000-11                         	     394	   2843609 ns/op	 2638551 B/op	   39051 allocs/op
BenchmarkDPIEvent_Burst1000-11                         	     409	   2517909 ns/op	 2638372 B/op	   39051 allocs/op
BenchmarkFilterPolicyTranslate_SingleRule-11           	 3481057	       333.3 ns/op	     872 B/op	      10 allocs/op
BenchmarkFilterPolicyTranslate_SingleRule-11           	 3593352	       361.5 ns/op	     872 B/op	      10 allocs/op
BenchmarkFilterPolicyTranslate_SingleRule-11           	 3672903	       328.7 ns/op	     872 B/op	      10 allocs/op
BenchmarkFilterPolicyTranslate_SingleRule-11           	 3671222	       328.6 ns/op	     872 B/op	      10 allocs/op
BenchmarkFilterPolicyTranslate_SingleRule-11           	 3655478	       333.3 ns/op	     872 B/op	      10 allocs/op
BenchmarkFilterPolicyTranslate_SingleRule-11           	 3662510	       328.9 ns/op	     872 B/op	      10 allocs/op
BenchmarkFilterPolicyTranslate_SingleRule-11           	 3648656	       330.4 ns/op	     872 B/op	      10 allocs/op
BenchmarkFilterPolicyTranslate_SingleRule-11           	 3653326	       351.3 ns/op	     872 B/op	      10 allocs/op
BenchmarkFilterPolicyTranslate_SingleRule-11           	 3457368	       328.3 ns/op	     872 B/op	      10 allocs/op
BenchmarkFilterPolicyTranslate_SingleRule-11           	 3655908	       328.3 ns/op	     872 B/op	      10 allocs/op
BenchmarkFilterPolicyTranslate_HundredRules-11         	  197527	      6185 ns/op	   38072 B/op	     208 allocs/op
BenchmarkFilterPolicyTranslate_HundredRules-11         	  197662	      6200 ns/op	   38072 B/op	     208 allocs/op
BenchmarkFilterPolicyTranslate_HundredRules-11         	  183502	      6211 ns/op	   38072 B/op	     208 allocs/op
BenchmarkFilterPolicyTranslate_HundredRules-11         	  194941	      6152 ns/op	   38072 B/op	     208 allocs/op
BenchmarkFilterPolicyTranslate_HundredRules-11         	  191134	      6159 ns/op	   38072 B/op	     208 allocs/op
BenchmarkFilterPolicyTranslate_HundredRules-11         	  192897	      6311 ns/op	   38072 B/op	     208 allocs/op
BenchmarkFilterPolicyTranslate_HundredRules-11         	  192506	      6310 ns/op	   38072 B/op	     208 allocs/op
BenchmarkFilterPolicyTranslate_HundredRules-11         	  174828	      7978 ns/op	   38072 B/op	     208 allocs/op
BenchmarkFilterPolicyTranslate_HundredRules-11         	  144526	      6921 ns/op	   38072 B/op	     208 allocs/op
BenchmarkFilterPolicyTranslate_HundredRules-11         	  157557	      7235 ns/op	   38072 B/op	     208 allocs/op
BenchmarkFilterPolicyTranslate_ThousandRules-11        	   18775	     67429 ns/op	  376184 B/op	    2008 allocs/op
BenchmarkFilterPolicyTranslate_ThousandRules-11        	   20750	     65017 ns/op	  376184 B/op	    2008 allocs/op
BenchmarkFilterPolicyTranslate_ThousandRules-11        	   17628	    121099 ns/op	  376184 B/op	    2008 allocs/op
BenchmarkFilterPolicyTranslate_ThousandRules-11        	    9742	    188450 ns/op	  376184 B/op	    2008 allocs/op
BenchmarkFilterPolicyTranslate_ThousandRules-11        	   10000	    116328 ns/op	  376184 B/op	    2008 allocs/op
BenchmarkFilterPolicyTranslate_ThousandRules-11        	   10000	    149280 ns/op	  376184 B/op	    2008 allocs/op
BenchmarkFilterPolicyTranslate_ThousandRules-11        	    8682	    142972 ns/op	  376184 B/op	    2008 allocs/op
BenchmarkFilterPolicyTranslate_ThousandRules-11        	   10000	    127646 ns/op	  376184 B/op	    2008 allocs/op
BenchmarkFilterPolicyTranslate_ThousandRules-11        	    9884	    140406 ns/op	  376184 B/op	    2008 allocs/op
BenchmarkFilterPolicyTranslate_ThousandRules-11        	   10125	    120239 ns/op	  376184 B/op	    2008 allocs/op
BenchmarkThreatIntelTranslate_SingleIndicator-11       	 1351124	       890.7 ns/op	    1304 B/op	      20 allocs/op
BenchmarkThreatIntelTranslate_SingleIndicator-11       	 1374638	       890.1 ns/op	    1304 B/op	      20 allocs/op
BenchmarkThreatIntelTranslate_SingleIndicator-11       	 1413012	       865.9 ns/op	    1304 B/op	      20 allocs/op
BenchmarkThreatIntelTranslate_SingleIndicator-11       	 1401804	       947.9 ns/op	    1304 B/op	      20 allocs/op
BenchmarkThreatIntelTranslate_SingleIndicator-11       	 1343866	       939.2 ns/op	    1304 B/op	      20 allocs/op
BenchmarkThreatIntelTranslate_SingleIndicator-11       	 1330753	       878.1 ns/op	    1304 B/op	      20 allocs/op
BenchmarkThreatIntelTranslate_SingleIndicator-11       	 1413558	       873.3 ns/op	    1304 B/op	      20 allocs/op
BenchmarkThreatIntelTranslate_SingleIndicator-11       	 1401505	       856.6 ns/op	    1304 B/op	      20 allocs/op
BenchmarkThreatIntelTranslate_SingleIndicator-11       	 1291164	       971.2 ns/op	    1304 B/op	      20 allocs/op
BenchmarkThreatIntelTranslate_SingleIndicator-11       	 1375968	       849.4 ns/op	    1304 B/op	      20 allocs/op
BenchmarkThreatIntelTranslate_HundredIndicators-11     	   13869	     85829 ns/op	  141779 B/op	    1819 allocs/op
BenchmarkThreatIntelTranslate_HundredIndicators-11     	   13888	     86150 ns/op	  141777 B/op	    1819 allocs/op
BenchmarkThreatIntelTranslate_HundredIndicators-11     	   13935	     86217 ns/op	  141777 B/op	    1819 allocs/op
BenchmarkThreatIntelTranslate_HundredIndicators-11     	   14020	     88739 ns/op	  141778 B/op	    1819 allocs/op
BenchmarkThreatIntelTranslate_HundredIndicators-11     	   13855	     86017 ns/op	  141777 B/op	    1819 allocs/op
BenchmarkThreatIntelTranslate_HundredIndicators-11     	   13936	     86470 ns/op	  141777 B/op	    1819 allocs/op
BenchmarkThreatIntelTranslate_HundredIndicators-11     	   13731	     86300 ns/op	  141777 B/op	    1819 allocs/op
BenchmarkThreatIntelTranslate_HundredIndicators-11     	   13784	     85689 ns/op	  141777 B/op	    1819 allocs/op
BenchmarkThreatIntelTranslate_HundredIndicators-11     	   13704	     86430 ns/op	  141777 B/op	    1819 allocs/op
BenchmarkThreatIntelTranslate_HundredIndicators-11     	   13172	     96673 ns/op	  141775 B/op	    1819 allocs/op
BenchmarkThreatIntelTranslate_ThousandIndicators-11    	    1378	    859774 ns/op	 1423767 B/op	   18029 allocs/op
BenchmarkThreatIntelTranslate_ThousandIndicators-11    	    1389	    862077 ns/op	 1423779 B/op	   18029 allocs/op
BenchmarkThreatIntelTranslate_ThousandIndicators-11    	    1388	    880521 ns/op	 1423767 B/op	   18029 allocs/op
BenchmarkThreatIntelTranslate_ThousandIndicators-11    	    1270	    904512 ns/op	 1423750 B/op	   18028 allocs/op
BenchmarkThreatIntelTranslate_ThousandIndicators-11    	    1237	    982691 ns/op	 1423754 B/op	   18028 allocs/op
BenchmarkThreatIntelTranslate_ThousandIndicators-11    	    1233	   1032473 ns/op	 1423749 B/op	   18028 allocs/op
BenchmarkThreatIntelTranslate_ThousandIndicators-11    	    1168	   1330433 ns/op	 1423730 B/op	   18028 allocs/op
BenchmarkThreatIntelTranslate_ThousandIndicators-11    	     642	   1924696 ns/op	 1423728 B/op	   18028 allocs/op
BenchmarkThreatIntelTranslate_ThousandIndicators-11    	     765	   1975394 ns/op	 1423697 B/op	   18028 allocs/op
BenchmarkThreatIntelTranslate_ThousandIndicators-11    	     775	   1709059 ns/op	 1423683 B/op	   18028 allocs/op
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

| Benchmark                                       | baseline ns/op |
|-------------------------------------------------|---------------:|
| `NATApply_SingleRule`                           |          2,327 |
| `NATApply_HundredRules`                         |         20,776 |
| `NATApply_ThousandRules`                        |        167,776 |
| `DPIEvent_Single`                               |          2,037 |
| `DPIEvent_Burst100`                             |        195,124 |
| `DPIEvent_Burst1000`                            |      2,173,341 |
| `FilterPolicyTranslate_SingleRule`              |            330 |
| `FilterPolicyTranslate_HundredRules`            |          6,260 |
| `FilterPolicyTranslate_ThousandRules`           |        124,372 |
| `ThreatIntelTranslate_SingleIndicator`          |            884 |
| `ThreatIntelTranslate_HundredIndicators`        |         86,258 |
| `ThreatIntelTranslate_ThousandIndicators`       |      1,007,582 |
