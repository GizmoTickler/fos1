# FOS1 Performance Baselines

This directory holds Go benchmark baselines for FOS1 hot paths. It
exists because `Status.md` listed "Performance Unknown (High Risk)"
under Weaknesses and there were no benchmarks in the repo. Sprint 30
Ticket 43 added the first one (NAT policy apply) and the surrounding
infrastructure. Sprint 31 Ticket 54 extended the harness to cover
three more hot paths:

- DPI event → CiliumPolicy (`pkg/security/dpi.PolicyPipeline.ProcessEvent`)
- FilterPolicy → CiliumPolicy translate (`pkg/security/policy.CiliumPolicyTranslator.TranslatePolicy`)
- Threat-intel Indicator → CiliumPolicy translate (`pkg/security/threatintel.Translator.Translate`)

Still unbenchmarked (Sprint 32 candidates): DHCP control-socket
round-trip, DNS zone update via CoreDNS / AdGuard, FRR reload /
routing sync, and any end-to-end envtest / Kind latency harness.

## Philosophy

- **One hot path at a time, measured in isolation.** Each bench
  isolates its hot path behind an in-process fake (where I/O exists)
  so the number is about the code, not Kubernetes API RTT or a real
  Cilium agent. Multi-component latency belongs in an envtest or Kind
  harness, not here.
- **Isolate the thing being measured.** Benchmarks use in-process
  fakes (e.g. `fakeCiliumClient` in `tools/bench/`) so we measure our
  code, not Kubernetes API RTT, not a real Cilium agent.
- **Numbers beat opinions.** Every change to a hot path should either
  hold the baseline or update it deliberately.
- **Non-blocking by default.** Regressions print warnings, not build
  failures. When a hot path matters enough to be blocking, we add a
  specific assertion — we do not globally fail CI on noise.

## Files

- `baseline-YYYY-MM.md` — dated baseline snapshot. Contains date,
  commit SHA, machine specs, the full `benchstat`-style summary, and
  the median ns/op values the regression check compares against. The
  latest file is the active baseline.
- `../../tools/bench/` — the Go package containing the benchmarks
  themselves.
- `../../scripts/ci/run-bench.sh` — CI wrapper that runs the bench,
  saves output as an artifact, and diffs median ns/op against the
  active baseline.
- `../../.github/workflows/ci.yml` — CI job `bench` that runs the
  wrapper with `continue-on-error: true`.

## Running the bench locally

    go test -bench=. -benchmem -count=10 -run '^$' ./tools/bench/...

Expected wall-clock: <10 minutes on a modern laptop. On an Apple M3
Pro the full 12-bench run (NAT + DPI + FilterPolicy + ThreatIntel) is
~3m 14s. The original three NAT-only benches alone still run in ~42s.

For cleaner median/variance numbers, pipe through `benchstat`:

    go install golang.org/x/perf/cmd/benchstat@latest
    go test -bench=. -benchmem -count=10 -run '^$' ./tools/bench/... | tee bench.out
    benchstat bench.out

## Reading the baseline file

Each `baseline-YYYY-MM.md` ends with a "Baseline (median ns/op)"
table. Those are the numbers `scripts/ci/run-bench.sh` compares
fresh runs against. The threshold is +20% — anything above that
prints a warning in the CI log.

## Regression threshold (v0)

- **Threshold:** 20% increase in median ns/op vs the baseline table.
- **Behaviour:** warning only. CI does not fail.
- **Rationale:** a 20% regression on a µs-scale microbench is well
  outside normal variance but still often noise on a shared runner.
  v0 treats it as "look at this", not "block the PR". When we
  dedicate a quieter runner or add multi-run medianing in CI we can
  tighten this.

## Updating a baseline intentionally

When a PR changes a hot path's performance on purpose (e.g. reworks
the apply loop, adds legitimate work, trades allocs for clarity):

1. Re-run the benchmark locally with `-count=10`.
2. Update the "Baseline (median ns/op)" table in the active
   `baseline-YYYY-MM.md` in the same PR.
3. Note why in the commit message.

If the month has rolled over, copy the existing file to
`baseline-YYYY-MM.md` for the new month and edit there; the CI
script picks the lexicographically latest `baseline-*.md`.

## Out of scope (v0)

- Coverage for every hot path. DPI event → policy, FilterPolicy
  translate, and threat-intel translate are now baselined (Ticket 54),
  alongside the original NAT apply baseline (Ticket 43). Routing sync,
  DHCP/Kea control-socket round-trip, DNS zone update, and FRR reload
  still have no baseline and are Sprint-32 candidates.
- Production load simulation. The benchmarks hammer a single in-
  process call; they do not model concurrent clients, CRD
  reconciliation storms, or Kubernetes API latency.
- Cross-machine comparison. Numbers are only directly comparable
  against other runs on the same machine/OS/Go version.
