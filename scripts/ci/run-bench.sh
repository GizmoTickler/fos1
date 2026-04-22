#!/usr/bin/env bash
# run-bench.sh — run the FOS1 performance benchmark harness and
# compare median ns/op against the active baseline.
#
# v0 behaviour: never exits non-zero because of a regression. It may
# still exit non-zero if `go test` itself fails (compile error,
# panic, etc.). CI is expected to run this step with
# `continue-on-error: true` regardless.
#
# Usage:
#   scripts/ci/run-bench.sh                 # runs, writes artifact
#   BENCH_COUNT=5 scripts/ci/run-bench.sh   # fewer iterations
#   BENCH_OUT=./out.txt scripts/ci/run-bench.sh
#
# Output:
#   $BENCH_OUT (default bench-output.txt)  — raw go test output
#   $BENCH_SUMMARY (default bench-summary.md) — human summary w/ diff

set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

BENCH_COUNT="${BENCH_COUNT:-10}"
BENCH_OUT="${BENCH_OUT:-bench-output.txt}"
BENCH_SUMMARY="${BENCH_SUMMARY:-bench-summary.md}"
# Percent regression that triggers a warning (integer percent).
REGRESSION_THRESHOLD_PCT="${REGRESSION_THRESHOLD_PCT:-20}"

# Pick the lexicographically latest baseline-YYYY-MM.md. New months
# create new files; CI always compares against the most recent one.
BASELINE_FILE="$(ls -1 docs/performance/baseline-*.md 2>/dev/null | sort | tail -n 1 || true)"

echo "==> running NAT apply benchmarks"
echo "    count=$BENCH_COUNT"
echo "    raw output -> $BENCH_OUT"
echo "    summary    -> $BENCH_SUMMARY"
echo "    baseline   -> ${BASELINE_FILE:-<none>}"

# Run the bench. If the test binary fails we still want the summary
# file written so CI can upload a partial artifact for debugging.
go test -bench=. -benchmem -count="$BENCH_COUNT" -run '^$' ./tools/bench/... \
  > "$BENCH_OUT" 2>&1
bench_rc=$?

# Strip everything but the Benchmark* lines for numerical analysis.
bench_lines_file="$(mktemp)"
grep '^Benchmark' "$BENCH_OUT" > "$bench_lines_file" || true

# Extract median ns/op per benchmark name using awk. Benchmark name
# is the first field with any trailing `-N` GOMAXPROCS suffix
# stripped; the ns/op value is the field immediately before the
# literal "ns/op".
# Portable awk (no gawk multi-dim arrays): emit "<name>\t<ns/op>" per
# iteration, then group + median in a second pass.
medians_raw="$(mktemp)"
awk '
  {
    name = $1
    sub(/-[0-9]+$/, "", name)
    for (i = 1; i <= NF; i++) {
      if ($i == "ns/op") {
        printf("%s\t%s\n", name, $(i-1))
      }
    }
  }
' "$bench_lines_file" | sort > "$medians_raw"

medians_file="$(mktemp)"
awk -F '\t' '
  {
    if ($1 != cur_name && cur_name != "") {
      emit(cur_name)
      k = 0
    }
    cur_name = $1
    vals[++k] = $2 + 0
  }
  END {
    if (cur_name != "") emit(cur_name)
  }
  function emit(n,    i, j, tmp, med) {
    for (i = 1; i <= k; i++) {
      for (j = i + 1; j <= k; j++) {
        if (vals[i] > vals[j]) {
          tmp = vals[i]; vals[i] = vals[j]; vals[j] = tmp
        }
      }
    }
    if (k % 2 == 1) {
      med = vals[(k + 1) / 2]
    } else {
      med = (vals[k / 2] + vals[k / 2 + 1]) / 2
    }
    printf("%s\t%.3f\n", n, med)
    for (i = 1; i <= k; i++) delete vals[i]
  }
' "$medians_raw" | sort > "$medians_file"

# Pull baseline ns/op per benchmark from the latest baseline file.
# The baseline table uses pipe-delimited markdown; values have comma
# separators. Extract the first `NATApply_*` token and the last
# integer (with commas) on each row.
baselines_file="$(mktemp)"
if [[ -n "$BASELINE_FILE" && -f "$BASELINE_FILE" ]]; then
  awk '
    /^\| *`NATApply_/ {
      # col 1 is empty, col 2 is the benchmark name cell.
      split($0, cells, "|")
      name = cells[2]
      val  = cells[3]
      gsub(/ /, "", name); gsub(/`/, "", name)
      gsub(/[ ,]/, "", val)
      if (name != "" && val ~ /^[0-9]+$/) {
        printf("Benchmark%s\t%s\n", name, val)
      }
    }
  ' "$BASELINE_FILE" | sort > "$baselines_file"
fi

# Join medians with baselines to emit a regression report.
report_file="$(mktemp)"
if [[ -s "$baselines_file" ]]; then
  join -t $'\t' -a 1 -e "-" -o '0,1.2,2.2' "$medians_file" "$baselines_file" \
    > "$report_file"
else
  awk '{printf("%s\t%s\t-\n", $1, $2)}' "$medians_file" > "$report_file"
fi

# Flag regressions. Integer comparison (*100) to keep bash portable.
warnings_file="$(mktemp)"
: > "$warnings_file"
awk -v thresh="$REGRESSION_THRESHOLD_PCT" '
  BEGIN { FS = "\t" }
  {
    name = $1; cur = $2 + 0; base = $3
    if (base == "-" || base == "") { next }
    b = base + 0
    if (b <= 0) { next }
    pct = ((cur - b) / b) * 100.0
    if (pct > thresh) {
      printf("%s\t%.3f\t%.3f\t%.1f\n", name, cur, b, pct)
    }
  }
' "$report_file" > "$warnings_file"

# Compose the Markdown summary.
{
  echo "# NAT Apply Bench Run"
  echo
  echo "- Baseline file: \`${BASELINE_FILE:-<none>}\`"
  echo "- Iterations per benchmark (count): \`$BENCH_COUNT\`"
  echo "- Regression threshold: \`>${REGRESSION_THRESHOLD_PCT}%\` median ns/op (warning only)"
  echo "- go test exit code: \`$bench_rc\`"
  echo
  echo "## Medians vs baseline"
  echo
  echo "| Benchmark | current median ns/op | baseline ns/op | delta |"
  echo "|-----------|---------------------:|---------------:|------:|"
  awk -F '\t' '
    {
      name = $1; cur = $2; base = $3
      delta = "n/a"
      if (base != "-" && base != "" && base + 0 > 0) {
        pct = ((cur + 0) - (base + 0)) / (base + 0) * 100.0
        delta = sprintf("%+.1f%%", pct)
      }
      base_out = (base == "-" ? "n/a" : base)
      printf("| `%s` | %.0f | %s | %s |\n", name, cur + 0, base_out, delta)
    }
  ' "$report_file"
  echo
  if [[ -s "$warnings_file" ]]; then
    echo "## Warnings"
    echo
    echo "The following benchmarks exceeded the ${REGRESSION_THRESHOLD_PCT}% threshold:"
    echo
    while IFS=$'\t' read -r name cur base pct; do
      echo "- \`$name\`: ${pct}% slower (current=${cur} ns/op, baseline=${base} ns/op)"
    done < "$warnings_file"
  else
    echo "## Warnings"
    echo
    echo "No benchmarks exceeded the ${REGRESSION_THRESHOLD_PCT}% threshold."
  fi
} > "$BENCH_SUMMARY"

# Also emit GitHub Actions-style warnings so the CI log surfaces them
# without needing to open the artifact.
if [[ -s "$warnings_file" ]]; then
  while IFS=$'\t' read -r name cur base pct; do
    printf '::warning::perf regression %s %s%% slower (current=%s ns/op baseline=%s ns/op)\n' \
      "$name" "$pct" "$cur" "$base"
  done < "$warnings_file"
fi

rm -f "$bench_lines_file" "$medians_raw" "$medians_file" "$baselines_file" "$report_file" "$warnings_file"

# We intentionally do not turn regressions into a non-zero exit code.
# We do surface a real `go test` failure (compile error, panic) so CI
# can mark this step failed even with continue-on-error.
exit "$bench_rc"
