# prometheus-query-validator

A CI guardrail that keeps Grafana dashboards and Prometheus alert rules honest
against the metrics the repository actually emits.

The tool walks:

- every Grafana dashboard JSON under `manifests/dashboards/*.json`
- the Prometheus alert-rules ConfigMap at `manifests/base/monitoring/alert-rules.yaml`

extracts every PromQL expression, runs each one through a live Prometheus
`/api/v1/query`, and classifies the outcome:

| Classification | Meaning                                                    |
|----------------|------------------------------------------------------------|
| `resolved`     | The expression returned at least one series.               |
| `empty`        | Valid PromQL, but no series matched.                       |
| `error`        | Prometheus rejected the expression (syntax or evaluation). |
| `allowlisted`  | Expression is in the target-architecture allowlist.        |

A non-allowlisted `empty` or `error` result fails the run (exit code 1). Use
that to gate CI so a dashboard panel or alert rule can't silently reference a
metric no owned exporter produces.

## Usage

```
go run ./tools/prometheus-query-validator \
    -prometheus-url http://127.0.0.1:19090 \
    -allowlist manifests/dashboards/.queries-target-architecture.txt \
    -dashboards manifests/dashboards \
    -alert-rules manifests/base/monitoring/alert-rules.yaml
```

Flags accept either a single file or a directory. Directories are scanned
non-recursively. `-dashboards` and `-alert-rules` may be repeated or
comma-separated.

Add `-format json` for a machine-readable report.

### Running against the Kind proof cluster

In CI the Kind harness port-forwards Prometheus to `127.0.0.1:19090` (see
`scripts/ci/prove-prometheus-scrapes.sh` for the canonical port). Re-use the
same port-forward:

```
kubectl port-forward -n monitoring service/prometheus 19090:9090 &
go run ./tools/prometheus-query-validator \
    -prometheus-url http://127.0.0.1:19090 \
    -allowlist manifests/dashboards/.queries-target-architecture.txt \
    -dashboards manifests/dashboards \
    -alert-rules manifests/base/monitoring/alert-rules.yaml
```

## Classifying A New Expression

When the validator reports `empty` or `error` for an expression that isn't
yet allowlisted, pick one of three responses:

1. **Owned, missing exporter.** The metric should come from an owned
   exporter (`pkg/kubernetes/metrics_server.go` for DPI, `pkg/ntp/metrics/exporter.go`
   for NTP, or a new exporter you plan to add). Wire the metric in, re-run,
   and check that it now resolves.
2. **Owned, dead panel / alert.** The metric does not belong here; delete
   the panel or alert rule.
3. **Target-architecture only.** The metric comes from an exporter this
   repo does not own (for example node-exporter, kube-state-metrics,
   cAdvisor). Copy the exact PromQL expression into
   `manifests/dashboards/.queries-target-architecture.txt` and add a `# why:`
   comment in the surrounding block explaining which exporter it lands on.

`error` classifications should generally not reach the allowlist. Fix the
syntax, or delete the panel/alert rule, before falling back to allowlisting.

## Files

- `main.go` — CLI entry point: flag parsing, file expansion, report printing
- `extractor.go` — dashboard JSON and alert-rule YAML parsers
- `allowlist.go` — allowlist file loader (`# comments`, blank lines ignored)
- `validator.go` — PromQL client + classifier
- `testdata/` — fixtures used by unit tests
- `*_test.go` — unit tests (extractor, validator, allowlist, and one
  end-to-end test against a fake Prometheus)

## Tests

```
go test ./tools/prometheus-query-validator/...
```

The `integration_test.go` target exercises the real dashboards and alert
rules against a fake Prometheus that resolves every non-allowlisted
expression. If it fails, either the extractor missed something or the
allowlist is out of sync with a newly-landed dashboard panel.
