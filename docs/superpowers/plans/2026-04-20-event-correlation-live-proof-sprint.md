# Event-Correlation And Live Observability Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the current observability baseline into a useful proof path by making DPI metrics reflect real events and by replacing the placeholder event-correlation runtime contract with a repo-owned correlator contract and process.

**Architecture:** Keep this sprint narrow and repository-owned. Do not try to solve the full monitoring/logging platform. Focus on two tracks: first, wire real DPI event producers into the existing metrics exporter and align dashboards/alerts to the metrics we truly emit; second, define and implement an explicit event-correlation source/sink/runtime contract that the repository can build, deploy, and test without leaning on an unspecified external image.

**Tech Stack:** Go, Kubernetes CRDs/controllers, Prometheus metrics, Grafana dashboards, Kustomize

---

## Sprint Scope

This sprint includes:

1. real DPI metric production from the current DPI manager path
2. dashboard/alert alignment to metrics that are actually emitted and scraped
3. an explicit `EventCorrelation` source/sink/runtime API contract
4. a repo-owned event-correlator runtime wired through the existing controller path

This sprint excludes:

- full Elasticsearch/Kibana retention hardening
- full Fluentd/log shipping redesign
- broad threat-intelligence datasource integration
- proving every monitoring component end to end in a live cluster

## Dependency Order

- Ticket 1 and Ticket 3 can run in parallel.
- Ticket 2 depends on Ticket 1 because alerts/dashboards should target real metric series, not guessed names.
- Ticket 4 depends on Ticket 3 because the correlator runtime needs a settled source/sink/config contract.

## Ticket 1: Wire DPI Metrics To Real Event Producers

**Owner:** Worker A

**Primary files:**
- Modify: `cmd/dpi-framework/main.go`
- Modify: `pkg/kubernetes/metrics_server.go`
- Modify: `pkg/kubernetes/dpi_types.go` only if a narrow conversion helper is needed
- Create or modify focused tests under: `pkg/kubernetes/`

**Do not touch:**
- `manifests/dashboards/**`
- `manifests/base/monitoring/**`
- `pkg/apis/security/v1alpha1/**`
- `pkg/security/ids/correlation/**`

**Problem statement:**
The metrics HTTP endpoint exists, but the current `cmd/dpi-framework` path only logs events. It does not update the Prometheus metrics in `pkg/kubernetes/metrics_server.go`, so scraping can succeed while the useful series stay empty.

**Required changes:**
- Wire the existing `RegisterEventHandler` path in `cmd/dpi-framework/main.go` to feed the metrics server.
- Use real `common.DPIEvent` values to update:
  - event counters
  - protocol connection/byte gauges when the event provides that information
  - Zeek status/log counters when the signal exists
- If conversion between `common.DPIEvent` and `kubernetes.DPIEvent` is awkward, add a narrow helper rather than duplicating mapping logic inline.
- Keep the metrics server transport/lifecycle contract from the previous sprint intact.

**Acceptance criteria:**
- A real DPI event emitted through the current manager/event-handler path changes the exported metrics.
- No metric update path depends on non-test-only simulation helpers.
- Focused tests prove that real event handling updates expected metric series.

**Verification:**
- `go test ./pkg/kubernetes/...`
- `go test ./cmd/dpi-framework ./pkg/kubernetes/... ./pkg/security/dpi/...`

## Ticket 2: Align Alerts And Dashboards To Real Owned Metrics

**Owner:** Worker B

**Primary files:**
- Modify: `manifests/base/monitoring/alert-rules.yaml`
- Modify: `manifests/base/monitoring/grafana.yaml`
- Modify: `manifests/dashboards/security-dashboard.json`
- Modify: `manifests/dashboards/network-dashboard.json`
- Modify: `manifests/dashboards/traffic-dashboard.json` only if needed
- Modify: `docs/dashboard-guide.md`

**Do not touch:**
- `pkg/**`
- `cmd/**`
- `pkg/security/ids/correlation/**`

**Problem statement:**
The monitoring manifests and dashboard guide still assume metrics and dashboards that are not actually produced or provisioned by the current repository-owned path.

**Required changes:**
- Remove or rewrite alert expressions that target series not emitted by the owned code path.
- Align security/dashboard panels to the real metric names from Ticket 1 and the existing owned NTP metrics.
- Provision Grafana dashboards through `grafana.yaml` so the in-repo dashboard JSON files are actually mounted and discoverable.
- Update `docs/dashboard-guide.md` so it describes what the repository actually provisions versus what remains aspirational.

**Acceptance criteria:**
- Alert rules reference metrics that are emitted by the current owned code path or are clearly out of scope and removed.
- Grafana manifest provisions the in-repo dashboards rather than just a datasource.
- Dashboard docs no longer imply live availability for dashboards the repo does not provision.

**Verification:**
- `kustomize build manifests/base/monitoring`
- `git diff -- manifests/base/monitoring manifests/dashboards docs/dashboard-guide.md`

## Ticket 3: Harden The EventCorrelation API And Controller Contract

**Owner:** Worker C

**Primary files:**
- Modify: `pkg/apis/security/v1alpha1/types.go`
- Modify: `manifests/base/security/ids/crds/eventcorrelation.yaml`
- Modify: `manifests/examples/security/ids/event-correlation.yaml`
- Modify: `pkg/security/ids/correlation/controller.go`
- Modify: `pkg/security/ids/correlation/controller_test.go`
- Modify: `docs/observability-architecture.md`

**Do not touch:**
- `cmd/dpi-framework/**`
- `manifests/base/monitoring/**`
- `manifests/dashboards/**`

**Problem statement:**
`EventCorrelation` currently has no explicit source or sink contract, the CRD phase enum disagrees with controller behavior (`Disabled`), and `generateRulesConfig()` hand-builds JSON in a fragile way.

**Required changes:**
- Extend `EventCorrelationSpec` with an explicit minimal source/sink contract that the repository can actually own.
- Keep the contract deliberately small. Recommended baseline:
  - file-based JSON-line event source
  - file/stdout JSON output sink
- Make the CRD schema match controller behavior for phase/status semantics.
- Replace hand-built JSON config generation with structured marshaling.
- Update the example CR and observability doc to match the new contract.

**Acceptance criteria:**
- The API can express where the correlator reads events from and where it writes correlated output.
- Controller-generated config is structurally marshaled, not string-concatenated.
- CRD schema and controller status behavior no longer disagree on allowed phases.
- Tests cover the new config generation and any changed status expectations.

**Verification:**
- `go test ./pkg/security/ids/correlation/... ./pkg/apis/security/...`
- `kustomize build manifests/base/security/ids`

## Ticket 4: Add A Repo-Owned Event-Correlator Runtime And Wire It Through The Controller Path

**Owner:** Worker D

**Primary files:**
- Create: `cmd/event-correlator/main.go`
- Create supporting runtime files under: `pkg/security/ids/correlation/`
- Modify: `pkg/security/ids/correlation/controller.go`
- Modify: `pkg/security/ids/correlation/controller_test.go`
- Modify manifests/examples only if needed for the owned runtime contract

**Do not touch:**
- `manifests/base/monitoring/**`
- `manifests/dashboards/**`
- `.github/workflows/**`

**Problem statement:**
The controller deploys `fos1/event-correlator:latest` and assumes `/usr/bin/event-correlator`, but no repo-owned correlator runtime exists.

**Required changes:**
- Implement a minimal repo-owned correlator binary that:
  - reads the controller-generated config
  - tails or reads JSON-line events from the configured file source
  - applies rule matching/threshold/time-window logic
  - writes correlated output to the configured sink
  - exposes `/health` and `/ready`
- Keep the owned baseline intentionally simple and testable. Do not build full threat-intel or distributed streaming in this sprint.
- Update the controller deployment contract only as needed to reflect the real binary/config expectations.

**Acceptance criteria:**
- The repo contains a buildable event-correlator command.
- The runtime can process representative JSON events and emit correlated output through the owned sink contract.
- Controller tests and runtime-focused tests cover the owned path well enough to stop depending on an unspecified external binary contract.

**Verification:**
- `go test ./cmd/event-correlator ./pkg/security/ids/correlation/...`
- `make verify-mainline`

## Dispatch Plan

Start with:

1. Worker A on Ticket 1
2. Worker C on Ticket 3

After those land and are reviewed:

3. Worker B on Ticket 2
4. Worker D on Ticket 4

## Review Notes For All Workers

- Do not broaden scope beyond the ticket.
- Do not edit files owned by another active ticket.
- If a ticket exposes a contradiction in the plan, stop and report it rather than guessing.
- Run the smallest relevant verification for the owned files before handing back changes.
