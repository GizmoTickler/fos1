# Sprint 29 / Ticket 32: Validate Dashboard And Alert-Rule Queries Against Live Series

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a CI validator that extracts every PromQL expression from the owned Grafana dashboards and Prometheus alert rules, runs each against the Kind Prometheus, and either confirms a series exists or fails the check. For each failing expression, either wire the missing metric into an owned exporter, delete the panel/alert, or move the reference to a clearly labelled "target architecture only" section.

**Architecture:** Python or Go validator that walks `manifests/dashboards/*.json` + `manifests/base/monitoring/alert-rules.yaml`, extracts PromQL, queries Prometheus `/api/v1/query`, and reports missing series with their source path. Runs as a new step in `.github/workflows/test-bootstrap.yml`.

**Tech Stack:** Go (preferred — matches repo), PromQL, Prometheus HTTP API, shell scripts, GitHub Actions.

**Prerequisite:** Ticket 29 lands first so Prometheus has baseline DPI/NTP targets reporting.

---

## Context

Current state:
- `manifests/dashboards/*.json` — network, security, traffic dashboards (3 files, large JSON bodies)
- `manifests/base/monitoring/alert-rules.yaml` — Prometheus alert rules
- Neither is validated against what owned exporters actually emit
- Risk: dashboards show "No data" in production because they reference metrics no owned exporter produces, and alerts never fire because the PromQL expression evaluates to an empty series

Owned exporters emitting live series today:
- DPI manager `:8080/metrics` (`pkg/kubernetes/metrics_server.go`)
- NTP controller `:9559/metrics` (`pkg/ntp/metrics/exporter.go`)
- Kubernetes / kube-state-metrics (standard)
- Node exporter (standard)

The validator must distinguish:
- **owned** expressions (must resolve) — fail CI if they don't
- **target-architecture** expressions (aspirational) — moved into a clearly-labelled section and skipped

---

## File Map

- Create: `tools/prometheus-query-validator/main.go`
  - Go tool: read dashboard JSON + alert rules YAML, extract PromQL, query Prometheus, report
- Create: `tools/prometheus-query-validator/README.md`
  - how to run, how to classify expressions as owned vs target
- Create: `manifests/dashboards/.queries-target-architecture.txt`
  - allowlist file: PromQL expressions explicitly not expected to resolve in Kind
- Modify: each of `manifests/dashboards/{network,security,traffic}-dashboard.json`
  - only if expressions need to be split into owned vs target, or deleted
- Modify: `manifests/base/monitoring/alert-rules.yaml`
  - only if rules need the same split
- Modify: `.github/workflows/test-bootstrap.yml`
  - new step: `Validate dashboard + alert-rule PromQL against live series`
- Modify: `docs/observability-architecture.md`
  - document the validator + the owned-vs-target split

---

## Task 1: Build The Extractor + Validator Tool

**Files:**
- Create: `tools/prometheus-query-validator/main.go`
- Create: `tools/prometheus-query-validator/{extractor,validator}_test.go`

- [ ] **Step 1:** Write `extractor.go` that walks a Grafana dashboard JSON and yields every PromQL expression (typically under `panels[*].targets[*].expr` and `templating.list[*].query` for template variables). Handle both current Grafana JSON shape and legacy.
- [ ] **Step 2:** Extend the extractor to also walk Prometheus alert rule YAML (`groups[*].rules[*].expr`).
- [ ] **Step 3:** Write `validator.go` that:
  - accepts a Prometheus base URL
  - POSTs each expression to `/api/v1/query`
  - classifies: `resolved` (≥1 series), `empty` (valid PromQL but no series), `error` (invalid syntax)
  - respects an allowlist file (one expression per line) of target-architecture expressions to skip
- [ ] **Step 4:** Unit tests for both extractor and validator using fixture files under `tools/prometheus-query-validator/testdata/`.

---

## Task 2: Triage Existing Dashboards And Alert Rules

**Files:**
- Read: `manifests/dashboards/*.json`
- Read: `manifests/base/monitoring/alert-rules.yaml`
- Create: `manifests/dashboards/.queries-target-architecture.txt`
- Modify: dashboards + alert rules as needed

- [ ] **Step 1:** Run the validator locally against a Kind cluster with Sprint 29 Ticket 29 baseline.
- [ ] **Step 2:** For each `empty` expression, decide:
  - **owned, missing exporter** — extend `pkg/kubernetes/metrics_server.go` or `pkg/ntp/metrics/exporter.go` to emit it; retry
  - **owned, dead panel** — delete the panel / alert rule
  - **target architecture** — add the verbatim expression to `.queries-target-architecture.txt` with a short `# why` comment
- [ ] **Step 3:** For each `error` expression, fix the syntax or delete the panel. Errors are never acceptable.
- [ ] **Step 4:** Re-run validator until exit code is 0 (all resolved or allowlisted).

---

## Task 3: Wire Into CI And Document

**Files:**
- Modify: `.github/workflows/test-bootstrap.yml`
- Modify: `docs/observability-architecture.md`

- [ ] **Step 1:** Add the validator build + run step after the other observability proofs. Pass it the Prometheus URL and the allowlist path.
- [ ] **Step 2:** In `docs/observability-architecture.md`, add §"Dashboard and Alert Query Validation":
  - what the validator does
  - the allowlist file + its meaning
  - how to add a new target-architecture expression
- [ ] **Step 3:** Update `Status.md` §Observability to add "dashboard/alert queries validated against live Kind series" to the verified list.

---

## Verification

- [ ] Validator unit tests pass
- [ ] Validator local run against Kind exits 0
- [ ] CI is green
- [ ] No dashboard panel or alert rule references an unresolved PromQL expression that isn't in the allowlist

---

## Out Of Scope

- Grafana dashboard provisioning via Operator (stays manifest-only)
- Alert routing / receiver config (already covered in alertmanager manifest)
- Log-based queries (Loki / ES) — this is PromQL only

---

## Suggested Branch Name

`sprint-29/ticket-32-dashboard-alert-validator`
