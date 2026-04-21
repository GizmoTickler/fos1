# Ops-First Observability And CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the highest-value operational gaps by wiring the in-repo metrics exporters to a verified deployment/scrape path and by making CI enforce the canonical `make verify-mainline` contract.

**Architecture:** Keep this sprint narrow and operational. Do not invent new platform layers. Standardize the existing exporter/runtime contracts, align manifests to the code that actually runs, and make GitHub Actions enforce the same verification path developers run locally. Treat Prometheus pod-annotation scraping as the owned baseline unless an existing operator-backed path is already both present and verified.

**Tech Stack:** Go, Prometheus client_golang, Kubernetes manifests, GitHub Actions, Kustomize, kubeconform

---

## Sprint Scope

This sprint intentionally excludes deeper threat-intelligence ingestion and event-correlator image/runtime behavior. It is limited to:

1. hardening the in-repo DPI metrics server contract
2. wiring the existing DPI/NTP exporters into the repository-owned Prometheus scrape path
3. making CI enforce `make verify-mainline`
4. updating status/developer docs to match the post-sprint reality

## Dependency Order

- Ticket 1 and Ticket 3 can run in parallel.
- Ticket 2 depends on Ticket 1 because the DPI metrics/health port contract must be settled in code before manifests are aligned.
- Ticket 4 depends on Ticket 2 and Ticket 3 because it documents the resulting runtime and CI contract.

## Ticket 1: Harden The DPI Metrics Server Runtime Contract

**Owner:** Worker A

**Primary files:**
- Modify: `pkg/kubernetes/metrics_server.go`
- Modify: `cmd/dpi-framework/main.go`
- Create: `pkg/kubernetes/metrics_server_test.go`

**Do not touch:**
- `.github/workflows/**`
- `manifests/base/ntp/**`
- `pkg/security/ids/correlation/**`

**Problem statement:**
`pkg/kubernetes/metrics_server.go` uses package-global HTTP handlers and `http.ListenAndServe`, which makes it hard to test, impossible to shut down cleanly, and risky to instantiate more than once in-process. `cmd/dpi-framework/main.go` starts it fire-and-forget, so shutdown is not coordinated and the runtime port contract is implicit.

**Required changes:**
- Refactor `MetricsServer` to own its own `http.ServeMux` and `http.Server` instead of registering handlers on the package-global default mux.
- Expose a lifecycle that the caller can stop cleanly during shutdown.
- Keep `/metrics`, `/healthz`, and `/readyz` behavior intact.
- Preserve the current metric names unless a change is required for correctness.
- Update `cmd/dpi-framework/main.go` to start and stop the metrics server through the new lifecycle.
- Keep the current single-listener shape: one HTTP listener serving probes and metrics together.

**Acceptance criteria:**
- Multiple `MetricsServer` instances can be constructed in tests without handler collisions.
- `cmd/dpi-framework/main.go` no longer leaks the metrics server on process shutdown.
- A focused test suite verifies:
  - `/healthz` returns `200`
  - `/readyz` returns `200`
  - `/metrics` exposes expected metric names after updates
  - server start/stop works without relying on global handlers

**Verification:**
- `go test ./pkg/kubernetes/...`
- `go test ./cmd/... ./pkg/...`

## Ticket 2: Align DPI And NTP Manifests To The Owned Prometheus Scrape Path

**Owner:** Worker B

**Primary files:**
- Modify: `manifests/base/security/dpi-manager.yaml`
- Modify: `manifests/base/ntp/deployment.yaml`
- Modify: `manifests/base/ntp/service.yaml`
- Modify: `manifests/base/ntp/ntp-monitoring.yaml`
- Modify: `manifests/base/monitoring/prometheus.yaml`
- Modify: `docs/observability-architecture.md`

**Do not touch:**
- `.github/workflows/**`
- `pkg/kubernetes/metrics_server.go`
- `cmd/dpi-framework/main.go`

**Problem statement:**
The repository has exporter code, but the deployment/scrape path is inconsistent. `cmd/dpi-framework/main.go` starts the metrics server on `:8080`, while `manifests/base/security/dpi-manager.yaml` advertises a separate metrics port `9090`. The NTP monitoring assets also mix an operator-style `ServiceMonitor` path with a pod/service deployment in `kube-system`, while the repository-owned Prometheus configuration currently relies on pod discovery and annotations.

**Required changes:**
- Align the DPI manifest port contract with the runtime established by Ticket 1.
- Add or fix pod annotations needed for the existing `kubernetes-pods` Prometheus scrape job to discover the DPI and NTP exporters.
- Ensure the NTP service/deployment labels, ports, and monitoring manifest no longer point at the wrong namespace or an unowned scrape mechanism as the default path.
- Keep any operator-style monitoring resources only if they are clearly documented as optional/additive rather than the baseline contract.
- Update `docs/observability-architecture.md` to describe the exact owned scrape path after the manifest changes.

**Acceptance criteria:**
- The repository-owned Prometheus config has a coherent scrape path for DPI and NTP exporters.
- The DPI manifest no longer exposes a metrics port that the process does not actually serve.
- The NTP monitoring assets no longer claim a default namespace/selector path that contradicts the deployment manifests.
- Documentation clearly distinguishes:
  - owned baseline scrape path
  - optional/operator-backed extras
  - still-unverified end-to-end areas

**Verification:**
- `kustomize build manifests/base`
- `make verify-mainline`

## Ticket 3: Make GitHub Actions Enforce `make verify-mainline`

**Owner:** Worker C

**Primary files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/validate-manifests.yml`
- Modify: `Makefile` only if a CI helper target is genuinely needed

**Do not touch:**
- `pkg/kubernetes/**`
- `pkg/ntp/**`
- `manifests/base/security/dpi-manager.yaml`
- `manifests/base/ntp/**`

**Problem statement:**
The repo now defines `make verify-mainline`, but the main CI workflow still runs ad hoc `go test` and `go build` steps separately. The workflows also use deprecated `set-output`, upload a coverage file that is never generated, and allow manifest validation to succeed even when `kubeconform` reports errors because of `|| true`.

**Required changes:**
- Make the main CI workflow call `make verify-mainline` as the authoritative Go verification step.
- Remove deprecated `set-output` usage in favor of supported GitHub Actions output handling, or simplify the workflow to avoid those probes entirely if they are unnecessary.
- Remove or fix the coverage upload step so it only runs when a coverage artifact is actually created.
- Make manifest validation fail on real kubeconform errors in the workflow that owns manifest validation.
- Avoid duplicating equivalent verification logic across multiple workflows unless the duplication is intentional and documented.

**Acceptance criteria:**
- Pull requests and pushes to `main` use a workflow that enforces `make verify-mainline`.
- The CI workflow no longer relies on deprecated output syntax.
- Manifest validation no longer passes by swallowing kubeconform failures.
- Workflow behavior remains understandable from the YAML itself without hidden assumptions.

**Verification:**
- `make verify-mainline`
- `git diff -- .github/workflows`

## Ticket 4: Update Developer And Status Docs To Match The New Ops Contract

**Owner:** Worker D

**Primary files:**
- Modify: `README.md`
- Modify: `docs/DEVELOPMENT.md`
- Modify: `Status.md`
- Modify: `docs/implementation-plan.md`
- Modify: `.github/PULL_REQUEST_TEMPLATE.md`

**Do not touch:**
- `pkg/**`
- `cmd/**`
- `manifests/**`

**Problem statement:**
Once Tickets 1-3 land, the repository’s operational story changes. The docs need to say exactly what is now enforced in CI and what observability path is actually owned by the repository, without overstating end-to-end runtime guarantees.

**Required changes:**
- Update the top-level status docs to reflect the new CI enforcement and exporter deployment/scrape baseline.
- Keep the docs careful about what remains unverified end-to-end.
- Update developer guidance and PR guidance so contributors know the required local verification path and what CI will enforce.

**Acceptance criteria:**
- `README.md`, `docs/DEVELOPMENT.md`, and `Status.md` all describe the same verification contract.
- `docs/implementation-plan.md` next-workstream text reflects what this sprint completed versus what remains.
- The PR template reminds contributors to run the canonical local gate rather than an outdated or partial check.

**Verification:**
- Read the modified docs together and check for contradictions.

## Dispatch Plan

Start with:

1. Worker A on Ticket 1
2. Worker C on Ticket 3

After both are reviewed and integrated:

3. Worker B on Ticket 2
4. Worker D on Ticket 4

## Review Notes For All Workers

- Do not broaden scope beyond the ticket.
- Do not edit files owned by another active ticket.
- If a ticket exposes a contradiction in the plan, stop and report it rather than guessing.
- Run the smallest relevant verification for the owned files before handing back changes.
