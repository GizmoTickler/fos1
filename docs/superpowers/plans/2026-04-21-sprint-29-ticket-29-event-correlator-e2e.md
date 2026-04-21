# Sprint 29 / Ticket 29: Land The Event-Correlator Runtime And Prove One Event End To End

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the uncommitted event-correlator runtime branch and add a Kind harness step that emits a deterministic canary event into the configured `spec.source.path`, asserts the sink produces the correlated JSON, and asserts the runtime `/ready` endpoint returns 200.

**Architecture:** The `EventCorrelation` CRD and its correlator runtime stay deliberately small (file source + file/stdout sink). The controller validates allowed host paths, mounts source/sink parent directories via `hostPath` with explicit read/write semantics, and advances `Phase=Running` only when the Deployment reports ready replicas. The repo already owns a Docker build path at `build/event-correlator/Dockerfile`. This ticket is the end-to-end proof, not the architectural change.

**Tech Stack:** Go, controller-runtime, Kubernetes core API types, Docker, Kind, shell scripts, GitHub Actions.

---

## Context

This ticket is partly in-flight on the currently-uncommitted working tree. The executing engineer (or agent) must:

1. Commit the in-flight branch (files listed below are currently modified/untracked).
2. Add the missing harness step that proves the runtime round-trip.

Uncommitted-in-working-tree files (pre-sprint baseline):
- new: `cmd/event-correlator/main.go`
- new: `build/event-correlator/Dockerfile`
- new: `pkg/security/ids/correlation/{runtime,config,processor,probes,deployment_paths}.go`
- new: `pkg/security/ids/correlation/{runtime_test,deployment_paths_test}.go`
- modified: `pkg/security/ids/correlation/{controller,controller_test}.go`
- modified: `manifests/base/security/ids/crds/eventcorrelation.yaml`
- modified: `manifests/examples/security/ids/event-correlation.yaml`
- new: `scripts/ci/{prove-prometheus-scrapes,prove-security-log-pipeline,k8s-wait-for-readiness,test-prove-prometheus-scrapes}.sh`
- modified: `.github/workflows/test-bootstrap.yml`

**Reference implementation plan** (already authored, in-flight): `docs/superpowers/plans/2026-04-20-event-correlation-runtime-implementation.md`. Do not reinvent — extend.

---

## File Map

- Commit/review: all files listed under "Uncommitted-in-working-tree" above
- Create: `scripts/ci/prove-event-correlation-e2e.sh`
  - emit deterministic canary into the configured `spec.source.path`
  - poll the sink file (or stdout log) for the expected correlated record
  - `curl` the runtime `/ready` endpoint
- Modify: `.github/workflows/test-bootstrap.yml`
  - add the new step after Prometheus/ES proof, gated on the same Kind cluster
- Modify: `pkg/security/ids/correlation/runtime.go`
  - only if runtime validation needs tightening; don't rewrite
- Modify: `docs/observability-architecture.md`
  - replace "controller-only" language in the correlation section with the proven runtime round-trip
- Modify: `Status.md`
  - move event correlation from "Partial" to a proven-runtime claim grounded in the new harness step

---

## Task 1: Commit And Verify The In-Flight Runtime Branch

**Files:** all uncommitted files listed in Context.

- [ ] **Step 1:** Run `make verify-mainline` on the working tree as-is. Fix any failures without scope creep.
- [ ] **Step 2:** Commit the in-flight correlator runtime + CI proof scripts as cohesive commits:
  - commit A: `feat(correlator): repo-owned runtime with file source/sink contract`
  - commit B: `ci(bootstrap): prove DPI/NTP scrape and Suricata canary log path`
  - commit C: `docs: event correlator runtime design spec` (already present as `d353667`)
- [ ] **Step 3:** Push and confirm CI green on the feature branch before continuing.

---

## Task 2: Add The Deterministic End-To-End Proof

**Files:**
- Create: `scripts/ci/prove-event-correlation-e2e.sh`
- Modify: `.github/workflows/test-bootstrap.yml`

- [ ] **Step 1:** Write a deterministic EventCorrelation example manifest under `manifests/examples/security/ids/event-correlation-e2e.yaml` that uses `spec.source.type=file`, `spec.sink.type=file`, and a rule that always matches on a single canary field.
- [ ] **Step 2:** Write `scripts/ci/prove-event-correlation-e2e.sh`:
  ```
  # apply the e2e manifest
  # wait for Deployment readiness
  # kubectl exec into the correlator pod, append a canary JSON line to source path
  # poll sink file for the correlated record with a known correlation id
  # curl http://<pod>:8080/ready — expect 200
  # fail fast with clear error output if any step times out
  ```
- [ ] **Step 3:** Wire the script into `.github/workflows/test-bootstrap.yml` after the existing Suricata/ES proof block.
- [ ] **Step 4:** Run locally in a Kind cluster; confirm the harness passes and produces readable output on failure.

---

## Task 3: Update Status Docs To Reflect Proven Runtime

**Files:**
- Modify: `docs/observability-architecture.md`
- Modify: `Status.md`
- Modify: `docs/project-tracker.md`

- [ ] **Step 1:** Replace "no verified end-to-end contract" language in `docs/observability-architecture.md` §Event Correlation with a description of the new round-trip proof.
- [ ] **Step 2:** Update `Status.md` §Event Correlation row from "Partial" to "Complete with E2E proof" + cite the harness script path.
- [ ] **Step 3:** Update `docs/project-tracker.md` Security Event Correlation line to match.

---

## Verification

- [ ] `make verify-mainline` passes
- [ ] `test-bootstrap.yml` GitHub Actions run is green and the new E2E step emits the canary round-trip successfully
- [ ] Status docs no longer imply controller-only verification

---

## Out Of Scope

- Broker/streaming input modes (file-only contract is the owned runtime)
- Multi-node correlator scaling / HA
- Threat-intelligence upstream feed ingestion
- Any non-canary traffic proof (that's Ticket 31)

---

## Suggested Branch Name

`sprint-29/ticket-29-event-correlator-e2e`
