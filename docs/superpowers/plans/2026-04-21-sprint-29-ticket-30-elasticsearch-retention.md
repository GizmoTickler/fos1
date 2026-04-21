# Sprint 29 / Ticket 30: Exercise Elasticsearch Retention And Rollover Beyond Bootstrap Presence

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that the `fos1-log-retention-14d` ILM policy + index template actually roll and delete indices under live load, not just that they're attached. Today the harness only asserts ILM/template **presence** and that a single canary document arrives in `fos1-security-*`.

**Architecture:** Production retention target stays at `14d` on a `30Gi` single-node PVC. For CI proof, ship an **accelerated ILM policy** (hot-phase `max_age` in seconds, delete phase in minutes) that runs only in the Kind harness. The production policy ships under the real name; the accelerated policy ships under a separate name and is applied only by the CI script. That keeps docs honest about what `14d`/`30Gi` means without pretending we proved it at production time scales.

**Tech Stack:** Kubernetes manifests, Elasticsearch REST API, `jq`, shell scripts, GitHub Actions, Kustomize.

**Prerequisite:** Ticket 29 lands first so the harness has a stable baseline cluster.

---

## Context

Current state:
- `manifests/base/monitoring/elasticsearch.yaml` ships `fos1-log-retention-14d` ILM policy + index template attaching both `fos1-security-*` and `fos1-logs-*`
- `scripts/ci/prove-security-log-pipeline.sh` writes one deterministic Suricata-style document and asserts it lands in the index, plus asserts policy/template attachment via `/_ilm/policy/...` and `/_index_template/...`
- Nothing proves the policy actually **fires**: no rollover, no aged-index deletion under the harness

Gap: A reader sees "14d retention verified" and assumes Kind harness proved the policy executed. It hasn't — only attachment.

---

## File Map

- Create: `manifests/base/monitoring/elasticsearch-ci-accelerated-ilm.yaml`
  - ConfigMap holding the accelerated ILM policy JSON (e.g. hot `max_age=30s`, delete after `2m`)
  - not included in the default kustomization — applied only by the CI script
- Modify: `scripts/ci/prove-security-log-pipeline.sh`
  - install the accelerated policy against a separate index pattern (`fos1-ci-retention-*`)
  - generate enough canary documents (or use force-rollover API) to trigger at least one rollover
  - sleep/poll for aged-index deletion
  - assert via `/_cat/indices?index=fos1-ci-retention-*` that at least one index rolled (generation ≥ 2) and at least one was deleted
- Modify: `.github/workflows/test-bootstrap.yml`
  - new step: `Prove ES rollover and deletion`
- Modify: `docs/observability-architecture.md`
  - new subsection: "CI accelerated ILM proof vs production 14d/30Gi target"
- Modify: `Status.md`
  - update the §Monitoring retention claim to cite the accelerated proof

---

## Task 1: Author The Accelerated ILM Policy For CI

**Files:**
- Create: `manifests/base/monitoring/elasticsearch-ci-accelerated-ilm.yaml`

- [ ] **Step 1:** Write an accelerated ILM policy JSON with:
  - `hot.actions.rollover.max_age: 30s`
  - `hot.actions.rollover.max_docs: 5`
  - `delete.min_age: 1m`
- [ ] **Step 2:** Write a companion index template JSON that matches `fos1-ci-retention-*` and attaches the accelerated policy.
- [ ] **Step 3:** Package both as a ConfigMap in `elasticsearch-ci-accelerated-ilm.yaml` for the CI script to read.
- [ ] **Step 4:** Ensure the ConfigMap is **not** referenced by the base kustomization — it's CI-only.

---

## Task 2: Extend The Harness To Force And Assert Rollover/Deletion

**Files:**
- Modify: `scripts/ci/prove-security-log-pipeline.sh`

- [ ] **Step 1:** After the existing `14d` policy/template presence checks, apply the accelerated policy via `PUT /_ilm/policy/fos1-ci-accelerated` and the accelerated template via `PUT /_index_template/fos1-ci-retention`.
- [ ] **Step 2:** Create the initial write alias / first index `fos1-ci-retention-000001`.
- [ ] **Step 3:** `POST` at least 10 canary documents with unique IDs. Between batches, call `POST /fos1-ci-retention/_rollover` with `max_age: 30s` conditions.
- [ ] **Step 4:** Poll `GET /_cat/indices/fos1-ci-retention-*?format=json` on a 5s cadence (max 180s). Assert:
  - at least 2 distinct generations exist at some point (rollover happened)
  - eventually the oldest generation is gone (deletion happened)
- [ ] **Step 5:** Emit structured log output (JSON or clearly-delimited plaintext) so CI failures are diagnosable without re-running locally.
- [ ] **Step 6:** Clean up the CI-only policy/template/indices on script exit (trap-based).

---

## Task 3: Wire Into Bootstrap Workflow And Document

**Files:**
- Modify: `.github/workflows/test-bootstrap.yml`
- Modify: `docs/observability-architecture.md`
- Modify: `Status.md`

- [ ] **Step 1:** Add the new harness step after the existing Suricata canary proof.
- [ ] **Step 2:** In `docs/observability-architecture.md`, add a subsection titled "CI Accelerated ILM Proof vs Production Retention Target" that:
  - names the CI policy (`fos1-ci-accelerated`, index pattern `fos1-ci-retention-*`)
  - explicitly separates the CI envelope from the production `14d`/`30Gi` target
  - states what is and is not proven (rollover + deletion execution YES; 14d wall-clock retention NO; snapshot/HA NO)
- [ ] **Step 3:** Update `Status.md` so the observability table no longer implies `14d` retention is verified; only "ILM rollover + delete actions execute under accelerated CI policy" is verified.

---

## Verification

- [ ] Local Kind run of `scripts/ci/prove-security-log-pipeline.sh` reports rollover + deletion in under 5 minutes
- [ ] `test-bootstrap.yml` CI run is green end-to-end
- [ ] No status claim asserts `14d` wall-clock retention as verified

---

## Out Of Scope

- Elasticsearch snapshot / restore
- Multi-node Elasticsearch HA
- Index lifecycle on `fos1-logs-*` beyond the same pattern (one pattern proves the contract)
- Natural-traffic document generation (that's Ticket 31)

---

## Suggested Branch Name

`sprint-29/ticket-30-elasticsearch-retention-proof`
