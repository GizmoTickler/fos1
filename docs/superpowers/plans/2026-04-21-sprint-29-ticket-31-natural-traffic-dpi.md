# Sprint 29 / Ticket 31: Prove DPI And Security-Log Ingestion Under Natural Traffic

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the sensor → log → metric pipeline works under a **real network payload**, not a hand-written log-line injection. Drive deterministic traffic from a test pod that matches an owned Suricata signature, assert Suricata emits the expected eve.json event, Fluentd ships it to `fos1-security-*`, and the DPI manager `:8080/metrics` event counter advances.

**Architecture:** Ship a small repo-owned Suricata signature that matches a deterministic pattern no real traffic would produce (e.g. a custom HTTP header or a distinctive URI). Spawn a short-lived test pod that emits the matching payload. Assert all three downstream signals. No external threat-intel feeds.

**Tech Stack:** Kubernetes manifests, Suricata rules, shell scripts, Elasticsearch REST API, Prometheus API, Kind.

**Prerequisite:** Ticket 29 lands first so the DPI + security-log baseline is stable.

---

## Context

Current proof slice (post-ops-sprint, post-ticket-28):
- DPI manager `:8080/metrics` pod-annotation scraping is proven live
- Suricata canary document insertion into Elasticsearch is proven (the document is written directly by the harness, not emitted by Suricata)
- No harness step causes Suricata to emit an event by actually observing traffic

Gap: everything above the sensor is proven. The sensor itself is not proven to participate in the pipeline.

Relevant owned exporters:
- `pkg/kubernetes/metrics_server.go` — exposes DPI and Zeek Prometheus metrics at `:8080/metrics`
- Suricata sensor: `manifests/base/security/suricata.yaml` — writes eve.json into `/var/log/fos1` (shared host path)
- Fluentd: `manifests/base/monitoring/fluentd.yaml` — tails `/var/log/fos1` and ships to Elasticsearch

---

## File Map

- Create: `manifests/base/security/suricata/rules/fos1-canary.rules`
  - single Suricata rule matching a deterministic pattern (e.g. `content:"FOS1-CANARY-A1B2C3"; http_header`)
  - classified as a test/benign sid; sid in a reserved range to avoid collision
- Modify: `manifests/base/security/suricata.yaml`
  - include the canary rules file in the active ruleset
- Create: `scripts/ci/prove-dpi-natural-traffic.sh`
  - spawn curl-producing test pod
  - poll Suricata eve.json for the expected sid
  - poll Elasticsearch `fos1-security-*` for the matching document
  - query Prometheus for the incremented DPI metric
- Modify: `.github/workflows/test-bootstrap.yml`
  - add the new step after Ticket 30's rollover step
- Modify: `pkg/kubernetes/metrics_server.go`
  - only if a specific counter needs to be exposed for the canary SID; reuse existing DPI event counters if possible
- Modify: `docs/observability-architecture.md`
  - document the natural-traffic proof path and distinguish from the log-line canary

---

## Task 1: Author The Canary Suricata Rule

**Files:**
- Create: `manifests/base/security/suricata/rules/fos1-canary.rules`
- Modify: `manifests/base/security/suricata.yaml`

- [ ] **Step 1:** Write a Suricata rule matching a distinctive HTTP request. Prefer matching a custom header value like `X-FOS1-Canary: A1B2C3D4` so the match cannot occur by accident:
  ```
  alert http any any -> any any (msg:"FOS1-CANARY-OBSERVED"; flow:established,to_server; http.header; content:"X-FOS1-Canary|3a 20|A1B2C3D4"; classtype:not-suspicious; sid:9000001; rev:1;)
  ```
- [ ] **Step 2:** Include the file via ConfigMap or rule-path volume mount in `manifests/base/security/suricata.yaml`. Reload Suricata on rule change.
- [ ] **Step 3:** Document the canary sid (`9000001`) as reserved/CI-only in `docs/design/policy-based-filtering.md` or an adjacent doc.

---

## Task 2: Author The Traffic-Generating Harness

**Files:**
- Create: `scripts/ci/prove-dpi-natural-traffic.sh`

- [ ] **Step 1:** Spawn a short-lived `curlimages/curl` pod on the node where Suricata is deployed. Use a ConfigMap-injected target so the pod hits a port that Suricata observes (either the node itself or a designated capture interface — whichever matches the manifest topology).
- [ ] **Step 2:** Execute `curl -H 'X-FOS1-Canary: A1B2C3D4' <target>`. Ensure the request crosses the traffic path Suricata inspects.
- [ ] **Step 3:** Poll the Suricata pod's eve.json on a 2s cadence (max 60s). Assert at least one event with `alert.signature_id == 9000001`.
- [ ] **Step 4:** Poll Elasticsearch `GET /fos1-security-*/_search?q=alert.signature_id:9000001` (max 90s). Assert ≥ 1 hit.
- [ ] **Step 5:** Port-forward Prometheus and query a DPI counter expected to advance (identify the exact metric name from `pkg/kubernetes/metrics_server.go`). Assert the counter is greater than a baseline captured at the start of the script.
- [ ] **Step 6:** Clean up the test pod via trap on exit.

---

## Task 3: Wire Into Bootstrap Workflow And Document

**Files:**
- Modify: `.github/workflows/test-bootstrap.yml`
- Modify: `docs/observability-architecture.md`
- Modify: `Status.md`

- [ ] **Step 1:** Add the new harness step after Ticket 30's rollover/deletion proof.
- [ ] **Step 2:** In `docs/observability-architecture.md`, add a §"Natural-Traffic DPI Proof" subsection that:
  - names the rule sid
  - describes the three assertions (eve.json, Elasticsearch, Prometheus)
  - distinguishes from the existing log-line canary (which proves log ingestion only)
- [ ] **Step 3:** Update `Status.md` to replace "canary-only proof" language with "canary + natural-traffic proof" where accurate.

---

## Verification

- [ ] Local Kind run: script reports Suricata event, Elasticsearch document, and Prometheus counter increment
- [ ] `test-bootstrap.yml` CI is green
- [ ] No status claim implies natural-traffic proof without pointing at the sid-9000001 harness

---

## Out Of Scope

- Multiple sensor coverage (one Suricata rule proves the pipeline shape)
- Zeek-specific natural-traffic proof (can be a follow-up ticket if valuable)
- Threat-intelligence upstream feeds
- Performance / throughput benchmarking under load

---

## Suggested Branch Name

`sprint-29/ticket-31-natural-traffic-dpi`
