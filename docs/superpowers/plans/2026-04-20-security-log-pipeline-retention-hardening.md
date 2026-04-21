# Security Log Pipeline And Retention Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the security log path real enough to prove Suricata/Zeek/DPI logs can reach Elasticsearch, while hardening persistence and retention for the core monitoring components.

**Architecture:** Keep this sprint operational and repository-owned. First, establish one consistent sensor-log contract between Suricata, Zeek, and DPI manager so the security side is not built on isolated `emptyDir` assumptions. Second, harden persistence for Prometheus, Grafana, and Alertmanager with explicit retention/storage settings. Third, make Fluentd ingest the actual security stream and define a proof-of-arrival path into Elasticsearch/Kibana. Fourth, add Elasticsearch-side retention controls and converge the docs around the new durability story.

**Tech Stack:** Kubernetes manifests, Go, Fluentd, Prometheus, Grafana, Alertmanager, Elasticsearch, Kibana, Kustomize

---

## Sprint Assumptions

Use these defaults unless the implementation finds an in-repo contradiction:

- Prometheus local retention: `7d`
- Elasticsearch log retention target: `14d`
- Persistent storage is PVC-backed where the manifest already models stateful operation
- Grafana persistence is for state and provisioning continuity, not for high availability

## Sprint Scope

This sprint includes:

1. a real shared security-log contract between Suricata, Zeek, and DPI manager
2. persistence for Prometheus, Grafana, and Alertmanager
3. Fluentd ingest changes needed to capture the actual security stream
4. Elasticsearch retention/capacity controls and doc convergence

This sprint excludes:

- full backup/snapshot automation
- multi-node Elasticsearch or high availability
- a full Fluentd redesign beyond what is required for the owned path
- threat-intelligence enrichment

## Dependency Order

- Ticket 1 and Ticket 2 can run in parallel.
- Ticket 3 depends on Ticket 1 because Fluentd should ingest the real agreed security-log path, not a guessed one.
- Ticket 4 depends on Ticket 2 for the retention/storage assumptions and should land after Ticket 3 if the docs describe the final end-to-end path.

## Ticket 1: Establish The Security Sensor Log Contract And Align Runtime Paths

**Owner:** Worker A

**Primary files:**
- Modify: `manifests/base/security/dpi-manager.yaml`
- Modify: `manifests/base/security/zeek.yaml`
- Modify: `manifests/base/security/suricata.yaml`
- Modify: `cmd/dpi-manager/main.go`
- Modify: `pkg/security/dpi/connectors/zeek.go`
- Modify: `pkg/security/dpi/connectors/suricata.go`

**Do not touch:**
- `manifests/base/monitoring/**`
- `docs/observability-architecture.md`
- `.github/**`

**Problem statement:**
Suricata, Zeek, and `dpi-manager` currently assume incompatible log paths and isolated volumes. `dpi-manager` cannot actually prove sensor ingestion because its `/var/log/suricata` and `/var/log/zeek` are not the same storage surfaced by the sensor pods.

**Required changes:**
- Choose one repository-owned security-log contract and apply it consistently. Recommended baseline:
  - shared host-visible paths for Suricata and Zeek logs
  - `dpi-manager` mounts those same paths read-only
- Align the default paths in `cmd/dpi-manager/main.go` and the connector defaults with the manifest contract.
- Make path mismatches fail loudly enough for operators to diagnose, rather than silently waiting on nonexistent files.
- Keep this ticket focused on path/volume contract and runtime alignment, not Fluentd ingestion.

**Acceptance criteria:**
- Suricata, Zeek, and `dpi-manager` all reference the same canonical log locations for the security signal path.
- The Go defaults and manifest defaults agree.
- The resulting security manifests render cleanly.

**Verification:**
- `go test ./cmd/dpi-manager ./pkg/security/dpi/...`
- `kustomize build manifests/base/security`

## Ticket 2: Harden Monitoring State For Prometheus, Grafana, And Alertmanager

**Owner:** Worker B

**Primary files:**
- Modify: `manifests/base/monitoring/prometheus.yaml`
- Modify: `manifests/base/monitoring/grafana.yaml`
- Modify: `manifests/base/monitoring/alertmanager.yaml`

**Do not touch:**
- `manifests/base/security/**`
- `manifests/base/monitoring/elasticsearch.yaml`
- `docs/**`

**Problem statement:**
Prometheus, Grafana, and Alertmanager still use `emptyDir`, so time series history, alert state, and Grafana state vanish on restart or reschedule.

**Required changes:**
- Replace `emptyDir` state volumes with persistent storage where appropriate.
- Add explicit Prometheus retention flags that match the sprint assumptions.
- Persist Alertmanager state under `/alertmanager`.
- Persist Grafana state under `/var/lib/grafana`.
- Keep this ticket narrowly on storage/persistence; do not broaden into Elasticsearch or docs.

**Acceptance criteria:**
- Prometheus no longer stores TSDB on `emptyDir`.
- Alertmanager no longer stores state on `emptyDir`.
- Grafana no longer stores state on `emptyDir`.
- Storage assumptions are explicit in the manifests rather than implicit.

**Verification:**
- `kustomize build manifests/base/monitoring`

## Ticket 3: Make Fluentd Ingest The Actual Security Stream And Define Proof Of Arrival

**Owner:** Worker C

**Primary files:**
- Modify: `manifests/base/monitoring/fluentd.yaml`
- Modify: `manifests/base/security/suricata.yaml` only if a narrowly-related logging contract adjustment is needed after Ticket 1
- Modify: `manifests/base/security/zeek.yaml` only if a narrowly-related logging contract adjustment is needed after Ticket 1
- Modify: `docs/observability-architecture.md`
- Modify: `docs/dashboard-guide.md` only if the proof path changes user-facing guidance

**Do not touch:**
- `manifests/base/monitoring/elasticsearch.yaml`
- `manifests/base/monitoring/prometheus.yaml`
- `pkg/**`

**Problem statement:**
Fluentd currently tails container logs with an unsafe parser assumption and filters out the actual sensor component labels (`ids`, `nids`). Even if the security tools emit logs, the current filter/parser path is likely to drop them before Elasticsearch.

**Required changes:**
- Fix the Fluentd parser so it matches Kubernetes container log realities rather than assuming raw JSON payloads at the file level.
- Include the actual security sensor labels in routing.
- If Ticket 1 lands a shared file-based security-log contract that cannot be proven through stdout alone, add explicit Fluentd sources for those files.
- Add one deterministic proof-of-arrival path in docs:
  - a known log/event source
  - the expected Elasticsearch index pattern
  - the expected Kibana query or verification step

**Acceptance criteria:**
- Fluentd manifest reflects the real security stream, not just generic `component=security`.
- The repository has a documented proof path showing how an operator verifies arrival in Elasticsearch/Kibana.
- The monitoring bundle renders cleanly after the change.

**Verification:**
- `kustomize build manifests/base/monitoring`
- `git diff -- manifests/base/monitoring/fluentd.yaml docs/observability-architecture.md docs/dashboard-guide.md`

## Ticket 4: Add Elasticsearch Retention Controls And Converge The Durability Docs

**Owner:** Worker D

**Primary files:**
- Modify: `manifests/base/monitoring/elasticsearch.yaml`
- Modify: `manifests/base/monitoring/kibana.yaml` only if needed for the retention/proof story
- Modify: `docs/observability-architecture.md`
- Modify: `Status.md`
- Modify: `docs/implementation-plan.md`
- Modify: `docs/project-tracker.md`

**Do not touch:**
- `pkg/**`
- `cmd/**`
- `.github/**`

**Problem statement:**
Elasticsearch persists data, but there is no repository-owned retention policy or documented storage envelope. The docs also still contain conflicting claims about how deployed or verified the broader observability stack really is.

**Required changes:**
- Add repository-owned Elasticsearch retention/capacity controls appropriate to a single-node baseline. This can be a documented/configured ILM-style or equivalent in-manifest policy, but it must be concrete.
- Keep the storage envelope and limitations explicit.
- Update the top-level observability/status docs so they agree on:
  - what is now durable
  - what is still template-only
  - what is still unverified end to end

**Acceptance criteria:**
- Elasticsearch no longer has an implicit “grow until full” retention story.
- The docs stop contradicting each other about the observability stack.
- The implementation plan’s next workstreams reflect the new remaining gaps after this sprint.

**Verification:**
- `kustomize build manifests/base/monitoring`
- `git diff --check`

## Dispatch Plan

Start with:

1. Worker A on Ticket 1
2. Worker B on Ticket 2

After those land and are reviewed:

3. Worker C on Ticket 3
4. Worker D on Ticket 4

## Review Notes For All Workers

- Do not broaden scope beyond the ticket.
- Do not edit files owned by another active ticket.
- If a ticket exposes a contradiction in the plan, stop and report it rather than guessing.
- Run the smallest relevant verification for the owned files before handing back changes.
