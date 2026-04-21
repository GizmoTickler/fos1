# Live-Cluster Verification And Node-Local DPI Topology Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the repository-owned observability path in a real local cluster harness and remove the current topology mismatch where one `dpi-manager` instance can only see one node’s sensor logs.

**Architecture:** Keep this sprint tightly operational. First, match the DPI processing topology to the existing node-local Suricata/Zeek log contract by colocating one `dpi-manager` per node and making policy/event metadata explicitly node-aware. Second, turn the permissive `test-bootstrap` workflow into a hard-fail harness with concrete runtime assertions. Third, add explicit runtime checks for the repository-owned Suricata log-arrival path and Elasticsearch ILM bootstrap. Fourth, prove the pod-annotation Prometheus scrape path for `dpi-manager` and `ntp-controller`, and update the topology docs to match.

**Tech Stack:** Kubernetes manifests, Go, GitHub Actions, Kind, shell scripts, Prometheus, Elasticsearch

---

## Sprint Scope

This sprint includes:

1. node-local `dpi-manager` execution and node-aware policy/event metadata
2. a hard-fail Kind-based observability harness in `test-bootstrap.yml`
3. runtime proof for Suricata log arrival into Elasticsearch and ILM bootstrap success
4. runtime proof for the repository-owned Prometheus scrape path and topology/doc convergence

This sprint excludes:

- multi-node or HA logging architecture
- snapshot automation
- redesigning the security pipeline away from the node-local file contract
- full threat-intelligence or cluster-wide event aggregation

## Dependency Order

- Ticket 1 and Ticket 2 can run in parallel.
- Ticket 3 depends on Ticket 2 because the workflow must become a hard-fail harness before runtime assertions are meaningful.
- Ticket 4 depends on Ticket 1 and Ticket 2 because it should validate the post-topology deployment shape and the hardened harness.

## Ticket 1: Node-Localize `dpi-manager` And Scope Policy/Event Identity

**Owner:** Worker A

**Primary files:**
- Modify: `manifests/base/security/dpi-manager.yaml`
- Modify: `cmd/dpi-manager/main.go`
- Modify: `pkg/security/dpi/manager.go`
- Modify: `pkg/security/dpi/policy_pipeline.go`
- Modify: `pkg/security/dpi/connectors/zeek.go`
- Modify: `pkg/security/dpi/connectors/suricata.go`
- Modify or create focused tests under: `pkg/security/dpi/`

**Do not touch:**
- `.github/workflows/**`
- `manifests/base/monitoring/**`
- `docs/observability-architecture.md`

**Problem statement:**
The repo now uses node-local host logs for Suricata and Zeek, but `dpi-manager` still runs as a single deployment. That means only the node hosting that pod is actually observable. If we convert `dpi-manager` to a DaemonSet without scoping policy identity, multiple nodes can race on identical policy names.

**Required changes:**
- Convert `dpi-manager` from `Deployment` to `DaemonSet`.
- Make node identity explicit in the manager runtime, using `spec.nodeName` / downward API.
- Remove or replace misleading service-style assumptions (`SURICATA_SERVICE`, `ZEEK_SERVICE`) if they are not used by the code.
- Scope policy names, labels, or audit metadata so multiple node-local managers do not collide ambiguously when reacting to similar events.
- Keep the hostPath log contract from the previous sprint intact.

**Acceptance criteria:**
- The active manifest topology is “sensor DaemonSets + node-local `dpi-manager` + node-local shared logs”.
- Policy/event metadata clearly identifies the node that observed or enforced a signal.
- Policy naming/collision behavior is intentional rather than incidental.

**Verification:**
- `go test ./cmd/dpi-manager ./pkg/security/dpi/...`
- `kustomize build manifests/base/security`

## Ticket 2: Turn `test-bootstrap` Into A Hard-Fail Observability Harness

**Owner:** Worker B

**Primary files:**
- Modify: `.github/workflows/test-bootstrap.yml`
- Create: scripts/helpers under `scripts/` as needed for cluster assertions

**Do not touch:**
- `pkg/**`
- `manifests/base/security/**`
- `manifests/base/monitoring/**`

**Problem statement:**
The current bootstrap workflow applies manifests with `|| true`, disables capabilities for Kind compatibility, and always prints success even when nothing meaningful is proven.

**Required changes:**
- Remove `|| true` from the deploy path or split non-fatal steps out explicitly.
- Add readiness gates and failure-time diagnostics.
- Make the workflow fail when the intended proof checks fail.
- Preserve the current Kind-based approach; do not broaden into a new CI system.
- If helper scripts make the workflow clearer, add them under `scripts/`.

**Acceptance criteria:**
- The bootstrap workflow no longer reports success by default when deployments or assertions fail.
- The workflow captures enough logs/events to diagnose failures.
- The workflow structure clearly separates “render/apply/deploy” from “runtime proof”.

**Verification:**
- YAML parse/inspection of `.github/workflows/test-bootstrap.yml`
- any local shell syntax checks for new helper scripts

## Ticket 3: Add Runtime Proof For Suricata Log Arrival And Elasticsearch ILM Bootstrap

**Owner:** Worker C

**Primary files:**
- Modify: `.github/workflows/test-bootstrap.yml`
- Modify or create helper scripts under: `scripts/`
- Modify: `manifests/base/monitoring/fluentd.yaml` only if a narrowly-related proof hook is required
- Modify: `manifests/base/monitoring/elasticsearch.yaml` only if a narrowly-related proof hook is required
- Modify: `docs/observability-architecture.md`

**Do not touch:**
- `pkg/**`
- `cmd/**`
- `manifests/base/security/dpi-manager.yaml`

**Problem statement:**
The repo documents a deterministic proof path for Suricata log arrival and identifies ILM bootstrap success as a required next-step proof, but there is no automated harness that verifies either.

**Required changes:**
- Seed a deterministic Suricata-style canary event into the actual log path visible to Fluentd in the Kind harness.
- Assert a document arrives in `fos1-security-*` with the expected fields.
- Assert the ILM policy and index template are present through Elasticsearch APIs.
- Create a canary index/doc flow if needed to verify the expected lifecycle settings are attached.
- Update `docs/observability-architecture.md` only as needed to describe the exact proof method and its limits.

**Acceptance criteria:**
- The harness can prove one end-to-end security log path from shared file -> Fluentd -> Elasticsearch.
- The harness can prove that the repository-owned ILM bootstrap installed the expected policy/template.
- Failures are actionable from workflow output.

**Verification:**
- run the smallest relevant local shell checks for helper scripts
- workflow YAML review and any repository-local render checks needed by the changed proof path

## Ticket 4: Prove The Repository-Owned Prometheus Scrape Path And Converge Topology Docs

**Owner:** Worker D

**Primary files:**
- Modify: `.github/workflows/test-bootstrap.yml`
- Modify or create helper scripts under: `scripts/`
- Modify: `manifests/base/ntp/kustomization.yaml` only if needed to keep the Kind harness focused on owned resources
- Modify: `docs/observability-architecture.md`
- Modify: `Status.md`
- Modify: `docs/implementation-plan.md`
- Modify: `DPI-FRAMEWORK-README.md`
- Modify: `docs/design/advanced-dpi-system.md`

**Do not touch:**
- `pkg/**`
- `cmd/**`
- `.github/workflows/ci.yml`

**Problem statement:**
The repo still lacks proof that Prometheus actually scrapes the owned `dpi-manager` and `ntp-controller` pod-annotation paths, and some docs still imply a central DPI framework rather than the node-local file-watcher topology the manifests now implement.

**Required changes:**
- Add runtime assertions against Prometheus targets or query APIs for `dpi-manager` and `ntp-controller`.
- Keep the Kind harness focused on resources that can actually run there; if operator-style NTP add-ons block that, narrow the tested kustomization path rather than pretending they work.
- Converge the topology docs so they describe the active node-local DPI contract and the current repository-owned runtime proof level.

**Acceptance criteria:**
- The harness proves the owned Prometheus scrape path for `dpi-manager` and `ntp-controller`.
- The docs no longer imply a central DPI manager when the repo now owns a node-local topology.
- Status docs reflect what is runtime-proven versus still manifest-only.

**Verification:**
- workflow/helper-script checks
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
