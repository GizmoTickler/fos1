# Observability Architecture

This document separates verified repository behavior from broader observability goals. It is not a blanket claim that every referenced component is deployed or operational in a cluster.

## Status Legend

- **Implemented and verified in code**: behavior covered by controller logic and targeted tests in this repository
- **Implemented in code, not yet verified end-to-end**: repository code exists, but this repository does not prove cluster deployment, scraping, or operator wiring
- **Defined by manifests or architecture only**: intended deployment shape that still depends on downstream images, cluster wiring, or future implementation work
- **External runtime dependency**: behavior owned by a container image, process, or cluster service outside the controller contract

## Event Correlation Runtime Contract

### Implemented and verified in code

The `EventCorrelation` controller in `pkg/security/ids/correlation/controller.go` owns a narrow Kubernetes runtime contract:

- it reconciles a `ConfigMap` named `<name>-config`
- it reconciles a single-replica `Deployment` named `<name>`
- it reconciles a `Service` named `<name>` exposing the `api` port on TCP `8080`
- the repo now owns a Docker build path for `fos1/event-correlator:latest` at `build/event-correlator/Dockerfile`
- it renders a structured `config.json` inside the managed `ConfigMap` with:
  - `source`: the minimal repository-owned event input contract
  - `sink`: the minimal repository-owned event output contract
  - `runtime.maxEventsInMemory` and `runtime.maxEventAge`
  - `rules`: the correlation rules from the custom resource
- it passes the config path plus runtime sizing flags to the correlator process, and derives the output format from `spec.sink.format`
- it validates `spec.source.path` and file-based `spec.sink.path` against approved path prefixes before reconciling the Deployment
- it mounts the source parent directory read-only using a `hostPath` volume
- it mounts the file sink parent directory read-write using a `hostPath` volume when `spec.sink.type=file`
- it sets status conditions based on owned resource reconciliation and Deployment readiness

The controller status contract is intentionally limited:

- `Phase=Disabled` only when `spec.enabled=false`
- `ConfigMapReady=True` means the rules `ConfigMap` has been reconciled
- `ServiceReady=True` means the Service has been reconciled
- `DeploymentReady=True` only when the reconciled Deployment reports `status.readyReplicas > 0`
- `Ready=True` and `Phase=Running` only when the Deployment reports ready replicas
- `Phase=Pending` means the controller created or updated runtime resources, but the Deployment is not yet ready

Focused tests under `pkg/security/ids/correlation/` verify the generated ConfigMap, Deployment, Service, and the Disabled -> Pending -> Running status transitions.

### Runtime behavior proven end to end

The repository-owned correlator runtime image now has a deterministic round-trip proof gated by the Kind bootstrap harness:

- [scripts/ci/prove-event-correlation-e2e.sh](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/prove-event-correlation-e2e.sh) applies [manifests/examples/security/ids/event-correlation-e2e.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/examples/security/ids/event-correlation-e2e.yaml), waits for the reconciled Deployment to become ready, injects a single canary JSON line carrying `canary_id="SPRINT29-TICKET29-CANARY"` into the configured `spec.source.path` via `kubectl exec`, polls the configured `spec.sink.path` for the correlated record emitted by the rule, and asserts that `GET http://127.0.0.1:8080/ready` returns HTTP 200
- the workflow step `Prove event correlation end-to-end` in [.github/workflows/test-bootstrap.yml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/.github/workflows/test-bootstrap.yml) runs the script after the Prometheus, Suricata-log, and Elasticsearch retention proofs, using the locally built `fos1-local/event-correlator:ci` image

The proof exercises the end-to-end contract that earlier doc revisions treated as unverified:

- the `build/event-correlator/Dockerfile` output contains a `/usr/bin/event-correlator` binary that consumes the controller-generated `config.json`
- the runtime honors `spec.source.type=file` with a `jsonl` format by tailing the file and processing appended lines
- the runtime honors `spec.sink.type=file` by writing correlated-event JSON records the proof script can read back
- `/ready` on port `8080` returns HTTP 200 once the file source and sink have been initialized

The proof intentionally exercises a single canary event and a threshold-1 rule so the round-trip does not depend on any non-deterministic field beyond `canary_id`. Multi-rule, multi-event, and non-canary traffic correlation are out of scope for this harness.

## Other Repository-Owned Observability Surfaces

### Implemented in code, with targeted runtime proof for the owned scrape baseline

The repository also contains observability-related code paths that should be treated as implemented building blocks rather than as a verified platform contract:

- `pkg/ntp/metrics/exporter.go` exposes an NTP Prometheus-style `/metrics` endpoint plus `/healthz`, and the owned manifest baseline now expects mTLS pod-annotation scraping on `ntp-controller` pods at `:9559/metrics`
- `pkg/kubernetes/metrics_server.go` exposes DPI and Zeek Prometheus metrics plus simple probe endpoints, and the owned manifest baseline now expects mTLS pod-annotation scraping on `dpi-manager` pods at `:8080/metrics`

Those manifest contracts now have a narrow live-cluster proof in the Kind harness. The proof is intentionally limited to discovery and successful scraping of the owned pod-annotation targets; it does not prove every downstream rule, dashboard, or operator-driven integration.

### Repository-owned baseline scrape path

The baseline metrics collection path owned by this repository is the pair of `fos1-dpi-manager-pods` and `fos1-ntp-controller-pods` jobs in [manifests/base/monitoring/prometheus.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/monitoring/prometheus.yaml). Those jobs discover pods only when they carry standard Prometheus pod annotations, trust the `fos1-internal-ca` bundle, and present the `prometheus-client-tls` client certificate for the owned mTLS metrics allowlists.

After the Ticket 2 manifest changes, the owned exporter contract is:

- [manifests/base/security/dpi-manager.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/security/dpi-manager.yaml): `dpi-manager` is now a node-local `DaemonSet`; each pod exposes `/metrics`, `/healthz`, and `/readyz` on the single HTTPS listener at port `8080`, and the pod template is annotated for pod-based scraping on `:8080/metrics`
- [manifests/base/ntp/ntp-controller.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/ntp/ntp-controller.yaml): the active `ntp-controller` deployment in the `network` namespace exposes the HTTPS exporter on port `9559`, carries the pod annotations for scraping on `:9559/metrics`, and exposes the HTTPS API listener on `8080`
- [manifests/base/monitoring/prometheus-client-cert.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/monitoring/prometheus-client-cert.yaml): cert-manager issues the `prometheus-client-tls` Secret with Subject CN `prometheus`, which is the client identity allowed by the owned metrics endpoints
- [manifests/base/ntp/service.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/ntp/service.yaml): the active `ntp-controller` service is the service-level endpoint used by optional operator resources such as the `ServiceMonitor`

This is the exact repository-owned path. It does not depend on a `ServiceMonitor`, and it does not require Prometheus Operator CRDs.

### Repository-owned Prometheus scrape proof path

The bootstrap harness now proves that the owned pod-annotation scrape path is active in a live Kind cluster:

- harness source: [scripts/ci/prove-prometheus-scrapes.sh](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/prove-prometheus-scrapes.sh) port-forwards Prometheus, inspects `/api/v1/targets`, and queries `up{...}` through `/api/v1/query`
- proof target 1: every ready `security/dpi-manager` pod discovered by the node-local `DaemonSet` must appear as an active `fos1-dpi-manager-pods` target with `health="up"` and an `up=1` sample
- proof target 2: every ready `network/ntp-controller` pod must appear as an active `fos1-ntp-controller-pods` target with `health="up"` and an `up=1` sample
- Kind scope narrowing: [`.github/workflows/test-bootstrap.yml`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/.github/workflows/test-bootstrap.yml) rewrites the copied `test-manifests/base/ntp/kustomization.yaml` so the proof deploys only `ntp-crd.yaml`, `ntp-controller.yaml`, and `service.yaml`; optional operator add-ons and the chrony daemonset/runtime slice are intentionally excluded because they are not required to prove the repository-owned Prometheus path

If those checks pass, the repository has proven the baseline it actually owns: Prometheus discovers the annotated pods, verifies the owned server certs against `fos1-internal-ca`, presents its client certificate, scrapes the active exporters, and records a live `up=1` series for both the node-local DPI manager path and the NTP controller path.

## Dashboard And Alert Query Validation

### Implemented and verified in code

The repository ships Grafana dashboards under `manifests/dashboards/*.json` and Prometheus alert rules in `manifests/base/monitoring/alert-rules.yaml`. Both are easy to drift away from the metrics owned exporters actually emit — a dashboard panel that references `cilium_agent_flows` will silently render "No data" and an alert that calls `suricata_alerts_total` will never fire because its expression is permanently empty.

To prevent that drift, the repository now owns a [`tools/prometheus-query-validator`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/tools/prometheus-query-validator) Go tool and runs it as a step of the Kind bootstrap harness:

- the tool walks every dashboard JSON and alert-rule expression at `panels[*].targets[*].expr`, `templating.list[*].query`, and `groups[*].rules[*].expr`
- each expression is POSTed to the live Kind Prometheus `/api/v1/query`
- outcomes are classified as `resolved` (≥1 series), `empty` (valid PromQL but no data), `error` (Prometheus rejected the expression), or `allowlisted` (skipped because the expression is recorded in the target-architecture allowlist)
- any non-allowlisted `empty` or `error` classification causes the validator to exit non-zero, which fails the bootstrap workflow

The CI entry point lives in [`.github/workflows/test-bootstrap.yml`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/.github/workflows/test-bootstrap.yml) under the **Validate dashboard + alert-rule PromQL against live series** step. It re-uses the same `kubectl port-forward` pattern and `19090:9090` port that `scripts/ci/prove-prometheus-scrapes.sh` uses, so the validator sees the same Prometheus instance that just proved the DPI and NTP pod-annotation scrape paths.

The allowlist lives at [`manifests/dashboards/.queries-target-architecture.txt`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/dashboards/.queries-target-architecture.txt). It contains the verbatim PromQL text of every expression that references a metric the repository does not currently own — today that is the node-exporter family (`node_cpu_seconds_total`, `node_memory_*`, `node_filesystem_*`, `node_network_*`, `node_load*`, `node_disk_*`) used by `manifests/dashboards/system-dashboard.json`. Those panels describe the intended cluster shape, not the repository-owned baseline, and the allowlist makes that split explicit.

### Adding A New Target-Architecture Expression

When a dashboard or alert rule references a metric the repository does not yet emit from an owned exporter, the validator will flag it as `empty` and fail CI. Decide between three responses:

1. **Owned, missing exporter.** Add the metric to `pkg/kubernetes/metrics_server.go` (DPI/Zeek) or `pkg/ntp/metrics/exporter.go` (NTP), or register a new owned exporter. Re-run the harness; the validator should now classify it `resolved`.
2. **Owned, dead panel / alert.** Delete the panel or alert rule. Dashboards are allowed to change shape, but a referenced metric must either resolve or be knowingly deferred.
3. **Target-architecture only.** Copy the exact PromQL text into `manifests/dashboards/.queries-target-architecture.txt` and add a `# why:` comment naming the upstream exporter (node-exporter, kube-state-metrics, cAdvisor, Cilium Hubble, etc.). That documents which future ticket will own wiring the exporter in. The allowlist match is byte-for-byte on the trimmed expression, so keep the copy verbatim.

`error` classifications should generally not be allowlisted. Fix the syntax or delete the rule — allowlisting a syntactically-invalid expression hides a real bug.

### What This Proof Does Not Cover

- The validator only queries Prometheus once at the end of the harness. It does not prove the dashboard rendering path, and it does not prove that Alertmanager ever receives a firing alert.
- It cannot tell the difference between "metric is missing" and "metric is present but has no samples in the current range"; an expression that evaluates to an empty series because nothing is generating traffic will still classify as `empty`. In practice the Kind harness generates enough owned DPI traffic through the canary proof pipeline that this has not been observed, but it remains a dependency of the upstream canary logic.
- The allowlist captures intent, not wiring. Expressions listed there are explicitly unresolved in the Kind baseline and remain open work to bridge in future tickets.

## Broader Observability Stack

### Defined by manifests or architecture only

The repository documents a broader observability direction around Prometheus, Grafana, Alertmanager, Elasticsearch, Fluentd, and Kibana. Those sections describe target architecture and deployment intent, not a uniformly verified runtime contract.

One repository-owned exception now exists for the security log ingress path: the Fluentd baseline in [manifests/base/monitoring/fluentd.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/monitoring/fluentd.yaml) explicitly tails both Kubernetes container logs and the shared host-visible security contract under `/var/log/fos1`. That keeps the log collector aligned with the Ticket 1 sensor contract instead of assuming every security event is emitted as a raw JSON container log line.

The monitoring manifests now also make the single-node durability envelope explicit:

- [manifests/base/monitoring/prometheus.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/monitoring/prometheus.yaml) persists TSDB data on a PVC and sets local retention to `7d`
- [manifests/base/monitoring/grafana.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/monitoring/grafana.yaml) persists Grafana state on a PVC
- [manifests/base/monitoring/alertmanager.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/monitoring/alertmanager.yaml) persists Alertmanager state on a PVC
- [manifests/base/monitoring/elasticsearch.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/monitoring/elasticsearch.yaml) runs as a single-node `StatefulSet` with one `30Gi` PVC, explicit disk-watermark protection, and a repository-owned ILM bootstrap that applies `14d` retention to `fos1-security-*` and `fos1-logs-*`

Those are manifest-level durability and retention controls. They are not proof that a cluster has actually applied the storage class, kept the PVCs bound across failures, or executed the Elasticsearch bootstrap successfully at runtime.

Concrete manifest/template surfaces currently in-tree include:

- `manifests/base/monitoring/kustomization.yaml`, which assembles Prometheus, Grafana, Alertmanager, Elasticsearch, Fluentd, Kibana, and alert-rule manifests
- `manifests/base/ntp/ntp-monitoring.yaml`, which defines optional additive `ServiceMonitor`, `PrometheusRule`, and `GrafanaDashboard` resources for clusters that already run the relevant operators, but is not part of the repository-owned Kind proof path
- `manifests/dashboards/*.json`, which provides dashboard JSON intended for Grafana consumption

At a high level, the intended platform shape is still:

- Prometheus for metrics collection
- Grafana for dashboards
- Alertmanager for alert routing
- Elasticsearch plus Fluentd plus Kibana for log storage and search

Those components may have manifests, examples, or design notes elsewhere in the tree, but this document should not be read as evidence that the repository currently validates their end-to-end operation.

Typical missing runtime dependencies for these manifests include:

- the required operators or CRDs for `ServiceMonitor`, `PrometheusRule`, and `GrafanaDashboard`
- container images and storage/runtime configuration for Prometheus, Grafana, Alertmanager, Elasticsearch, Fluentd, and Kibana
- actual Service, scrape, and network-policy wiring beyond the owned pod-annotation baseline and the narrow Kind proof described above

### Single-node limitations and storage envelope

The repository-owned logging baseline is intentionally single-node and non-HA:

- Elasticsearch is explicitly configured with `discovery.type=single-node`
- log indices are templated with `index.number_of_replicas=0`, so there is no replica safety on node loss
- the baseline data envelope is one `30Gi` PVC for Elasticsearch data, with retention deleting `fos1-security-*` and `fos1-logs-*` indices once they are at least `14d` old
- the repository does not yet own snapshotting, restore automation, rollover sizing, or multi-node shard placement

This means the retention story is no longer "grow until full," but it is still a baseline lab or small-cluster posture rather than a hardened HA logging platform.

### Repository-owned security log proof path

The deterministic proof-of-arrival path owned by this repository is Suricata `eve-log` ingestion:

- bootstrap harness source: [scripts/ci/prove-security-log-pipeline.sh](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/prove-security-log-pipeline.sh) appends a deterministic Suricata-style JSON canary directly into the Kind node path at `/var/log/fos1/suricata/eve.json`, which is the same host log contract mounted into Fluentd
- expected Elasticsearch index pattern: `fos1-security-*`
- expected indexed fields for the canary proof: `security_sensor="suricata"`, `event_type="alert"`, the unique `canary_id`, and `log_contract="/var/log/fos1/suricata/eve.json"`
- expected Elasticsearch bootstrap proof: the harness also calls Elasticsearch APIs to verify the `fos1-log-retention-14d` ILM policy, the `fos1-log-retention-template` index template, and a template-backed canary index that inherits `index.lifecycle.name=fos1-log-retention-14d`

If those checks pass, the repository-owned path has been proven end to end for one security sensor stream: a Suricata-format event reached the shared file contract, Fluentd tailed it, Elasticsearch indexed it under the security-specific prefix, and the repository-owned retention bootstrap attached the expected lifecycle settings to a matching index. Zeek logs are also tailed from `/var/log/fos1/zeek/current/*.log`, but the Suricata `eve.json` path remains the deterministic proof target because it is structured JSON with stable fields and does not depend on Kibana UI setup.

The log-line canary above is explicitly a **log-ingestion proof only**. Sprint 29 Ticket 31 adds a separate natural-traffic proof that exercises the sensor itself; see [Natural-Traffic DPI Proof](#natural-traffic-dpi-proof) below.

### Natural-Traffic DPI Proof

The natural-traffic DPI proof is a Sprint 29 Ticket 31 addition and is intentionally distinct from the log-line canary above. Where the log-line canary appends a hand-written JSON document directly into Suricata's eve.json host path, the natural-traffic proof drives a real HTTP payload across the interface Suricata inspects and asserts the sensor itself emits the matching event:

- owned Suricata rule: [manifests/base/security/suricata/rules/fos1-canary.rules](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/security/suricata/rules/fos1-canary.rules), shipped as ConfigMap `suricata-rules-canary` in the `security` namespace and mounted into `/etc/suricata/rules/fos1-canary.rules`
- reserved signature id: `9000001` (CI-reserved; see [docs/design/policy-based-filtering.md "Reserved Suricata SIDs"](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/docs/design/policy-based-filtering.md))
- reload contract: the DaemonSet pod template carries a `fos1.io/rules-canary-checksum` annotation that CI rewrites whenever the canary rule body changes, forcing a rollout so Suricata re-reads the rule
- traffic source: [scripts/ci/prove-dpi-natural-traffic.sh](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/prove-dpi-natural-traffic.sh) spawns a short-lived `curlimages/curl` pod pinned via `nodeSelector: kubernetes.io/hostname` to the node where Suricata is running. The pod issues `curl -H 'X-FOS1-Canary: A1B2C3D4' <target>` a handful of times against an in-cluster target so the request crosses the host interface `af-packet` is listening on

Three assertions must all pass, in order:

1. **Sensor emission**: the Suricata eve.json file on its host node contains at least one `event_type=alert` record with `alert.signature_id == 9000001`. The harness polls every 2s for up to 60s via `docker exec <kind-node> grep ... eve.json`.
2. **Elasticsearch index**: `GET /fos1-security-*/_search?q=alert.signature_id:9000001` returns at least one hit whose `_source.security_sensor == "suricata"`. The harness polls every 5s for up to 90s through a port-forward on the monitoring Elasticsearch service.
3. **Prometheus metric advance**: `sum(dpi_events_total)` — exported by `pkg/kubernetes/metrics_server.go` on each `dpi-manager` DaemonSet pod at `:8080/metrics` — has strictly increased past a baseline captured before the curl ran. The harness deliberately does **not** pin a specific `{event_type, application, category}` label set because the exact label combination that advances depends on which DPI connector ingested the alert.

What distinguishes this from the log-line canary:

| Aspect | Log-line canary (prove-security-log-pipeline.sh) | Natural-traffic canary (prove-dpi-natural-traffic.sh) |
| --- | --- | --- |
| Event source | `docker exec ... cat >> eve.json` | Suricata observing real packets on its inspection interface |
| Proves sensor? | No — Suricata is never consulted | Yes — the sid:9000001 signature must fire |
| Proves log ingestion? | Yes | Yes (via Fluentd → Elasticsearch) |
| Proves DPI counter advance? | No | Yes (Prometheus `sum(dpi_events_total)`) |
| Owned rule sid | n/a | `9000001` |

What this natural-traffic proof still does **not** verify:

- that the sid:9000001 path is equivalent to every other detection path Suricata or Zeek might run in production; only one HTTP-header signature is exercised
- that traffic between arbitrary in-cluster pods is inspected; the harness pins the curl pod to the Suricata node with `hostNetwork=true` so the payload definitely crosses the monitored interface
- throughput or timing characteristics of the pipeline under load

What this proof does not yet verify (carryover from the log-line canary):

- that `fos1-logs-*` non-security indices are flowing end to end
- that Kibana data views, saved objects, or dashboards are provisioned automatically
- that the `14d` delete phase has actually executed against an aged index at production wall-clock time scales
- that PVC-backed monitoring state has been exercised through restart or reschedule events

### CI Accelerated ILM Proof vs Production Retention Target

The production retention target shipped in [manifests/base/monitoring/elasticsearch.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/monitoring/elasticsearch.yaml) stays at `fos1-log-retention-14d` against `fos1-security-*` and `fos1-logs-*` on a single `30Gi` PVC. That envelope has never been exercised end-to-end by the Kind harness, because a 14-day wall-clock wait does not fit in a CI budget, and the harness only proves that the policy and template are **attached**, not that they fire.

To close the gap between "attached" and "fires", the repository now ships a second, clearly-labelled policy + template that the CI harness installs and tears down per run:

- CI-only artifacts source: [manifests/base/monitoring/elasticsearch-ci-accelerated-ilm.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/monitoring/elasticsearch-ci-accelerated-ilm.yaml) packages an accelerated ILM policy and index template into a ConfigMap. The manifest is **not** referenced by `manifests/base/monitoring/kustomization.yaml`; it is applied explicitly by the CI workflow step and is not part of a normal cluster deployment.
- CI ILM policy name: `fos1-ci-accelerated` with `hot.actions.rollover.max_age=30s`, `hot.actions.rollover.max_docs=5`, and `delete.min_age=1m`
- CI index template: `fos1-ci-retention-template` matching `fos1-ci-retention-*` and attaching the accelerated policy, including `index.lifecycle.rollover_alias=fos1-ci-retention`
- CI harness source: [scripts/ci/prove-es-retention-rollover.sh](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/prove-es-retention-rollover.sh) port-forwards Elasticsearch, temporarily lowers `indices.lifecycle.poll_interval` to `1s` via the transient cluster settings API, installs the CI policy and template, bootstraps write alias `fos1-ci-retention` at backing index `fos1-ci-retention-000001`, posts canary documents in batches with explicit `POST /fos1-ci-retention/_rollover` calls between batches, and polls `GET /_cat/indices/fos1-ci-retention-*?format=json` on a 5-second cadence up to 180 seconds
- CI harness assertions:
  - at least 2 distinct generations of `fos1-ci-retention-*` were observed at some point during the run (rollover executed)
  - the initial backing index `fos1-ci-retention-000001` eventually disappeared from the index list (the delete phase executed)
- CI cleanup: the script is trap-based and removes the CI policy, template, backing indices, the CI ConfigMap (if it installed it itself), and the transient poll-interval override on exit

What IS proven by the accelerated CI path:

- an ILM policy with `rollover` and `delete` actions attached to a matching template actually drives Elasticsearch to create a new generation and delete the oldest under live writes
- the policy/template + write-alias + bootstrap-index wiring produces a legal, functioning rollover chain when given real documents

What is explicitly NOT proven by the accelerated CI path:

- the production `14d` wall-clock retention — the CI policy is seconds/minutes, not days
- the production `30Gi` PVC storage envelope — the CI indices never grow to that scale
- high availability or multi-node shard placement — the Elasticsearch StatefulSet remains `discovery.type=single-node`
- snapshot and restore — the repository does not yet own snapshot automation
- behavior on the real `fos1-security-*` or `fos1-logs-*` indices — the CI proof runs against a dedicated `fos1-ci-retention-*` pattern specifically so it cannot contaminate or displace the production retention policy attachment

Timing caveat: the accelerated proof depends on ILM actually evaluating the policy on each poll tick. The baseline `elasticsearch.yml` sets `indices.lifecycle.poll_interval=10m`, which the CI script overrides via the transient cluster settings API for the duration of the run and then restores. If that override is removed or the cluster rejects it, the proof will legitimately fail rather than silently pass, and ordering of `override_ilm_poll_interval` before `install_accelerated_policy` matters: lower the poll interval first, then install the policy, then write documents and force rollover. That ordering needs a live Kind validation before the first merge to confirm timing budgets hold on the GitHub Actions runner.

## RBAC No-Cluster-Admin CI Gate (Sprint 30 / Ticket 42)

### Implemented and verified in code

Sprint 30 Ticket 42 introduces [`scripts/ci/prove-no-cluster-admin.sh`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/prove-no-cluster-admin.sh) as a CI gate wired into `.github/workflows/validate-manifests.yml`. The script walks every `ClusterRoleBinding` across `manifests/` and `test-manifests/` and fails if any binding targets `roleRef.name: cluster-admin` without an explicit `metadata.annotations.fos1.io/rbac-exception` value. The annotation is the only mechanism that keeps the gate green; no wildcards, no exceptions outside the annotation.

This CI proof is observability-adjacent in the sense that it makes the repository's RBAC posture legible: a reader can trust that every ServiceAccount is bound to a named, scoped ClusterRole. The authoritative per-controller verb/resource table lives at [`docs/design/rbac-baseline.md`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/docs/design/rbac-baseline.md).

What this gate does NOT prove:
- that ClusterRoles themselves are minimal (the script only blocks `cluster-admin` binding; it does not re-audit per-role verb/resource minimality)
- that exception annotations are scoped correctly — the annotation is a free-text reason field
- that RBAC is actually enforced at runtime against an API server; that is a cluster-level policy concern outside this repo

## Performance Baseline CI Job (Sprint 30 / Ticket 43 + Sprint 31 / Ticket 54)

### Implemented and verified in code

Sprint 30 Ticket 43 adds a non-blocking performance baseline harness; Sprint 31 Ticket 54 expands it to four hot paths total. The bench harness lives in [`tools/bench/`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/tools/bench/) and uses `go test -bench` against in-process fakes (no Kubernetes API, no real Cilium):

- [`tools/bench/nat_apply_bench_test.go`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/tools/bench/nat_apply_bench_test.go) — `pkg/network/nat.Manager.ApplyNATPolicy` (Ticket 43)
- [`tools/bench/dpi_policy_bench_test.go`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/tools/bench/dpi_policy_bench_test.go) — DPI event → Cilium policy (Ticket 54)
- [`tools/bench/filterpolicy_translate_bench_test.go`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/tools/bench/filterpolicy_translate_bench_test.go) — FilterPolicy → CiliumNetworkPolicy translator (Ticket 54)
- [`tools/bench/threatintel_translate_bench_test.go`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/tools/bench/threatintel_translate_bench_test.go) — Threat-intel indicator → CiliumPolicy translator (Ticket 54)

The [`scripts/ci/run-bench.sh`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/run-bench.sh) harness runs all four benches in CI, compares results against [`docs/performance/baseline-2026-04.md`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/docs/performance/baseline-2026-04.md), and prints warnings (non-failing) for regressions beyond a configurable threshold.

The baseline file records ops/s, p50/p95/p99 latency, memory allocation per op, machine details, and git commit. Regressions flagged in CI output are explicitly warnings; a future ticket can promote the gate to blocking once the signal is understood on the real CI runner.

What these benches do NOT prove:
- throughput under real Cilium policy apply (each harness uses an in-process fake to isolate the hot path)
- performance of remaining hot paths — routing sync, DHCP control socket, DNS zone update all remain unbenchmarked
- p99 tail behavior under contention — the benches run single-goroutine by design

## Leader Failover CI Proof (Sprint 31 / Ticket 47)

### Implemented and verified in code

Sprint 31 Ticket 47 adds [`scripts/ci/prove-leader-failover.sh`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/prove-leader-failover.sh) as a Kind harness step wired into `.github/workflows/test-bootstrap.yml` after the IDS controller is rolled out. The script targets `ids-controller` (selected because it is already deployed in the Kind harness and now scaled to two replicas; the original Ticket 47 plan suggested `dpi-manager`, but `dpi-manager` is a DaemonSet and cannot run leader election without defeating its node-local purpose).

The script:
- reads the active leader's pod identity from the `ids-controller` Lease (`coordination.k8s.io/v1` in the `security` namespace)
- deletes that pod and starts a stopwatch
- polls the Lease until the `holderIdentity` flips to the standby pod
- asserts the transition completes within the documented RTO (target: ≤ 30s under the default lease config of 15s lease duration / 10s renew deadline / 2s retry period)

What this proof does NOT cover:
- multi-leader split-brain — the proof is a single failover cycle, not a network-partition scenario
- repeated failover under churn — the proof runs once per CI invocation
- HA for external daemons (FRR / Suricata / Zeek / Kea singletons) or shared-state observability (Elasticsearch / Prometheus / Grafana / Alertmanager single-replica) — these are Sprint 32 candidates
- DaemonSets like `dpi-manager` are intentionally per-node and excluded from leader election

## Cert Rotation CI Proof (Sprint 31 / Ticket 49)

### Implemented and verified in code

Sprint 31 Ticket 49 adds [`scripts/ci/prove-cert-rotation.sh`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/prove-cert-rotation.sh) as a Kind harness step. The script targets the API server because it is the one path under test that combines mTLS (`RequireAndVerifyClientCert`) with the shared `pkg/security/certificates.LoadTLSConfig` + fsnotify reload helper.

The script:
- captures the current API server cert serial via `openssl s_client`
- triggers a renewal — preferred path is `cmctl renew` against the `Certificate` object; fallback is to delete the underlying Secret so cert-manager reconciles a fresh one (slightly slower but exercises the same reload code path)
- polls the API server `/healthz` endpoint at a tight cadence and asserts every probe returns HTTP 200 across the rotation window (the listener must not bounce; in-place fsnotify reload is required)
- captures the new cert serial via `openssl s_client` and asserts it differs from the pre-rotation serial

What this proof does NOT cover:
- mutual auth across the controller mesh — this is now covered separately by [`scripts/ci/prove-mtls-mesh.sh`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/prove-mtls-mesh.sh), which exercises the shared mTLS helper and owned-listener Subject-CN allowlist behavior
- TLS for external daemons (Kea control socket, Zeek Broker, chronyc) — FRR vtysh and Suricata command traffic now have repo-owned mTLS sidecars, but the remaining daemon control paths still speak plaintext on in-pod loopback / Unix paths
- Prometheus scrape rekey for the `fos1-internal-ca` chain — scrape configs still need `tls_config.ca_file`, `cert_file`, and `key_file`; mTLS-enabled targets fail closed under default trust until Ticket 57 lands
- trust-anchor compromise / replacement — the proof exercises rotation of leaf certs, not root replacement

## Operational Reading Guide

When reading observability-related status in this repository:

- trust controller conditions only for the resources that controller directly owns
- treat the pod-annotation scrape path for DPI and NTP as both the owned manifest contract and a narrow Kind-proven runtime path
- treat runtime probe semantics and data-plane processing as dependencies unless separately verified by integration proof
- treat architecture diagrams as target-state documentation unless a controller test or integration test proves the behavior

## Next Implementation Dependencies

The following items remain outside the verified contract covered here and define the next implementation dependencies:

- live security-event ingestion into the correlator beyond the deterministic canary proof; the Kind harness only exercises a single controlled event through the file source and file sink, not production Suricata or Zeek traffic
- proof that correlated events are exported to a durable sink or observability backend beyond the owned file sink contract
- broader observability-stack verification for alerting, dashboards, optional operator add-ons, and long-term storage behavior
