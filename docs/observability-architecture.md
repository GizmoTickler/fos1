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

### Runtime dependencies not proven end to end

The controller does **not** prove that event correlation is functionally processing events. That still depends on the runtime image and surrounding cluster plumbing:

- the repo-owned image build output must contain a working `/usr/bin/event-correlator` binary that understands the generated `config.json` format and command-line flags
- the runtime must expose working `/health` and `/ready` HTTP endpoints on port `8080`
- the runtime must have the referenced source file available when `spec.source.type=file`
- the runtime must honor the minimal owned sink contract:
  - `spec.sink.type=file` writes JSON output to the configured path
  - `spec.sink.type=stdout` writes JSON output to stdout

Because those behaviors are downstream of the controller, a reconciled ConfigMap, Deployment, or Service is not treated as proof that events are being correlated. Only Deployment readiness advances controller status to `Running`.

## Other Repository-Owned Observability Surfaces

### Implemented in code, with targeted runtime proof for the owned scrape baseline

The repository also contains observability-related code paths that should be treated as implemented building blocks rather than as a verified platform contract:

- `pkg/ntp/metrics/exporter.go` exposes an NTP Prometheus-style `/metrics` endpoint plus `/healthz`, and the owned manifest baseline now expects pod-annotation scraping on `ntp-controller` pods at `:9559/metrics`
- `pkg/kubernetes/metrics_server.go` exposes DPI and Zeek Prometheus metrics plus simple probe endpoints, and the owned manifest baseline now expects pod-annotation scraping on `dpi-manager` pods at `:8080/metrics`

Those manifest contracts now have a narrow live-cluster proof in the Kind harness. The proof is intentionally limited to discovery and successful scraping of the owned pod-annotation targets; it does not prove every downstream rule, dashboard, or operator-driven integration.

### Repository-owned baseline scrape path

The baseline metrics collection path owned by this repository is the `kubernetes-pods` job in [manifests/base/monitoring/prometheus.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/monitoring/prometheus.yaml). That job discovers pods only when they carry standard Prometheus pod annotations.

After the Ticket 2 manifest changes, the owned exporter contract is:

- [manifests/base/security/dpi-manager.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/security/dpi-manager.yaml): `dpi-manager` is now a node-local `DaemonSet`; each pod exposes `/metrics`, `/healthz`, and `/readyz` on the single HTTP listener at port `8080`, and the pod template is annotated for pod-based scraping on `:8080/metrics`
- [manifests/base/ntp/ntp-controller.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/ntp/ntp-controller.yaml): the active `ntp-controller` deployment in the `network` namespace exposes the exporter on port `9559`, carries the pod annotations for scraping on `:9559/metrics`, and exposes the API listener on `8080`
- [manifests/base/ntp/service.yaml](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/manifests/base/ntp/service.yaml): the active `ntp-controller` service is the service-level endpoint used by optional operator resources such as the `ServiceMonitor`

This is the exact repository-owned path. It does not depend on a `ServiceMonitor`, and it does not require Prometheus Operator CRDs.

### Repository-owned Prometheus scrape proof path

The bootstrap harness now proves that the owned pod-annotation scrape path is active in a live Kind cluster:

- harness source: [scripts/ci/prove-prometheus-scrapes.sh](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/scripts/ci/prove-prometheus-scrapes.sh) port-forwards Prometheus, inspects `/api/v1/targets`, and queries `up{...}` through `/api/v1/query`
- proof target 1: every ready `security/dpi-manager` pod discovered by the node-local `DaemonSet` must appear as an active `kubernetes-pods` target with `health="up"` and an `up=1` sample
- proof target 2: every ready `network/ntp-controller` pod must appear as an active `kubernetes-pods` target with `health="up"` and an `up=1` sample
- Kind scope narrowing: [`.github/workflows/test-bootstrap.yml`](/Users/varuntirumalareddy/Documents/Code-Playgroud/fos1/.github/workflows/test-bootstrap.yml) rewrites the copied `test-manifests/base/ntp/kustomization.yaml` so the proof deploys only `ntp-crd.yaml`, `ntp-controller.yaml`, and `service.yaml`; optional operator add-ons and the chrony daemonset/runtime slice are intentionally excluded because they are not required to prove the repository-owned Prometheus path

If those checks pass, the repository has proven the baseline it actually owns: Prometheus discovers the annotated pods, scrapes the active exporters, and records a live `up=1` series for both the node-local DPI manager path and the NTP controller path.

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
- that the `14d` delete phase has actually executed against an aged index
- that PVC-backed monitoring state has been exercised through restart or reschedule events

## Operational Reading Guide

When reading observability-related status in this repository:

- trust controller conditions only for the resources that controller directly owns
- treat the pod-annotation scrape path for DPI and NTP as both the owned manifest contract and a narrow Kind-proven runtime path
- treat runtime probe semantics and data-plane processing as dependencies unless separately verified by integration proof
- treat architecture diagrams as target-state documentation unless a controller test or integration test proves the behavior

## Next Implementation Dependencies

The following items remain outside the verified contract covered here and define the next implementation dependencies:

- end-to-end validation that the event correlator image consumes live security events; this repository does not prove live security-event ingestion into the correlator end to end
- proof that correlated events are exported to a durable sink or observability backend
- broader observability-stack verification for alerting, dashboards, optional operator add-ons, and long-term storage behavior
