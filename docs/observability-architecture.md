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
- it renders `spec.rules` into `rules.json` inside the managed `ConfigMap`
- it passes `maxEventsInMemory`, `maxEventAge`, and `outputFormat` to the runtime command line
- it sets status conditions based on owned resource reconciliation and Deployment readiness

The controller status contract is intentionally limited:

- `Phase=Disabled` only when `spec.enabled=false`
- `ConfigMapReady=True` means the rules `ConfigMap` has been reconciled
- `ServiceReady=True` means the Service has been reconciled
- `DeploymentReady=True` only when the reconciled Deployment reports `status.readyReplicas > 0`
- `Ready=True` and `Phase=Running` only when the Deployment reports ready replicas
- `Phase=Pending` means the controller created or updated runtime resources, but the Deployment is not yet ready

Focused tests under `pkg/security/ids/correlation/` verify the generated ConfigMap, Deployment, Service, and the Disabled -> Pending -> Running status transitions.

### External runtime dependencies

The controller does **not** prove that event correlation is functionally processing events. That still depends on the runtime image and surrounding cluster plumbing:

- the image `fos1/event-correlator:latest` must exist and be pullable
- `/usr/bin/event-correlator` must exist in that image
- the binary must understand the generated `rules.json` format and command-line flags
- the runtime must expose working `/health` and `/ready` HTTP endpoints on port `8080`
- the runtime must have a real event ingestion path and output sink

Because those behaviors are downstream of the controller, a reconciled ConfigMap, Deployment, or Service is not treated as proof that events are being correlated. Only Deployment readiness advances controller status to `Running`.

## Other Repository-Owned Observability Surfaces

### Implemented in code, not yet verified end-to-end

The repository also contains observability-related code paths that should be treated as implemented building blocks rather than as a verified platform contract:

- `pkg/ntp/metrics/exporter.go` exposes an NTP Prometheus-style `/metrics` endpoint plus `/healthz`, but this document does not treat that as proof that Prometheus is scraping it in a cluster
- `pkg/kubernetes/metrics_server.go` exposes DPI and Zeek Prometheus metrics plus simple probe endpoints, but the repository does not currently verify a default deployment path that publishes or scrapes those metrics

These code paths matter because they are the concrete exporter/controller-side pieces the manifests are expected to consume later, but they should not be confused with an end-to-end validated observability stack.

## Broader Observability Stack

### Defined by manifests or architecture only

The repository documents a broader observability direction around Prometheus, Grafana, Alertmanager, Elasticsearch, Fluentd, and Kibana. Those sections describe target architecture and deployment intent, not a uniformly verified runtime contract.

Concrete manifest/template surfaces currently in-tree include:

- `manifests/base/monitoring/kustomization.yaml`, which assembles Prometheus, Grafana, Alertmanager, Elasticsearch, Fluentd, Kibana, and alert-rule manifests
- `manifests/base/ntp/ntp-monitoring.yaml`, which defines a `ServiceMonitor`, `PrometheusRule`, and `GrafanaDashboard` for the NTP service
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
- actual Service, scrape, and network-policy wiring between exporters and collectors

## Operational Reading Guide

When reading observability-related status in this repository:

- trust controller conditions only for the resources that controller directly owns
- treat exporter packages as code-level capabilities unless a deployment path and scrape path are separately verified
- treat image behavior, probe semantics, and data-plane processing as external dependencies unless separately verified
- treat architecture diagrams as target-state documentation unless a controller test or integration test proves the behavior

## Next Implementation Dependencies

The following items remain outside the verified contract covered here and define the next implementation dependencies:

- end-to-end validation that the event correlator image consumes live security events
- proof that correlated events are exported to a durable sink or observability backend
- an owned deployment path that publishes the in-repo exporter endpoints and wires them to collectors
- broader observability-stack verification for metrics, logging, alerting, and dashboards
