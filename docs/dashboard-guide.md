# Dashboard Guide

This repository currently provisions a small Grafana baseline around the metrics the codebase actually emits today. The provisioned dashboards come from:

- `manifests/dashboards/security-dashboard.json`
- `manifests/dashboards/network-dashboard.json`
- `manifests/dashboards/traffic-dashboard.json`

Grafana is defined in `manifests/base/monitoring/grafana.yaml` and ships with a Prometheus datasource plus file-based dashboard provisioning.

## What Is Provisioned

The base monitoring stack provisions these dashboards:

1. **Security Dashboard**
   Tracks owned DPI metrics:
   - `dpi_events_total`
   - `dpi_zeek_status`
   - `dpi_zeek_logs_processed`
   - `dpi_protocol_connections`

2. **Network Dashboard**
   Focuses on protocol-level DPI counters and gauges:
   - `dpi_protocol_connections`
   - `dpi_protocol_bytes`
   - `dpi_events_total`
   - `dpi_zeek_status`
   - `dpi_zeek_logs_processed`

3. **Timing Dashboard**
   Stored in `manifests/dashboards/traffic-dashboard.json` for now, but intentionally visualizes the owned NTP exporter metrics:
   - `ntp_sync`
   - `ntp_offset_milliseconds`
   - `ntp_jitter_milliseconds`
   - `ntp_source_count`
   - `ntp_sources_reachable`
   - `ntp_stratum`
   - `ntp_frequency_drift_ppm`

## What Is Not Provisioned

The base monitoring stack does not currently provision live dashboards for:

- traffic interface throughput/utilization metrics such as `traffic_interface_*`
- QoS or traffic-class metrics such as `traffic_class_*`
- firewall match or violation metrics such as `firewall_rule_*`
- a generic system dashboard for node-exporter style `node_*` metrics

Those concepts may appear in older docs or placeholder JSON, but they are not part of the repository-owned DPI/NTP metrics path described by this sprint.

## Accessing The Dashboards

1. Deploy the base monitoring manifests.
2. Open Grafana through the `grafana` service in the `monitoring` namespace.
3. Log in with the configured admin credentials or the secret-backed credentials used in your environment.
4. Open the dashboard picker and look for `Security Dashboard`, `Network Dashboard`, and `Timing Dashboard`.

## Alert Coverage

`manifests/base/monitoring/alert-rules.yaml` now covers only repository-owned metrics:

- DPI event burst detection
- Zeek stopped or stalled processing
- large protocol-connection spikes
- NTP sync, offset, and jitter thresholds

If you need broader infrastructure alerting, add it alongside the components that actually emit those metrics rather than assuming it exists in the baseline monitoring bundle.

## Related Optional Resources

`manifests/base/ntp/ntp-monitoring.yaml` still contains optional Prometheus Operator and Grafana Operator resources for NTP. Those resources are additive and separate from the baseline Grafana deployment under `manifests/base/monitoring/`.
