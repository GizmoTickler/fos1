# Sprint 33 — Shared-State HA + External-Daemon HA (Proposed)

**Window:** TBD
**State:** Proposed
**Production-readiness target:** ~85–90% → ~88–93%

## Goal

Sprint 31 gave every owned controller leader election with hot-standby failover. The remaining single points of failure are now the systems we don't own — Elasticsearch, Prometheus, Grafana, Alertmanager — and the external daemons FRR, Suricata, Kea, and Zeek. Sprint 33 takes the shared-state stack from single-node to clustered, and gives the external daemons a documented HA story (per-daemon: native cluster mode, sidecar replication, or operator-controlled active/standby).

## Baseline

Main HEAD when this sprint opens: TBD. Assumes Sprint 32 (mTLS / external-daemon TLS) is merged so the cluster's secure transport is in place before adding more replicas.

## Proposed tickets (65–73)

| # | Theme | Key deliverable | Priority |
|---|---|---|---|
| 65 | Elasticsearch HA — replica + snapshot | Bump `manifests/base/monitoring/elasticsearch.yaml` from single-node to 3-node, configure shard replicas (`number_of_replicas: 1`), wire snapshot repository to S3-compatible storage (operator overlay), Kind harness proves shard rebalance after node drop | P0 |
| 66 | Prometheus HA — pair + Thanos sidecar (or remote write) | 2× Prometheus replicas with Thanos sidecar OR remote-write to a long-term store. Kind harness proves dashboards return data after one Prometheus pod is killed | P0 |
| 67 | Alertmanager HA cluster | 3-node Alertmanager gossip cluster. Existing alert rules verified to deduplicate across the cluster | P0 |
| 68 | Grafana HA + sticky-session backplane | 2× Grafana replicas behind a Service with session affinity OR Grafana's DB backend pointed at a clustered Postgres. Kind harness proves dashboard loads after one replica is killed | P1 |
| 69 | FRR HA — VRRP / Anycast | FRR supports VRRP and Anycast. Document the choice; ship a 2-node config; run the Kind harness with the active FRR pod killed and assert routes converge within a documented RTO | P1 |
| 70 | Suricata HA — DaemonSet failover semantics | Suricata is a per-node DaemonSet today. Document what "HA" means for a sensor (per-node redundancy comes from k8s scheduling, not Suricata). Add a Kind harness step that kills a Suricata pod and asserts a restart preserves eve.json continuity | P1 |
| 71 | Kea HA — peer config + lease replication | Kea supports HA via the `ha` hook library. Wire two Kea replicas in active/standby with lease replication. Kind harness proves DHCP leases survive killing the primary | P1 |
| 72 | Zeek HA — cluster manager + workers | Zeek's native cluster mode (manager + N workers). 1 manager, 2 workers in the harness. Assert traffic analysis output continues across worker drop | P2 |
| 73 | Post-sprint truth-up | Standard truth-up. Recompute production readiness. Open Sprint 34 placeholder | P2 |

## Acceptance theme

After Sprint 33, every singleton in the dependency graph has either a documented HA mode in production, or an explicit non-HA caveat with the failure mode and recovery RTO documented. No production posture claim depends on "this pod won't crash."

## Critical path (draft)

`65 → 66 → 67 → 68 → (69, 70, 71, 72 in parallel) → 73`

State stack (Elasticsearch, Prometheus, Alertmanager, Grafana) goes first because the rest of the system depends on its observability proof path. External-daemon HA can be parallelized once the proof path is HA.

## Out of scope

- Cross-region failover or DR replication — single-cluster posture only in v1
- Multi-cluster federation — that's a v2+ design conversation
- Non-K8s-native HA solutions (e.g. Heartbeat, Pacemaker) — only K8s-native or operator-driven primitives in scope
