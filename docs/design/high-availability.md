# High Availability — Controller Active/Standby

> Sprint 31 / Ticket 47. Companion to the controller mains under `cmd/`
> and the manifests under `manifests/base/`.

## Goal

Every owned controller participates in active/standby leader election so a
pod-level failure (node drain, OOM kill, rolling restart) does not stop
reconciliation for longer than the documented Recovery Time Objective.

**RTO target: ≤ 30 seconds.** Two replicas of every controller run; one
holds the Lease object, the other blocks until the lease's
`RenewDeadline` expires.

## Architecture

```
                ┌─────────────────────────────────────┐
                │ coordination.k8s.io/v1 Lease object │
                │  name: <controller>.fos1.io         │
                │  namespace: <controller's ns>       │
                │  spec.holderIdentity: <pod-name>    │
                └─────────────────────────────────────┘
                              ▲           ▲
                              │ renew     │ poll
                              │ every     │ every
                              │ 2s        │ 2s
                ┌─────────────┴───┐   ┌───┴─────────────┐
                │ Pod A (LEADER)  │   │ Pod B (STANDBY) │
                │ runs reconciler │   │ blocks until    │
                │                 │   │ Pod A loses     │
                │                 │   │ the lease       │
                └─────────────────┘   └─────────────────┘
```

### Library

Two implementations, both backed by `coordination.k8s.io/v1` Leases:

1. **`sigs.k8s.io/controller-runtime/pkg/manager`** — used by
   `cmd/api-server/main.go` because it already runs on the manager.
   Manager-level leader election gates only runnables that report
   `NeedLeaderElection() == true` (controllers / reconcilers).
   Webhook server, metrics, and the cache run in both leader and
   standby.
2. **`pkg/leaderelection` (this repo)** — a thin wrapper over
   `k8s.io/client-go/tools/leaderelection` for controllers that don't
   use controller-runtime today. The wrapper enforces the
   fos1-standard timings (15s / 10s / 2s) and writes a structured log
   on each leadership transition.

Both speak the same Lease object format, so a controller can migrate
between the two without changing the Lease name or RBAC.

### Timings

| Field         | Value | Rationale |
| ------------- | ----- | --------- |
| LeaseDuration | 15s   | Time a lease is valid before any peer can attempt acquisition. RTO floor. |
| RenewDeadline | 10s   | Active leader retries renewal for up to 10s before giving up. Must be `< LeaseDuration`. |
| RetryPeriod   | 2s    | How often peers poll the lease and how often the leader retries renewal. |

These give an RTO ≤ 30s under standard apiserver latency. They are the
same values controller-runtime defaults to, so the manager-level and
client-go-level controllers behave identically.

### Deployment Shape

Every controller `Deployment` in `manifests/base/*/`:

* `replicas: 2`
* `strategy.rollingUpdate.maxUnavailable: 1` so a rolling restart only
  ever takes one replica out at a time.
* `affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution`
  on `kubernetes.io/hostname` with the controller's `app` label. The
  `preferred` flavour (not `required`) lets a single-node Kind cluster
  schedule both replicas — required would block scheduling and the CI
  failover proof would never have a standby to elect.
* Two downward-API env vars on the container:
  * `POD_NAMESPACE` — the namespace the Lease is created in.
  * `POD_NAME` — used as the leader-election Identity, which is also
    what the failover proof script kills.

### RBAC

Every controller's RBAC includes a **namespace-scoped** `Role` named
`<controller>-leaderelection` with the verbs:

```yaml
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

A `RoleBinding` in the same namespace binds it to the controller's
ServiceAccount. **No `ClusterRole` or `ClusterRoleBinding`** is added —
the lease lives in a single namespace and Sprint 30 / Ticket 42's
minimum-privilege baseline (`scripts/ci/prove-no-cluster-admin.sh`)
must keep passing.

## Failover Proof

`scripts/ci/prove-leader-failover.sh` runs in
`.github/workflows/test-bootstrap.yml` after the
`Deploy IDS controller for event correlation proof` step:

1. Read the current `holderIdentity` from the
   `ids-controller.fos1.io` Lease in the `security` namespace.
2. Force-delete that pod with `--grace-period=0 --force`.
3. Poll the Lease's `holderIdentity` every 2s for up to 60s.
4. Assert the new holder is a different pod and is `Ready`.
5. Warn if the handover took longer than the 30s RTO target.

The target is **`ids-controller`**, not `dpi-manager` (the original plan
suggested), because:

* `dpi-manager` is a `DaemonSet` (one pod per node, node-local). Leader
  election does not apply: the pods are intentionally independent and
  there is no concept of an "active" instance for the cluster as a
  whole. Forcing leader election onto a DaemonSet would defeat its
  purpose.
* `ids-controller` is a `Deployment` already deployed in the Kind
  harness (separate apply step after the base security kustomization).
  It now runs `replicas: 2` with the standard pod-level antiAffinity,
  giving the proof a real standby to elect.

## What HA Does Not Cover

Active/standby controller HA is the only thing in scope for Sprint 31
Ticket 47. The following remain single-instance and are flagged as
Sprint 32 candidates:

* **External daemon singletons.** The runtime side of FRR (BGP / OSPF),
  Suricata (IDS), Zeek (IDS), and Kea (DHCP) is shipped as
  single-pod / single-process daemons. Their state is process-local;
  none of them participate in the leader-election contract above.
  Failover for these is a separate per-daemon design (FRR has BFD, Kea
  has a HA hooks library, Suricata can run as parallel sensors).
* **Shared-state services.** Elasticsearch and Prometheus run as
  single-replica StatefulSets today; they hold real persistent data and
  cannot be replicated by leader election alone. Multi-node clustering
  (ES cross-zone replication, Prometheus federation or Thanos) is a
  separate sprint.
* **DaemonSets.** `dpi-manager` is the only owned DaemonSet that runs
  reconciliation logic; it is intentionally per-node and is excluded
  from leader election.
* **Single-replica Deployments by design.** `trafficshaper-controller`
  uses `hostNetwork: true` to drive TC on the uplink netdev. Two
  replicas on the same host would conflict. Its RBAC already grants
  the lease verbs (Sprint 31 Ticket 52 added them in advance), so once
  the operator deploys it across two nodes a future ticket can flip
  `replicas: 1` to `replicas: 2` without any RBAC work. The same
  caveat applies to any future host-mode controller.

## How To Onboard A New Controller

1. **Pick the library.** New controllers should prefer
   `pkg/leaderelection` unless they already need the controller-runtime
   manager (cache, webhook server, runnable graph).
2. **Wire `main.go`.** Wrap the existing run loop in a leader callback.
   Pass the kube client, `POD_NAMESPACE`, and `POD_NAME` from the
   downward API.
3. **Update the Deployment.** `replicas: 2`, `maxUnavailable: 1`,
   `podAntiAffinity` (preferred), and the `POD_NAMESPACE` /
   `POD_NAME` env entries.
4. **Add the RBAC.** A namespace-scoped `Role` +
   `RoleBinding` with the lease verbs above. **Do not add a
   `ClusterRoleBinding`** — `prove-no-cluster-admin.sh` will fail
   the build if a cluster-admin binding sneaks in.
5. **(Optional) Extend the failover proof.** If the new controller is
   important enough to gate merges on, add a step that runs
   `LEADER_FAILOVER_DEPLOYMENT=<name> bash
   scripts/ci/prove-leader-failover.sh` to the test-bootstrap
   workflow. The script accepts override env vars for namespace,
   deployment, lease name, and timeout.
