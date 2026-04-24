# Sprint 31 / Ticket 47: HA / Controller Leader Election Baseline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Every owned controller participates in leader election with a documented RTO (≤ 30s). Deployments scale to 2 replicas with anti-affinity. A CI harness proves one failover cycle in Kind.

**Architecture:** Use `sigs.k8s.io/controller-runtime/pkg/manager`'s built-in leader election (`LeaderElection: true`, `LeaderElectionID: <controller-name>`, `LeaderElectionNamespace: <controller-ns>`). Backed by `coordination.k8s.io/v1` Lease objects. Standby replica blocks at `mgr.Start(ctx)` until it becomes leader.

**Tech Stack:** Go, `controller-runtime`, Kubernetes Leases, Kind, shell scripts.

---

## File Map

- Modify every controller `main.go`:
  - `cmd/api-server/main.go`
  - `cmd/certificate-controller/main.go`
  - `cmd/cilium-controller/main.go`
  - `cmd/dpi-framework/main.go`
  - `cmd/dpi-manager/main.go`
  - `cmd/ids-controller/main.go`
  - `cmd/threatintel-controller/main.go`
  - `cmd/wireguard-controller/main.go`
  - any other controller main discovered under `cmd/`
- Modify every controller `Deployment`:
  - `manifests/base/*/deployment.yaml` (replicas: 2 + podAntiAffinity on `kubernetes.io/hostname`)
- Modify every controller's RBAC to grant `coordination.k8s.io/leases` verbs `get,list,watch,create,update,patch,delete` scoped to the controller's namespace:
  - `manifests/base/*/rbac.yaml`
- Create: `scripts/ci/prove-leader-failover.sh` — kill active leader, assert standby promotes within RTO
- Modify: `.github/workflows/test-bootstrap.yml` — add leader-failover proof step
- Create: `docs/design/high-availability.md` — architecture, RTO target, single-node Kind fallback behavior
- Modify: `Status.md` — HA row from "Single point of failure" to "Leader election with hot standby; RTO ≤ 30s"
- Modify: `docs/design/implementation_caveats.md` — close "HA is single-replica" caveat; open new ones for what HA does NOT cover (shared state in Elasticsearch/Prometheus, external-daemon singletons like FRR)

## Tasks

### Task 1: Wire Leader Election Into Every Controller Main

- [ ] For each controller main, import `sigs.k8s.io/controller-runtime/pkg/manager` and construct the manager with:
  ```go
  mgr, err := manager.New(cfg, manager.Options{
      LeaderElection:          true,
      LeaderElectionID:        "<controller-name>.fos1.io",
      LeaderElectionNamespace: os.Getenv("POD_NAMESPACE"),
      LeaderElectionReleaseOnCancel: true,
  })
  ```
- [ ] Controllers that don't use controller-runtime manager today (check each): migrate them, or use `leaderelection.NewLeaderElector` from `k8s.io/client-go` directly.
- [ ] Every Deployment sets `POD_NAMESPACE` from the downward API.

### Task 2: Deployment Scale + Anti-Affinity

- [ ] Every `manifests/base/*/deployment.yaml` sets `replicas: 2`.
- [ ] Add a `preferredDuringSchedulingIgnoredDuringExecution` podAntiAffinity keyed on `kubernetes.io/hostname` with the controller's `app` label. Use `preferred` (not required) so single-node Kind still schedules both replicas.
- [ ] Each Deployment's rollout strategy sets `maxUnavailable: 1` to allow rolling restart without losing quorum.

### Task 3: RBAC Grant For Leases

- [ ] Every controller ServiceAccount gets a Role (namespace-scoped, not ClusterRole — leases are per-namespace) granting:
  ```yaml
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  ```
- [ ] Re-run Ticket 42's `scripts/ci/prove-no-cluster-admin.sh` to confirm no new `cluster-admin` bindings were introduced.

### Task 4: Failover Proof Harness

- [ ] `scripts/ci/prove-leader-failover.sh`:
  - pick one controller (recommend `dpi-manager` since it's already deployed in the Kind harness)
  - `kubectl get lease <controller>.fos1.io -o jsonpath='{.spec.holderIdentity}'` → record current leader pod name
  - `kubectl delete pod <leader-pod>` with `--grace-period=0 --force`
  - poll lease `holderIdentity` on 2s cadence up to 60s
  - assert the new holder is a different pod and is `Ready`
  - tear-down: let the killed pod recreate naturally
- [ ] Add the step to `.github/workflows/test-bootstrap.yml` after the existing controller-deployment steps.

### Task 5: Docs + Status

- [ ] `docs/design/high-availability.md`:
  - model: active/standby per controller
  - RTO target: ≤ 30s under default lease timings (`LeaseDuration: 15s`, `RenewDeadline: 10s`, `RetryPeriod: 2s`)
  - single-node fallback: `preferred` anti-affinity so two replicas co-schedule on one node; lease still elects a leader
  - what HA does NOT cover: external daemon singletons (FRR, Suricata, Zeek, Kea process), shared-state services (Elasticsearch, Prometheus) — flagged as Sprint 32 candidates
- [ ] `Status.md` HA row: complete wording per Acceptance.
- [ ] `docs/design/implementation_caveats.md`: close the old caveat, open explicit new ones for what's out of scope.

## Verification

- [ ] `make verify-mainline` green
- [ ] CI harness reports successful failover in Kind
- [ ] Every controller Deployment has 2 replicas in the rendered manifest
- [ ] No new `cluster-admin` bindings

## Out Of Scope

- External daemon HA (FRR, Suricata, Kea) — Sprint 32
- Elasticsearch / Prometheus HA — Sprint 32
- State replication beyond lease-based leader election (controllers remain stateless per reconcile cycle)
- N>2 replicas

## Suggested Branch

`sprint-31/ticket-47-ha-leader-election`
