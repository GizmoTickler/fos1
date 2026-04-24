# Sprint 31 / Ticket 52: VLAN-Scoped TC Shaper Controller

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Ticket 39 shipped the TC loader + clsact qdisc bootstrap + per-ifindex priority map as infrastructure with no CRD consumer. Introduce a `TrafficShaper` CRD that drives the TC loader for VLAN-scoped or uplink egress shaping.

**Architecture:** New CRD + controller. Composes with Ticket 45 (pod egress via Cilium Bandwidth Manager) — the two handle different scopes:
- `QoSProfile` (Ticket 45): per-pod egress caps via annotations
- `TrafficShaper` (this ticket): per-interface (uplink, VLAN, bond) priority marking + shaping via TC/eBPF

**Tech Stack:** Go, Kubernetes CRDs, `pkg/hardware/ebpf.TCLoader` (from Ticket 39).

**Prerequisite:** Ticket 39 merged (it is). Ticket 40 status writer (merged) is used for reconciliation.

---

## File Map

- Create: `pkg/apis/network/v1alpha1/trafficshaper_types.go` — `TrafficShaper` + `TrafficShaperList` + deepcopy
- Create: `pkg/controllers/trafficshaper_controller.go`
- Create: `pkg/controllers/trafficshaper_controller_test.go`
- Create: `pkg/security/qos/traffic_shaper.go` — translator: `TrafficShaper.Spec.Rules` → `TCLoader.SetPriority` calls
- Create: `manifests/base/trafficshaper/{crd,deployment,rbac,kustomization}.yaml`
- Create: `manifests/examples/qos/trafficshaper-example.yaml`
- Modify: `docs/design/qos.md` — extend with §VLAN-Scoped Shaping (Ticket 52)
- Modify: `Status.md` QoS row: "per-pod egress via Cilium Bandwidth Manager (45) + per-interface via TrafficShaper (52)"

## CRD Shape

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: TrafficShaper
metadata:
  name: uplink-priority
  namespace: network
spec:
  interface: eth0
  direction: egress          # egress | ingress | both
  rules:
    - matchCIDR: "10.0.0.0/8"
      priority: 5            # TC priority class
      rate: "100Mbit"        # optional rate cap via TBF
    - matchDSCP: 46          # optional DSCP match
      priority: 1
status:
  appliedRuleCount: 2
  conditions:
    - type: Applied
      status: "True"
    # ...
```

## Tasks

### Task 1: CRD Types + Deepcopy

- [ ] Define `TrafficShaperSpec` with `Interface string`, `Direction string`, `Rules []Rule` where `Rule` has `MatchCIDR`, `MatchDSCP`, `Priority`, `Rate`.
- [ ] Define `TrafficShaperStatus` with `LastAppliedHash`, `Conditions`, `AppliedRuleCount`.
- [ ] Generate deepcopy (controller-gen or manual matching the existing Sprint 30 patterns).

### Task 2: Translator + Controller

- [ ] `pkg/security/qos/traffic_shaper.go`:
  - `Translate(spec *TrafficShaperSpec) ([]TCLoaderOp, error)` — turn rules into `TCLoader.SetPriority` / `AttachIngress` / `AttachEgress` calls
  - `Apply(shaper *TrafficShaper)` — invoke `TCLoader`, return error on failure
  - idempotent via spec-hash
- [ ] `pkg/controllers/trafficshaper_controller.go`:
  - reconcile loop matches Sprint 30 pattern (NAT / FilterPolicy)
  - uses `pkg/controllers/status.Writer[*TrafficShaper]` (Ticket 40)
  - conditions: `Applied`/`Degraded`/`Invalid`/`Removed`

### Task 3: Manifests + Example

- [ ] CRD, Deployment (1 replica, will scale to 2 after Ticket 47 adopts leader election), RBAC (verbs on `trafficshapers`, `coordination.k8s.io/leases` if launched after 47).
- [ ] Example: `trafficshaper-example.yaml` shaping an uplink interface `eth0` with DSCP 46 → priority 1.

### Task 4: Tests

- [ ] Unit tests for the translator (rule fan-out, hash stability, empty spec rejected).
- [ ] Controller tests with a fake TCLoader: add, update (change rules), delete transitions.

### Task 5: Docs + Status

- [ ] `docs/design/qos.md` §VLAN-Scoped Shaping (Ticket 52): architecture, composition with Ticket 45, kernel requirements (6.6+ for AttachTCX same as Ticket 39).
- [ ] `Status.md` QoS row updated.

## Verification

- [ ] `make verify-mainline` green
- [ ] `go test ./pkg/controllers/trafficshaper_controller_test.go ./pkg/security/qos/...` passes
- [ ] Example manifest validates under `kubeconform` (skipped because CRD not in library — same as QoSProfile)

## Out Of Scope

- Classful HTB/TBF on non-Cilium paths — stays aspirational
- Per-VLAN automatic discovery — operator specifies `spec.interface` explicitly
- Ingress shaping (TC ingress on clsact is supported but rules are simpler; v0 is egress-first)

## Suggested Branch

`sprint-31/ticket-52-vlan-tc-shaper`
