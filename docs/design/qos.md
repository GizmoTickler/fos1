# QoS Enforcement Design (v1)

**Status:** Accepted (Sprint 30 / Ticket 45; complemented by Ticket 39)
**Supersedes:** Legacy TC-based prototype in `pkg/security/qos/manager.go`
(removed in Ticket 45)
**Related:**
[ADR-0001 Cilium-first control plane](adr-0001-cilium-first-control-plane-contract.md),
Ticket 39 (TC-attached QoS classifier — orthogonal uplink-side loader,
delivered as infrastructure in `pkg/hardware/ebpf.TCLoader` +
`bpf/tc_qos_shape.c`).

---

## Goal

Enforce per-pod egress rate limits in FOS1 using a Kubernetes-native control
surface (`QoSProfile` CRD) and an in-kernel Cilium backend, without
reintroducing the `tc`/`ip` binary dependency that the Ticket 20 prototype
had.

## Decision

Use **Cilium's Bandwidth Manager** via Kubernetes pod annotations.

- A `QoSProfile` CR names a **pod selector** and an **egress bandwidth**
  (and optionally an ingress bandwidth).
- The controller (`pkg/controllers/qos_controller.go`) reconciles the CR
  into two standard annotations on each matching pod:
  - `kubernetes.io/egress-bandwidth` — honored by Cilium's Bandwidth
    Manager.
  - `kubernetes.io/ingress-bandwidth` — written when set on the CR;
    forward-compatible.
- Cilium (running with `--enable-bandwidth-manager=true`, already enabled
  in `manifests/base/cilium/cilium.yaml`) installs an eBPF TBF rate
  limiter on each matching pod's veth at admission/CNI-ADD time.

## Why Not TC?

The Ticket 20 prototype shelled out to `tc qdisc add` on reconcile. Three
problems pushed us off that path:

1. **Binary dependency at runtime.** Container images must ship `tc` and
   `ip`, and the controller runs on every node with `NET_ADMIN`. That's a
   real attack-surface and supply-chain cost.
2. **No idempotency.** `tc qdisc add` fails if the qdisc already exists;
   correct handling requires parsing `tc -j` output, building diffs, and
   reconciling piecewise. Cilium already did this work once — we don't
   need to redo it.
3. **Scope mismatch.** The TC prototype modelled classful HTB shaping
   (per-class min/max, DSCP filters). That is the right backend for
   **uplink** shaping on WAN interfaces (Ticket 39's territory), not for
   per-pod rate limiting.

Cilium's Bandwidth Manager is designed for exactly the per-pod case and
integrates with pod lifecycle events we already receive.

## In Scope (v1)

- Per-pod **egress** rate limits, keyed by a `metav1.LabelSelector`.
- Cluster-scoped profiles (`spec.clusterScoped: true`) and namespaced
  profiles (default — selector is evaluated in the CR's namespace).
- Idempotent re-apply: the translator emits a stable hash
  (`fos1.io/qos-applied-hash`) and the reconciler skips any pod whose
  existing annotations already match the desired state.
- Tear-down on delete: `fos1.io/qos-profile=<name>` bookkeeping means
  a profile-delete cleanly strips only its own pods' annotations without
  clobbering annotations owned by another profile.
- Status writeback via the shared `pkg/controllers/status.Writer` with
  `Applied`, `Degraded`, `Invalid`, `Removed` conditions, matching the
  pattern used by NAT, FilterPolicy, and MultiWAN.

## Non-Goals (v1)

- **Classful HTB shaping.** DSCP-aware class bands with per-class rate +
  ceiling live under a future VLAN-shaper controller. Ticket 39 ships
  the underlying TC-bpf loader (`pkg/hardware/ebpf.TCLoader` +
  `bpf/tc_qos_shape.c`) that attaches to **uplink** NICs via a `clsact`
  qdisc and stamps `skb->priority` for downstream classful qdiscs —
  there is no CR consumer yet, by design. It does not overlap with
  per-pod Bandwidth Manager.
- **Ingress rate limiting in the data path.** Cilium's Bandwidth Manager
  currently enforces **egress only**. The CR accepts an ingress value so
  the control plane is forward-compatible, but operators should not
  expect ingress enforcement today — that's a Cilium/kernel capability
  we adopt when it lands.
- **Per-VLAN QoS tagging (802.1p).** Handled in the VLAN manager's
  queue-mapping path (`pkg/network/vlan/qos.go`), either via the `ip`
  command fallback or via the Ticket 39 TC-bpf loader; not in per-pod
  annotations.
- **Hardware offload** of the rate limiter. Cilium's BPF-TBF runs on the
  host CPU. Intel I225/X540/X550 hardware traffic classes belong to
  Ticket 35's hardware-integration track.
- **Classless shaping on arbitrary interfaces** (e.g. bond0, wg0). The
  annotations apply to pod veths only. Host-interface shaping is outside
  the CNI path and therefore outside this CR's scope.

## Kernel / Cilium Requirements

Bandwidth Manager requires:

- A kernel with the `sch_fq` qdisc compiled in (mainline 4.19+; Talos
  Linux ships this).
- Cilium ≥ v1.14. The base `cilium.yaml` currently pins v1.17.1 (see
  `manifests/base/cilium/cilium.yaml`).
- `--enable-bandwidth-manager=true` on the agent (set in the base
  DaemonSet args **and** the `cilium-config` ConfigMap).

No additional kernel modules or BPF object files are needed; the
data-path program is part of Cilium's own BPF pipeline.

## Caveats

1. **Annotation-at-admission is one-shot.** Cilium applies the rate
   limiter when the pod veth is created (CNI-ADD). Changing the
   annotation on a running pod is **not** guaranteed to change the
   enforced rate — some Cilium versions require a pod restart to pick up
   a new annotation value. The FOS1 controller still patches annotations
   on running pods so the value is correct going forward; operators
   should treat a QoSProfile as the desired state at next pod churn.
2. **Selector ambiguity.** If two `QoSProfile` CRs select overlapping
   pods, last-writer-wins on the `kubernetes.io/egress-bandwidth`
   annotation. The `fos1.io/qos-profile` bookkeeping records the last
   profile to touch the pod; operators can detect the conflict by
   listing pods and grouping by that annotation. v1 does **not** have a
   profile priority mechanism — add explicit tests if you author
   overlapping selectors.
3. **Ingress is aspirational.** As above — `spec.ingressBandwidth` is
   accepted and written as an annotation, but the kernel/Cilium may not
   yet enforce it. Operators should treat v1 as egress-only.

## Architecture

```
     ┌─────────────────┐
     │  QoSProfile CR  │  (user)
     └────────┬────────┘
              │
              ▼ informer
     ┌─────────────────────────┐      ┌──────────────────────┐
     │ pkg/controllers/        │      │ pkg/controllers/     │
     │   qos_controller.go     │◀────▶│   status/writer.go   │
     └────────┬────────────────┘      │ (status subresource) │
              │                       └──────────────────────┘
              ▼ Translate + ApplyToPods
     ┌──────────────────────────────┐
     │ pkg/security/qos/            │
     │   bandwidth_manager.go       │  (pure translator +
     │                              │   kubernetes patch loop)
     └──────────┬───────────────────┘
                │ MergePatch on Pod annotations
                ▼
     ┌──────────────────────────────┐
     │ Pod.metadata.annotations     │
     │   kubernetes.io/egress-bw    │
     │   fos1.io/qos-profile        │
     │   fos1.io/qos-applied-hash   │
     └──────────┬───────────────────┘
                │
                ▼ CNI-ADD / kubelet sync
     ┌──────────────────────────────┐
     │ Cilium Bandwidth Manager     │
     │ (eBPF TBF on pod veth)       │
     └──────────────────────────────┘
```

## Testing

- `pkg/security/qos/bandwidth_manager_test.go` — translator + reconciler
  unit tests covering idempotency, drift repair, partial apply, cluster
  scope, and tear-down isolation between profiles.
- `pkg/controllers/qos_controller_test.go` — controller decision tree
  (Invalid, partial apply, delete sweep, legacy `uploadBandwidth`
  fallback).
- Manual verification in a Kind cluster: apply
  `manifests/examples/qos/qosprofile-example.yaml`, create a pod with
  label `app: noisy`, and confirm both
  `kubernetes.io/egress-bandwidth=10M` and the `fos1.io/qos-profile`
  annotation land on the pod.

## Migration Notes

The previous TC-based `QoSManager` in `pkg/security/qos/manager.go` has
been reduced to a data-only types shim. The types themselves
(`QoSProfile`, `TrafficClass`, `ClassStatistics`) remain exported for
downstream packages that referenced them, but they carry no behaviour.
Any new QoS work should target the `bandwidth_manager.go` surface.

The existing `manifests/examples/traffic/*-qos.yaml` files still apply
cleanly — the controller's extractor treats the legacy `uploadBandwidth`
field as a fallback for `egressBandwidth` so pre-Ticket-45 profiles are
picked up as egress rate limits as long as a `podSelector` is added.
Without a `podSelector` the CR is flagged Invalid=True (the explicit
signal that a profile has nothing to enforce under v1 semantics).
