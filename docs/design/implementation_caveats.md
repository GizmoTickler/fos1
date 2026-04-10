# Implementation Caveats

This document tracks important caveats, tradeoffs, and remaining gaps that Architects should review before the next implementation step.

## Ticket 1 — Cilium-First Control-Plane Contract

### Caveats
- Kernel-native helpers still exist and may be used as support code, but they are not the authoritative v1 control plane.
- Several docs still describe older or mixed control-plane assumptions.
- The contract intentionally deprecates placeholder success paths, which may require follow-up cleanup in older controllers.

## Ticket 2 — Cilium Client Route Operations

### Caveats
- Route operations are applied through `kubectl`/CRD flows rather than a native client-go apply path.
- Route deletion depends on CRD identity and assumes the object name can be derived from route fields.
- Route listing is CRD-backed, not native eBPF/Cilium datapath inspection.

## Ticket 3 — Route Synchronization

### Caveats
- Kernel route discovery falls back to empty results when the environment cannot list routes due to permission or test-environment limitations.
- VRF identity resolution is still string-based and not a full VRF registry lookup.
- Cilium route synchronization is CRD-backed, so route truth is derived from Route objects rather than direct eBPF map inspection.
- Deletion relies on route identity fields being present on the sync object.

## Ticket 4 — Routing Controller Reconciliation

### Caveats
- The legacy `pkg/cilium/controllers/controller_manager.go` path still uses its own routing controller wiring and is not yet unified with the `pkg/controllers` routing controller flow.
- The new Cilium-backed routing adapter requires a real Cilium client; callers that still construct the routing controller without one will fail fast.
- VRF/table translation is still best-effort and uses current string/ID heuristics, not a full authoritative VRF registry.

## Notes for Review

- Anything listed here should be treated as a deliberate tradeoff, not a hidden bug.
- If a caveat blocks production use, it should be promoted into a ticket rather than left here indefinitely.
