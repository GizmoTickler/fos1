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

## Ticket 5 — VRF/PBR

### Caveats
- VRF identity uses FNV-1a hash mod 252 for string names; this introduces collision risk for large VRF counts. Recommend explicit TableID in production.
- `SyncRoutingTable` hardcodes vrfID=0 for non-main VRFs instead of resolving VRF name to table ID.
- Route namespace not set in `applyRouteManifest` metadata.

## Ticket 6+7 — NAT Core

### Caveats
- Cilium client methods called with `nil` context; should use `context.Background()`.
- Only the first source address is used when multiple are provided; the rest are silently ignored.
- DNAT partial apply is not rolled back if the second port mapping fails.

## Ticket 8 — NAT Controller

### Caveats
- `isDNATPartialFailure` can panic on short error strings; should use `strings.HasPrefix`.
- Controller `extractConfig` does not handle `nat66` or `nat64` types.
- Removed status is set then immediately deleted (dead code).

## Ticket 9+10 — FRR/BGP/OSPF

### Caveats
- No rollback for `GenerateDaemonsFile`/`GenerateFRRConf` failures, leaving partial state possible.
- OSPF `refreshStatus` has no nil guard on `frrClient`.

## Ticket 11 — DHCP

### Caveats
- Controller does not persist status updates to the API server (in-memory only).
- `GetLeases` always returns `nil, nil` on success (unused method).

## Ticket 12 — DNS

### Caveats
- Default fallback zone "local" returned when no zone matches, which could mask config errors.
- PTR zones not cached locally (asymmetry with forward zones).

## Ticket 13 — NTP

### Caveats
- DNS records logged but not persisted to DNS backend.
- Missing trailing newlines in some files (style).

## Ticket 14 — WireGuard

### Caveats
- Typo in resource constant: "wiregaurd" should be "wireguard".
- Secret resolution deferred; stores "secret:name/key" strings instead of reading K8s secrets.
- Status update uses CoreV1 RESTClient for CRD resources (wrong API group).

## Ticket 16 — IDS

### Caveats
- EnableIPS/DisableIPS only toggle a local boolean; they do not reconfigure Suricata.
- Per-interface stats always empty (no per-interface socket query).
- Alert IDs are positional (change across calls).

## Ticket 17 — DPI to Cilium

### Caveats
- `DirectCiliumClient.DeleteNetworkPolicy` is log-only (consistent with its design as a dev client).
- No namespace in kubectl delete for policies.

## Ticket 18 — Auth

### Caveats
- `providerConstructors` map has no concurrent-write guard; safe during init, but `RegisterProviderConstructor` is exported.

## Sprint 31 Ticket 50 — Residual nftables NAT Imports Removed

### Status
- `pkg/network/nat/kernel.go` deleted (dead `KernelNATManager`, no active callers).
- `pkg/deprecated/nat/` deleted (dead `NAT66Manager`, no active callers).
- Active NAT path remains `pkg/network/nat/manager.go` (Cilium-first, ADR-0001).

### Residual
- `pkg/security/firewall/kernel.go` still imports `github.com/google/nftables` and remains the only production implementation of the `FirewallManager` interface consumed by `pkg/security/policy/{translator,zone_manager}.go`. Ticket 46 incorrectly reported it was gone; it is live interface code, not residual dead code, so removal is out of scope for Ticket 50 and requires a separate Cilium-backed `FirewallManager` implementation before it can be deleted. Until then, `github.com/google/nftables` remains in `go.mod`.

## Notes for Review

- Anything listed here should be treated as a deliberate tradeoff, not a hidden bug.
- If a caveat blocks production use, it should be promoted into a ticket rather than left here indefinitely.
