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

## Ticket 33 — FilterPolicy Cilium Enforcement

### Caveats
- The controller mutates FilterPolicy.Status in the in-memory cache but does
  not yet persist those conditions via a CRD status subresource update. This
  matches the previous behavior of the stub controller; callers relying on
  server-observable conditions should lift the NAT controller's
  `writeStatusToCRD` pattern (see `pkg/controllers/nat_controller.go:558`)
  into this controller as a follow-up.
- Spec-hash idempotency is computed from a canonical JSON projection of the
  spec. Fields added to `FilterPolicySpec` in the future must be included
  in `canonicalizeSpec()` or the hash will not reflect real changes.
- The Cilium client's `DeleteNetworkPolicy` shells out to
  `kubectl delete cnp --ignore-not-found`, so the delete path depends on
  `kubectl` being on PATH wherever this controller runs. This is consistent
  with the existing NAT controller contract.
- `FirewallRule` CRD and nftables enforcement are non-goals per ADR-0001
  (Cilium-first control plane). `FilterPolicy` is the authoritative policy
  surface; sprint 29 ticket 33 removed `pkg/cilium/controllers/firewall_controller.go`,
  `pkg/security/firewall/`, the nftables-based `PolicyTranslator`/`ZoneManager`,
  and the `manifests/base/cilium/crds/firewall_rules.yaml` CRD manifest.
  Existing clusters that had `FirewallRule` CRs applied must migrate them
  to `FilterPolicy` before upgrading.

## Ticket 38 — eBPF XDP Compile and Load Pipeline

### Caveats

- Only XDP is implemented in the owned compile/load path. TC, sockops,
  and cgroup program types go through `ErrEBPFProgramTypeUnsupported`
  and are explicit non-goals until Sprint 30 Ticket 39 extends to TC.
- The compiled ELF (`pkg/hardware/ebpf/bpf/xdp_ddos_drop.o`) is
  committed to the repository so `go build` works on machines without
  a BPF-capable clang. This means a contributor who edits
  `bpf/xdp_ddos_drop.c` MUST re-run `make bpf-objects` on a Linux (or
  Homebrew-llvm) host and commit the regenerated object. CI does not
  currently diff the committed ELF against a fresh recompile.
- Apple's bundled `/usr/bin/clang` does NOT ship the BPF backend; the
  Makefile target fails fast with an actionable error when run against
  a clang that lacks `bpf` in `-print-targets`. `make verify-mainline`
  does NOT invoke `make bpf-objects`, so macOS CI runners can still go
  green without an LLVM install.
- The embedded object is validated by ELF magic (`0x7f 'E' 'L' 'F'`)
  before the loader runs. An empty or placeholder file yields
  `ErrEBPFObjectMissing`, which the program-manager dispatch surfaces
  to callers — but there is no cryptographic/BTF integrity check on
  the committed bytes.
- `link.XDPGenericMode` is used for attachment so the Linux
  integration test can drive a `netlink.Dummy` interface without a
  driver-native XDP path. Production deployments on NICs that support
  native XDP should select the mode explicitly when this loader moves
  behind a CRD-driven controller; right now the flag is hard-coded.
- Capability detection uses a raw `unix.Capget` syscall against
  `LINUX_CAPABILITY_VERSION_3`. Older kernels (pre-5.8) do not know
  `CAP_BPF` and will only admit `CAP_NET_ADMIN`; the helper falls back
  correctly, but operators running pre-5.8 kernels should understand
  that the privilege-split refactor that `CAP_BPF` enables is not
  available to them.
- The integration test creates a dummy interface named `fos1testxdp`
  and tears it down via `t.Cleanup`. If the test is killed mid-run,
  the interface may linger and block the next attempt; the helper
  pre-cleans any pre-existing link with the same name.

## Notes for Review

- Anything listed here should be treated as a deliberate tradeoff, not a hidden bug.
- If a caveat blocks production use, it should be promoted into a ticket rather than left here indefinitely.
