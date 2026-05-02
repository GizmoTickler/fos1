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
- ~~The controller mutates FilterPolicy.Status in the in-memory cache but does
  not yet persist those conditions via a CRD status subresource update.~~
  **Closed by Sprint 30 Ticket 40.** The shared
  `pkg/controllers/status.Writer` helper now persists FilterPolicy
  conditions via the `/status` subresource with retry-on-conflict. Adopted
  by FilterPolicy, NAT, and MultiWAN controllers.
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

## Ticket 39 — eBPF TC QoS Shaping + Qdisc Bootstrap

### Caveats

- The TC loader at `pkg/hardware/ebpf/tc_loader_linux.go` attaches via
  `link.AttachTCX`, which requires kernel ≥ 6.6. On older kernels the loader
  returns an error with an actionable message; there is no TC BPF legacy
  attach fallback. Operators on pre-6.6 kernels should either upgrade the
  kernel or leave the TC loader unused until a legacy-attach path is added.
- The clsact qdisc bootstrap is idempotent via a "get-or-create" pattern, but
  if another component (e.g. a Cilium-managed clsact) has already taken
  ownership of the qdisc, our loader does not attempt to arbitrate. First
  writer wins. A future CRD-driven controller should serialize clsact
  ownership per netdev.
- The per-ifindex priority map (`tc_priority_map`) is exposed as
  infrastructure: the TC program reads it at classify time, and user-space
  must populate it before the first packet hits the attach point. Today no
  CRD-driven controller consumes this map; a future VLAN-shaper controller
  is the natural consumer.
- Only the TC ingress/egress classifier landed; full classful HTB / HFSC
  shaping is out of scope. Combine Ticket 39 with Ticket 45 (Bandwidth
  Manager) for per-pod egress enforcement plus per-uplink classification.
- The committed ELF (`pkg/hardware/ebpf/bpf/tc_qos_shape.o`) mirrors the
  Ticket 38 pattern: contributors who edit `bpf/tc_qos_shape.c` must
  re-run `make bpf-objects` on a BPF-capable clang host and commit the
  regenerated object. CI does not currently diff committed ELF against a
  fresh recompile.

## Ticket 40 — Shared CRD Status Writeback Helper

### Caveats

- The helper at `pkg/controllers/status/writer.go` retries on conflict with
  a bounded retry budget. If a caller writes status faster than the
  conflict-retry budget can drain, some updates will be dropped. In
  practice reconcile loops self-throttle, so this has not been observed.
- The helper is type-erased via an interface seam rather than generics; the
  per-CRD adapter functions that construct the typed patch live in each
  controller package (`nat_controller.go`, `policy/controller.go`,
  `multiwan_controller.go`). Adopting the helper in a new controller
  requires authoring that adapter.
- The helper uses `Patch` with `types.MergePatchType` on the `/status`
  subresource. Array-typed fields (e.g. `Conditions`) must be fully rewritten
  on each update rather than mutated in place; this matches controller-runtime
  convention but is worth calling out when auditing a new adopter.

## Ticket 41 — Read-Only REST API v0

### Caveats

- `/v1/filter-policies` is read-only in v0. Write verbs
  (POST / PUT / PATCH / DELETE), watch/streaming endpoints, and resource
  families beyond FilterPolicy are explicit follow-up tickets, not bugs.
- Authentication is **mTLS only** — the API server enforces
  `tls.RequireAndVerifyClientCert` and checks the peer's Subject-CN against
  a ConfigMap-backed allowlist. OAuth / OIDC / SPIFFE are not wired.
- Trust anchor is the `fos1-internal-ca` ClusterIssuer (Sprint 31 /
  Ticket 49). The same `ca.crt` is reused for client-cert verification —
  every authorized caller carries a leaf cert minted by the same chain.
  Mount path: `/var/run/secrets/fos1.io/tls/`. Rotation is in-place via
  the shared TLS reloader; see `docs/design/internal-tls-secrets.md`.
- The OpenAPI spec at `/openapi.json` is hand-authored, not generated.
  Schema drift between the CRD and the OpenAPI response is possible; a
  future ticket should generate it from `pkg/apis/`.

## Ticket 42 — RBAC Minimum-Privilege Baseline

### Caveats

- `scripts/ci/prove-no-cluster-admin.sh` walks both `manifests/` and
  `test-manifests/`. If a downstream consumer renders additional manifests
  into a path outside those two trees, the gate does not see them.
- The `fos1.io/rbac-exception` annotation is free-text. Operators should
  audit the annotation value in code review; the CI gate only enforces
  presence, not content.
- Per-role minimality is documented in `docs/design/rbac-baseline.md` but
  not enforced by a separate CI check today. The "no cluster-admin" gate is
  the only machine-checked property; verb/resource minimality is a review
  expectation.
- Vendor-shipped ClusterRoles (e.g. Cilium's) are kept at vendor defaults
  rather than trimmed. This is an explicit choice; see `rbac-baseline.md`
  §Vendor Baselines for rationale.

## Ticket 43 — NAT Policy Apply Performance Baseline

### Caveats

- The bench harness at `tools/bench/nat_apply_bench_test.go` uses an
  in-process fake `cilium.Client`. It does not exercise the real
  Kubernetes API, real Cilium policy generation, or real network stack.
  The numbers measure `pkg/network/nat.Manager.ApplyNATPolicy` CPU cost,
  not end-to-end latency.
- The baseline at `docs/performance/baseline-2026-04.md` was measured on
  an Apple M3 Pro developer laptop, not a dedicated CI runner. Numbers are
  directionally reliable for regression detection but should not be
  compared across machines or OS builds.
- CI regression detection is a **warning, not a failure** in v0. Once the
  signal is understood on the real CI runner, a future ticket can promote
  the gate to blocking.
- Only NAT policy apply is baselined. Other hot paths (DPI event → Cilium
  policy, routing sync, DHCP control socket, DNS zone update) are explicit
  follow-up tickets.

## Ticket 44 — URLhaus Threat-Intel v0

### Caveats

- Only the URLhaus CSV feed is ingested in v0. MISP and STIX/TAXII are
  non-goals today and would require ADR-0001 to be revisited.
- The feed fetcher assumes HTTPS. Feed credentials / HTTP basic auth are
  not wired; upstream authenticated feeds are out of scope.
- The translator emits Cilium deny policies with a last-seen TTL; entries
  are expired when the feed no longer mentions them past the TTL window.
  If the upstream feed is temporarily unavailable, the controller holds the
  last-known entry set rather than failing closed. Operators who need
  fail-closed behavior should layer a FilterPolicy default-deny on top.
- `ThreatFeed.Status` records last-fetch time, entry count, and expiry
  state. The controller does not emit Kubernetes `Events` on feed errors
  in v0; observability relies on controller logs.

## Ticket 45 — QoS Enforcement via Cilium Bandwidth Manager

### Caveats

- Bandwidth Manager enforces **egress only** — there is no ingress rate
  limiting in v0. The BPF TBF runs on the pod netdev's egress path.
  Ingress enforcement is a Sprint 31 candidate and will need a different
  backend (TC, XDP, or a Cilium roadmap feature).
- `QoSProfile.Spec.podSelector` uses label selectors; pods that drift out
  of the selector scope have the annotation removed via
  `kubernetes.io/egress-bandwidth`. Pods must be recreated or their
  admission hook must re-run for the annotation change to be picked up by
  Cilium — the annotation is read at admission time, not reconciled in
  place.
- Only `kubernetes.io/egress-bandwidth` (and optionally
  `kubernetes.io/ingress-bandwidth` for forward compatibility) is written.
  Classful HTB / HFSC shaping, DSCP-aware classification, and VLAN-scoped
  per-uplink priority marking live on the Ticket 39 TC loader
  infrastructure and are not consumed by this controller in v1.
- The bandwidth value must use a Cilium-understood unit suffix (e.g.
  `"10M"`). Validation happens at reconcile time; a malformed value sets
  the `QoSProfile.Status.Conditions` Invalid condition rather than
  crashing the reconciler.

## Sprint 31 Ticket 50 — Residual nftables NAT Imports Removed

### Status
- `pkg/network/nat/kernel.go` deleted (dead `KernelNATManager`, no active callers) — feat `b6433fc`, merge `c78252f`.
- `pkg/deprecated/nat/` deleted (dead `NAT66Manager`, no active callers) — same commits.
- Cleanup commit `bac62b2` then dropped `github.com/google/nftables` from `go.mod` and `go.sum`. `grep -rn 'github.com/google/nftables' pkg/ cmd/` is empty post-Sprint-31.
- Active NAT path remains `pkg/network/nat/manager.go` (Cilium-first, ADR-0001).

### Plan correction recorded post-merge
- The original Ticket 50 plan and the Sprint 30 Ticket 46 truth-up both claimed `pkg/security/firewall/kernel.go` was a "live consumer" of `github.com/google/nftables` and would block dependency removal until a Cilium-backed `FirewallManager` replacement was authored. **That was wrong.** `pkg/security/firewall/` (including `kernel.go`, the `PolicyTranslator`, and the `ZoneManager`) had already been removed in Sprint 29 Ticket 33 along with the `FirewallRule` CRD per ADR-0001. With the NAT-side imports gone in Ticket 50, the `github.com/google/nftables` dependency had no remaining live consumers, and cleanup commit `bac62b2` dropped it. Ticket 55 (this truth-up) records the correction so future readers don't re-introduce the stale "blocked on FirewallManager replacement" framing.

### Residual
- None. nftables is fully removed (not just non-goal). Cilium remains the sole enforcement backend per ADR-0001.

## Sprint 31 Ticket 47 — Controller HA via Leader Election

### Status

- Every owned controller under `cmd/` now wires leader election against
  `coordination.k8s.io/v1` Leases:
  - `cmd/api-server/` uses `sigs.k8s.io/controller-runtime/pkg/manager`
    LeaderElection with the lease in the `security` namespace.
  - `cmd/certificate-controller/`, `cmd/cilium-controller/`,
    `cmd/dpi-framework/`, `cmd/event-correlator/`,
    `cmd/ids-controller/`, `cmd/threatintel-controller/`, and
    `cmd/wireguard-controller/` use `pkg/leaderelection` (a thin
    wrapper over `k8s.io/client-go/tools/leaderelection` with the
    fos1-standard 15s/10s/2s timings).
- Every owned controller `Deployment` runs `replicas: 2`,
  `maxUnavailable: 1`, and `preferredDuringSchedulingIgnoredDuringExecution`
  podAntiAffinity on `kubernetes.io/hostname`. Each gets a
  namespace-scoped `Role` + `RoleBinding` for `coordination.k8s.io/leases`
  (no new `ClusterRoleBinding`).
- `scripts/ci/prove-leader-failover.sh` proves one Kind failover cycle on
  `ids-controller` (the failover-proof target — see Caveats below). Wired
  into `.github/workflows/test-bootstrap.yml` after the IDS controller is
  rolled out.

### Caveats — what HA does NOT cover

- **External daemon singletons remain single-process.** FRR (BGP/OSPF),
  Suricata (IDS), Zeek (IDS), and Kea (DHCP) are shipped as single-pod
  / single-process daemons with process-local state. They do not
  participate in the leader-election contract; failover for these is a
  per-daemon design (FRR has BFD, Kea has a HA hooks library, Suricata
  can run as parallel sensors). Sprint 32 candidate.
- **Shared-state observability remains single-replica.** Elasticsearch
  and Prometheus run as single-replica StatefulSets and hold real
  persistent data; leader election alone does not replicate that
  state. Multi-node clustering (ES cross-zone replication, Prometheus
  federation or Thanos) is a separate sprint.
- **DaemonSets are intentionally excluded.** `dpi-manager` is a
  `DaemonSet` (one pod per node, node-local). The plan suggested
  `dpi-manager` as the failover-proof target; this was a plan-level
  inconsistency (you cannot run leader election on a node-local
  DaemonSet without defeating its purpose). The proof script targets
  `ids-controller` instead — also already deployed in the Kind harness
  and now scaled to two replicas.
- **`trafficshaper-controller` stays at `replicas: 1`.** It uses
  `hostNetwork: true` to drive TC on the uplink; two replicas on the
  same host conflict on the netdev. Its RBAC was already extended to
  include the lease verbs in Sprint 31 Ticket 52, so once an operator
  runs it across two nodes a follow-up can flip the replica count
  without RBAC churn.
- **Each non-CR controller exits on missing `POD_NAMESPACE`.** Operators
  who build their own Deployment manifests must set `POD_NAMESPACE` and
  `POD_NAME` from the downward API or the binary will fail fast on
  startup. This is a deliberate fail-closed design.
- **`dpi-framework` `main.go` is wired but unused in the deployed
  manifest set.** There is no `manifests/base/*/dpi-framework`
  Deployment in tree; `dpi-manager` is the production path. The wiring
  is preserved in the binary so any operator who ships their own
  Deployment for it gets HA out of the box. RBAC for the lease is
  the operator's responsibility in that case.
- **No metrics on lease acquisition / loss.** The wrapper logs
  structured klog events on transition but does not export Prometheus
  metrics. Adding `leader_transitions_total` is a small follow-up; not
  in scope for Ticket 47.

## Ticket 49 — Inter-Controller TLS And Secrets Management Baseline

### What this ticket actually does

- Mints per-controller server certs from a single
  `fos1-internal-ca` ClusterIssuer (CA-typed, chained from a 10y
  self-signed root). Manifests live at
  `manifests/base/certificates/cluster-issuer-internal.yaml`.
- Adds a shared `pkg/security/certificates.LoadTLSConfig(certDir)` +
  `WatchAndReload` helper. Every owned HTTP listener loads its cert
  through it, so cert-manager renewals reload in place via fsnotify.
- Migrates the existing API server (Ticket 41) to the same helper while
  preserving the mTLS contract (`RequireAndVerifyClientCert`). The
  per-file `--server-cert` / `--server-key` / `--client-ca` flags remain
  for overlays that point at an external CA.

### Caveats

- **Ticket 56 now owns mTLS for the current HTTP listener mesh.**
  The shared `LoadMutualTLSConfig` helper installs mounted cert material
  for both server and client auth, and currently owned non-API listeners
  (NTP exporter/API, DPI metrics, correlator probes when TLS is enabled)
  enforce deny-by-default Subject-CN allowlists. Live Prometheus scrape
  compatibility still depends on Ticket 57 because Prometheus must mount
  a client cert and trust the `fos1-internal-ca` chain.
- **External daemons remain plaintext on in-pod sockets.** Suricata's
  Unix socket, Zeek Broker, Kea's control socket, FRR's vtysh, and
  chronyc all live inside the same pod as their controller and speak
  plaintext on a loopback / Unix path. The threat model treats those
  as same-trust-boundary; cross-host paths are scheduled for Sprint 32
  with a sidecar TLS terminator.
- **Trust anchor is a self-signed root, not an enterprise PKI.** The
  `fos1-internal-ca-root` ClusterIssuer is selfSigned and the root key
  lives in a Secret in the cert-manager namespace. Production
  deployments that require HSM-backed signing should replace the root
  via an overlay (Vault / cloud-KMS / external CA) — the rest of the
  design is unchanged.
- **Some controllers mount the Secret without serving TLS yet.**
  `ids-controller`, `threatintel-controller`, `wireguard-controller`,
  and `certificate-controller` all reconcile the cert and mount it but
  do not yet expose a TLS listener. The mount is done now so the
  follow-up that flips the listener can land without manifest churn.
  The rotation proof exercises only the controllers that *do* serve
  TLS today.
- **Prometheus must trust `fos1-internal-ca` and present a client cert.**
  The scrape configs in `manifests/base/monitoring/prometheus.yaml` need a
  `tls_config.ca_file`, `cert_file`, and `key_file` for the chain and
  Prometheus client identity. This is Ticket 57; until then, mTLS-enabled
  owned metrics targets fail closed under default Prometheus config.
- **The CA `Secret` is read by cert-manager from its own namespace.**
  We follow the cert-manager convention: a CA-typed ClusterIssuer
  reads `spec.ca.secretName` from the cert-manager namespace. Anyone
  who relocates cert-manager must re-point the issuer.
- **`scripts/ci/prove-cert-rotation.sh` targets the API server.** That
  controller is the one path under test that combines mTLS + the
  shared loader. The script tolerates absence of `cmctl` by deleting
  the Secret as the renewal trigger; that path is slightly slower
  (cert-manager has to reconcile from scratch) but exercises the same
  reload code path.

## Sprint 31 Ticket 48 — CRUD v1 REST API for FilterPolicy

### Caveats

- Write verbs are scoped to FilterPolicy only. Other resource families
  (NAT, routing, DPI, zones, threat feeds) remain read-only or
  `kubectl`-only. Adding a new resource family requires authoring a new
  handler set under `pkg/api/`.
- PATCH dispatches between `application/merge-patch+json` (JSON Merge
  Patch, RFC 7396) and `application/strategic-merge-patch+json`
  (Kubernetes Strategic Merge Patch) via the `Content-Type` header.
  `application/json-patch+json` (RFC 6902) and
  `application/apply-patch+yaml` (Server-Side Apply) are NOT wired —
  callers that need them get 415 Unsupported Media Type.
- PUT requires `metadata.resourceVersion` for optimistic concurrency.
  Callers that omit it get 409 Conflict, not silent overwrite.
- Server-side validation runs on the handler before forwarding to the
  API server, so the 422 `Invalid` body the client sees is the
  fos1-side validator's body, not Kubernetes admission. The two
  validators may drift if a CRD-level OpenAPI schema field is added
  without updating `pkg/api/`.
- DELETE accepts a `propagationPolicy` query parameter
  (`Foreground` / `Background` / `Orphan`); the default is `Background`.
  Callers that want strict cascade should pass it explicitly.
- Watch / streaming endpoints (chunked JSON-lines on `?watch=true`) are
  NOT in this ticket. Sprint 32 candidate.
- The OpenAPI spec at `/openapi.json` is hand-authored and was extended
  in this ticket; it remains a manual artifact and can drift from the
  CRD. A future ticket should generate it from `pkg/apis/`.

## Sprint 31 Ticket 51 — eBPF sockops + cgroup Program Types

### Caveats

- The sockops loader at `pkg/hardware/ebpf/sockops_loader_linux.go`
  attaches to a cgroup v2 path. The default in the program-manager
  dispatch is `/sys/fs/cgroup`; per-scope cgroup paths require a
  controller that talks to the loader directly. There is no in-tree
  CRD-driven controller for sockops yet.
- The cgroup loader at
  `pkg/hardware/ebpf/cgroup_loader_linux.go` attaches the cgroup
  egress counter program as `BPF_CGROUP_INET_EGRESS`. Other cgroup
  attach types (`BPF_CGROUP_INET_INGRESS`, `BPF_CGROUP_SOCK_OPS`,
  connect/bind hooks, etc.) are not implemented.
- Linux integration tests for both loaders skip without a unified
  cgroup v2 hierarchy at `/sys/fs/cgroup`. Hosts that still use cgroup
  v1 (rare on modern kernels) will see all sockops/cgroup tests skip
  even with `CAP_BPF` / `CAP_NET_ADMIN`.
- The committed ELFs (`pkg/hardware/ebpf/bpf/sockops_redirect.o` and
  `cgroup_egress_counter.o`) follow the Sprint 30 Tickets 38/39
  pattern: contributors who edit `bpf/sockops_redirect.c` or
  `bpf/cgroup_egress_counter.c` must re-run `make bpf-objects` on a
  BPF-capable clang host and commit the regenerated objects. CI does
  not currently diff committed ELFs against a fresh recompile.
- Other program types (sk_msg, sk_lookup, lwt_in / lwt_out / lwt_xmit,
  lwt_seg6local, raw_tracepoint, tracing, etc.) still return
  `ErrEBPFProgramTypeUnsupported` from `pkg/hardware/ebpf/program_manager.go`.
  Sprint 32 candidates.

## Sprint 31 Ticket 52 — VLAN-Scoped TC Shaper Controller (TrafficShaper CRD)

### Caveats

- `trafficshaper-controller` runs at `replicas: 1` because it uses
  `hostNetwork: true` to drive TC on the uplink; two replicas on the
  same host conflict on the netdev. RBAC for the lease verbs was
  extended in this ticket so an operator running the controller across
  two nodes can flip the replica count without RBAC churn (see
  Ticket 47 caveat).
- The `TrafficShaper` CRD composes with the `QoSProfile` CRD from
  Sprint 30 Ticket 45: pod egress caps come from `QoSProfile`
  (Cilium Bandwidth Manager); uplink/VLAN shaping comes from
  `TrafficShaper` (TC clsact qdisc + per-ifindex priority map). They
  do NOT coordinate beyond the manifest level — two CRDs targeting
  the same interface can produce confusing layered behavior.
- The TC loader infrastructure is shared with Sprint 30 Ticket 39, so
  all of Ticket 39's caveats apply (kernel ≥ 6.6 for `AttachTCX`,
  first-writer-wins on the clsact qdisc, no legacy-attach fallback).
- The controller uses the Sprint 30 Ticket 40 `pkg/controllers/status.Writer`
  helper for Applied/Degraded/Invalid/Removed conditions; the helper's
  caveats apply here too (retry-on-conflict bound, type-erased adapter
  per CRD).

## Sprint 31 Ticket 53 — MISP JSON Threat-Intel Feed

### Caveats

- Authentication is API-key only via `spec.authSecretRef` → Secret
  `apiKey` data key. Certificate-based MISP auth, OAuth, and any other
  auth scheme are explicit non-goals.
- The MISP JSON parser handles domain / IP / URL indicators in the
  `Event.Attribute` array. Other indicator types (file hashes,
  registry keys, mutex names, etc.) are silently ignored — they do not
  fail the feed but they do not produce Cilium policies either.
- STIX / TAXII remains a non-goal. ADR-0001 would need to be revisited
  to add either as a feed type.
- The fake HTTP server in the test harness verifies the canned-response
  fetch-parse-translate-apply cycle but does not exercise a real MISP
  endpoint's pagination, rate limiting, or large-event behavior. A
  follow-up integration test against a containerized MISP server is a
  Sprint 32 candidate.
- Missing Secret produces an `Invalid` condition on `ThreatFeed.Status`
  rather than crashing the reconciler; same pattern as the URLhaus
  feed (Ticket 44).

## Sprint 31 Ticket 54 — Performance Baseline Coverage Expansion

### Caveats

- All four bench harnesses (`tools/bench/nat_apply_bench_test.go`,
  `dpi_policy_bench_test.go`, `filterpolicy_translate_bench_test.go`,
  `threatintel_translate_bench_test.go`) use in-process fakes. They do
  not exercise the real Kubernetes API, real Cilium policy generation,
  or the real network stack. The numbers measure CPU cost of the
  in-process translator, not end-to-end latency.
- All baselines in `docs/performance/baseline-2026-04.md` are still
  measured on an Apple M3 Pro developer laptop, not a dedicated CI
  runner (carryover from Ticket 43). Numbers are directionally reliable
  for regression detection but should not be compared across machines
  or OS builds.
- CI regression detection remains a warning, not a failure (Ticket 43
  envelope). Once the four hot-path baselines are stable across CI
  runner generations, the gate can promote to blocking.
- Remaining hot paths (routing sync, DHCP control socket, DNS zone
  update) are still unbenchmarked. Adding them is a Sprint 32
  candidate.
- The benches run single-goroutine by design; p99 tail behavior under
  contention is not measured.

## Sprint 31 Ticket 55 — Post-Sprint-31 Truth-Up

### Plan corrections recorded during this ticket

- **Ticket 47 plan vs reality:** the plan suggested `dpi-manager` as the
  failover-proof target, but `dpi-manager` is a DaemonSet (one pod per
  node, node-local) and cannot run leader election without defeating
  its purpose. The proof script targets `ids-controller` instead, which
  is already deployed in the Kind harness and now scaled to two
  replicas. Status docs across `Status.md`, `docs/project-tracker.md`,
  and `docs/observability-architecture.md` reflect the actual target.
- **Ticket 50 plan vs reality:** the plan said `pkg/security/firewall/kernel.go`
  was a "live consumer" of `github.com/google/nftables`. That was wrong
  — `pkg/security/firewall/` had been removed in Sprint 29 Ticket 33,
  so the dependency had no live consumers. Cleanup commit `bac62b2`
  dropped the unused dependency from `go.mod` and `go.sum` after the
  Ticket 50 NAT-side delete merged. Caveat block above
  (§"Sprint 31 Ticket 50 — Residual nftables NAT Imports Removed")
  reflects the corrected story.
- **Ticket 49 commit shape:** the plan called for a feat + merge pair.
  In practice the agent committed directly to `main` as `c60f906`
  without a merge commit. Truth-up records the direct commit.

## Notes for Review

- Anything listed here should be treated as a deliberate tradeoff, not a hidden bug.
- If a caveat blocks production use, it should be promoted into a ticket rather than left here indefinitely.
