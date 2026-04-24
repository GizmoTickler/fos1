# Implementation Backlog

This document is the execution backlog derived from the current codebase state and the Cilium-first architecture decision.

## Baseline

Branch status at planning time:
- local `main` matched remote `main`

Architecture direction:
- Cilium-first control plane

References:
- `docs/design/adr-0001-cilium-first-control-plane-contract.md`
- `docs/design/implementation_caveats.md`

## Working Rules

Apply these rules to all tickets:
- no placeholder success paths in active reconciliation flows
- reconciliation must be idempotent
- status must reflect applied state
- tests must be updated with behavior changes
- docs should be updated after behavior is verified

## Definition Of Done

A ticket is done when:
- the targeted path performs a real backend operation
- failure cases surface through returned errors and status
- success is not based only on logs or mock behavior
- any remaining non-goals are called out explicitly

## Critical Path

1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 8 -> 11 -> 12 -> 14 -> 17 -> 19 -> 20

Tickets not on the critical path (7, 9, 10, 13, 15, 16, 18) can proceed in parallel once their P0 dependencies are met. Specifically:
- Ticket 7 (NAT66/NAT64/port forwarding) extends ticket 6 but is not required before ticket 8, which addresses controller status semantics independently of NAT variant coverage.
- Tickets 9 and 10 (FRR hardening, BGP/OSPF wiring) depend on ticket 5 but are independent of the NAT path.
- Ticket 13 (NTP) is self-contained after core services infrastructure exists.
- Tickets 15, 16, 18 are leaf tickets with no downstream dependents in scope.

## P0

### Ticket 1: Freeze The Cilium-First Control-Plane Contract
Status:
- completed

Deliverable:
- `docs/design/adr-0001-cilium-first-control-plane-contract.md`

### Ticket 2: Implement Real Cilium Route Operations In The Client Layer
Status:
- completed

Primary areas:
- `pkg/cilium/types.go`
- `pkg/cilium/client.go`
- `pkg/cilium/direct.go`
- `pkg/cilium/kubernetes.go`

### Ticket 3: Replace Placeholder Logic In `pkg/cilium/route_sync.go`
Status:
- completed

Primary areas:
- `pkg/cilium/route_sync.go`
- route client listing and deletion behavior

### Ticket 4: Remove Dummy Synchronization From The Routing Controller
Status:
- completed

Primary areas:
- `pkg/controllers/routing_controller.go`

Caveat:
- the older `pkg/cilium/controllers` routing flow is still separate and should be reviewed for consolidation later

### Ticket 5: Define And Implement VRF / Policy-Based Routing Reconciliation Semantics
Status:
- completed

Scope:
- define route table, VRF, and policy-rule ownership across controller, kernel helper, and Cilium path
- implement consistent table/VRF reconciliation semantics
- document ordering and route identity rules

Primary areas:
- `pkg/network/routing/kernel.go`
- `pkg/network/routing/policy/kernel.go`
- `pkg/controllers/routing_controller.go`
- `pkg/cilium/router.go`

Acceptance:
- custom table behavior is deterministic
- VRF and policy-rule semantics are documented and enforced
- tests cover table and VRF edge cases

### Ticket 6: Implement Real Cilium NAT Core For SNAT And DNAT
Status:
- completed

Primary areas:
- `pkg/network/nat/manager.go`
- `pkg/cilium/client.go`
- `pkg/cilium/network_controller.go`

Acceptance:
- SNAT and DNAT are enforced through the active Cilium path
- no log-only success remains in the active path

### Ticket 7: Extend NAT Support To NAT66, NAT64, And Port Forwarding
Status:
- completed

Acceptance:
- advanced NAT variants work through the same authoritative path
- validation rejects bad family combinations

### Ticket 8: Make The NAT Controller Fully Statusful And Idempotent
Status:
- completed

Primary areas:
- `pkg/controllers/nat_controller.go`

Acceptance:
- status reflects applied, degraded, invalid, and removed state correctly

## P1

### Ticket 9: Harden FRR Configuration Validation And Reload Flow
Status:
- completed

Scope:
- `ConfigGenerator.ValidateConfig()` in `pkg/network/routing/frr/config.go` currently returns nil with a TODO for vtysh validation
- `Manager.ApplyConfiguration()` in `pkg/network/routing/frr/manager.go` generates config and reloads daemons but does not validate before reload and silently swallows reload errors
- implement real validation via `vtysh --check` or equivalent before applying config
- make reload errors propagate rather than being logged and dropped
- add rollback-on-failure using the existing backup mechanism

Primary areas:
- `pkg/network/routing/frr/config.go`
- `pkg/network/routing/frr/manager.go`
- `pkg/network/routing/frr/client.go`

Acceptance:
- `ValidateConfig` performs real syntax validation against vtysh
- `ApplyConfiguration` fails and rolls back if validation or reload fails
- tests cover invalid config rejection and rollback behavior

### Ticket 10: Wire BGP And OSPF Controllers To Real FRR State
Status:
- completed

Scope:
- `BGPHandler.Start()` and `OSPFHandler.Start()` in `pkg/network/routing/protocols/` translate config to FRR types and call the FRR client, but do not read back applied state
- protocol manager in `pkg/network/routing/protocols/manager.go` starts protocols but has no status feedback loop
- wire protocol handlers to read actual FRR daemon state (neighbor status, route counts) and surface it
- connect protocol controller status conditions to real daemon output

Primary areas:
- `pkg/network/routing/protocols/bgp.go`
- `pkg/network/routing/protocols/ospf.go`
- `pkg/network/routing/protocols/manager.go`
- `pkg/network/routing/frr/client.go`

Acceptance:
- BGP and OSPF controllers report real neighbor/adjacency state
- protocol status reflects actual FRR daemon output, not assumptions
- tests verify state read-back from FRR client

### Ticket 11: Implement Real Kea Control-Socket Reconciliation In The DHCP Controller
Status:
- completed

Scope:
- `pkg/dhcp/kea/client.go` has a Kea control agent client with real HTTP command execution and tests
- `pkg/dhcp/controller/controller.go` reconciles DHCP CRDs but the DNS connector uses placeholder domain suffixes
- connect the DHCP controller reconciliation to the real Kea client for config push and reload
- replace placeholder domain suffix logic in `pkg/dhcp/controller/dns_connector.go`

Primary areas:
- `pkg/dhcp/kea/client.go`
- `pkg/dhcp/kea_manager.go`
- `pkg/dhcp/controller/controller.go`
- `pkg/dhcp/controller/dns_connector.go`

Acceptance:
- DHCP controller applies real Kea config via the control socket
- config changes trigger actual Kea reload
- DNS connector uses real domain suffixes from DHCP configuration
- tests cover config push and reload flow

### Ticket 12: Wire The DNS Manager To Real CoreDNS And AdGuard Operations
Status:
- completed

Scope:
- `pkg/dns/manager/manager.go` has multiple placeholder methods: `UpdateZone`, `UpdatePTRZone`, `UpdateFilters`, `UpdateClient`, `UpdateReflection` all return nil without doing real work
- `pkg/dns/coredns/` has real zonefile generation and reload logic with tests
- `pkg/dns/adguard/` has a real API client with tests
- connect the DNS manager's update methods to the actual CoreDNS and AdGuard backends
- replace the placeholder zone lookup that returns a default zone

Primary areas:
- `pkg/dns/manager/manager.go`
- `pkg/dns/coredns/controller.go`
- `pkg/dns/coredns/zonefile.go`
- `pkg/dns/adguard/api_client.go`
- `pkg/dns/adguard/controller.go`
- `pkg/dns/mdns/controller.go`

Acceptance:
- DNS manager update methods drive real CoreDNS zone updates and AdGuard filter/client changes
- mDNS reflection updates are wired to the real mDNS controller
- no placeholder return-nil methods remain in the active DNS reconciliation path
- tests cover zone update, filter update, and PTR zone flows

### Ticket 13: Finish NTP Controller Reconciliation And NTS Wiring
Status:
- completed

Scope:
- `pkg/ntp/controller/controller.go` has placeholder reconciliation and returns placeholder status
- `pkg/ntp/chrony/manager.go` uses a placeholder command-line reload instead of real Chrony control
- `pkg/ntp/manager/manager.go` returns a placeholder configuration
- DNS and DHCP integration files in `pkg/ntp/manager/` use placeholder values
- wire the NTP controller to real Chrony config generation and reload
- implement NTS (Network Time Security) configuration

Primary areas:
- `pkg/ntp/controller/controller.go`
- `pkg/ntp/chrony/manager.go`
- `pkg/ntp/chrony/config.go`
- `pkg/ntp/manager/manager.go`

Acceptance:
- NTP controller reconciliation produces real Chrony config and triggers reload
- NTS configuration is generated and applied when specified
- status reflects actual Chrony state
- placeholder values in DNS/DHCP integration are replaced with real lookups

### Ticket 14: Standardize On One WireGuard Backend And Fix Controller Reconciliation
Status:
- completed

Scope:
- `pkg/vpn/wireguard.go` contains the WireGuard interface management backend
- `pkg/vpn/controller/wireguard_controller.go` has placeholder reconciliation: status updates are log-only and `getVPNFromCRD` returns a dummy VPN object
- choose one authoritative backend (kernel module vs userspace) and remove the other
- make the controller reconcile real interface and peer state

Primary areas:
- `pkg/vpn/wireguard.go`
- `pkg/vpn/controller/wireguard_controller.go`

Acceptance:
- WireGuard CRDs reconcile into real interface and peer state
- controller status reflects actual interface status, not log-only success
- `getVPNFromCRD` returns a real VPN configuration from the CRD spec
- tests verify interface creation, peer add/remove, and status reporting

### Ticket 15: Integrate cert-manager Outputs Into Service Consumers
Status:
- completed

Scope:
- `pkg/security/certificates/manager.go` wraps the cert-manager client with real cert-manager API types
- `pkg/security/certificates/controller.go` has certificate controller logic
- no downstream service currently consumes cert-manager-issued certificates end to end
- connect at least one consumer (e.g., WireGuard, AdGuard HTTPS, or NTS) to cert-manager outputs

Primary areas:
- `pkg/security/certificates/manager.go`
- `pkg/security/certificates/controller.go`

Acceptance:
- at least one downstream service reads cert-manager-managed TLS artifacts
- certificate renewal triggers consumer reload or reconfiguration
- tests verify the consumption path end to end

### Ticket 16: Make IDS Managers Reflect Real Suricata And Zeek Engine State
Status:
- completed

Scope:
- `pkg/security/ids/manager.go` returns hardcoded example data for `GetStatus()`, `GetAlerts()`, and `GetStatistics()` instead of querying real engines
- `UpdateRules()` logs and returns nil without applying changes
- `pkg/security/ids/suricata/client.go` has a real Suricata Unix socket client with Eve log parsing
- `pkg/security/ids/zeek/broker_client.go` has a real Zeek Broker client
- wire the IDS manager methods to read from the real Suricata and Zeek clients

Primary areas:
- `pkg/security/ids/manager.go`
- `pkg/security/ids/suricata/client.go`
- `pkg/security/ids/suricata/controller.go`
- `pkg/security/ids/zeek/broker_client.go`
- `pkg/security/ids/zeek/controller.go`

Acceptance:
- `GetStatus()`, `GetAlerts()`, and `GetStatistics()` return data from real engines
- `UpdateRules()` applies rule changes to Suricata and Zeek
- no hardcoded example data remains in the active path
- tests verify real client integration (at minimum via mocked socket/broker)

### Ticket 17: Wire DPI Events Into Real Cilium Policy Responses
Status:
- completed

Scope:
- `pkg/security/dpi/policy_pipeline.go` has a `PolicyPipeline` that processes DPI events and generates Cilium policies with severity thresholds, deduplication, and TTL expiry
- `pkg/security/dpi/connectors/suricata.go` adds placeholder data in parts of its stats collection
- verify that `ProcessEvent` creates and applies real `CiliumPolicy` objects via the Cilium client
- ensure policy expiry and cleanup actually removes applied policies
- make at least one DPI connector (Suricata or Zeek) trigger the pipeline end to end

Primary areas:
- `pkg/security/dpi/policy_pipeline.go`
- `pkg/security/dpi/connectors/suricata.go`
- `pkg/security/dpi/connectors/zeek.go`
- `pkg/security/dpi/manager.go`
- `pkg/cilium/client.go`

Acceptance:
- at least one supported DPI event type triggers real Cilium policy creation
- policy expiry removes the applied Cilium policy
- enforcement actions are auditable through status or events
- tests cover event-to-policy creation and expiry cleanup

### Ticket 18: Fix Auth Manager Provider Construction And Harden Provider Behavior
Status:
- completed

Scope:
- `pkg/security/auth/manager.go` has factory methods for local, LDAP, OAuth, SAML, RADIUS, and certificate providers that all return `"<type> provider not implemented"` errors
- `pkg/security/auth/providers/` contains actual provider implementations (LDAP, local, OAuth) with real logic in separate files
- the manager factory methods need to be wired to instantiate the real provider implementations from `pkg/security/auth/providers/factory.go`
- harden provider behavior for error handling and session lifecycle

Primary areas:
- `pkg/security/auth/manager.go`
- `pkg/security/auth/providers/factory.go`
- `pkg/security/auth/providers/ldap.go`
- `pkg/security/auth/providers/local.go`
- `pkg/security/auth/providers/oauth.go`
- `pkg/security/auth/controller.go`

Acceptance:
- auth manager factory methods construct real provider instances from the providers package
- no "not implemented" errors remain for providers that have implementations
- provider construction failures surface through returned errors and status
- tests verify provider instantiation and basic auth flow for at least one provider type

## P2

### Ticket 19: Consolidate The eBPF Runtime And Remove Placeholder Cilium Integration Discovery
Status:
- completed

### Ticket 20: Build The Integration And Reconciliation Test Matrix, Then Correct Status Docs
Status:
- completed

## Post-Ticket-20 Sprint

This sprint continues from the verified `origin/main` state after tickets 1-20. The repository now builds and tests cleanly, so the focus shifts from core backend bring-up to control-plane convergence, removal of placeholder success paths in secondary packages, and operational hardening.

Fresh baseline before this sprint:
- `git rebase origin/main` reported `HEAD is up to date.`
- `go test ./...` passed
- `go build ./...` passed

## P0

### Ticket 21: Replace Log-Only DPI Policy Responses In `pkg/kubernetes/policy_controller.go`
Status:
- completed

Scope:
- `pkg/kubernetes/policy_controller.go` is the controller path started by `cmd/dpi-framework/main.go` when Kubernetes mode is enabled
- `createCiliumPolicy()` currently only logs intent instead of creating or deleting real Cilium resources
- wire this controller to an authoritative Cilium policy application path so high-severity DPI events cause concrete policy changes
- make failure and retry behavior explicit rather than silently succeeding on log output

Primary areas:
- `pkg/kubernetes/policy_controller.go`
- `pkg/kubernetes/client.go`
- `pkg/cilium/client.go`
- `pkg/cilium/kubernetes.go`

Acceptance:
- high-severity queued DPI events create a real Cilium policy through the configured client
- policy naming is deterministic and safe for repeated events
- transient errors are retried through the existing workqueue
- tests cover at least one successful apply path and one failure/retry path

### Ticket 22: Replace Placeholder Informers And Placeholder Policy Apply Paths In `pkg/security/policy`
Status:
- completed

Scope:
- `pkg/security/policy/controller.go` still creates placeholder list/watch informers and placeholder Cilium apply/remove behavior
- make informer wiring explicit and non-fake so controller startup does not imply active reconciliation unless real watches exist
- route translated policies through the actual Cilium client rather than placeholder monitor registration
- ensure deletion and disablement remove concrete applied policies instead of only mutating in-memory state

Primary areas:
- `pkg/security/policy/controller.go`
- `pkg/security/policy/translator.go`
- `pkg/security/policy/types.go`
- `pkg/security/policy/*_test.go`

Acceptance:
- controller startup no longer creates fake successful informers
- translated policies are applied and deleted through a real backend interface
- disabled or deleted policies remove applied policy state
- tests cover add/update/delete behavior without placeholder list/watch responses

### Ticket 23: Retire Or Wire Legacy Route Synchronizer Placeholder Paths
Status:
- completed

Scope:
- `pkg/cilium/route_sync.go` still contains placeholder kernel-route discovery, placeholder Cilium-route discovery, placeholder diffing, and fallback success behavior for add/remove operations
- decide whether this package remains authoritative support code or should be explicitly narrowed/deprecated
- if retained, replace placeholder route discovery/diff behavior with real source-of-truth behavior consistent with the post-ticket-3 route path
- if not retained, make unsupported flows fail explicitly instead of pretending success

Primary areas:
- `pkg/cilium/route_sync.go`
- `pkg/cilium/route_sync_test.go`
- `pkg/cilium/types.go`

Acceptance:
- no active method in `pkg/cilium/route_sync.go` returns placeholder success for route mutation
- unsupported flows return explicit errors with actionable messages
- tests cover whichever contract is chosen: real reconciliation or explicit non-support

### Ticket 24: Remove Log-Only Operations From The Direct And Kubernetes Cilium Helper Clients
Status:
- completed

Scope:
- `pkg/cilium/direct.go` and parts of `pkg/cilium/kubernetes.go` still log success for DPI integration, NAT, VLAN routing, and related helper operations
- align helper clients with the authoritative behavior already present in `pkg/cilium/client.go`, or make unsupported operations return explicit errors
- ensure these helper clients no longer appear production-capable while only logging requests

Primary areas:
- `pkg/cilium/direct.go`
- `pkg/cilium/kubernetes.go`
- `pkg/cilium/client_test.go`

Acceptance:
- direct/kubernetes helper methods no longer return success for log-only operations
- supported operations delegate to real resource creation/update behavior
- unsupported operations return explicit errors instead of silent success
- tests cover at least one converted real path and one explicit unsupported path

## P1

### Ticket 25: Put Event Correlation On A Verified Runtime Contract
Status:
- completed

Scope:
- `pkg/security/ids/correlation/controller.go` creates Kubernetes resources for an event correlator runtime, but there is no verified end-to-end contract for config generation, deployment semantics, or status transitions
- add focused controller tests to verify the generated ConfigMap, Deployment, Service, and status conditions
- document what is actually implemented versus what remains a downstream image/runtime dependency

Primary areas:
- `pkg/security/ids/correlation/controller.go`
- new tests under `pkg/security/ids/correlation/`
- `docs/observability-architecture.md`

Acceptance:
- controller tests verify reconciliation outputs and status transitions
- docs clearly separate implemented controller behavior from external runtime assumptions
- no status claims imply a working event processor unless deployment readiness supports it

### Ticket 26: Replace Placeholder Hardware Offload Statistics With Real Ethtool-Derived Behavior
Status:
- completed

Scope:
- `pkg/hardware/offload/manager.go` returns placeholder statistics while the rest of the manager already queries ethtool features
- implement real statistics discovery where available, or explicit "not supported" reporting where the driver/kernel does not expose counters
- avoid placeholder zero-value success that looks like a valid datapoint

Primary areas:
- `pkg/hardware/offload/manager.go`
- `pkg/hardware/types/offload_types.go`
- new tests under `pkg/hardware/offload/`

Acceptance:
- `GetOffloadStatistics()` no longer returns placeholder success
- stats fields are populated from real ethtool data when available
- unsupported counters return explicit, documented behavior
- tests cover both supported and unsupported-statistics cases

### Ticket 27: Reconcile Observability Documentation To Actual Shipped Components
Status:
- completed

Scope:
- `docs/observability-architecture.md` currently reads as a full-stack architecture document independent of the repository's verified runtime state
- rewrite it to distinguish between manifests/templates, implemented exporters/controllers, and not-yet-verified operational paths
- align the document with the post-ticket-20 status model used elsewhere

Primary areas:
- `docs/observability-architecture.md`
- optionally `Status.md` if cross-links need to be added

Acceptance:
- observability docs distinguish implemented code, deployable manifests, and future architecture clearly
- no section implies verified runtime ownership that the codebase does not yet provide
- next implementation dependencies are explicitly called out

### Ticket 28: Build Automation For The Verified Mainline Checks
Status:
- completed

Scope:
- the current repo state verifies locally with `go test ./...` and `go build ./...`, but that verification is not yet captured as a first-class automation requirement in the sprint context
- add a lightweight automation target or documented CI entrypoint for the current verified checks
- ensure future tickets can reference one canonical verification command sequence

Primary areas:
- `Makefile`
- `docs/DEVELOPMENT.md`
- CI/workflow files if present or introduced

Acceptance:
- one canonical command or target runs the current mainline verification steps
- docs reference that target as the required pre-merge check
- the target succeeds on the current codebase

## Suggested Parallel Ownership (Post-20)

Engineer A:
- ticket 21 first (Kubernetes DPI policy path)

Engineer B:
- ticket 22 first (security policy controller path)

Engineer C:
- ticket 23 first, then ticket 24 (shared `pkg/cilium` convergence path; keep sequential to avoid overlap)

Engineer D:
- ticket 25 first (event correlation verification and docs)

Engineer E:
- ticket 26 first, then ticket 27 or 28 (hardware and ops/docs hardening)

## Suggested Parallel Ownership

Engineer A:
- ticket 5 first (blocking), then tickets 9 and 10 in parallel (both depend on 5 but are independent of each other)

Engineer B:
- ticket 6 first (blocking), then ticket 7, then ticket 8 (sequential: 8 depends on 6, and 7 should land before 8 to avoid reconciling NAT status without all variants)

Engineer C:
- tickets 11 and 12 can start in parallel (independent backends), then ticket 13 after either completes (uses similar service-controller patterns)

Engineer D:
- ticket 14 first (blocking), then tickets 15 and 18 in parallel (15 depends on 14 for the cert consumer path; 18 is independent)

Engineer E:
- ticket 16 first (blocking), then ticket 17 (depends on 16 for real engine state), then ticket 19 (independent but lower priority)

Shared stabilization:
- ticket 20 (should begin after at least milestones 1-3 are complete to have meaningful reconciliation paths to test)

## Sprint 29: Runtime Depth And Post-Baseline Hardening

This sprint continues from the verified `origin/main` state after tickets 1-28 plus the post-ticket-20 convergence sprint and the ops follow-through. The owned Kind harness now proves the DPI/NTP pod-annotation scrape path plus a deterministic Suricata canary into Elasticsearch with `fos1-log-retention-14d` ILM/template attachment. Sprint 29 broadens proof beyond the current canary/presence slice, closes out advertised-but-unshipped enforcement and auth surfaces, and raises test depth on historically thin packages.

Fresh baseline expected before this sprint:
- in-flight event-correlator runtime branch (`cmd/event-correlator/` plus `pkg/security/ids/correlation/{runtime,config,processor,probes,deployment_paths}.go` and the associated harness) is landed on `origin/main`
- `make verify-mainline` passes on that state
- the Kind bootstrap harness already proves DPI/NTP pod scraping and the Suricata canary plus ILM/template attachment

Scope intentionally excludes:
- eBPF program compilation and loading for XDP or TC (needs its own dedicated sprint)
- HA/clustering and controller state replication
- REST or gRPC management API server
- upstream threat-intelligence feed ingestion

Critical path:
- 29 -> 30 -> 31 -> (32, 33, 34, 35 in parallel) -> 36 -> 37

### P0

#### Ticket 29: Land The Event-Correlator Runtime And Prove One Event End To End
Status:
- completed

Scope:
- the in-flight branch adds `cmd/event-correlator/main.go`, `build/event-correlator/Dockerfile`, and a file-contract runtime at `pkg/security/ids/correlation/{runtime,config,processor,probes,deployment_paths}.go`
- the controller already mounts source/sink parent directories via hostPath and sets `Phase=Running` only when the Deployment reports ready replicas, but no repo path proves that a real event flows source -> correlator -> sink
- extend the Kind harness so it emits a deterministic canary event into the configured `spec.source.path`, asserts the sink produces the correlated JSON, and asserts the runtime `/ready` endpoint returns 200
- keep the runtime file-only and intentionally small; do not add broker/broker-less transports in this ticket

Primary areas:
- `cmd/event-correlator/main.go`
- `pkg/security/ids/correlation/`
- `build/event-correlator/Dockerfile`
- `.github/workflows/test-bootstrap.yml`
- `scripts/ci/`
- `docs/observability-architecture.md`

Acceptance:
- Kind harness writes one deterministic input event and asserts the correlated output lands in the configured sink
- controller status still only advances to `Running` on real Deployment readiness, not on ConfigMap/Service reconciliation alone
- tests cover runtime config validation (missing `source.path`, unsupported sink type, disallowed host path prefix)
- docs stop describing event correlation as "controller-only" once the runtime proof exists

#### Ticket 30: Exercise Elasticsearch Retention And Rollover Beyond Bootstrap Presence
Status:
- completed

Scope:
- today the harness proves `fos1-log-retention-14d` ILM/template attachment and a single canary document landing in `fos1-security-*`, but it does not prove rollover or aged-index deletion
- add a harness step that either writes enough canary documents to force at least one ILM rollover, or installs an accelerated ILM policy (hot-phase `max_age` in seconds, delete phase minutes) for the proof window
- assert via Elasticsearch APIs that at least one index rolled and at least one aged index was deleted
- document the accelerated-policy contract clearly so nobody confuses the proof envelope with the production `14d` retention target

Primary areas:
- `manifests/base/monitoring/elasticsearch.yaml`
- `scripts/ci/prove-security-log-pipeline.sh`
- `.github/workflows/test-bootstrap.yml`
- `docs/observability-architecture.md`

Acceptance:
- harness proves at least one `fos1-security-*` rollover and one aged-index deletion under an owned policy
- docs distinguish the accelerated CI policy from the production `14d`/`30Gi` baseline
- no status claim asserts retention behavior as verified without pointing at the rollover/deletion proof step

### P1

#### Ticket 31: Prove DPI And Security-Log Ingestion Under Natural Traffic
Status:
- completed

Scope:
- the current harness proof is a log-line canary injected near the sink, not a network event flowing through Suricata/Zeek
- add a harness step that emits a deterministic network payload from a test pod (for example a curl matching an owned Suricata signature or a protocol pattern Zeek logs) and asserts:
  - Suricata eve.json emits the expected event
  - Fluentd ships it into `fos1-security-*`
  - the DPI manager `:8080/metrics` counter for that event class advances
- this is the proof that the sensor -> log -> metric pipeline works, not only that Elasticsearch accepts hand-written documents

Primary areas:
- `scripts/ci/`
- `manifests/base/security/{suricata,zeek,dpi-manager}.yaml`
- `.github/workflows/test-bootstrap.yml`
- `docs/observability-architecture.md`

Acceptance:
- harness drives a real network payload, not a log-line injection, and proves event observability end to end through at least one sensor path
- proof is deterministic and does not depend on external threat feeds
- docs describe the natural-traffic proof explicitly and distinguish it from the existing canary

#### Ticket 32: Validate Dashboard And Alert-Rule Queries Against Live Series
Status:
- completed

Scope:
- `manifests/dashboards/*.json` and `manifests/base/monitoring/alert-rules.yaml` today reference metrics that may or may not exist in the owned exporter set
- add a CI validator that extracts every PromQL expression from the owned dashboards and alert rules, runs each one against the Kind Prometheus, and either confirms a series exists or fails the check
- for each failing expression, either wire the missing metric into an owned exporter, delete the panel/alert, or move the reference to a clearly labelled "target architecture only" section

Primary areas:
- `manifests/dashboards/`
- `manifests/base/monitoring/alert-rules.yaml`
- new validator under `scripts/ci/` or `tools/`
- `.github/workflows/test-bootstrap.yml`
- `docs/observability-architecture.md`

Acceptance:
- every PromQL expression in an owned dashboard or alert rule either returns a series in the Kind harness, is documented as target architecture, or is deleted
- the validator runs in the existing bootstrap workflow
- docs match the validated set of series

#### Ticket 33: Translate `FilterPolicy` And `FirewallRule` CRDs Into Real Cilium Network Policies
Status:
- completed

Scope:
- `Status.md` still reports `FilterPolicy`/`FirewallRule` as type-definitions-only with no enforcement
- ADR-0001 says the authoritative enforcement path is Cilium, not nftables
- implement the translator path so at least one `FilterPolicy` example reconciles into a real `CiliumNetworkPolicy` (or `CiliumClusterwideNetworkPolicy`) through the existing Cilium client
- make the controller idempotent and statusful in the same shape as the NAT controller (spec-hash comparison, `Applied`/`Degraded`/`Invalid`/`Removed` conditions)
- do not add an nftables backend in this ticket; if nftables is still named in docs as a supported backend, either remove the claim or mark it an explicit non-goal

Primary areas:
- `pkg/controllers/filter_policy_controller.go`
- `pkg/apis/.../FilterPolicy` types
- `pkg/cilium/network_controller.go`
- `pkg/cilium/client.go`
- example manifests under `manifests/examples/security/`
- `docs/design/policy-based-filtering.md`

Acceptance:
- at least one `FilterPolicy` CR produces a real Cilium network policy through the active client
- deletion removes the applied policy
- controller is idempotent and statusful with the same condition set the NAT controller already uses
- tests cover add/update/delete and reject invalid rule combinations
- docs stop advertising an nftables backend, or explicitly label it a non-goal

#### Ticket 34: Decide And Converge On SAML / RADIUS / Certificate Auth Providers
Status:
- completed

Scope:
- `pkg/security/auth/manager.go` factory methods still return `<type> provider not implemented` for SAML, RADIUS, and certificate providers, even though local, LDAP, and OAuth are fully wired
- pick one of two outcomes per provider and execute it:
  - implement the provider against a real library (e.g. `crewjam/saml` for SAML) with the same construction/session semantics as the LDAP/OAuth providers, or
  - remove the provider from the factory, the `AuthProvider` CRD enum, manifest examples, and docs so the repo stops advertising a capability it does not ship
- no "not implemented" error string may remain in an active manager factory path

Primary areas:
- `pkg/security/auth/manager.go`
- `pkg/security/auth/providers/`
- `pkg/apis/.../AuthProvider` types
- `manifests/examples/` auth examples
- `docs/design/security-orchestration-system.md`

Acceptance:
- every `AuthProvider` kind accepted by the CRD maps to a real provider construction path
- no "<x> provider not implemented" string remains in the active path
- tests verify construction and at least one authentication flow for any newly implemented provider
- docs and CRD enum agree with shipped behavior

#### Ticket 35: Real NIC Capability Reporting And Packet-Capture Contract
Status:
- completed

Scope:
- `pkg/hardware/nic/` and `pkg/hardware/capture/` still return placeholder zero-values or interface-only stubs, similar to the pre-ticket-26 offload-statistics state
- apply the ticket-26 pattern: implement real ethtool / AF_PACKET / `SO_ATTACH_FILTER` queries where the running kernel/driver actually exposes them, and return explicit "unsupported on this driver/kernel" errors everywhere else
- document which NIC families (Intel X540, X550, I225) are expected to return real data versus explicit unsupported on the current build matrix

Primary areas:
- `pkg/hardware/nic/`
- `pkg/hardware/capture/`
- `pkg/hardware/types/`
- `docs/design/hardware-integration.md`

Acceptance:
- `GetStatistics` / capability queries no longer return placeholder zero-value success for NIC or capture paths
- unsupported counters/features return explicit documented errors
- tests cover at least one supported path and one explicitly unsupported path
- docs explain supported versus unsupported NIC/driver paths for the current build matrix

### P2

#### Ticket 36: Raise Reconciliation-Style Coverage On Thin Packages
Status:
- completed

Scope:
- `Status.md` §Testing reports ~30-35% coverage, concentrated in a few packages
- target reconciliation-style tests (apply real spec -> read back applied state -> assert), not line-coverage chasing, on packages that currently lack them: `pkg/traffic/`, `pkg/security/policy/`, `pkg/hardware/wan/`, `pkg/network/ebpf/`
- any package still at near-zero coverage after this ticket must be explicitly called out as an accepted gap in `docs/design/test_matrix.md`

Primary areas:
- `pkg/traffic/`
- `pkg/security/policy/`
- `pkg/hardware/wan/`
- `pkg/network/ebpf/`
- `docs/design/test_matrix.md`

Acceptance:
- each listed package has at least one reconciliation-style test that exercises a real apply plus readback
- `go test -cover ./...` reports at least 50% on each listed package, or the gap is explicitly accepted in `test_matrix.md` with a reason
- regressions in those packages produce loud, specific test failures

#### Ticket 37: Truth-Up Status Docs After Sprint 29 Lands
Status:
- completed

Scope:
- same truth-up pattern used after tickets 20 and 27: reconcile every status claim in `Status.md`, `docs/project-tracker.md`, `docs/implementation-plan.md`, and `docs/observability-architecture.md` against what Sprint 29 actually landed
- no status claim may survive this ticket without pointing at a merged test, manifest, or harness step

Primary areas:
- `Status.md`
- `docs/project-tracker.md`
- `docs/implementation-plan.md`
- `docs/observability-architecture.md`

Acceptance:
- no status claim in the listed docs is unsupported by a landed test, manifest, or harness step
- all Sprint 29 ticket outcomes (including removed capabilities) are reflected
- remaining non-goals after Sprint 29 are explicit

## Suggested Parallel Ownership (Sprint 29)

Engineer A:
- ticket 29 first (event-correlator end-to-end proof), then ticket 31 (natural-traffic proof reuses the same Kind harness scaffolding)

Engineer B:
- ticket 30 first (Elasticsearch retention/rollover), then ticket 32 (dashboard/alert validator reuses Prometheus/Elasticsearch fixtures)

Engineer C:
- ticket 33 (`FilterPolicy` -> real Cilium policy; self-contained once 29 merges)

Engineer D:
- ticket 34 first (auth provider closeout), then ticket 35 (NIC/capture reporting)

Shared stabilization:
- ticket 36 runs alongside the ticket work once the touched packages stabilize
- ticket 37 lands last, after 29-36 are merged

## Sprint 30: Critical-Path Production Gaps

Candidate scope for the sprint that follows Sprint 29. Finalize after Ticket 37 (post-Sprint-29 truth-up) closes so status claims are accurate when this sprint opens.

Sprint 30 target gaps, distilled from `Status.md` §Critical Implementation Gaps and §Production Readiness Assessment, and from caveats flagged during Sprint 29 execution:

- **eBPF compilation + loading** — the framework manages program state but no BPF bytecode is produced or attached. Noted as the biggest remaining feature gap per `Status.md`.
- **CRD status writeback** — Ticket 33 left `FilterPolicy.Status.Conditions` mutating the cached object only; NAT controller's `writeStatusToCRD` pattern (`pkg/controllers/nat_controller.go:558`) should be lifted into a shared helper and adopted by at least FilterPolicy.
- **Management API** — no REST/gRPC surface; management only via `kubectl` + CRDs.
- **RBAC / internal TLS / secrets story** — each controller runs without explicit ClusterRole scoping, internal service TLS, or a documented secrets model.
- **Performance baseline** — zero benchmarks; unknown throughput/connection limits.
- **QoS enforcement** — CRDs and controllers exist (`pkg/controllers/qos_controller.go`, `pkg/security/qos/manager.go`) but `Status.md` reports enforcement as stub. `pkg/network/vlan/qos.go:73` still returns `"not implemented"`.
- **Threat-intelligence ingestion** — Sprint 29 non-goal; candidate for Sprint 30 if capacity permits.

Working rules for Sprint 30: same as prior sprints (no placeholder success paths, idempotent reconciliation, statusful conditions, tests updated with behavior changes, docs updated after behavior is verified).

Critical path (draft):
- 38 -> 39 -> 40 -> (41, 42 in parallel) -> 43 -> (44, 45 in parallel) -> 46

### P0

#### Ticket 38: Prototype eBPF XDP Program Compilation And Attachment
Status:
- completed

Landed commits:
- feat `3a9f677`, merge `de851a6`

Scope:
- produce one owned eBPF XDP program under `bpf/xdp_ddos_drop.c` (simple allowlist-drop based on a map-backed denylist, enough to prove the toolchain)
- integrate LLVM/Clang compilation into the build: either via a Makefile target that invokes `clang -O2 -target bpf -c` or via `github.com/cilium/ebpf/cmd/bpf2go` embedded in a Go generator
- wire `pkg/hardware/ebpf/program_manager.go` to actually load the compiled object via `github.com/cilium/ebpf` (already an indirect dependency) and attach to XDP on a target interface
- update `pkg/network/ebpf/manager.go` `LoadProgram` / `AttachProgram` to call the real path when the program type is XDP, and return an explicit "type not yet supported" error for unimplemented types
- add a Linux-only integration test that skips when `CAP_BPF`/`CAP_NET_ADMIN` is not available

Primary areas:
- new: `bpf/xdp_ddos_drop.c`
- new: `pkg/hardware/ebpf/xdp_loader_linux.go`
- new: `pkg/hardware/ebpf/xdp_loader_stub.go`
- modify: `pkg/hardware/ebpf/program_manager.go`
- modify: `pkg/network/ebpf/manager.go`
- modify: `Makefile` (add `bpf-objects` target)
- new: `pkg/hardware/ebpf/xdp_loader_linux_test.go`

Acceptance:
- a single XDP program builds and loads on Linux with the required capabilities
- non-Linux and insufficient-capability paths return explicit errors, not silent success
- the `ProgramInfo` status transitions to a real `Attached=true` only after the BPF_PROG_ATTACH syscall succeeds
- tests cover the supported path and the unsupported-platform path

### Ticket 39: Extend eBPF Loading To A TC-Attached QoS Shaping Program
Status:
- completed

Landed commits:
- feat `f9f3565` (landed directly on main, no merge commit)

Scope:
- produce one owned TC classifier program under `bpf/tc_qos_shape.c` (simple classify-and-mark using a map-backed class table)
- extend the ticket-38 loader to support TC attach via `clsact` qdisc and `BPF_PROG_TYPE_SCHED_CLS`
- route QoS controller output (`pkg/controllers/qos_controller.go`) through the new loader; remove the `Status.md` claim that QoS is a stub once the real path lands
- reconcile the `pkg/network/vlan/qos.go:73` "not implemented" return with either a real path or an explicit non-goal

Primary areas:
- new: `bpf/tc_qos_shape.c`
- modify: `pkg/hardware/ebpf/xdp_loader_linux.go` (extend to TC) or split into `tc_loader_linux.go`
- modify: `pkg/controllers/qos_controller.go`
- modify: `pkg/network/vlan/qos.go`
- modify: `Status.md`, `docs/design/ebpf-implementation.md`

Acceptance:
- at least one QoS profile applies a real TC program via the eBPF loader
- QoS controller status reflects applied-state, not configuration-accepted
- tests match the ticket-38 shape

### Ticket 40: Shared CRD Status Writeback Helper Adopted By FilterPolicy And One Other Controller
Status:
- completed

Landed commits:
- feat `47b8088`, merge `2a2851c`

Scope:
- extract the `writeStatusToCRD` pattern from `pkg/controllers/nat_controller.go:558` into `pkg/controllers/status/writer.go` (or similar shared location)
- adopt it in `pkg/security/policy/controller.go` so `FilterPolicy.Status.Conditions` + `LastAppliedHash` are persisted back to the API (Ticket 33 left this as in-memory only)
- adopt it in at least one additional controller as a second consumer (candidate: `routing_controller.go` or `dhcp_controller.go`)
- write a unit test that round-trips a status mutation through the helper against a fake client

Primary areas:
- new: `pkg/controllers/status/writer.go`
- new: `pkg/controllers/status/writer_test.go`
- modify: `pkg/controllers/nat_controller.go`
- modify: `pkg/security/policy/controller.go`
- modify: one more controller
- modify: `docs/design/implementation_caveats.md` (close the Sprint-29 follow-up note)

Acceptance:
- no controller duplicates the write-status-subresource idiom inline
- FilterPolicy `Status.Conditions` now survive a controller restart
- tests verify retry-on-conflict behavior

### P1

### Ticket 41: Read-Only REST Management API (v0)
Status:
- completed

Landed commits:
- feat `e3bc979`, merge `9c70daf`

Scope:
- add `cmd/api-server/main.go` serving Go `net/http` routes under `/v1/`
- expose one resource family read-only (suggest `/v1/filter-policies` + `/v1/filter-policies/{ns}/{name}`), backed by the existing controller's informer cache
- add authentication via TLS client certs using the existing cert-manager-issued CA
- include `/healthz` and `/readyz`
- ship a minimal OpenAPI spec at `/openapi.json`

Primary areas:
- new: `cmd/api-server/`
- new: `pkg/api/`
- modify: `manifests/base/api/` (new)
- modify: `docs/design/` new `api-server.md`

Acceptance:
- server starts, serves requests, enforces mTLS
- one integration test exercises list + get
- read-only v0 is explicit; write paths are a clearly-labelled follow-up

### Ticket 42: RBAC ClusterRoles And Internal Service Baseline
Status:
- completed

Landed commits:
- feat `e13b91a`, merge `4af3403` (branch not pushed)

Scope:
- author minimum-privilege ClusterRoles for every controller currently using the generic `cluster-admin` or loose RBAC
- add a CI check (Go test or shell script) that parses the manifests and asserts no ClusterRoleBinding references `cluster-admin`
- optionally, wire `kube-rbac-proxy` sidecars for `:metrics` endpoints

Primary areas:
- new/modify: `manifests/base/*/rbac.yaml` per controller
- new: `scripts/ci/prove-no-cluster-admin.sh`
- modify: `.github/workflows/validate-manifests.yml`

Acceptance:
- no controller has `cluster-admin` in its binding
- CI enforces it
- docs enumerate each controller's required verbs/resources

### Ticket 43: Performance Baseline Harness For One Hot Path
Status:
- completed

Landed commits:
- feat `2b844d7`, merge `4ce31e8`

Scope:
- add `tools/bench/` with a `go test -bench` harness that measures one hot path (recommended: NAT policy apply, or DPI event → Cilium policy creation)
- produce a baseline report `docs/performance/baseline-2026-XX.md` with: ops/s, p50/p95/p99 latency, memory allocation per op
- wire the harness into CI as a non-blocking run that uploads the report as an artifact
- explicitly document which hot paths are NOT covered (most of them, in v0)

Primary areas:
- new: `tools/bench/`
- new: `docs/performance/`
- modify: `.github/workflows/test-bootstrap.yml`

Acceptance:
- one benchmark runs repeatably in CI
- baseline numbers recorded in the repo with the date + commit
- regressions beyond a configurable threshold flag in CI output (warning, not failure, in v0)

### Ticket 44: Threat-Intelligence Feed Ingestion v0
Status:
- completed

Landed commits:
- feat `2c042a5`, merge `fb9dfb0`

Scope:
- ingest one public blocklist feed (recommend abuse.ch URLhaus CSV for simplicity; MISP if a test server is available) into a Kubernetes-native CRD (`ThreatFeed`) with periodic refresh
- translate feed entries into `CiliumPolicy` deny rules via the Ticket 17 DPI-event pipeline or a direct translator
- expire entries past the feed's max-age

Primary areas:
- new: `pkg/security/threatintel/`
- new: `cmd/threatintel-controller/`
- modify: `pkg/apis/security/v1alpha1/` new `ThreatFeed` types
- new: `manifests/examples/security/threatfeed-urlhaus.yaml`
- modify: `docs/design/threat-intelligence-system.md`

Acceptance:
- one feed fetch + parse + translation cycle runs end-to-end
- `ThreatFeed` CRD reports last-fetch time, entry count, expiry state
- CI harness or fake HTTP server verifies the fetch-translate-apply cycle

### Ticket 45: QoS Enforcement Via Cilium Bandwidth Manager
Status:
- completed

Landed commits:
- feat `3326f46`, merge `a04ce71`

Scope:
- decide whether to target Cilium Bandwidth Manager (preferred, fits ADR-0001) or the Ticket-39 TC loader for QoS enforcement; document the choice
- wire `QoSProfile` CRs into the chosen backend
- update `Status.md` QoS row from stub to real

Primary areas:
- `pkg/controllers/qos_controller.go`
- `pkg/security/qos/manager.go`
- `manifests/examples/qos/`

Acceptance:
- at least one `QoSProfile` produces real rate-limiting behavior verified in Kind
- tests cover apply/update/delete transitions

### P2

### Ticket 46: Post-Sprint-30 Truth-Up
Status:
- completed

Scope:
- same pattern as Ticket 37: reconcile every status claim in `Status.md`, `docs/project-tracker.md`, `docs/implementation-plan.md`, `docs/observability-architecture.md`, `docs/design/implementation_caveats.md` against what Sprint 30 actually landed
- update `Status.md` production-readiness percentage

Primary areas:
- as above

Acceptance:
- no status claim unsupported by a landed test, manifest, or harness step
- remaining gaps for Sprint 31+ explicitly enumerated

## Sprint 31 (placeholder): Post-Sprint-30 Production Hardening

Candidate scope only. Sprint 31 ticket definitions are out of scope for Ticket 46; they will be finalized in a separate planning session after this truth-up closes.

Candidate gaps, distilled from the post-Sprint-30 state of `Status.md` §Critical Gaps and from caveats flagged during Sprint 30 execution:

- **HA / clustering** — the current posture is single-node for Elasticsearch, Prometheus, Grafana, Alertmanager; controllers run as single replicas with no leader election or state replication. This is the single largest residual production blocker after Sprint 30.
- **Write-path API** — Ticket 41 shipped read-only `/v1/filter-policies`. Write verbs (POST/PUT/PATCH/DELETE), watch/streaming endpoints, and additional resource families (NAT, routing, DPI, zones) remain future work.
- **Broader eBPF program types** — Sprint 30 Tickets 38-39 landed XDP + TC loaders. `sockops` and `cgroup` program types still return `ErrEBPFProgramTypeUnsupported` from `pkg/hardware/ebpf/program_manager.go`.
- **More threat feeds** — Ticket 44 shipped URLhaus CSV. MISP, STIX/TAXII, and IP-reputation feeds are candidates; MISP/STIX are currently non-goals and would need ADR revisiting.
- **Performance optimization beyond one hot path** — Ticket 43 baselined NAT policy apply only. DPI event → Cilium policy, routing sync, DHCP control socket, and DNS zone update remain unbenchmarked.
- **Internal TLS + secrets management for non-API components** — Ticket 41 introduced mTLS for the REST API only. Inter-controller service TLS and a documented secrets model remain open.
- **Ingress rate limiting** — Ticket 45 shipped per-pod egress rate limiting via Cilium Bandwidth Manager. Ingress enforcement and classful/VLAN-scoped shaping on top of the Ticket-39 TC loader remain open.
- **VLAN-scoped TC shaper controller** — Ticket 39 landed the TC loader + clsact bootstrap + per-ifindex priority map as infrastructure. A CRD-driven controller that drives those maps from `QoSProfile` or a new `TrafficShaper` surface is still to be scoped.

Working rules for Sprint 31: same as prior sprints (no placeholder success paths, idempotent reconciliation, statusful conditions, tests updated with behavior changes, docs updated after behavior is verified).

## Architect Review Questions

1. Should CRD-backed route state remain the interim source of truth before direct Cilium datapath inspection exists?
2. Should VRF identifiers remain string-based for now, or should a dedicated registry model be introduced before ticket 5?
3. Should `pkg/controllers` and `pkg/cilium/controllers` routing flows be consolidated before further routing work proceeds?
4. When should `kubectl`-backed client behavior be replaced with client-go or direct APIs?

## Related Documents

- `docs/implementation-plan.md`
- `docs/design/adr-0001-cilium-first-control-plane-contract.md`
- `docs/design/implementation_caveats.md`
