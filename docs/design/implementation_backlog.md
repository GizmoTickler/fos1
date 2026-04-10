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

## Architect Review Questions

1. Should CRD-backed route state remain the interim source of truth before direct Cilium datapath inspection exists?
2. Should VRF identifiers remain string-based for now, or should a dedicated registry model be introduced before ticket 5?
3. Should `pkg/controllers` and `pkg/cilium/controllers` routing flows be consolidated before further routing work proceeds?
4. When should `kubectl`-backed client behavior be replaced with client-go or direct APIs?

## Related Documents

- `docs/implementation-plan.md`
- `docs/design/adr-0001-cilium-first-control-plane-contract.md`
- `docs/design/implementation_caveats.md`
