# Test Matrix

## Controller Reconciliation Tests

| Controller | Package | Test File | Reconciliation Test | Error Case Test | Status |
|---|---|---|---|---|---|
| BGPController | `pkg/controllers` | `bgp_controller_test.go` | Yes (create, disable, delete) | Yes (missing AS number, missing spec, start failure) | Implemented |
| OSPFController | `pkg/controllers` | `ospf_controller_test.go` | Yes (create, delete, stub/NSSA areas) | Yes (missing router ID, missing spec, start failure) | Implemented |
| PolicyController | `pkg/controllers` | `policy_controller_test.go` | Yes (create, delete) | Yes (missing priority, match, action, apply error) | Implemented |
| MultiWANController | `pkg/controllers` | `multiwan_controller_test.go` | Yes (create with LB/failover, delete) | Yes (missing WAN interfaces, missing gateway, apply error) | Implemented |
| QoSController | `pkg/controllers` | `qos_controller_test.go` | Yes (spec extraction, delete) | Yes (missing interface, classes, spec; real QoS manager validation) | Implemented |
| NATController | `pkg/controllers` | `nat_controller_test.go` | Yes (SNAT/DNAT create, degraded, delete) | Yes (invalid spec, apply failure) | Pre-existing |
| RoutingController (VRF sync) | `pkg/controllers` | `routing_controller_test.go` | Yes (VRF sync, route conversion, idempotency, stale route removal) | Yes (Cilium client error, invalid destinations, invalid table ID) | Pre-existing |
| ~~FirewallController~~ | — | — | Removed in sprint 29 ticket 33 per ADR-0001 | FilterPolicy is the authoritative policy surface (`pkg/security/policy/controller_test.go`) | Removed |
| DPIController | `pkg/cilium/controllers` | `controller_manager_test.go` | Yes (create enabled/disabled) | Yes (missing spec, Cilium error) | Implemented |
| NetworkInterfaceController | `pkg/cilium/controllers` | `controller_manager_test.go` | Yes (physical, VLAN) | Yes (unsupported type, missing type) | Implemented |
| RoutingController (Cilium) | `pkg/cilium/controllers` | `controller_manager_test.go` | N/A (requires RouteSynchronizer) | Yes (missing spec, destination, invalid CIDR) | Partial |
| ControllerManager | `pkg/cilium/controllers` | `controller_manager_test.go` | N/A (orchestrator) | N/A | Partial (construction tested) |

## Package Unit Tests

| Package | Test File(s) | What Is Tested | Classification |
|---|---|---|---|
| `pkg/cilium` | `client_test.go`, `router_test.go`, `route_sync_test.go` | Cilium client, route sync, router logic | Implemented |
| `pkg/controllers` | `routing_controller_test.go`, `nat_controller_test.go`, `bgp_controller_test.go`, `ospf_controller_test.go`, `policy_controller_test.go`, `multiwan_controller_test.go`, `qos_controller_test.go` | All major controllers | Implemented |
| `pkg/cilium/controllers` | `controller_manager_test.go` | DPI, NetworkInterface, Routing controllers (FirewallController removed in sprint 29 ticket 33) | Implemented |
| `pkg/network/routing/frr` | `config_test.go`, `manager_test.go` | FRR config generation, vtysh validation | Implemented |
| `pkg/network/routing/protocols` | `bgp_test.go`, `ospf_test.go` | BGP/OSPF protocol handlers | Implemented |
| `pkg/network/routing/policy` | (test files) | Policy-based routing | Implemented |
| `pkg/network/nat` | (test files) | NAT config, apply result, status | Implemented |
| `pkg/network/vlan` | (test files) | VLAN management | Implemented |
| `pkg/network/events` | (test files) | Network event system | Implemented |
| `pkg/dhcp` | `kea_manager_test.go` | Kea DHCP manager | Implemented |
| `pkg/dhcp/kea` | `client_test.go` | Kea control socket client | Implemented |
| `pkg/dhcp/controller/test` | (test files) | DHCP controller | Implemented |
| `pkg/dns/manager` | `manager_test.go` | DNS manager | Implemented |
| `pkg/dns/coredns` | (test files) | CoreDNS integration | Implemented |
| `pkg/dns/adguard` | (test files) | AdGuard integration | Implemented |
| `pkg/ntp/api` | (test files) | NTP API | Implemented |
| `pkg/ntp/chrony` | (test files) | Chrony integration | Implemented |
| `pkg/ntp/controller` | (test files) | NTP controller | Implemented |
| `pkg/ntp/manager` | (test files) | NTP manager | Implemented |
| `pkg/security/dpi` | `manager_test.go`, `policy_pipeline_test.go` | DPI event-to-policy pipeline | Implemented |
| `pkg/security/ids` | `manager_test.go` | IDS/IPS manager | Implemented |
| `pkg/security/ids/suricata` | (test files) | Suricata connector | Implemented |
| `pkg/security/ids/zeek` | (test files) | Zeek connector | Implemented |
| `pkg/security/auth` | `manager_test.go` | Auth manager, providers | Implemented |
| `pkg/security/firewall` | removed | Non-goal per ADR-0001; replaced by `pkg/security/policy` Cilium translator (sprint 29 ticket 33) |
| `pkg/security/firewall/ipset` | removed | Removed with the rest of `pkg/security/firewall` (sprint 29 ticket 33) |
| `pkg/security/policy` | `controller_test.go`, `translator_test.go` | Cilium-first FilterPolicy translator + statusful reconciler with Applied/Degraded/Invalid/Removed conditions and spec-hash idempotency | Implemented |
| `pkg/vpn` | (test files) | VPN types | Implemented |
| `pkg/vpn/controller` | (test files) | WireGuard controller | Implemented |
| `pkg/traffic` | `manager_test.go`, `classifier_test.go`, `bandwidth_test.go` | Manager apply/delete reconciliation, classifier rule CRUD + matching, bandwidth alloc/release + unit parsing | Implemented (Ticket 36) |
| `pkg/hardware/wan` | `manager_test.go` | WAN manager add/remove/set-active/state/statistics/connectivity with fake netlink backend | Implemented (Ticket 36) |
| `pkg/network/ebpf` | `manager_test.go`, `reconcile_test.go` | ProgramManager lifecycle + MapManager error paths via fake hardware manager | Implemented (Ticket 36) |
| `test/integration` | (test files) | Cross-component integration | Implemented |

## Coverage Gaps

### Packages with no test files

| Package | Reason | Priority |
|---|---|---|
| `pkg/security/qos` | QoS manager calls `tc`/`ip` commands directly; needs interface abstraction for testability | Medium |
| `pkg/network/routing` | Core routing types and RouteManager; mostly used via other tested packages | Low |
| `pkg/network/routing/multiwan` | MultiWAN types; tested indirectly via controller tests | Low |
| `pkg/network/interfaces` | Interface management; design-phase only | Low |
| `pkg/network/ipam` | IP address management; design-phase only | Low |
| `pkg/hardware/*` (except `wan`) | Hardware integration (NIC, eBPF, capture, offload); requires real hardware | Low |
| `pkg/dns/mdns` | mDNS reflection; design-phase only | Low |
| `pkg/security/dpi/common` | Shared DPI types | Low |
| `pkg/security/dpi/connectors` | DPI engine connectors | Low |
| `pkg/security/ids/correlation` | Event correlation; design-phase | Low |
| `pkg/security/certificates` | cert-manager integration; design-phase | Low |
| `pkg/security/auth/providers` | Auth provider implementations; tested via auth manager | Low |
| `pkg/vpn/wireguard` | WireGuard interface operations; requires real interfaces | Low |

## Sprint 29 / Ticket 36 -- Thin-package reconciliation coverage

Reconciliation-style tests (apply real spec -> read back applied state ->
assert) were added to three historically-thin packages. Each introduces a
minimal injection seam in production code; tests drive the public API
through the seam without kernel privileges or external daemons.

| Package | Coverage before | Coverage after | Target | Notes |
|---|---:|---:|---:|---|
| `pkg/traffic/` | 0.0 % | 51.4 % | >= 50 % | Seams: `checkInterfaceExists` / `getInterfaceSpeed` package variables; `trafficControlApplier` / `trafficControlRemover` per-manager hooks; `newManager()` helper that disables the background statistics goroutine. Tests cover Manager.ApplyConfiguration / DeleteConfiguration / GetStatus / ListConfigurations / GetClassStatistics / GetInterfaceStatistics, Classifier CRUD and matching across every dimension, BandwidthAllocator allocate/release/query with unit parsing. |
| `pkg/hardware/wan/` | 0.0 % | 57.6 % | >= 50 % | Seams: `netlinkBackend` interface abstracting the six `netlink.*` calls; `connectivityChecker` hook replacing the ping-based probe. All tests use `MonitorEnabled: false` to avoid the monitor goroutine. Covers AddWANInterface / RemoveWANInterface / SetActiveWAN / SetWANInterfaceState / GetWANInterface / GetWANStatus / GetWANStatistics / ListWAN* / TestWANConnectivity, plus `parsePingOutput`. |
| `pkg/network/ebpf/` | 43.2 % | 93.2 % | >= 50 % | Seam: `hardwareManager` interface describing the subset of `*hwEbpf.Manager` this wrapper consumes. Tests supply an in-memory fake and drive the full load / attach / detach / unload / replace lifecycle, plus ListPrograms type-translation branches and MapManager error paths. |

### Packages covered by other tickets

| Package | Status |
|---|---|
| `pkg/security/policy/` | Covered by Sprint 29 / Ticket 33 (FilterPolicy -> Cilium). Not in scope for Ticket 36. |

### Accepted gaps

None for the Ticket 36 packages: all three cleared the 50 % bar with
pure-unit tests once the seams above were in place.

### Controllers with partial or no integration tests

- **ControllerManager** (`pkg/cilium/controllers`): Only construction is tested. Full start/stop requires running informers with a real or fake API server.
- **Cilium RoutingController** (`pkg/cilium/controllers`): Requires a `RouteSynchronizer` instance for full reconciliation testing. Error paths are covered.

## Classification Key

- **Implemented**: Tests verify real behavior through the actual code paths (not stubs). The component functions as designed.
- **Partial**: Some test coverage exists but gaps remain (e.g., only error paths tested, or only extraction logic tested without full reconciliation).
- **Untested**: No test files exist for the package. May be tested indirectly through other packages.
- **Design-phase**: Package contains interface definitions or placeholder code that is not yet functional.
