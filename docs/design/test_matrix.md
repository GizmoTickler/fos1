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
| FirewallController | `pkg/cilium/controllers` | `controller_manager_test.go` | Yes (create with selectors/rules) | Yes (missing spec, Cilium error, missing protocol) | Implemented |
| DPIController | `pkg/cilium/controllers` | `controller_manager_test.go` | Yes (create enabled/disabled) | Yes (missing spec, Cilium error) | Implemented |
| NetworkInterfaceController | `pkg/cilium/controllers` | `controller_manager_test.go` | Yes (physical, VLAN) | Yes (unsupported type, missing type) | Implemented |
| RoutingController (Cilium) | `pkg/cilium/controllers` | `controller_manager_test.go` | N/A (requires RouteSynchronizer) | Yes (missing spec, destination, invalid CIDR) | Partial |
| ControllerManager | `pkg/cilium/controllers` | `controller_manager_test.go` | N/A (orchestrator) | N/A | Partial (construction tested) |

## Package Unit Tests

| Package | Test File(s) | What Is Tested | Classification |
|---|---|---|---|
| `pkg/cilium` | `client_test.go`, `router_test.go`, `route_sync_test.go` | Cilium client, route sync, router logic | Implemented |
| `pkg/controllers` | `routing_controller_test.go`, `nat_controller_test.go`, `bgp_controller_test.go`, `ospf_controller_test.go`, `policy_controller_test.go`, `multiwan_controller_test.go`, `qos_controller_test.go` | All major controllers | Implemented |
| `pkg/cilium/controllers` | `controller_manager_test.go` | Firewall, DPI, NetworkInterface, Routing controllers | Implemented |
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
| `pkg/security/firewall` | (test files) | Firewall rules | Implemented |
| `pkg/security/firewall/ipset` | (test files) | IP set management | Implemented |
| `pkg/security/policy` | (test files) | Security policy | Implemented |
| `pkg/vpn` | (test files) | VPN types | Implemented |
| `pkg/vpn/controller` | (test files) | WireGuard controller | Implemented |
| `test/integration` | (test files) | Cross-component integration | Implemented |

## Coverage Gaps

### Packages with no test files

| Package | Reason | Priority |
|---|---|---|
| `pkg/security/qos` | QoS manager calls `tc`/`ip` commands directly; needs interface abstraction for testability | Medium |
| `pkg/traffic` | Traffic manager/classifier/allocator; needs interface-based testing | Medium |
| `pkg/network/routing` | Core routing types and RouteManager; mostly used via other tested packages | Low |
| `pkg/network/routing/multiwan` | MultiWAN types; tested indirectly via controller tests | Low |
| `pkg/network/ebpf` | eBPF interfaces; design-phase only | Low |
| `pkg/network/interfaces` | Interface management; design-phase only | Low |
| `pkg/network/ipam` | IP address management; design-phase only | Low |
| `pkg/hardware/*` | Hardware integration (NIC, eBPF, capture, offload, WAN); requires real hardware | Low |
| `pkg/dns/mdns` | mDNS reflection; design-phase only | Low |
| `pkg/security/dpi/common` | Shared DPI types | Low |
| `pkg/security/dpi/connectors` | DPI engine connectors | Low |
| `pkg/security/ids/correlation` | Event correlation; design-phase | Low |
| `pkg/security/certificates` | cert-manager integration; design-phase | Low |
| `pkg/security/auth/providers` | Auth provider implementations; tested via auth manager | Low |
| `pkg/vpn/wireguard` | WireGuard interface operations; requires real interfaces | Low |

### Controllers with partial or no integration tests

- **ControllerManager** (`pkg/cilium/controllers`): Only construction is tested. Full start/stop requires running informers with a real or fake API server.
- **Cilium RoutingController** (`pkg/cilium/controllers`): Requires a `RouteSynchronizer` instance for full reconciliation testing. Error paths are covered.

## Classification Key

- **Implemented**: Tests verify real behavior through the actual code paths (not stubs). The component functions as designed.
- **Partial**: Some test coverage exists but gaps remain (e.g., only error paths tested, or only extraction logic tested without full reconciliation).
- **Untested**: No test files exist for the package. May be tested indirectly through other packages.
- **Design-phase**: Package contains interface definitions or placeholder code that is not yet functional.
