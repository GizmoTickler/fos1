# Implementation Plan
**Version:** 1.0
**Date:** 2025-11-12
**Repository:** Kubernetes-Based Router/Firewall (FOS1)

## Executive Summary

This document provides a **comprehensive implementation roadmap** to transform this repository from an architectural blueprint (15-20% functional) into a production-ready Kubernetes-based router/firewall system. The plan is organized into phases, with clear priorities, estimated effort, and success criteria.

**Total Estimated Timeline:** 18-24 months
**Recommended Team Size:** 3-5 experienced engineers
**Current Status:** Alpha/Proof-of-Concept
**Target Status:** Production-Ready v1.0

---

## Critical Success Factors

1. **Kernel Integration First** - Without netlink syscalls, nothing actually manipulates the network
2. **Test-Driven Development** - Raise coverage from <20% to >80%
3. **Incremental Delivery** - Each phase produces a working increment
4. **Documentation as Code** - Keep docs in sync with implementation
5. **Performance from Day 1** - Design for 10Gbps+ throughput

---

## Phase 0: Foundation & Infrastructure (Months 1-2)

**Goal:** Establish development environment, CI/CD, and testing framework

### 0.1 Development Environment

**Tasks:**
- [ ] Set up multi-node Kubernetes development cluster
- [ ] Configure Talos Linux test environment
- [ ] Install all external dependencies (FRR, Suricata, Zeek, Kea, etc.)
- [ ] Create development VM/container images
- [ ] Document development setup in `docs/development/setup.md`

**Deliverables:**
- Working dev environment with all services
- Reproducible setup scripts
- Dev environment documentation

**Estimated Effort:** 2 weeks

---

### 0.2 CI/CD Pipeline

**Tasks:**
- [ ] Set up GitHub Actions workflows (or GitLab CI)
- [ ] Implement automated testing on PR
- [ ] Add linting and static analysis
- [ ] Configure container image builds
- [ ] Set up automated deployment to test cluster
- [ ] Add test coverage reporting

**Deliverables:**
- `.github/workflows/test.yml` - Run tests on every PR
- `.github/workflows/build.yml` - Build container images
- `.github/workflows/deploy.yml` - Deploy to test cluster
- Coverage reports in CI

**Estimated Effort:** 2 weeks

---

### 0.3 Testing Framework

**Tasks:**
- [ ] Set up test infrastructure (testify, mock frameworks)
- [ ] Create test utilities package (`pkg/internal/testutil/`)
- [ ] Implement mock Kubernetes API server
- [ ] Create network namespace test helpers
- [ ] Add integration test framework
- [ ] Set up test data fixtures

**Deliverables:**
- `pkg/internal/testutil/` - Test utilities
- `test/fixtures/` - Test data
- `test/integration/` - Integration test framework
- Unit test template and examples

**Estimated Effort:** 2 weeks

**Total Phase 0:** 6 weeks

---

## Phase 1: Network Stack Foundation (Months 2-4)

**Goal:** Implement kernel integration for network interfaces, VLANs, and basic routing

### 1.1 Network Interface Kernel Integration ✅ COMPLETE

**Current State:** ✅ Fully implemented with netlink integration

**Implementation Tasks:**
- [x] Integrate `github.com/vishvananda/netlink` library
- [x] Implement `createInterface()` with netlink.LinkAdd()
- [x] Implement `deleteInterface()` with netlink.LinkDel()
- [x] Add interface state monitoring via netlink.LinkSubscribe()
- [x] Implement MTU, MAC address configuration
- [x] Add IPv4/IPv6 address assignment
- [x] Handle interface up/down state transitions
- [x] Add comprehensive error handling

**Files Modified:**
- `pkg/network/manager.go` - Added netlink integration
- `pkg/network/interfaces/kernel.go` - NEW: Full kernel operations implementation
- `pkg/network/interfaces/vlan.go` - Updated imports

**Testing:**
- [x] Unit tests with network namespaces
- [x] Integration tests creating real interfaces
- [x] Test interface state transitions
- [x] Test error conditions (permissions, conflicts)

**Success Criteria:**
- ✅ Can create/delete physical and virtual interfaces
- ✅ Interface state properly synchronized with kernel
- ✅ Comprehensive test coverage with 25+ test cases

**Completed:** 2025-11-17
**Actual Effort:** 1 day

---

### 1.2 VLAN Kernel Implementation ✅ COMPLETE

**Current State:** ✅ Fully implemented with netlink integration, QoS, statistics, and DSCP marking

**Implementation Tasks:**
- [x] Implement VLAN interface creation via netlink
- [x] Add VLAN ID configuration (1-4094)
- [x] Implement 802.1Q tagging
- [x] Add QoS priority handling (802.1p)
- [x] Implement VLAN trunk configuration
- [x] Add VLAN interface lifecycle management
- [x] Integrate with existing VLAN manager events
- [x] Implement Traffic Control (TC) for QoS classes with HTB
- [x] Add statistics collection from /sys/class/net/
- [x] Implement DSCP marking with TC u32 filters and skbedit

**Features Implemented:**
- **802.1p VLAN Priority**: Egress QoS mapping via `ip link` commands (priority 0-7)
- **Traffic Control (TC)**: HTB qdisc with rate limiting, ceiling, and burst control
- **QoS Classes**: Multiple classes with configurable leaf qdiscs (SFQ/RED/GRED/Codel/FQ-Codel)
- **Advanced Queue Disciplines**: RED, GRED, Codel, FQ-Codel with ECN support
- **Ingress QoS**: IFB device-based ingress traffic shaping
- **DSCP Marking**: TC u32 filters with skbedit action for both IPv4 and IPv6
- **Statistics Collection**: Real-time stats from netlink and /sys/class/net/
- **Rate Parsing**: Support for Gbit, Mbit, Kbit rate strings
- **Detailed Stats**: CRC errors, frame errors, collisions, multicast counters

**Files Modified:**
- `pkg/network/vlan/manager.go` - QoS/stats integration, DSCP lifecycle
- `pkg/network/vlan/qos.go` - Full QoS with TC, DSCP marking via tc command
- `pkg/network/vlan/stats.go` - Statistics collection from sysfs/netlink
- `pkg/network/vlan/manager_test.go` - 20+ VLAN manager tests
- `pkg/network/vlan/qos_test.go` - 13+ QoS and DSCP tests
- `pkg/network/vlan/stats_test.go` - 10+ statistics tests
- `pkg/network/vlan/controller.go` - Fixed IPv4/IPv6 address handling

**Testing:**
- [x] Create VLAN interfaces on physical NICs
- [x] Test VLAN tagging and untagging
- [x] Test trunk ports with multiple VLANs
- [x] QoS priority tests (802.1p)
- [x] TC QoS classes with rate limiting
- [x] DSCP marking validation (including common values: BE, AF, EF, CS)
- [x] DSCP to TOS field conversion tests
- [x] Statistics collection and monitoring tests
- [x] Comprehensive unit test coverage (70+ tests)

**Success Criteria:**
- ✅ VLAN interfaces operational in kernel via netlink
- ✅ Traffic properly tagged/untagged (802.1Q)
- ✅ QoS configuration via TC working (HTB + classes)
- ✅ DSCP marking functional via TC filters
- ✅ Statistics collected from kernel in real-time
- ✅ All tests compile and pass

**Completed:** 2025-11-17
**Actual Effort:** 1 day

**Follow-up Tasks:** ✅ All Complete
- [x] **Ingress QoS with IFB Devices** - Implemented IFB device creation, ingress qdisc, traffic redirection, and automatic kernel module loading
- [x] **Integration Tests** - Added 6 comprehensive integration tests requiring root privileges (VLAN creation, QoS, statistics, DSCP, trunk, ingress QoS)
- [x] **Advanced TC Features** - Implemented RED, GRED, Codel, and FQ-Codel queueing disciplines with full parameter support and ECN capability

**Advanced QoS Features Added (Follow-up):**
- **IFB Devices**: Ingress traffic shaping by redirecting to virtual IFB interface
- **RED (Random Early Detection)**: Congestion avoidance with adaptive mode and ECN support
- **GRED (Generalized RED)**: Multi-class RED with 8 Drop Priorities for DiffServ
- **Codel**: Controlled Delay AQM algorithm with target/interval parameters
- **FQ-Codel**: Fair Queue + Codel for improved performance under load
- **Queue Type Selection**: Per-class queue discipline selection (SFQ/RED/GRED/Codel/FQ-Codel)
- **ECN Support**: Explicit Congestion Notification for RED/GRED/Codel/FQ-Codel
- **Integration Tests**: Real kernel verification with dummy interfaces (requires root)

**Additional Files Created/Modified (Follow-up):**
- `pkg/network/vlan/qos.go` - Added RED/GRED/Codel/FQ-Codel implementations, IFB support
- `pkg/network/vlan/types.go` - Added QueueType, REDParams, CodelParams structures
- `pkg/network/vlan/integration_test.go` - 6 integration tests (510+ lines)
- `pkg/network/vlan/qos_test.go` - Added 5 advanced TC test suites (370+ additional lines)
- `pkg/network/vlan/controller_test.go` - Fixed deep copy issues for unstructured objects

**Follow-up Completed:** 2025-11-17
**Follow-up Effort:** 2 hours

---

### 1.3 Static Routing Implementation ✅ COMPLETE

**Current State:** ✅ Fully implemented with netlink integration, ECMP, and comprehensive testing

**Implementation Tasks:**
- [x] Implement route installation via netlink.RouteAdd()
- [x] Add route deletion via netlink.RouteDel()
- [x] Implement route table management
- [x] Add route priority/metrics
- [x] Implement multi-path routing (ECMP)
- [x] Add route synchronization with kernel
- [x] Handle route conflicts and updates
- [x] Implement route filtering

**Files Modified:**
- `pkg/network/routing/kernel.go` - NEW: Full kernel operations implementation with netlink
- `pkg/network/routing/manager.go` - Updated to use kernel route manager
- `pkg/network/routing/synchronizer.go` - Fixed for NextHops array
- `pkg/network/routing/manager_test.go` - NEW: 20+ comprehensive unit tests
- `pkg/network/routing/integration_test.go` - NEW: 6 integration tests (requires root)

**Features Implemented:**
- **Route Installation**: Full netlink integration for adding routes to kernel
- **Route Deletion**: Proper route removal with error handling
- **Route Table Management**: Support for multiple routing tables (main, local, custom)
- **Route Priority/Metrics**: Full metric and preference support
- **Multi-Path Routing (ECMP)**: Support for routes with multiple next hops with weights
- **Route Synchronization**: Kernel route monitoring and synchronization
- **Route Filtering**: Advanced filtering by destination, next hop, protocol, VRF, table, tags
- **Protocol Support**: Support for static, BGP, OSPF, kernel, boot protocols
- **Scope Support**: Support for global, site, link, host scopes
- **VRF Support**: Full VRF isolation support
- **Route Tagging**: Support for route tags for organization
- **Error Handling**: Comprehensive error handling with proper cleanup
- **Route Monitoring**: Real-time route change monitoring via netlink subscription

**Testing:**
- [x] Install static routes in kernel (integration tests)
- [x] Verify routing table contents (integration tests)
- [x] Test route priorities (unit tests)
- [x] ECMP multi-path tests (integration tests)
- [x] Route update/delete tests (integration tests)
- [x] Route validation tests (20+ unit tests)
- [x] Route filtering tests (unit tests)
- [x] Protocol and scope tests (unit tests)

**Success Criteria:**
- ✅ Static routes operational in kernel via netlink
- ✅ Multi-path routing (ECMP) working with weights
- ✅ Route changes properly reconciled
- ✅ All tests compile and pass

**Completed:** 2025-11-17
**Actual Effort:** 1 day

---

### 1.4 IP Address Management ✅ COMPLETE

**Current State:** ✅ Fully implemented with comprehensive IP address management

**Implementation Tasks:**
- [x] Implement IP address assignment via netlink
- [x] Add IPv4 and IPv6 support
- [x] Implement subnet configuration
- [x] Add duplicate address detection
- [x] Handle address lifecycle
- [x] Implement address synchronization

**Files Created/Modified:**
- `pkg/network/ipam/types.go` - NEW: Complete type definitions for IP addresses, subnets, and allocations
- `pkg/network/ipam/kernel.go` - NEW: Kernel address manager with netlink integration
- `pkg/network/ipam/manager.go` - NEW: High-level IPAM manager with subnet allocation
- `pkg/network/ipam/manager_test.go` - NEW: Comprehensive unit tests (30+ test cases)
- `pkg/network/ipam/integration_test.go` - NEW: Integration tests requiring root (10 test cases)

**Features Implemented:**
- **IP Address Assignment**: Full netlink integration for adding/deleting addresses to interfaces
- **IPv4 and IPv6 Support**: Complete support for both address families with family detection
- **Subnet Management**: Subnet tracking, CIDR parsing, range calculation, and allocation tracking
- **Duplicate Address Detection (DAD)**: Full DAD support for IPv6 with state monitoring and callbacks
- **Address Lifecycle**: Complete lifecycle management (add/delete/update/sync)
- **Address Synchronization**: Real-time address monitoring via netlink subscription
- **IP Allocation**: Automatic IP allocation from managed subnets with preferred IP support
- **Address Flags**: Support for permanent, secondary, temporary, deprecated, tentative, and other flags
- **Address Scopes**: Support for global, site, link, and host scopes
- **Reserved IPs**: IP reservation system to prevent allocation of specific addresses
- **Broadcast Calculation**: Automatic broadcast address calculation for IPv4 subnets
- **Subnet Ranges**: Automatic calculation of usable IP ranges within subnets
- **Address States**: State tracking (unknown, tentative, valid, duplicate, deprecated, failed)
- **Address Updates**: Real-time address update events with callback support

**Testing:**
- [x] Assign IPv4/IPv6 addresses to interfaces (integration tests)
- [x] Test address conflicts and duplicate detection (integration tests)
- [x] Verify subnet calculations (unit tests)
- [x] Test address lifecycle (add/delete/update) (integration tests)
- [x] Test IP allocation and release (integration tests)
- [x] Test preferred IP allocation (integration tests)
- [x] Test multiple concurrent allocations (integration tests)
- [x] Test address synchronization with kernel (integration tests)
- [x] Test DAD completion for IPv6 (integration tests)
- [x] Test address flushing (integration tests)
- [x] Comprehensive unit tests for all types and methods (30+ tests)

**Success Criteria:**
- ✅ IP addresses properly configured on interfaces via netlink
- ✅ Both IPv4 and IPv6 working with proper family detection
- ✅ DAD working for IPv6 addresses
- ✅ Subnet allocation and management functional
- ✅ Address lifecycle properly managed
- ✅ Real-time address monitoring working
- ✅ All tests compile and pass (non-root tests)

**Completed:** 2025-11-17
**Actual Effort:** 1 day

**Total Phase 1:** 10 weeks

---

## Phase 2: Routing Protocols & Advanced Networking (Months 5-7)

**Goal:** Implement dynamic routing with FRRouting integration

### 2.1 FRRouting Integration ⚠️ CRITICAL

**Current State:** FRR controllers exist but no daemon communication

**Implementation Tasks:**
- [ ] Implement FRR vtysh command execution
- [ ] Add FRR configuration file generation
- [ ] Implement FRR daemon lifecycle management
- [ ] Add FRR status monitoring
- [ ] Create FRR API client (if using gRPC API)
- [ ] Implement configuration reload/refresh
- [ ] Add error handling and retries

**Files to Modify:**
- Create `pkg/network/routing/frr/` package
- `pkg/network/routing/frr/client.go` - FRR communication
- `pkg/network/routing/frr/config.go` - Config generation
- `pkg/controllers/bgp_controller.go` - Real BGP integration
- `pkg/controllers/ospf_controller.go` - Real OSPF integration

**Testing:**
- [ ] Start/stop FRR daemons
- [ ] Configure BGP sessions
- [ ] Verify route advertisements
- [ ] Test BGP peering
- [ ] OSPF neighbor tests

**Success Criteria:**
- FRR daemons manageable from code
- BGP sessions established
- Routes learned and installed

**Estimated Effort:** 4 weeks

---

### 2.2 BGP Implementation

**Implementation Tasks:**
- [ ] Implement BGP session configuration
- [ ] Add BGP peer management
- [ ] Implement prefix advertisements
- [ ] Add route filtering (import/export)
- [ ] Implement BGP communities
- [ ] Add AS path manipulation
- [ ] Implement route maps

**Files to Modify:**
- `pkg/network/routing/protocols/bgp.go` - Real BGP logic
- `pkg/controllers/bgp_controller.go` - BGP reconciliation

**Testing:**
- [ ] Establish BGP peerings
- [ ] Exchange routes with peers
- [ ] Test route filtering
- [ ] Verify communities
- [ ] Test failover scenarios

**Success Criteria:**
- BGP fully operational
- Routes exchanged with peers
- Policy-based filtering working

**Estimated Effort:** 3 weeks

---

### 2.3 OSPF Implementation

**Implementation Tasks:**
- [ ] Implement OSPF area configuration
- [ ] Add interface OSPF settings
- [ ] Implement OSPF authentication
- [ ] Add route redistribution
- [ ] Implement stub areas
- [ ] Add OSPF metrics/costs

**Files to Modify:**
- `pkg/network/routing/protocols/ospf.go` - Real OSPF logic
- `pkg/controllers/ospf_controller.go` - OSPF reconciliation

**Testing:**
- [ ] Form OSPF adjacencies
- [ ] Exchange LSAs
- [ ] Test route calculation
- [ ] Verify SPF algorithm
- [ ] Test area types

**Success Criteria:**
- OSPF fully operational
- Routes learned via OSPF
- Areas configured correctly

**Estimated Effort:** 3 weeks

---

### 2.4 Policy-Based Routing

**Implementation Tasks:**
- [ ] Implement routing policy tables
- [ ] Add policy rules (by source, dest, port, etc.)
- [ ] Implement mark-based routing
- [ ] Add route table selection
- [ ] Integrate with firewall marks

**Files to Modify:**
- `pkg/network/routing/policy/` - Policy routing logic

**Testing:**
- [ ] Route based on source IP
- [ ] Route based on destination
- [ ] Test firewall mark routing
- [ ] Verify policy priorities

**Success Criteria:**
- Policy-based routing operational
- Traffic routed per policies

**Estimated Effort:** 2 weeks

**Total Phase 2:** 12 weeks

---

## Phase 3: Firewall & Security (Months 8-10)

**Goal:** Implement nftables-based firewall and policy enforcement

### 3.1 nftables Integration ⚠️ CRITICAL

**Current State:** nftables interface definitions only, no implementation

**Implementation Tasks:**
- [ ] Integrate nftables library or use netlink directly
- [ ] Implement table creation/deletion
- [ ] Add chain management (input, output, forward)
- [ ] Implement rule generation from FilterPolicy
- [ ] Add rule priority and ordering
- [ ] Implement IP sets for efficient matching
- [ ] Add connection tracking integration
- [ ] Implement stateful filtering

**Files to Modify:**
- `pkg/security/firewall/nftables.go` - Full implementation
- Create `pkg/security/firewall/rules/` for rule generation

**Testing:**
- [ ] Create nftables tables
- [ ] Add chains and rules
- [ ] Test packet matching
- [ ] Verify stateful filtering
- [ ] Test connection tracking

**Success Criteria:**
- nftables rules generated and applied
- Stateful firewall operational
- Connection tracking working

**Estimated Effort:** 4 weeks

---

### 3.2 FilterPolicy Implementation

**Current State:** Types defined but no policy enforcement

**Implementation Tasks:**
- [ ] Implement policy-to-rule translation
- [ ] Add hierarchical policy support
- [ ] Implement zone-based policies
- [ ] Add policy precedence handling
- [ ] Implement default deny policies
- [ ] Add logging and auditing
- [ ] Integrate with nftables

**Files to Modify:**
- `pkg/security/policy/` - Policy enforcement logic
- `pkg/controllers/filter_policy_controller.go` - Policy reconciliation

**Testing:**
- [ ] Create filter policies
- [ ] Verify rule generation
- [ ] Test policy precedence
- [ ] Zone-based filtering tests
- [ ] Test logging

**Success Criteria:**
- Policies translated to nftables rules
- Zone-based filtering working
- Audit logs captured

**Estimated Effort:** 3 weeks

---

### 3.3 NAT Implementation ⚠️ CRITICAL

**Current State:** NAT types defined, no actual NAT

**Implementation Tasks:**
- [ ] Implement SNAT via nftables
- [ ] Add DNAT and port forwarding
- [ ] Implement masquerading
- [ ] Add 1:1 NAT
- [ ] Implement NAT66 for IPv6
- [ ] Add NAT session tracking
- [ ] Integrate with Cilium NAT policies

**Files to Modify:**
- `pkg/network/nat/manager.go` - NAT implementation
- `pkg/controllers/nat_controller.go` - NAT reconciliation

**Testing:**
- [ ] SNAT outbound traffic
- [ ] DNAT inbound traffic
- [ ] Port forwarding tests
- [ ] 1:1 NAT verification
- [ ] NAT66 IPv6 tests

**Success Criteria:**
- All NAT types working
- NAT sessions tracked
- Cilium integration complete

**Estimated Effort:** 3 weeks

---

### 3.4 IPSet Management

**Implementation Tasks:**
- [ ] Implement nftables set creation
- [ ] Add dynamic set updates
- [ ] Implement timeout-based sets
- [ ] Add set-based filtering
- [ ] Integrate with threat intelligence

**Files to Create:**
- `pkg/security/firewall/ipset/` - IPSet management

**Testing:**
- [ ] Create and populate sets
- [ ] Test dynamic updates
- [ ] Verify timeout expiration
- [ ] Set-based filtering tests

**Success Criteria:**
- IPSets operational
- Dynamic updates working
- Integrated with firewall

**Estimated Effort:** 2 weeks

**Total Phase 3:** 12 weeks

---

## Phase 4: eBPF & Performance (Months 11-13)

**Goal:** Implement eBPF program compilation, loading, and XDP/TC hooks

### 4.1 eBPF Compilation Infrastructure ⚠️ CRITICAL

**Current State:** eBPF manager exists but no BPF compilation

**Implementation Tasks:**
- [ ] Integrate Cilium eBPF library
- [ ] Set up LLVM/Clang for BPF compilation
- [ ] Implement BPF program loading via bpf() syscall
- [ ] Add eBPF verification handling
- [ ] Implement eBPF map creation
- [ ] Add map update/lookup operations
- [ ] Create BPF program templates (XDP, TC, sockops)

**Files to Modify:**
- `pkg/network/ebpf/manager.go` - Add BPF loading
- `pkg/hardware/ebpf/manager.go` - Add compilation
- Create `pkg/network/ebpf/compiler/` for BPF compilation
- Create `bpf/` directory for BPF C programs

**Testing:**
- [ ] Compile BPF programs
- [ ] Load programs into kernel
- [ ] Verify BPF verifier acceptance
- [ ] Test map operations
- [ ] XDP program attachment

**Success Criteria:**
- BPF programs compiled from C
- Programs loaded and verified
- Maps operational

**Estimated Effort:** 5 weeks

---

### 4.2 XDP Programs for Early Packet Processing

**Implementation Tasks:**
- [ ] Implement XDP DDoS mitigation
- [ ] Add XDP packet filtering
- [ ] Implement XDP rate limiting
- [ ] Add XDP load balancing
- [ ] Create XDP statistics collection

**Files to Create:**
- `bpf/xdp_firewall.c` - XDP filtering program
- `bpf/xdp_ddos.c` - DDoS mitigation
- `bpf/xdp_ratelimit.c` - Rate limiting

**Testing:**
- [ ] Attach XDP to interfaces
- [ ] Test packet filtering
- [ ] Verify DDoS mitigation
- [ ] Load balancing tests
- [ ] Performance benchmarks

**Success Criteria:**
- XDP programs operational
- Early filtering working
- Performance >10Gbps

**Estimated Effort:** 4 weeks

---

### 4.3 TC Programs for Traffic Control

**Implementation Tasks:**
- [ ] Implement TC egress QoS
- [ ] Add TC ingress classification
- [ ] Implement TC rate shaping
- [ ] Add TC priority queuing
- [ ] Create TC packet mangling

**Files to Create:**
- `bpf/tc_qos.c` - QoS implementation
- `bpf/tc_classify.c` - Classification
- `bpf/tc_shaper.c` - Traffic shaping

**Testing:**
- [ ] Attach TC programs
- [ ] Test QoS priorities
- [ ] Verify rate shaping
- [ ] Classification tests
- [ ] Throughput tests

**Success Criteria:**
- TC QoS operational
- Traffic shaping working
- Bandwidth limits enforced

**Estimated Effort:** 3 weeks

**Total Phase 4:** 12 weeks

---

## Phase 5: IDS/IPS & DPI (Months 14-16)

**Goal:** Complete integration with Suricata, Zeek, and DPI engines

### 5.1 Suricata Integration ⚠️ CRITICAL

**Current State:** Kubernetes controller exists, no daemon communication

**Implementation Tasks:**
- [ ] Implement Suricata Unix socket communication
- [ ] Add Suricata control commands (reload, stats)
- [ ] Implement EVE JSON log parsing
- [ ] Add alert processing and forwarding
- [ ] Implement rule management
- [ ] Add signature updates
- [ ] Integrate with policy system for dynamic blocking

**Files to Modify:**
- `pkg/security/ids/suricata/controller.go` - Add daemon control
- `pkg/security/dpi/connectors/suricata.go` - Complete implementation

**Testing:**
- [ ] Start/stop Suricata
- [ ] Load custom rules
- [ ] Trigger alerts
- [ ] Parse EVE JSON
- [ ] Test dynamic blocking

**Success Criteria:**
- Suricata fully managed
- Alerts processed in real-time
- Dynamic rule updates

**Estimated Effort:** 4 weeks

---

### 5.2 Zeek Integration

**Current State:** Kubernetes controller exists, no daemon communication

**Implementation Tasks:**
- [ ] Implement Zeek broker API client
- [ ] Add Zeek log parsing (conn.log, dns.log, etc.)
- [ ] Implement Zeek script deployment
- [ ] Add Zeek cluster management
- [ ] Integrate protocol analysis with DPI
- [ ] Add anomaly detection

**Files to Modify:**
- `pkg/security/ids/zeek/controller.go` - Add daemon control
- `pkg/security/dpi/connectors/zeek.go` - Complete implementation

**Testing:**
- [ ] Deploy Zeek clusters
- [ ] Parse connection logs
- [ ] Test protocol analysis
- [ ] Deploy custom scripts
- [ ] Anomaly detection tests

**Success Criteria:**
- Zeek fully operational
- Logs parsed and processed
- Protocol analysis working

**Estimated Effort:** 4 weeks

---

### 5.3 DPI Engine Integration

**Implementation Tasks:**
- [ ] Complete application detection
- [ ] Add SSL/TLS inspection
- [ ] Implement protocol decoders
- [ ] Add payload inspection
- [ ] Integrate with nProbe (optional)
- [ ] Add DPI-based policies

**Files to Modify:**
- `pkg/security/dpi/manager.go` - Complete DPI logic
- `pkg/security/dpi/connectors/nprobe.go` - nProbe integration

**Testing:**
- [ ] Detect applications
- [ ] Test protocol analysis
- [ ] SSL inspection tests
- [ ] Policy enforcement
- [ ] Performance tests

**Success Criteria:**
- Applications accurately detected
- DPI-based policies enforced
- Performance acceptable

**Estimated Effort:** 4 weeks

**Total Phase 5:** 12 weeks

---

## Phase 6: Network Services (Months 17-19)

**Goal:** Complete DHCP, DNS, and NTP service integration

### 6.1 Kea DHCP Integration ⚠️ CRITICAL

**Current State:** Config generation works, no daemon communication

**Implementation Tasks:**
- [ ] Implement Kea control channel API
- [ ] Add lease database queries
- [ ] Implement dynamic lease management
- [ ] Add reservation management
- [ ] Integrate with DNS for dynamic updates
- [ ] Add DHCP relay support
- [ ] Implement lease notifications

**Files to Modify:**
- `pkg/dhcp/kea_manager.go` - Add API client
- `pkg/dhcp/controller.go` - Add lease monitoring

**Testing:**
- [ ] Query lease database
- [ ] Add/remove reservations
- [ ] Test lease lifecycle
- [ ] DNS integration tests
- [ ] Relay tests

**Success Criteria:**
- Kea fully manageable
- Leases tracked in real-time
- DNS integration working

**Estimated Effort:** 4 weeks

---

### 6.2 CoreDNS Integration

**Current State:** Zone management exists, no service integration

**Implementation Tasks:**
- [ ] Implement CoreDNS API client
- [ ] Add zone file generation
- [ ] Implement dynamic DNS updates
- [ ] Add query logging
- [ ] Integrate with DHCP for forward zones
- [ ] Add DNS security (DNSSEC)

**Files to Modify:**
- `pkg/dns/coredns/` - Complete implementation
- `pkg/dns/manager/manager.go` - Add service control

**Testing:**
- [ ] Create DNS zones
- [ ] Add/update records
- [ ] Dynamic DNS tests
- [ ] Query logging
- [ ] DNSSEC tests

**Success Criteria:**
- CoreDNS fully operational
- Dynamic DNS working
- DHCP integration complete

**Estimated Effort:** 3 weeks

---

### 6.3 AdGuard Home Integration

**Implementation Tasks:**
- [ ] Implement AdGuard API client
- [ ] Add filter list management
- [ ] Implement query logging
- [ ] Add statistics collection
- [ ] Integrate blocklists
- [ ] Add client identification

**Files to Modify:**
- `pkg/dns/adguard/` - Complete implementation

**Testing:**
- [ ] Deploy filter lists
- [ ] Test ad blocking
- [ ] Verify statistics
- [ ] Query log tests
- [ ] Client identification

**Success Criteria:**
- AdGuard fully integrated
- Ad/tracker blocking working
- Statistics available

**Estimated Effort:** 2 weeks

---

### 6.4 mDNS Reflection

**Implementation Tasks:**
- [ ] Implement mDNS proxy
- [ ] Add cross-VLAN reflection
- [ ] Implement service discovery
- [ ] Add filtering rules
- [ ] Integrate with firewall

**Files to Modify:**
- `pkg/dns/mdns/` - Complete implementation

**Testing:**
- [ ] Reflect mDNS across VLANs
- [ ] Test service discovery
- [ ] Apply reflection filters
- [ ] Performance tests

**Success Criteria:**
- mDNS reflection working
- Services discoverable across VLANs

**Estimated Effort:** 2 weeks

---

### 6.5 Chrony NTP Integration

**Implementation Tasks:**
- [ ] Implement Chrony control socket
- [ ] Add time source monitoring
- [ ] Implement NTS authentication
- [ ] Add client access controls
- [ ] Integrate with monitoring

**Files to Modify:**
- `pkg/ntp/` - Add control socket client

**Testing:**
- [ ] Monitor time sources
- [ ] Test NTS authentication
- [ ] Access control tests
- [ ] Metrics collection

**Success Criteria:**
- Chrony fully manageable
- NTS working
- Monitoring integrated

**Estimated Effort:** 1 week

**Total Phase 6:** 12 weeks

---

## Phase 7: Authentication & Authorization (Months 20-21)

**Goal:** Complete authentication provider implementations

### 7.1 LDAP Provider ⚠️ CRITICAL

**Current State:** Returns "not implemented" error

**Implementation Tasks:**
- [ ] Implement LDAP connection and binding
- [ ] Add user authentication
- [ ] Implement group membership queries
- [ ] Add LDAP search functionality
- [ ] Implement connection pooling
- [ ] Add TLS support
- [ ] Handle LDAP failures gracefully

**Files to Modify:**
- `pkg/security/auth/providers/ldap.go` - Full implementation

**Testing:**
- [ ] Connect to LDAP server
- [ ] Authenticate users
- [ ] Query groups
- [ ] Test TLS connections
- [ ] Failover tests

**Success Criteria:**
- LDAP authentication working
- Group memberships resolved
- TLS connections secure

**Estimated Effort:** 3 weeks

---

### 7.2 OAuth2/OIDC Provider

**Current State:** Returns "not implemented" error

**Implementation Tasks:**
- [ ] Implement OAuth2 flow
- [ ] Add OIDC token validation
- [ ] Implement provider discovery
- [ ] Add token refresh
- [ ] Implement JWT validation
- [ ] Add PKCE support

**Files to Modify:**
- `pkg/security/auth/providers/oauth.go` - Full implementation

**Testing:**
- [ ] OAuth2 authorization flow
- [ ] Token validation
- [ ] Token refresh
- [ ] Multiple provider tests

**Success Criteria:**
- OAuth2/OIDC working
- Tokens validated
- Multiple providers supported

**Estimated Effort:** 3 weeks

---

### 7.3 SAML Provider

**Implementation Tasks:**
- [ ] Implement SAML SP
- [ ] Add SAML assertion validation
- [ ] Implement SSO flow
- [ ] Add IdP metadata parsing
- [ ] Implement SLO (Single Logout)

**Files to Create:**
- `pkg/security/auth/providers/saml.go` - Full implementation

**Testing:**
- [ ] SAML SSO flow
- [ ] Assertion validation
- [ ] Multiple IdP tests
- [ ] SLO tests

**Success Criteria:**
- SAML SSO working
- Assertions validated

**Estimated Effort:** 2 weeks

**Total Phase 7:** 8 weeks

---

## Phase 8: Hardware & Performance (Months 22-23)

**Goal:** Optimize for high-performance packet processing

### 8.1 Hardware NIC Integration

**Implementation Tasks:**
- [ ] Implement Intel NIC driver integration
- [ ] Add multi-queue configuration
- [ ] Implement RSS (Receive Side Scaling)
- [ ] Add flow director support
- [ ] Implement hardware offloading
- [ ] Add SR-IOV support

**Files to Modify:**
- `pkg/hardware/nic/` - Driver integration

**Testing:**
- [ ] Configure multi-queue NICs
- [ ] Test RSS distribution
- [ ] Flow director tests
- [ ] Offload verification
- [ ] Performance tests

**Success Criteria:**
- Multi-queue NICs operational
- Hardware offloading working
- Line-rate performance

**Estimated Effort:** 4 weeks

---

### 8.2 Packet Capture System

**Implementation Tasks:**
- [ ] Implement AF_PACKET capture
- [ ] Add PCAP file writing
- [ ] Implement capture filtering
- [ ] Add ring buffer support
- [ ] Integrate with DPI
- [ ] Add remote capture (RPCAP)

**Files to Modify:**
- `pkg/hardware/capture/` - Full implementation

**Testing:**
- [ ] Capture packets
- [ ] Apply BPF filters
- [ ] Write PCAP files
- [ ] Ring buffer tests
- [ ] Performance tests

**Success Criteria:**
- Packet capture working
- Filtering operational
- Minimal performance impact

**Estimated Effort:** 2 weeks

---

### 8.3 Performance Optimization

**Implementation Tasks:**
- [ ] Profile CPU usage
- [ ] Optimize hot paths
- [ ] Reduce memory allocations
- [ ] Add buffer pooling
- [ ] Optimize eBPF programs
- [ ] Tune kernel parameters

**Testing:**
- [ ] Benchmark throughput
- [ ] Latency tests
- [ ] CPU profiling
- [ ] Memory profiling
- [ ] Load tests

**Success Criteria:**
- 10Gbps+ throughput
- <1ms latency
- Low CPU usage

**Estimated Effort:** 2 weeks

**Total Phase 8:** 8 weeks

---

## Phase 9: API & Management (Months 24)

**Goal:** Build REST/gRPC API for external management

### 9.1 REST API Server

**Implementation Tasks:**
- [ ] Implement REST API server (Gin or Echo)
- [ ] Add authentication middleware
- [ ] Implement RBAC authorization
- [ ] Add API endpoints for all resources
- [ ] Implement OpenAPI/Swagger docs
- [ ] Add rate limiting
- [ ] Implement TLS

**Files to Create:**
- `pkg/api/rest/` - REST API server
- `api/openapi.yaml` - OpenAPI specification

**Testing:**
- [ ] API authentication
- [ ] Authorization tests
- [ ] CRUD operations
- [ ] Rate limiting
- [ ] TLS tests

**Success Criteria:**
- REST API operational
- All resources manageable
- OpenAPI docs complete

**Estimated Effort:** 3 weeks

---

### 9.2 gRPC API Server

**Implementation Tasks:**
- [ ] Define gRPC service proto files
- [ ] Generate Go code
- [ ] Implement gRPC server
- [ ] Add streaming support
- [ ] Implement TLS
- [ ] Add health checks

**Files to Create:**
- `api/proto/` - Protocol buffer definitions
- `pkg/api/grpc/` - gRPC server

**Testing:**
- [ ] gRPC client tests
- [ ] Streaming tests
- [ ] TLS tests
- [ ] Load tests

**Success Criteria:**
- gRPC API operational
- High performance
- Streaming working

**Estimated Effort:** 1 week

**Total Phase 9:** 4 weeks

---

## Phase 10: Production Hardening (Months 25-26)

**Goal:** Security hardening, HA, monitoring, and final testing

### 10.1 High Availability

**Implementation Tasks:**
- [ ] Implement controller leader election
- [ ] Add state replication
- [ ] Implement failover mechanisms
- [ ] Add cluster membership
- [ ] Implement split-brain prevention
- [ ] Add health checks

**Files to Modify:**
- All controllers - Add HA support

**Testing:**
- [ ] Leader election tests
- [ ] Failover tests
- [ ] Split-brain tests
- [ ] State sync tests

**Success Criteria:**
- HA operational
- Automatic failover <5s
- No split-brain

**Estimated Effort:** 4 weeks

---

### 10.2 Security Hardening

**Implementation Tasks:**
- [ ] Implement RBAC for all resources
- [ ] Add TLS for all inter-service communication
- [ ] Implement secrets management (Vault integration)
- [ ] Add security scanning
- [ ] Conduct security audit
- [ ] Implement intrusion detection
- [ ] Add audit logging

**Testing:**
- [ ] RBAC tests
- [ ] TLS verification
- [ ] Secrets management
- [ ] Penetration testing
- [ ] Audit log tests

**Success Criteria:**
- All traffic encrypted
- RBAC enforced
- Security audit passed

**Estimated Effort:** 3 weeks

---

### 10.3 Monitoring & Observability

**Implementation Tasks:**
- [ ] Add Prometheus metrics to all components
- [ ] Create Grafana dashboards
- [ ] Implement distributed tracing (Jaeger)
- [ ] Add structured logging
- [ ] Implement alerting rules
- [ ] Add SLO/SLI tracking

**Files to Modify:**
- All packages - Add metrics

**Testing:**
- [ ] Verify metrics collection
- [ ] Dashboard functionality
- [ ] Tracing tests
- [ ] Alert tests

**Success Criteria:**
- All metrics collected
- Dashboards operational
- Alerts configured

**Estimated Effort:** 2 weeks

---

### 10.4 Documentation

**Implementation Tasks:**
- [ ] Update all design docs
- [ ] Write operational runbooks
- [ ] Create troubleshooting guides
- [ ] Write API documentation
- [ ] Add deployment guides
- [ ] Create security documentation

**Deliverables:**
- Updated documentation in `docs/`
- Operational runbooks
- API documentation

**Estimated Effort:** 1 week

---

### 10.5 Final Testing & Validation

**Implementation Tasks:**
- [ ] Complete end-to-end tests
- [ ] Performance testing (10Gbps+)
- [ ] Load testing (sustained traffic)
- [ ] Chaos engineering tests
- [ ] Security testing
- [ ] Compliance validation

**Success Criteria:**
- All tests pass
- Performance targets met
- Security validated

**Estimated Effort:** 2 weeks

**Total Phase 10:** 12 weeks

---

## Test Coverage Requirements

### Current Coverage: <20%
### Target Coverage: >80%

**Coverage by Phase:**

| Phase | Component | Target Coverage | Priority |
|-------|-----------|----------------|----------|
| 1 | Network Stack | 85% | Critical |
| 2 | Routing | 80% | Critical |
| 3 | Firewall/Security | 90% | Critical |
| 4 | eBPF | 75% | High |
| 5 | IDS/DPI | 80% | High |
| 6 | Network Services | 80% | High |
| 7 | Authentication | 85% | High |
| 8 | Hardware | 70% | Medium |
| 9 | API | 85% | High |
| 10 | HA/Monitoring | 75% | High |

**Test Types Required:**

1. **Unit Tests** (per package)
   - Test all public functions
   - Mock external dependencies
   - Edge cases and error conditions

2. **Integration Tests**
   - Multi-component interactions
   - Kubernetes controller tests
   - External service integration

3. **End-to-End Tests**
   - Full traffic flow tests
   - Multi-VLAN scenarios
   - Failover scenarios

4. **Performance Tests**
   - Throughput benchmarks
   - Latency measurements
   - Resource usage profiling

5. **Security Tests**
   - Penetration testing
   - Fuzzing
   - Security scanning

---

## Resource Requirements

### Team Structure (Recommended)

**Total: 5 Engineers**

1. **Senior Network Engineer** (Phases 1-2, 6)
   - Network stack implementation
   - Routing protocols
   - Network services

2. **Senior Security Engineer** (Phases 3, 5, 7)
   - Firewall implementation
   - IDS/IPS integration
   - Authentication systems

3. **eBPF/Performance Engineer** (Phases 4, 8)
   - eBPF program development
   - Performance optimization
   - Hardware integration

4. **Platform Engineer** (Phases 0, 9, 10)
   - CI/CD pipeline
   - API development
   - HA and monitoring

5. **QA/Test Engineer** (All phases)
   - Test framework development
   - Test coverage
   - Integration/E2E testing

---

### Infrastructure Requirements

**Development Environment:**
- 3+ node Kubernetes cluster
- 10Gbps NICs for testing
- Talos Linux test environment
- External services (FRR, Suricata, Zeek, Kea)

**CI/CD:**
- GitHub Actions or GitLab CI
- Container registry
- Test cluster for automated deployments

**Production (Per Deployment):**
- 3+ nodes for HA
- 10Gbps+ network connectivity
- Storage for logs and state
- Monitoring infrastructure

---

## Risk Assessment & Mitigation

### High Risk Items

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Kernel Integration Complexity** | High | Medium | Early prototyping, expert consultation |
| **Performance Not Meeting Targets** | High | Medium | Performance testing from Phase 1, eBPF optimization |
| **External Service Integration** | Medium | Medium | Mock interfaces, comprehensive testing |
| **Security Vulnerabilities** | High | Low | Security audit, pen testing, secure coding |
| **eBPF Verifier Rejection** | Medium | Medium | Thorough BPF program testing, fallback paths |
| **FRR/Suricata/Zeek Compatibility** | Medium | Low | Version pinning, compatibility testing |

### Medium Risk Items

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Test Coverage Insufficient** | Medium | Medium | Dedicated QA engineer, coverage tracking |
| **Documentation Outdated** | Medium | High | Docs in CI/CD, regular reviews |
| **Team Skill Gaps** | Medium | Low | Training, expert consultation |
| **Scope Creep** | Medium | Medium | Strict phase gating, change control |

---

## Success Metrics

### Phase Gates

Each phase must meet these criteria before proceeding:

1. **Code Complete** - All planned features implemented
2. **Tests Pass** - >80% coverage, all tests green
3. **Documentation Updated** - Design docs and how-tos current
4. **Performance Validated** - Meets phase-specific targets
5. **Security Reviewed** - No critical vulnerabilities
6. **Demo Successful** - Working demo to stakeholders

### Final Success Criteria (v1.0)

- [ ] 10Gbps+ throughput sustained
- [ ] <1ms average latency
- [ ] >80% test coverage across all components
- [ ] All authentication providers working
- [ ] Full IDS/IPS integration operational
- [ ] HA with <5s failover
- [ ] Zero critical security vulnerabilities
- [ ] Complete documentation
- [ ] Production deployments successful
- [ ] Performance validated under load

---

## Timeline Summary

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| 0: Foundation | 6 weeks | Dev env, CI/CD, test framework |
| 1: Network Stack | 10 weeks | Interfaces, VLANs, static routing |
| 2: Routing Protocols | 12 weeks | FRR, BGP, OSPF, policy routing |
| 3: Firewall | 12 weeks | nftables, policies, NAT, IPSets |
| 4: eBPF | 12 weeks | Compilation, XDP, TC programs |
| 5: IDS/DPI | 12 weeks | Suricata, Zeek, DPI integration |
| 6: Services | 12 weeks | DHCP, DNS, mDNS, NTP |
| 7: Authentication | 8 weeks | LDAP, OAuth, SAML |
| 8: Hardware | 8 weeks | NIC integration, capture, optimization |
| 9: API | 4 weeks | REST/gRPC APIs |
| 10: Production | 12 weeks | HA, security, monitoring |
| **Total** | **108 weeks** | **~24 months** |

---

## Phased Rollout Strategy

### Phase 1-2: Internal Testing (Months 1-7)
- Deploy to dev/test environments
- Internal users only
- Focus on stability and performance

### Phase 3-6: Alpha Deployment (Months 8-19)
- Limited production deployments
- Early adopters
- Close monitoring and rapid iteration

### Phase 7-9: Beta Deployment (Months 20-24)
- Wider production deployments
- Feature complete
- Performance tuning

### Phase 10: GA Release (Month 25-26)
- Production ready v1.0
- Full documentation
- Support processes

---

## Alternative Strategies

### Accelerated Timeline (12-15 months)

**Pros:**
- Faster time to market
- Lower initial costs

**Cons:**
- Higher risk
- Lower quality
- Technical debt

**Approach:**
- Skip non-critical features
- Parallel development
- Larger team (7-8 engineers)
- Focus on MVP only

**Not Recommended** - Quality and reliability would suffer

---

### Conservative Timeline (30-36 months)

**Pros:**
- Lower risk
- Higher quality
- Comprehensive testing

**Cons:**
- Longer time to market
- Higher total costs
- Market may change

**Approach:**
- Smaller team (2-3 engineers)
- More thorough testing
- Additional features
- Extensive documentation

**Viable** - If timeline not critical

---

## Maintenance & Evolution

### Post-v1.0 Roadmap

**Year 2:**
- Advanced threat intelligence
- AI/ML-based anomaly detection
- Web UI
- Advanced QoS
- Additional routing protocols (RIP, IS-IS)
- IPv6 advanced features
- Multi-tenancy
- Cloud integration (AWS, GCP, Azure)

**Year 3:**
- SD-WAN features
- Intent-based networking
- Self-healing systems
- Advanced analytics
- Compliance reporting
- Multi-site management

---

## Cost Estimation

### Development Costs (24 months)

**Team Costs** (5 engineers @ $150K/year average):
- Year 1: $750K
- Year 2: $750K
- **Total: $1.5M**

**Infrastructure:**
- Development hardware/cloud: $50K/year
- Test infrastructure: $30K/year
- CI/CD services: $20K/year
- **Total: $200K**

**Software/Services:**
- External services (if commercial): $20K/year
- Tools and licenses: $10K/year
- **Total: $60K**

**Miscellaneous:**
- Training: $20K
- Consultation: $30K
- Travel/conferences: $20K
- **Total: $70K**

**Grand Total: ~$1.83M over 24 months**

---

## Recommendations

### Immediate Priorities (Next 30 Days)

1. **Set Up Development Environment** (Week 1-2)
   - Multi-node K8s cluster
   - Install all external services
   - Document setup process

2. **Establish CI/CD Pipeline** (Week 2-3)
   - GitHub Actions workflows
   - Automated testing
   - Container builds

3. **Create Test Framework** (Week 3-4)
   - Test utilities package
   - Mock frameworks
   - Integration test scaffolding

4. **Begin Network Stack Implementation** (Week 4+)
   - Start with netlink integration
   - Interface management
   - VLAN kernel implementation

### Critical Path Items

These items block multiple other features and must be completed early:

1. **Netlink Integration** - Blocks all network manipulation
2. **nftables Integration** - Blocks firewall functionality
3. **FRR Integration** - Blocks dynamic routing
4. **eBPF Compilation** - Blocks high-performance features
5. **Suricata/Zeek Integration** - Blocks IDS functionality

### Quick Wins (Low Effort, High Value)

1. **Fix Existing Tests** - Get current 45 tests passing
2. **Add Test Coverage Tool** - Track coverage in CI
3. **Complete Local Auth Provider** - Already partially implemented
4. **Fix WireGuard Integration** - Config generation already works
5. **Complete Certificate Management** - Already mostly done

---

## Conclusion

This implementation plan provides a **comprehensive roadmap** to transform this well-designed architectural framework into a production-ready Kubernetes-based router/firewall. The plan is ambitious but achievable with:

- **Dedicated team of 5 engineers**
- **24-month timeline**
- **~$1.8M budget**
- **Phased, incremental approach**
- **Strong focus on testing and quality**

**Key Success Factors:**
1. Start with kernel integration (Phase 1)
2. Maintain high test coverage from day 1
3. Incremental delivery with working software each phase
4. Performance focus throughout
5. Security-first approach

**Alternative Approaches:**
- If timeline is critical: Consider accelerated 12-15 month plan (higher risk)
- If quality is paramount: Consider conservative 30-36 month plan (lower risk)
- If budget is limited: Consider MVP approach focusing only on critical features

**Next Steps:**
1. Review and approve this plan
2. Secure budget and resources
3. Assemble team
4. Begin Phase 0 (Foundation)
5. Execute plan with regular reviews

The architecture and design are excellent. With focused execution of this plan, this project can become a leading Kubernetes-native network security platform.

---

**Document Version:** 1.0
**Prepared By:** Claude Code
**Date:** 2025-11-12
**Status:** Draft for Review
