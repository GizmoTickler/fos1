# eBPF Implementation Design

## Overview

This document describes the design for the eBPF (extended Berkeley Packet Filter) implementation in the Kubernetes-based Router/Firewall system. The implementation leverages Cilium's eBPF implementation for high-performance packet processing, network address translation, traffic control, load balancing, and network visibility.

> **IMPORTANT UPDATE (March 2025)**: We have standardized on Cilium's native network policies (CNP/CCNP) for all networking policy enforcement. The custom EBPFNetworkPolicy CRD has been deprecated. This document has been updated to reflect this architectural decision.

## Goals

- Implement high-performance packet processing using eBPF
- Support all major eBPF hooks (XDP, TC, sockops, cgroup)
- Integrate fully with the routing and VRF design
- Utilize Cilium's native policy system and CRDs for network policy enforcement
- Leverage Cilium's infrastructure for core networking capabilities
- Enable comprehensive monitoring and debugging capabilities via Hubble
- Use native Cilium implementations where possible to reduce maintenance overhead

## Non-Goals

- Support for user-supplied custom eBPF programs
- Integration with non-Kubernetes environments
- Compatibility with non-Linux operating systems
- Support for deprecated eBPF features
- Maintaining custom network policy implementations that duplicate Cilium functionality

## Design Details

### Overall Architecture

The eBPF implementation consists of several key components:

1. **Cilium's eBPF Programs**: The core networking functionality using Cilium's eBPF programs
2. **Native Cilium Policies**: Using CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy for policy enforcement
3. **Custom eBPF Programs**: Additional eBPF programs for specialized router/firewall features
4. **eBPF Map Integration**: Integration with Cilium's maps for state sharing
5. **Hubble**: Monitoring and observability for network flows and policy decisions

The architecture fully leverages Cilium for core networking functionality, particularly network policy enforcement, while maintaining custom programs only for specialized functionality not provided by Cilium.

```
┌─────────────────────────────────┐
│    CiliumNetworkPolicy CRDs    │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│        Cilium Agent             │◄───┐
└───────────────┬─────────────────┘    │
                │                       │
                ▼                       │ Custom
┌─────────────────────────────────┐    │ Config
│    Cilium's eBPF Programs       │    │  CRDs
└───────────────┬─────────────────┘    │
                │                       │
        ┌───────┴────────┐             │
        │                │             │
        ▼                ▼             │
┌─────────────┐   ┌─────────────┐     │
│ Cilium Maps │   │ Custom Maps │◄────┘
└─────────────┘   └─────────────┘
        │                │
        └───────┬────────┘
                │
                ▼
┌─────────────────────────────────┐
│            Kernel               │
└─────────────────────────────────┘
```

### eBPF Programs

The eBPF implementation includes programs for various hooks:

#### XDP Programs

XDP (eXpress Data Path) programs run at the earliest point in the network stack, before the kernel allocates SKBs. They provide the highest performance for packet processing.

1. **Packet Filtering**: Early dropping of unwanted traffic
2. **DDoS Mitigation**: Rate limiting and blacklist enforcement
3. **Fast Path Forwarding**: Direct packet forwarding for known flows
4. **Load Balancing**: Distribute traffic across endpoints

#### TC Programs

TC (Traffic Control) programs run at the ingress and egress points of network interfaces, after XDP but still early in the network stack.

1. **NAT and NAT66**: Network address translation for IPv4 and IPv6
2. **Stateful Firewall**: Connection tracking and rule enforcement
3. **QoS and Traffic Shaping**: Bandwidth control and prioritization
4. **Packet Marking**: Mark packets for routing decisions
5. **VLAN Processing**: Handle VLAN tags and filtering

#### Socket Operations Programs

Socket operations programs intercept and control socket-level operations.

1. **Connection Monitoring**: Track connection establishment and termination
2. **Socket Redirection**: Optimize socket-to-socket communication
3. **Transparent Proxying**: Intercept connections for processing
4. **Application-Layer Gateway**: Protocol-specific handling
5. **Connection Analytics**: Gather metrics on connections

#### CGroup Programs

CGroup programs apply policies at the container/pod level.

1. **Per-Container Policies**: Enforce network policies for specific containers
2. **Resource Accounting**: Track bandwidth usage per container
3. **Egress Control**: Filter outbound connections from containers
4. **Socket Assignment**: Control which sockets containers can bind to

### eBPF Maps

eBPF maps store state that eBPF programs can access. The implementation uses a hierarchical approach to map management:

#### Global Maps

1. **Routing Table Map**: Global routing information
2. **Policy Map**: Network policies affecting all traffic
3. **Configuration Map**: System-wide settings

#### Functional Maps

1. **Connection Tracking Map**: State for established connections
2. **NAT Translation Map**: NAT translation entries
3. **Firewall Rule Map**: Active firewall rules
4. **QoS State Map**: Traffic control state

#### Local Maps

1. **Per-Program Maps**: Program-specific state
2. **Per-Interface Maps**: Interface-specific configuration
3. **Per-Container Maps**: Container-specific policies

### Map Management

The Map Manager provides several key functions:

1. **Map Creation and Initialization**: Create maps with appropriate types and sizes
2. **Map Updates**: Safely update map entries from user space
3. **Map Synchronization**: Keep maps in sync with system state
4. **Garbage Collection**: Remove stale entries from maps
5. **Map Dumping**: Extract map contents for debugging

```go
type MapManager interface {
    // CreateMap creates a new eBPF map
    CreateMap(name string, mapType MapType, keySize, valueSize, maxEntries int) (Map, error)
    
    // DeleteMap removes an eBPF map
    DeleteMap(name string) error
    
    // GetMap retrieves an eBPF map
    GetMap(name string) (Map, error)
    
    // ListMaps lists all eBPF maps
    ListMaps() ([]Map, error)
    
    // UpdateMap updates entries in an eBPF map
    UpdateMap(name string, entries map[interface{}]interface{}) error
    
    // DumpMap dumps the contents of an eBPF map
    DumpMap(name string) (map[interface{}]interface{}, error)
}
```

### Program Management

The Program Manager handles the lifecycle of eBPF programs:

1. **Program Loading**: Compile and load eBPF programs
2. **Program Attachment**: Attach programs to hooks
3. **Program Detachment**: Remove programs from hooks
4. **Program Replacement**: Hot-swap programs without interruption
5. **Program Verification**: Ensure programs meet safety requirements

```go
type ProgramManager interface {
    // LoadProgram loads an eBPF program
    LoadProgram(program Program) error
    
    // UnloadProgram unloads an eBPF program
    UnloadProgram(name string) error
    
    // AttachProgram attaches an eBPF program to a hook
    AttachProgram(programName, hookName string) error
    
    // DetachProgram detaches an eBPF program from a hook
    DetachProgram(programName, hookName string) error
    
    // ReplaceProgram replaces an existing program with a new one
    ReplaceProgram(oldName, newName string) error
    
    // ListPrograms lists all loaded eBPF programs
    ListPrograms() ([]ProgramInfo, error)
}
```

### Configuration

#### Network Policies

Network policies are configured using Cilium's native CRDs:

1. **CiliumNetworkPolicy (CNP)**: Namespace-scoped policies
2. **CiliumClusterwideNetworkPolicy (CCNP)**: Cluster-wide policies

These replace the deprecated EBPFNetworkPolicy CRD and provide superior integration with Cilium's datapath.

#### Custom eBPF Program Configuration

For specialized functionality not covered by Cilium's native features, custom eBPF programs are configured through CRDs:

```yaml
apiVersion: ebpf.fos1.io/v1alpha1
kind: EBPFProgram
metadata:
  name: xdp-filter
spec:
  description: "XDP packet filter for DDoS mitigation"
  type: "xdp"  # xdp, tc-ingress, tc-egress, sockops, cgroup
  interface: "eth0"  # For XDP and TC programs
  priority: 10  # Lower numbers = higher priority
  settings:
    rateLimiting:
      enabled: true
      packetsPerSecond: 1000000
    blacklist:
      enabled: true
      ipSetRef: "malicious-ips"
    stateful: true
    actions:
      default: "pass"  # pass, drop, redirect
      rules:
        - match:
            protocol: "udp"
            dstPort: 53
          action: "pass"
        - match:
            protocol: "tcp"
            dstPort: 80
          action: "pass"
status:
  loaded: true
  attached: true
  mapRefs:
    - "xdp-filter-blacklist"
    - "xdp-filter-state"
  metrics:
    packetsProcessed: 1250000
    packetsDropped: 5000
    lastUpdated: "2025-03-15T12:34:56Z"
```

#### Traffic Control Configuration CRD

```yaml
apiVersion: ebpf.fos1.io/v1alpha1
kind: TrafficControl
metadata:
  name: qos-policy
spec:
  description: "QoS policy for VoIP traffic"
  interface: "eth0"
  direction: "egress"  # ingress, egress
  priority: 20
  queueingDiscipline: "htb"  # htb, fq_codel, etc.
  classes:
    - name: "voip"
      priority: 1
      rate: "10Mbps"
      ceiling: "20Mbps"
      match:
        ipProto: "udp"
        dstPorts: [5060, 5061, "10000-20000"]
    - name: "web"
      priority: 2
      rate: "50Mbps"
      ceiling: "100Mbps"
      match:
        ipProto: "tcp"
        dstPorts: [80, 443]
    - name: "default"
      priority: 3
      rate: "5Mbps"
      ceiling: "unlimited"
status:
  active: true
  programRef: "tc-egress-qos-eth0"
  lastUpdated: "2025-03-15T14:30:20Z"
```

#### NAT Configuration CRD

```yaml
apiVersion: ebpf.fos1.io/v1alpha1
kind: NATConfig
metadata:
  name: ebpf-nat
spec:
  description: "eBPF-based NAT configuration"
  interfaces:
    source: "eth1"  # Internal interface
    destination: "eth0"  # External interface
  type: "masquerade"  # masquerade, static
  ipVersion: "ipv4"  # ipv4, ipv6, both
  portMappings:
    - protocol: "tcp"
      internalIP: "192.168.1.10"
      internalPort: 80
      externalPort: 8080
  sourceCIDRs:
    - "192.168.0.0/16"
  excludeCIDRs:
    - "192.168.100.0/24"
status:
  active: true
  programRefs:
    - "nat-prerouting"
    - "nat-postrouting"
  translationCount: 1256
  lastUpdated: "2025-03-15T14:45:10Z"
```

### Monitoring and Debugging

The eBPF implementation includes comprehensive monitoring and debugging capabilities:

1. **Program Tracing**: Trace execution of eBPF programs
2. **Map Inspection**: View and manipulate map contents
3. **Packet Capture**: Capture packets at different processing stages
4. **Performance Metrics**: Gather metrics on program performance
5. **Flow Tracking**: Track flows processed by eBPF programs

#### Metrics Collection

Metrics are collected from eBPF programs and maps and exposed via Prometheus:

```go
type EBPFMetrics interface {
    // CollectMetrics collects metrics from eBPF programs and maps
    CollectMetrics() (map[string]Metric, error)
    
    // GetProgramMetrics retrieves metrics for a specific program
    GetProgramMetrics(programName string) ([]Metric, error)
    
    // GetMapMetrics retrieves metrics for a specific map
    GetMapMetrics(mapName string) ([]Metric, error)
    
    // RegisterCustomMetric registers a custom metric
    RegisterCustomMetric(name, help string, metricType MetricType) error
}
```

#### Debugging Tools

The implementation includes several debugging tools:

1. **Program Dumper**: Dump the bytecode of loaded programs
2. **Map Dumper**: Dump the contents of eBPF maps
3. **Trace Tool**: Trace execution of eBPF programs
4. **Packet Debugger**: Debug packet processing

### Integration with Cilium

The implementation leverages Cilium for core functionality while adding custom features:

1. **Cilium CNI Integration**: Use Cilium as the CNI provider
2. **Cilium Network Policies**: Use Cilium policies for basic filtering
3. **Custom Programs**: Add custom eBPF programs for router-specific features
4. **Map Sharing**: Share maps between Cilium and custom programs
5. **Program Coordination**: Coordinate program execution with Cilium

#### Cilium Integration API

```go
type CiliumIntegration interface {
    // GetCiliumMaps gets maps managed by Cilium
    GetCiliumMaps() ([]Map, error)
    
    // GetCiliumPrograms gets programs managed by Cilium
    GetCiliumPrograms() ([]ProgramInfo, error)
    
    // RegisterWithCilium registers a custom program with Cilium
    RegisterWithCilium(program Program) error
    
    // UnregisterFromCilium unregisters a custom program from Cilium
    UnregisterFromCilium(programName string) error
    
    // GetCiliumEndpoints gets Cilium endpoint information
    GetCiliumEndpoints() ([]Endpoint, error)
}
```

### Custom Controller

The custom controller manages the integration between the Kubernetes API, Cilium, and custom eBPF programs:

1. **CRD Watching**: Watch for changes to eBPF-related CRDs
2. **Translation**: Translate CRD specifications to eBPF program configurations
3. **Program Management**: Manage the lifecycle of custom eBPF programs
4. **Cilium Coordination**: Coordinate with Cilium for integration

```go
type EBPFController struct {
    programManager     ProgramManager
    mapManager         MapManager
    ciliumIntegration  CiliumIntegration
    metrics            EBPFMetrics
    configTranslator   ConfigTranslator
}
```

### Implementation

The eBPF programs are implemented using Cilium's Go eBPF library, which provides a clean API for working with eBPF from Go:

```go
func buildXDPProgram(config EBPFProgramConfig) (*ebpf.Program, error) {
    // Load pre-compiled eBPF bytecode
    spec, err := ebpf.LoadCollectionSpec("xdp_program.o")
    if err != nil {
        return nil, fmt.Errorf("failed to load eBPF spec: %w", err)
    }
    
    // Create maps the program will use
    maps := make(map[string]*ebpf.Map)
    for name, mapDef := range spec.Maps {
        m, err := ebpf.NewMap(mapDef)
        if err != nil {
            return nil, fmt.Errorf("failed to create map %s: %w", name, err)
        }
        maps[name] = m
    }
    
    // Load the program with references to the maps
    prog, err := ebpf.NewProgramWithOptions(spec.Programs["xdp_main"], ebpf.ProgramOptions{
        Maps: maps,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to load program: %w", err)
    }
    
    return prog, nil
}
```

### Example eBPF Program

Below is an example of an XDP program implemented in C that would be compiled to eBPF bytecode:

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);   // IP address
    __type(value, __u32);  // Packet count
    __uint(max_entries, 65536);
} connection_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32); // Configuration values
    __uint(max_entries, 16);
} config SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (eth + 1 > data_end)
        return XDP_PASS; // Not enough data to read ethernet header
    
    // Only process IP packets
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (ip + 1 > data_end)
        return XDP_PASS; // Not enough data to read IP header
    
    // Get rate limit from config
    __u32 key = 0;
    __u32 *limit = bpf_map_lookup_elem(&config, &key);
    if (!limit)
        return XDP_PASS; // No config found
    
    // Get and update packet count
    __u32 *count = bpf_map_lookup_elem(&connection_count, &ip->saddr);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u32 init_val = 1;
        bpf_map_update_elem(&connection_count, &ip->saddr, &init_val, BPF_ANY);
    }
    
    // Apply rate limiting
    if (count && *count > *limit)
        return XDP_DROP; // Rate limit exceeded
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

## Compile and Load Pipeline (Sprint 30 Tickets 38 / 39)

The owned compile/load path lands two programs end to end:

- `xdp_ddos_drop` — XDP denylist drop (Ticket 38).
- `tc_qos_shape` — TC classifier that marks `skb->priority` per
  interface for classful shaping (Ticket 39).

This section describes how the sources, objects, embeds, and loaders
fit together, and labels the program types that are explicitly out of
scope.

### Source layout

- `bpf/xdp_ddos_drop.c` — owned XDP source. Parses Ethernet/IPv4 and
  drops packets whose source address is present in an LPM-trie
  denylist map; passes everything else.
- `bpf/tc_qos_shape.c` — owned TC source. Defines two `SchedCLS`
  programs (`tc_qos_ingress` / `tc_qos_egress`) that look the skb's
  ifindex up in a `BPF_MAP_TYPE_HASH` map (`qos_iface_priority`) and,
  on a hit, stamp the configured priority onto `skb->priority`. Never
  drops.
- `bpf/headers/bpf_helpers.h` — pinned minimal subset of libbpf's
  `bpf_helpers.h`. Pinning (rather than vendoring all of libbpf) keeps
  the repository reproducible and avoids pulling a submodule.
- `bpf/headers/vmlinux_minimal.h` — pinned UAPI subset. Ticket 39
  extended this with a minimal `struct __sk_buff` (up to and including
  `priority`, `ifindex`, `data`, `data_end`) and the `TC_ACT_*` return
  codes used by classifier programs.
- `bpf/out/` — build output directory, `.gitignore`d. Produced by
  `make bpf-objects`.
- `pkg/hardware/ebpf/bpf/xdp_ddos_drop.o` and `tc_qos_shape.o` — the
  compiled ELF objects that Go embeds into the binary via `//go:embed`.

### Build target

`make bpf-objects` discovers every `bpf/*.c` source and compiles it
with:

```
clang -O2 -g -target bpf -D__TARGET_ARCH_<arch> -I bpf/headers \
  -Wall -Werror -c bpf/<name>.c -o bpf/out/<name>.o
```

The target pre-flights the clang binary with `clang -print-targets` and
aborts with an actionable error if the BPF backend is missing. Apple's
system `/usr/bin/clang` does not include the BPF backend; use
`brew install llvm` and pass `BPF_CLANG=/opt/homebrew/opt/llvm@21/bin/clang`,
or run the target on a Linux host with upstream clang.

After `make bpf-objects` produces `bpf/out/*.o`, the target copies every
object into `pkg/hardware/ebpf/bpf/` so `go build` picks up the new
embed contents.

`go:generate` directives on the loader files provide the same hook for
`go generate` flows (one per program):

```
//go:generate sh -c "cd ../../.. && make bpf-objects && cp bpf/out/xdp_ddos_drop.o pkg/hardware/ebpf/bpf/xdp_ddos_drop.o"
//go:generate sh -c "cd ../../.. && make bpf-objects && cp bpf/out/tc_qos_shape.o pkg/hardware/ebpf/bpf/tc_qos_shape.o"
```

### Loader seam

`pkg/hardware/ebpf/xdp_loader_linux.go` exposes three functions:

- `XDPDDoSDropObject() ([]byte, error)` returns the embedded ELF bytes.
  If the embed slot is empty (i.e. `make bpf-objects` has not been run),
  it returns `ErrEBPFObjectMissing` so callers see an explicit,
  actionable failure rather than a silent success.
- `NewXDPLoader(objectBytes []byte) (*XDPLoader, error)` parses the ELF
  via `ebpf.LoadCollectionSpecFromReader`, bumps `RLIMIT_MEMLOCK`,
  validates that the process has CAP_BPF/CAP_NET_ADMIN or UID 0, and
  instantiates the collection.
- `XDPLoader.Attach(iface string) (link.Link, error)` resolves the
  interface via `netlink.LinkByName` and calls `link.AttachXDP` with
  `XDPGenericMode` so the attach succeeds on dummy interfaces used by
  the integration test.

The non-Linux build in `xdp_loader_stub.go` returns
`ErrEBPFUnsupportedPlatform` from every method. `go build ./...`
succeeds on macOS/Windows; the XDP surface is simply unusable there.

### TC loader seam (Ticket 39)

`pkg/hardware/ebpf/tc_loader_linux.go` mirrors the XDP seam:

- `TCQoSShapeObject() ([]byte, error)` returns the embedded TC ELF,
  or `ErrEBPFObjectMissing` when `make bpf-objects` has not been run.
- `NewTCLoader(objectBytes) (*TCLoader, error)` parses the ELF, bumps
  `RLIMIT_MEMLOCK`, validates capabilities, and asserts that both
  `tc_qos_ingress` and `tc_qos_egress` plus the `qos_iface_priority`
  map are present in the collection. Mismatches fail loudly rather
  than producing a half-loaded loader.
- `TCLoader.SetPriority(iface string, prio uint32) error` /
  `ClearPriority(iface string) error` are thin wrappers around the
  backing map so user-space controllers do not need to resolve
  ifindex themselves.
- `TCLoader.AttachIngress(iface) / AttachEgress(iface)` ensure a
  `clsact` qdisc exists on the target (`netlink.QdiscAdd(...)` with
  `Parent: HANDLE_CLSACT`, tolerating `EEXIST`) and then call
  `link.AttachTCX` with `ebpf.AttachTCXIngress` / `Egress`. Qdisc
  errors are wrapped with `ErrTCQdiscUnsupported` so operators can
  distinguish "this environment cannot clsact" from "the attach
  itself failed".

**Kernel requirements:** `AttachTCX` requires Linux >= 6.6 (the TCX
hook landed in v6.6). Older kernels that only support classic tc
filters would need a netlink-tc attach path; we treat that as a
non-goal because TCX is upstream-forward and removes the filter-
priority bookkeeping tc(8) imposes. The integration test skips with
`t.Skip` on `ENOTSUP` / `EINVAL`.

The non-Linux build in `tc_loader_stub.go` returns
`ErrEBPFUnsupportedPlatform` from every method; darwin `go build`
still succeeds.

### Program-manager dispatch

`pkg/hardware/ebpf/program_manager.go`'s `LoadProgram` dispatches on
`Program.Type`:

- `ProgramTypeXDP` with empty Code → load the owned embedded XDP
  object via `XDPLoader`.
- `ProgramTypeTCIngress` / `ProgramTypeTCEgress` with empty Code →
  load the owned embedded TC object via `TCLoader`; `InnerProg` is
  bound to the ingress or egress section as requested, the other
  section stays live inside the collection until `Close`.
- Any of the three above with non-empty Code → legacy path (caller-
  supplied ELF bytes, used by `compiler.go` and hand-compiled tests).
- `ProgramTypeSockOps`, `ProgramTypeCGroup`, or any unknown string →
  return `ErrEBPFProgramTypeUnsupported`.

`AttachProgram` routes TC hook types through the shared
`attachTCProgram` helper, which prefers the owned loader's attach
path (with clsact bootstrap and map wiring in one place) and falls
back to a raw `link.AttachTCX` call (still with best-effort clsact
bootstrap) for legacy Code-based loads.

### Composition with the Cilium Bandwidth Manager path (Ticket 45)

Ticket 45's `QoSProfile` controller translates pod-selector + egress
bandwidth into `kubernetes.io/egress-bandwidth` annotations that
Cilium's in-kernel Bandwidth Manager enforces on the pod's netdev
(`lxc*`). That is orthogonal to the Ticket 39 TC loader, which is
intended to attach to VLAN / physical uplink NICs where Bandwidth
Manager has no hook. The two paths are composable — per-pod egress
caps run on the pod side, classful priority marking runs on the
uplink side — and there is no overlap in state: neither writes the
other's annotations or maps. Ticket 39 deliberately does **not** wire
a new CRD consumer; the loader ships as infrastructure a future
`VLANShaper`-style controller can call, which keeps the change
focused and avoids re-litigating Ticket 45's CRD surface.

### Integration tests

`pkg/hardware/ebpf/xdp_loader_linux_test.go` runs only on Linux. It:

1. Skips if the embedded object is missing (`ErrEBPFObjectMissing`).
2. Skips if the process lacks UID 0 AND CAP_BPF/CAP_NET_ADMIN.
3. Creates a `netlink.Dummy` interface named `fos1testxdp`.
4. Loads the program, attaches it, asserts a non-nil link handle.
5. Detaches and removes the interface in `t.Cleanup`.

`pkg/hardware/ebpf/tc_loader_linux_test.go` follows the same pattern
for TC:

1. Skips on missing embedded object, missing caps, or pre-6.6 kernel
   (detected via `ENOTSUP` / `EINVAL` from `AttachTCX`).
2. Creates a dummy interface `fos1testtc`.
3. Loads the collection, populates + clears the priority map, attaches
   both ingress and egress TCX links, asserts non-nil handles, and
   detaches.
4. A separate `TestEnsureClsactQdisc_Idempotent` asserts the clsact
   bootstrap tolerates `EEXIST`.

### Non-goals for v1

- sockops / cgroup loaders — future tickets.
- Classful HTB shaping attached automatically by the controller — the
  TC loader exposes the priority-marking primitive; a future ticket
  wires it to a VLAN shaper CR alongside the existing tc-binary-backed
  implementation in `pkg/network/vlan/qos.go`.
- Packet-level DDoS heuristics (the denylist is populated elsewhere).
- BTF-based CO-RE vs. legacy compile — the current programs are
  legacy (explicit headers); CO-RE is a follow-up if kernel drift
  becomes an operational problem.
- User-space map population controller — a future ticket wires the
  Suricata / threat-intel pipeline to `DenylistMap()` and a future
  VLANShaper wires uplink interfaces to `PriorityMap()`.

## Implementation Plan

The eBPF implementation will be developed in phases:

1. **Phase 1**: Basic XDP and TC programs
   - Packet filtering
   - Simple NAT
   - Basic map management

2. **Phase 2**: Advanced features
   - Connection tracking
   - Stateful firewall
   - QoS and traffic shaping

3. **Phase 3**: Socket and CGroup programs
   - Socket operations
   - Per-container policies
   - Socket redirection

4. **Phase 4**: Cilium integration
   - Map sharing
   - Program coordination
   - Policy integration

5. **Phase 5**: Advanced monitoring and debugging
   - Performance metrics
   - Flow tracking
   - Debugging tools

## Example Use Cases

### DDoS Mitigation

```yaml
apiVersion: ebpf.fos1.io/v1alpha1
kind: EBPFProgram
metadata:
  name: ddos-protection
spec:
  description: "XDP-based DDoS protection"
  type: "xdp"
  interface: "eth0"
  priority: 1
  settings:
    rateLimiting:
      enabled: true
      packetsPerSecond: 1000000
      connectionsPerSecond: 10000
      connectionsPerIP: 100
    synFloodProtection: true
    icmpFloodProtection: true
    udpFloodProtection: true
```

### Advanced NAT with Connection Tracking

```yaml
apiVersion: ebpf.fos1.io/v1alpha1
kind: NATConfig
metadata:
  name: advanced-nat
spec:
  description: "Advanced NAT with connection tracking"
  interfaces:
    source: "eth1"
    destination: "eth0"
  type: "masquerade"
  ipVersion: "both"
  portMappings:
    - protocol: "tcp"
      internalIP: "192.168.1.10"
      internalPort: 80
      externalPort: 80
  connectionTracking:
    enabled: true
    tcpTimeout: 86400  # seconds
    udpTimeout: 300    # seconds
    maxConnections: 1000000
  hairpinning: true
  endpointIndependent: true
```

### Traffic Prioritization for VoIP

```yaml
apiVersion: ebpf.fos1.io/v1alpha1
kind: TrafficControl
metadata:
  name: voip-priority
spec:
  description: "Prioritize VoIP traffic"
  interface: "eth0"
  direction: "egress"
  priority: 10
  queueingDiscipline: "htb"
  classes:
    - name: "voip"
      priority: 1
      rate: "10Mbps"
      ceiling: "50Mbps"
      match:
        applications: ["sip", "rtp"]
        ipProto: "udp"
        dstPorts: [5060, 5061, "10000-20000"]
      markDSCP: 46  # EF
```

### Container Network Isolation

```yaml
apiVersion: ebpf.fos1.io/v1alpha1
kind: ContainerPolicy
metadata:
  name: container-isolation
spec:
  description: "Network isolation for containers"
  selector:
    matchLabels:
      role: "database"
  ingress:
    - from:
        podSelector:
          matchLabels:
            role: "backend"
      ports:
        - protocol: "tcp"
          port: 5432
  egress:
    - to:
        podSelector:
          matchLabels:
            role: "monitoring"
      ports:
        - protocol: "tcp"
          port: 9090
  enforcement: "ebpf-cgroup"
```

## Performance Considerations

1. **Hook Selection**: Choose the appropriate hook for each function
   - XDP for high-throughput packet filtering
   - TC for more complex processing
   - Socket ops for connection-level operations

2. **Map Efficiency**: Design maps for efficient access
   - LRU maps for connection tracking
   - Hash maps for fast lookups
   - Per-CPU maps for atomic operations

3. **Program Complexity**: Balance functionality and performance
   - Minimize branching in hot paths
   - Use tail calls for complex processing
   - Leverage BPF helpers for heavy lifting

4. **Resource Consumption**: Monitor and manage resource usage
   - Track map memory usage
   - Limit per-CPU map sizes
   - Implement efficient garbage collection

## Limitations and Constraints

1. **Kernel Compatibility**: Requires Linux kernel 5.4 or newer for all features
2. **Hardware Offload**: XDP offload requires compatible NICs
3. **Program Complexity**: eBPF verifier limits program complexity
4. **Map Size**: eBPF maps have size limitations
5. **Helper Functions**: Limited set of helper functions available