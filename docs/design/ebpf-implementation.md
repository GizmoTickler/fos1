# eBPF Implementation Design

## Overview

This document describes the design for the eBPF (extended Berkeley Packet Filter) implementation in the Kubernetes-based Router/Firewall system. The implementation leverages eBPF for high-performance packet processing, network address translation, traffic control, load balancing, and network visibility.

## Goals

- Implement high-performance packet processing using eBPF
- Support all major eBPF hooks (XDP, TC, sockops, cgroup)
- Integrate fully with the routing and VRF design
- Provide configuration-based programmability through CRDs
- Leverage Cilium's infrastructure while adding custom functionality
- Enable comprehensive monitoring and debugging capabilities
- Implement using Cilium's Go eBPF library

## Non-Goals

- Support for user-supplied custom eBPF programs
- Integration with non-Kubernetes environments
- Compatibility with non-Linux operating systems
- Support for deprecated eBPF features

## Design Details

### Overall Architecture

The eBPF implementation consists of several key components:

1. **eBPF Programs**: The actual eBPF code that runs in the kernel
2. **Program Manager**: Handles loading, unloading, and updating eBPF programs
3. **Map Manager**: Manages eBPF maps for state sharing
4. **Configuration Controller**: Translates CRDs to eBPF program configurations
5. **Monitoring System**: Gathers metrics and provides debugging tools

The architecture leverages Cilium for core functionality while adding a thin controller layer for router/firewall specific features.

```
┌─────────────────────────────────┐
│       Custom Controller         │◄───┐
└───────────────┬─────────────────┘    │
                │                       │
                ▼                       │
┌─────────────────────────────────┐    │
│        Cilium Integration       │    │ Configuration
└───────────────┬─────────────────┘    │    CRDs
                │                       │
                ▼                       │
┌─────────────────────────────────┐    │
│      eBPF Program Manager       │◄───┘
└───────────────┬─────────────────┘
                │
        ┌───────┴────────┐
        │                │
        ▼                ▼
┌─────────────┐   ┌─────────────┐
│ eBPF Maps   │   │ eBPF Programs│
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

eBPF programs are configured through CRDs that define their behavior without requiring users to write eBPF code.

#### eBPF Program Configuration CRD

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