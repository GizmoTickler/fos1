# Routing Implementation Design

## Overview

This document describes the design for the routing implementation in the Kubernetes-based Router/Firewall system. The routing implementation will provide comprehensive routing capabilities including static routes, dynamic routing protocols, policy-based routing, and VRF support, all integrated with Cilium's eBPF-based networking.

## Goals

- Support static and dynamic routing protocols (BGP, OSPF, IS-IS, BFD, PIM)
- Implement policy-based routing with advanced filtering
- Enable route redistribution between protocols with fine-grained control
- Support multiple routing tables and VRF instances
- Integrate with Cilium for eBPF-accelerated routing
- Provide flexible multi-WAN connectivity with various load balancing methods
- Support multipath routing with unequal cost paths
- Enable route summarization and aggregation
- Support multiple default routes with different metrics
- Allow route leaking between VRF instances
- Implement hierarchical QoS that applies after routing decisions

## Non-Goals

- Support for RIP/RIPng protocols
- Proprietary routing protocols
- Automatic route optimization
- Deep packet inspection within the routing component itself (will integrate with DPI)

## Design Details

### Overall Architecture

The routing implementation consists of several key components:

1. **Route Manager**: Core component that manages routes across various routing tables
2. **Protocol Handlers**: Modules for specific routing protocols (BGP, OSPF, etc.)
3. **Policy Engine**: Implements policy-based routing decisions
4. **VRF Manager**: Handles VRF instances and route isolation
5. **Cilium Synchronizer**: Synchronizes routes between kernel and Cilium
6. **Multi-WAN Manager**: Manages multiple uplinks with load balancing and failover
7. **Monitoring System**: Tracks routing metrics and generates events

The architecture leverages FRR (FRRouting) for dynamic routing protocols while using custom components for policy routing and Cilium integration.

```
                            ┌───────────────────┐
                            │   Route Manager   │
                            └───────┬───────────┘
                                    │
         ┌───────────────────┬─────┴──────┬─────────────────┬───────────────────┐
         │                   │            │                 │                   │
┌────────▼────────┐ ┌────────▼───────┐ ┌──▼──────────┐ ┌───▼────────────┐ ┌───▼───────────┐
│ Protocol Handlers│ │  Policy Engine │ │ VRF Manager │ │Cilium Synchronizer│ │Multi-WAN Manager│
└────────┬────────┘ └────────┬───────┘ └──┬──────────┘ └───┬────────────┘ └───┬───────────┘
         │                   │            │                │                  │
         │                   │            │                │                  │
┌────────▼────────┐ ┌────────▼───────┐ ┌──▼──────────┐ ┌───▼────────────┐ ┌───▼───────────┐
│   FRRouting     │ │ Routing Tables │ │ VRF Devices │ │  Cilium API    │ │ Load Balancer │
└─────────────────┘ └────────────────┘ └─────────────┘ └────────────────┘ └───────────────┘
```

### Route Management

#### Route CRD

Routes are managed through a `Route` CRD:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Route
metadata:
  name: internal-network
spec:
  description: "Route to internal network"
  destination: "10.100.0.0/16"
  nextHop: "192.168.1.254"
  metric: 100
  vrf: "main"  # Optional VRF name
  table: "main"  # Optional routing table
  preference: 20  # Administrative distance
  protocol: "static"  # static, bgp, ospf, is-is, kernel
  scope: "global"  # global, link, host
  preemptible: true  # Can be replaced by more specific routes
  tags:
    - "internal"
    - "corporate"
status:
  installed: true
  installedIn:
    - "kernel"
    - "cilium"
  activeNextHops:
    - "192.168.1.254"
  lastUpdated: "2025-03-15T10:15:30Z"
  error: ""
```

For IPv6:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Route
metadata:
  name: internal-network-ipv6
spec:
  description: "IPv6 route to internal network"
  destination: "2001:db8:100::/48"
  nextHop: "2001:db8:1::254"
  metric: 100
  vrf: "main"
  protocol: "static"
```

#### Route API Interface

```go
type RouteManager interface {
    // AddRoute adds a new route
    AddRoute(route Route) error
    
    // DeleteRoute removes a route
    DeleteRoute(destination string, routeParams RouteParams) error
    
    // GetRoute retrieves a route
    GetRoute(destination string, routeParams RouteParams) (*Route, error)
    
    // ListRoutes lists all routes, optionally filtered
    ListRoutes(filter RouteFilter) ([]*Route, error)
    
    // UpdateRoute updates an existing route
    UpdateRoute(destination string, routeParams RouteParams, newRoute Route) error
    
    // GetRoutingTable retrieves the entire routing table
    GetRoutingTable(tableName string, vrf string) ([]*Route, error)
}

type Route struct {
    Destination     string
    NextHops        []NextHop
    Metric          int
    Preference      int
    Protocol        string
    Scope           string
    VRF             string
    Table           string
    Preemptible     bool
    Tags            []string
    InstalledIn     []string
    LastUpdated     time.Time
    Error           string
}

type NextHop struct {
    Address         string
    Interface       string
    Weight          int
}

type RouteParams struct {
    VRF             string
    Table           string
    Protocol        string
}

type RouteFilter struct {
    Destination     string
    NextHop         string
    Protocol        string
    VRF             string
    Table           string
    Tag             string
}
```

### Dynamic Routing Protocols

#### Protocol Configuration

Dynamic routing protocols are configured through corresponding CRDs:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: BGPConfig
metadata:
  name: bgp-config
spec:
  enabled: true
  asNumber: 65000
  routerId: "192.168.1.1"
  neighbors:
    - address: "192.168.100.1"
      remoteAsNumber: 65001
      description: "ISP Router"
      keepaliveInterval: 30
      holdTime: 90
      connectRetryInterval: 10
      authentication:
        type: "md5"
        secretRef:
          name: "bgp-password"
          key: "password"
      bfdEnabled: true
  addressFamilies:
    - type: "ipv4-unicast"
      enabled: true
      redistributions:
        - protocol: "connected"
          routeMapRef: "redist-connected"
        - protocol: "static"
          routeMapRef: "redist-static"
      networks:
        - "192.168.0.0/16"
        - "10.0.0.0/8"
    - type: "ipv6-unicast"
      enabled: true
      redistributions:
        - protocol: "connected"
      networks:
        - "2001:db8::/32"
  vrf: "main"
  ebgpMultihop: 2
  deterministic-med: true
  multipath: true
status:
  state: "established"
  uptime: "10h15m"
  prefixReceived: 150
  prefixSent: 25
  neighbors:
    - address: "192.168.100.1"
      state: "established"
      uptime: "10h15m"
      prefixReceived: 150
      prefixSent: 25
```

Similar CRDs would exist for OSPF, IS-IS, and other protocols.

#### Protocol API Interface

```go
type ProtocolManager interface {
    // StartProtocol starts a routing protocol
    StartProtocol(protocolName string, config ProtocolConfig) error
    
    // StopProtocol stops a routing protocol
    StopProtocol(protocolName string) error
    
    // RestartProtocol restarts a routing protocol
    RestartProtocol(protocolName string) error
    
    // GetProtocolStatus retrieves the status of a protocol
    GetProtocolStatus(protocolName string) (*ProtocolStatus, error)
    
    // ListProtocols lists all running protocols
    ListProtocols() ([]string, error)
    
    // UpdateProtocolConfig updates the configuration of a protocol
    UpdateProtocolConfig(protocolName string, config ProtocolConfig) error
    
    // GetProtocolRoutes retrieves routes learned via a specific protocol
    GetProtocolRoutes(protocolName string) ([]*Route, error)
}
```

### Policy-Based Routing

#### Policy Configuration

Policy-based routing is configured through a `RoutingPolicy` CRD:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: guest-network-policy
spec:
  description: "Policy for guest network traffic"
  priority: 100
  match:
    source:
      networks:
        - "192.168.30.0/24"
      interfaces:
        - "vlan30"
    destination:
      networks:
        - "0.0.0.0/0"
    protocol: "all"  # tcp, udp, icmp, all
    ports: []  # Optional specific ports
    applications: []  # Optional application names (requires DPI)
    traffidType: []  # Optional traffic types
    time:
      daysOfWeek: []  # Optional day restrictions
      timeOfDay: []  # Optional time restrictions
  action:
    type: "route"  # route, table, nat
    nextHop: "192.168.100.2"  # For route action
    table: "alt-wan"  # For table action
    mark: 0x1  # Optional packet mark
    dscp: 0  # Optional DSCP value
  vrf: "main"
status:
  active: true
  matchCount: 1250
  lastMatched: "2025-03-15T12:34:56Z"
```

#### Policy API Interface

```go
type PolicyManager interface {
    // AddPolicy adds a new routing policy
    AddPolicy(policy RoutingPolicy) error
    
    // DeletePolicy removes a routing policy
    DeletePolicy(name string) error
    
    // GetPolicy retrieves a routing policy
    GetPolicy(name string) (*RoutingPolicy, error)
    
    // ListPolicies lists all routing policies
    ListPolicies() ([]*RoutingPolicy, error)
    
    // UpdatePolicy updates an existing routing policy
    UpdatePolicy(name string, policy RoutingPolicy) error
    
    // GetPolicyStatus retrieves the status of a policy
    GetPolicyStatus(name string) (*PolicyStatus, error)
}

type RoutingPolicy struct {
    Name        string
    Description string
    Priority    int
    Match       PolicyMatch
    Action      PolicyAction
    VRF         string
    Active      bool
    MatchCount  int64
    LastMatched time.Time
}

type PolicyMatch struct {
    Source          PolicyMatchSource
    Destination     PolicyMatchDestination
    Protocol        string
    Ports           []PortRange
    Applications    []string
    TrafficType     []string
    Time            PolicyMatchTime
}

type PolicyAction struct {
    Type        string
    NextHop     string
    Table       string
    Mark        int
    DSCP        int
}
```

### VRF Support

#### VRF Configuration

VRF instances are configured through a `VRF` CRD:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: VRF
metadata:
  name: customer-a
spec:
  description: "VRF for Customer A"
  tableId: 100
  interfaces:
    - "vlan100"
    - "vlan101"
  routeTargets:
    import:
      - "65000:100"
    export:
      - "65000:100"
  leakRoutes:
    - fromVRF: "main"
      destinations:
        - "8.8.8.8/32"
        - "8.8.4.4/32"
    - toVRF: "main"
      destinations:
        - "192.168.100.0/24"
  ciliumPolicy: true  # Use Cilium policy for isolation
status:
  state: "active"
  routeCount: 45
  interfaces:
    - name: "vlan100"
      state: "up"
    - name: "vlan101"
      state: "up"
```

#### VRF API Interface

```go
type VRFManager interface {
    // CreateVRF creates a new VRF instance
    CreateVRF(vrf VRF) error
    
    // DeleteVRF removes a VRF instance
    DeleteVRF(name string) error
    
    // GetVRF retrieves a VRF instance
    GetVRF(name string) (*VRF, error)
    
    // ListVRFs lists all VRF instances
    ListVRFs() ([]*VRF, error)
    
    // UpdateVRF updates an existing VRF instance
    UpdateVRF(name string, vrf VRF) error
    
    // LeakRoutes leaks routes between VRF instances
    LeakRoutes(fromVRF string, toVRF string, routes []string) error
    
    // AddInterfaceToVRF adds an interface to a VRF
    AddInterfaceToVRF(vrfName string, interfaceName string) error
    
    // RemoveInterfaceFromVRF removes an interface from a VRF
    RemoveInterfaceFromVRF(vrfName string, interfaceName string) error
}
```

### Multi-WAN Support

#### Multi-WAN Configuration

Multi-WAN is configured through a `MultiWAN` CRD:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: MultiWAN
metadata:
  name: multi-wan-config
spec:
  description: "Dual WAN configuration"
  wanInterfaces:
    - name: "wan1"
      interface: "eth0"
      weight: 100
      priority: 10
      description: "Primary fiber connection"
      gateway: "192.168.100.1"
      monitoring:
        targets:
          - "8.8.8.8"
          - "1.1.1.1"
        method: "ping"
        interval: 5
        timeout: 1
        failThreshold: 3
        successThreshold: 2
    - name: "wan2"
      interface: "eth1"
      weight: 50
      priority: 20
      description: "Backup LTE connection"
      gateway: "192.168.200.1"
      monitoring:
        targets:
          - "8.8.8.8"
          - "1.1.1.1"
        method: "ping"
        interval: 5
        timeout: 1
        failThreshold: 3
        successThreshold: 2
  loadBalancing:
    enabled: true
    method: "weighted"  # weighted, round-robin, per-connection, per-packet
    sticky: true
    stickyTimeout: 300
  failover:
    enabled: true
    preempt: true
    preemptDelay: 60
  defaultRouteMetric: 100
status:
  activeWANs:
    - name: "wan1"
      state: "up"
      rtt: 15.6
      packetLoss: 0
    - name: "wan2"
      state: "up"
      rtt: 45.2
      packetLoss: 0
  currentPrimary: "wan1"
  lastStateChange: "2025-03-15T08:45:12Z"
```

#### Multi-WAN API Interface

```go
type MultiWANManager interface {
    // AddWANInterface adds a new WAN interface
    AddWANInterface(wan WANInterface) error
    
    // RemoveWANInterface removes a WAN interface
    RemoveWANInterface(name string) error
    
    // GetWANInterface retrieves a WAN interface
    GetWANInterface(name string) (*WANInterface, error)
    
    // ListWANInterfaces lists all WAN interfaces
    ListWANInterfaces() ([]*WANInterface, error)
    
    // UpdateWANInterface updates an existing WAN interface
    UpdateWANInterface(name string, wan WANInterface) error
    
    // GetWANStatus retrieves the status of a WAN interface
    GetWANStatus(name string) (*WANStatus, error)
    
    // SetActivePrimary sets the active primary WAN
    SetActivePrimary(name string) error
    
    // ConfigureLoadBalancing configures load balancing
    ConfigureLoadBalancing(config LoadBalancingConfig) error
    
    // ConfigureFailover configures failover
    ConfigureFailover(config FailoverConfig) error
}
```

### Cilium Integration

The routing implementation will synchronize routes between the kernel routing tables and Cilium's eBPF maps using the following approach:

1. Routes are first installed in the kernel routing tables
2. A synchronization component monitors for route changes
3. Routes are then programmed into Cilium using Cilium's API
4. Cilium policies enforce isolation for VRF instances
5. Traffic is directed through Cilium's eBPF programs for acceleration

#### Cilium Synchronizer API

```go
type CiliumSynchronizer interface {
    // SyncRoute synchronizes a route with Cilium
    SyncRoute(route Route) error
    
    // RemoveRoute removes a route from Cilium
    RemoveRoute(destination string, routeParams RouteParams) error
    
    // SyncRoutingTable synchronizes an entire routing table with Cilium
    SyncRoutingTable(tableName string, vrf string) error
    
    // GetCiliumRoutes retrieves routes installed in Cilium
    GetCiliumRoutes() ([]*Route, error)
    
    // SyncVRFPolicies synchronizes VRF isolation policies with Cilium
    SyncVRFPolicies(vrf VRF) error
}
```

### Route Filtering and Maps

#### Route Map Configuration

Route maps are configured through a `RouteMap` CRD:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RouteMap
metadata:
  name: customer-routes
spec:
  description: "Filter customer routes"
  entries:
    - sequence: 10
      action: "permit"
      match:
        prefix: "192.168.0.0/16"
        prefixLen: "24-28"
        protocol: "bgp"
        community: "65000:100"
        asPath: "^65001"
        metric: 100
        tag: "customer"
      set:
        metric: 200
        localPreference: 150
        community: "65000:200"
        nextHop: "192.168.1.1"
        weight: 100
        asPathPrepend: "65000 65000"
    - sequence: 20
      action: "deny"
      match:
        prefix: "10.0.0.0/8"
status:
  applied: true
  lastApplied: "2025-03-15T09:30:45Z"
```

#### Route Map API

```go
type RouteMapManager interface {
    // CreateRouteMap creates a new route map
    CreateRouteMap(routeMap RouteMap) error
    
    // DeleteRouteMap deletes a route map
    DeleteRouteMap(name string) error
    
    // GetRouteMap retrieves a route map
    GetRouteMap(name string) (*RouteMap, error)
    
    // ListRouteMaps lists all route maps
    ListRouteMaps() ([]*RouteMap, error)
    
    // UpdateRouteMap updates an existing route map
    UpdateRouteMap(name string, routeMap RouteMap) error
    
    // ApplyRouteMap applies a route map to a specific context
    ApplyRouteMap(name string, context RouteMapContext) error
}

type RouteMap struct {
    Name        string
    Description string
    Entries     []RouteMapEntry
    Applied     bool
    LastApplied time.Time
}

type RouteMapEntry struct {
    Sequence    int
    Action      string
    Match       RouteMapMatch
    Set         RouteMapSet
}

type RouteMapMatch struct {
    Prefix          string
    PrefixLen       string
    Protocol        string
    Community       string
    AsPath          string
    Metric          int
    Tag             string
}

type RouteMapSet struct {
    Metric          int
    LocalPreference int
    Community       string
    NextHop         string
    Weight          int
    AsPathPrepend   string
}

type RouteMapContext struct {
    Protocol    string
    Direction   string  // in, out
    Peer        string
    Interface   string
}
```

### Route Aggregation and Summarization

#### Route Aggregation Configuration

Route aggregation is configured through a `RouteAggregate` CRD:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RouteAggregate
metadata:
  name: customer-networks
spec:
  description: "Aggregate customer networks"
  aggregate: "192.168.0.0/16"
  summary: true  # Generate a summary route
  method: "auto"  # auto, manual
  includeNetworks:
    - "192.168.10.0/24"
    - "192.168.20.0/24"
    - "192.168.30.0/24"
  excludeNetworks: []
  attributes:
    metric: 100
    tag: "customer-summary"
  advertisementControl:
    advertiseMap: "customer-advert-map"
    suppressMap: "suppress-specifics"
  vrf: "main"
status:
  active: true
  specifics: 15
  summarized: true
```

#### Route Aggregation API

```go
type RouteAggregationManager interface {
    // CreateAggregate creates a new route aggregate
    CreateAggregate(aggregate RouteAggregate) error
    
    // DeleteAggregate deletes a route aggregate
    DeleteAggregate(name string) error
    
    // GetAggregate retrieves a route aggregate
    GetAggregate(name string) (*RouteAggregate, error)
    
    // ListAggregates lists all route aggregates
    ListAggregates() ([]*RouteAggregate, error)
    
    // UpdateAggregate updates an existing route aggregate
    UpdateAggregate(name string, aggregate RouteAggregate) error
    
    // RefreshAggregate refreshes a route aggregate
    RefreshAggregate(name string) error
}
```

### Controller Implementation

The routing implementation will include a controller that watches for changes to the routing-related CRDs and applies the changes to the underlying system:

```go
type RoutingController struct {
    routeManager        RouteManager
    protocolManager     ProtocolManager
    policyManager       PolicyManager
    vrfManager          VRFManager
    multiWANManager     MultiWANManager
    ciliumSynchronizer  CiliumSynchronizer
    routeMapManager     RouteMapManager
    aggregationManager  RouteAggregationManager
}
```

The controller will reconcile the desired state (CRDs) with the actual state (routing tables, FRR configuration, Cilium) and update the status of the CRDs accordingly.

### Example Configurations

#### Static Routes

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Route
metadata:
  name: datacenter-route
spec:
  description: "Route to datacenter"
  destination: "10.0.0.0/16"
  nextHop: "192.168.100.1"
  metric: 100
  protocol: "static"
  preference: 1
```

#### BGP Configuration

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: BGPConfig
metadata:
  name: bgp-isp1
spec:
  enabled: true
  asNumber: 65000
  routerId: "192.168.1.1"
  neighbors:
    - address: "192.168.100.1"
      remoteAsNumber: 65001
      description: "ISP 1"
  addressFamilies:
    - type: "ipv4-unicast"
      enabled: true
      redistributions:
        - protocol: "connected"
        - protocol: "static"
```

#### Policy-Based Routing

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: voip-traffic
spec:
  description: "Route VoIP traffic through low-latency WAN"
  priority: 10
  match:
    applications:
      - "sip"
      - "rtp"
  action:
    type: "route"
    nextHop: "192.168.100.1"
  vrf: "main"
```

#### Multi-WAN Configuration

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: MultiWAN
metadata:
  name: dual-wan
spec:
  wanInterfaces:
    - name: "wan1"
      interface: "eth0"
      weight: 100
      priority: 10
    - name: "wan2"
      interface: "eth1"
      weight: 50
      priority: 20
  loadBalancing:
    enabled: true
    method: "weighted"
  failover:
    enabled: true
```

#### VRF Configuration

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: VRF
metadata:
  name: customer-a
spec:
  description: "VRF for Customer A"
  tableId: 100
  interfaces:
    - "vlan100"
  leakRoutes:
    - fromVRF: "main"
      destinations:
        - "8.8.8.8/32"
  ciliumPolicy: true
```

## Metrics and Monitoring

The routing implementation will export metrics via Prometheus for monitoring:

- Route counts by protocol, table, and VRF
- Protocol neighbor status
- Route changes per minute
- Policy match counts
- WAN interface metrics (latency, packet loss, jitter)
- Failover events
- Load balancing distribution

Syslog entries will be generated for significant routing events:

- Route additions and deletions
- Protocol state changes
- Policy matches
- WAN interface state changes
- Failover events

## Performance Considerations

1. **Route Processing**: Efficient route installation and removal to handle large routing tables
2. **Protocol Scaling**: Proper tuning of FRR parameters for protocol scaling
3. **eBPF Acceleration**: Leveraging Cilium's eBPF programs for fast path forwarding
4. **Policy Evaluation**: Efficient policy matching algorithms
5. **Route Synchronization**: Batched updates between kernel and Cilium

## Implementation Plans

1. **Phase 1**: Static routing and VRF implementation
2. **Phase 2**: Integration with FRR for dynamic routing protocols
3. **Phase 3**: Policy-based routing implementation
4. **Phase 4**: Multi-WAN and load balancing
5. **Phase 5**: Cilium integration and route synchronization
6. **Phase 6**: Route aggregation and filtering
7. **Phase 7**: Metrics and monitoring integration