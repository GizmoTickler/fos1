# Routing Configuration Guide

This guide explains how to configure various routing features in the Kubernetes-based Router/Firewall system, including static routes, dynamic routing protocols, policy-based routing, and failover mechanisms.

## Table of Contents

1. [Basic Concepts](#basic-concepts)
2. [Static Routing](#static-routing)
3. [NAT and NAT66 Configuration](#nat-and-nat66-configuration)
4. [Inter-VLAN Routing](#inter-vlan-routing)
5. [Dynamic Routing with FRRouting](#dynamic-routing-with-frrouting)
   - [BGP Configuration](#bgp-configuration)
   - [OSPF Configuration](#ospf-configuration)
   - [Route Redistribution](#route-redistribution)
   - [BFD Configuration](#bfd-configuration)
6. [Policy-Based Routing](#policy-based-routing)
7. [Multi-WAN Configuration](#multi-wan-configuration)
   - [Load Balancing](#load-balancing)
   - [Failover Configuration](#failover-configuration)
8. [Traffic Engineering](#traffic-engineering)
9. [Examples](#examples)

## Basic Concepts

The routing configuration in this system is managed through several Kubernetes Custom Resources (CRs) and implemented using a unified Cilium-based network stack:

- **Subnet CR**: Defines basic static routing and NAT configuration
- **FRRouteConfig CR**: Configures dynamic routing protocols
- **RoutingPolicy CR**: Defines policy-based routing rules
- **MultiwanConfig CR**: Configures multiple WAN uplinks with load balancing and failover

All routing functions are implemented using Cilium's eBPF capabilities, providing high-performance packet processing at the kernel level.

## Static Routing

Static routes are configured through the `Subnet` CR:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: lan-subnet
spec:
  name: LAN
  network: 192.168.1.0/24
  interface: eth1
  routing:
    defaultGateway: 192.168.1.254  # Optional external gateway
    defaultGatewayIpv6: 2001:db8:1::254  # Optional IPv6 gateway
    staticRoutes:
      - destination: 10.10.10.0/24
        nextHop: 192.168.1.10
        metric: 100
      - destination: 10.20.20.0/24
        nextHop: 192.168.1.20
        metric: 200
```

For IPv6 static routes:

```yaml
routing:
  staticRoutesIpv6:
    - destination: 2001:db8:2::/64
      nextHop: 2001:db8:1::10
      metric: 100
```

## NAT and NAT66 Configuration

NAT for IPv4 and NAT66 for IPv6 are implemented using Cilium's eBPF-based NAT capabilities:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: vlan20-subnet
spec:
  name: VLAN20
  network: 192.168.20.0/24
  interface: vlan20
  routing:
    nat: true  # Enable Cilium NAT for IPv4
    natOutbound: true  # Enable outbound NAT only
    natMasquerade: true  # Enable IP masquerading
```

For IPv6 NAT66:

```yaml
routing:
  nat66: true  # Enable Cilium NAT66 for IPv6
  nat66Outbound: true  # Enable outbound NAT66 only
  nat66Masquerade: true  # Enable IPv6 masquerading
```

To create port forwards (destination NAT):

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: PortForward
metadata:
  name: web-server
spec:
  description: "Web Server Port Forward"
  protocol: tcp
  externalInterface: eth0  # WAN interface
  externalPort: 80
  internalAddress: 192.168.1.100
  internalPort: 80
  enabled: true
```

## Inter-VLAN Routing

Inter-VLAN routing is automatically enabled for all VLANs by default. To restrict traffic between VLANs, use Cilium network policies:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: restrict-vlan-access
spec:
  description: "Allow only HTTP/HTTPS from IoT VLAN to Server VLAN"
  endpointSelector:
    matchLabels:
      vlan: server
  ingress:
  - fromEndpoints:
    - matchLabels:
        vlan: iot
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      - port: "443"
        protocol: TCP
```

## Dynamic Routing with FRRouting

Dynamic routing is implemented using FRRouting (FRR) and configured through the `FRRouteConfig` CR.

### BGP Configuration

To configure BGP:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: FRRouteConfig
metadata:
  name: bgp-config
spec:
  bgp:
    enabled: true
    asn: 65000  # Local Autonomous System Number
    routerId: 192.168.1.1
    neighbors:
      - address: 192.168.100.2
        remoteAsn: 65001
        description: "Upstream ISP"
        keepalive: 30
        holdTime: 90
        passwordSecret: bgp-password-secret
        bfd: true
      - address: 192.168.200.2
        remoteAsn: 65002
        description: "Peer Router"
        bfd: true
    networks:
      - 192.168.0.0/16
      - 10.0.0.0/8
    redistribution:
      - protocol: connected
      - protocol: static
      - protocol: ospf
        metric: 100
```

### OSPF Configuration

To configure OSPF:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: FRRouteConfig
metadata:
  name: ospf-config
spec:
  ospf:
    enabled: true
    routerId: 192.168.1.1
    areas:
      - areaId: 0
        interfaces:
          - name: eth1
            networkType: broadcast
            priority: 100
            cost: 10
          - name: vlan10
            networkType: broadcast
            priority: 50
            cost: 20
      - areaId: 1
        interfaces:
          - name: vlan20
            networkType: broadcast
            priority: 50
            cost: 20
        stubArea: true
    redistribution:
      - protocol: connected
      - protocol: static
      - protocol: bgp
        metric: 100
```

### Route Redistribution

Route redistribution is configured in the `FRRouteConfig` CR under each routing protocol section:

```yaml
redistribution:
  - protocol: connected  # Redistribute directly connected routes
  - protocol: static     # Redistribute static routes
  - protocol: bgp        # Redistribute BGP routes
    metric: 100          # Set metric for redistributed routes
    routeMap: filter-bgp # Apply route-map to filter routes
```

To define filter policies:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RouteMap
metadata:
  name: filter-bgp
spec:
  name: FILTER-BGP
  entries:
    - sequence: 10
      action: permit
      match:
        prefix: 10.0.0.0/8
      set:
        metric: 200
    - sequence: 20
      action: deny
      match:
        prefix: 192.168.0.0/16
```

### BFD Configuration

Bidirectional Forwarding Detection (BFD) provides fast failure detection for dynamic routing:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: BFDConfig
metadata:
  name: bfd-config
spec:
  enabled: true
  intervals:
    minTx: 300
    minRx: 300
    multiplier: 3
  peers:
    - address: 192.168.100.2
      interface: eth0
    - address: 192.168.200.2
      interface: eth0
```

## Policy-Based Routing

Policy-based routing allows routing decisions based on more than just the destination address:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: guest-routing
spec:
  description: "Route Guest traffic through secondary ISP"
  sourceVlan: guest
  sourceNetwork: 192.168.30.0/24
  interface: eth1  # Secondary ISP interface
  table: 200       # Routing table ID
  priority: 100    # Rule priority
```

For application-aware routing with DPI:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: streaming-routing
spec:
  description: "Route streaming apps through high-bandwidth ISP"
  applications:
    - netflix
    - youtube
    - hulu
  interface: eth1  # High-bandwidth ISP interface
  table: 300
  priority: 50
```

## Multi-WAN Configuration

### Load Balancing

To configure load balancing across multiple WAN links:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: MultiWanConfig
metadata:
  name: multiwan-config
spec:
  enabled: true
  interfaces:
    - name: eth0
      weight: 100
      priority: 10
      description: "Primary ISP"
      trackTarget: 8.8.8.8
      trackMethod: ping
      trackInterval: 5
      trackTimeout: 2
      trackThreshold: 3
    - name: eth1
      weight: 50
      priority: 20
      description: "Secondary ISP"
      trackTarget: 1.1.1.1
      trackMethod: ping
      trackInterval: 5
      trackTimeout: 2
      trackThreshold: 3
  loadBalance: true  # Enable load balancing
  loadBalanceMethod: weighted  # Options: weighted, round-robin, random
```

### Failover Configuration

For failover configuration:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: MultiWanConfig
metadata:
  name: failover-config
spec:
  enabled: true
  interfaces:
    - name: eth0
      priority: 10  # Lower priority = higher preference
      description: "Primary fiber ISP"
      trackTarget: 8.8.8.8
      trackMethod: ping
      trackInterval: 5
      trackTimeout: 2
      trackThreshold: 3
    - name: eth1
      priority: 20
      description: "Backup LTE connection"
      trackTarget: 1.1.1.1
      trackMethod: ping
      trackInterval: 5
      trackTimeout: 2
      trackThreshold: 3
  loadBalance: false  # Disable load balancing for pure failover
  failbackThreshold: 5  # Number of successful checks before failing back to primary
```

## Traffic Engineering

For advanced traffic engineering with DSCP marking:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: voip-traffic
spec:
  description: "VoIP Traffic Priority"
  match:
    applications:
      - voip
      - sip
      - rtp
    protocols:
      - udp
    ports:
      - 5060-5061
      - 10000-20000
  action:
    dscp: 46  # Expedited Forwarding
    priority: high
    queue: 1
    outInterface: eth0  # Force traffic out specific interface
```

## Examples

### Example 1: Small Business with Dual-WAN

This example shows a business network with two internet connections, VLANs, and policy-based routing:

1. Configure the WAN interfaces:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: primary-wan
spec:
  name: eth0
  type: physical
  dhcp: true
---
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: backup-wan
spec:
  name: eth1
  type: physical
  dhcp: true
```

2. Set up Multi-WAN for failover:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: MultiWanConfig
metadata:
  name: business-wan
spec:
  enabled: true
  interfaces:
    - name: eth0
      priority: 10
      description: "Primary Fiber Connection"
      trackTarget: 8.8.8.8
    - name: eth1
      priority: 20
      description: "Backup Cable Connection"
      trackTarget: 1.1.1.1
  loadBalance: false
```

3. Configure VLANs and policy-based routing:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: staff-vlan
spec:
  name: vlan10
  type: vlan
  parent: eth2
  vlanId: 10
  addresses:
    - 10.10.10.1/24
---
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: guest-vlan
spec:
  name: vlan20
  type: vlan
  parent: eth2
  vlanId: 20
  addresses:
    - 10.20.20.1/24
```

4. Create subnets with routing configuration:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: staff-subnet
spec:
  name: Staff
  network: 10.10.10.0/24
  interface: vlan10
  dhcp:
    enabled: true
  routing:
    nat: true
---
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: guest-subnet
spec:
  name: Guest
  network: 10.20.20.0/24
  interface: vlan20
  dhcp:
    enabled: true
  routing:
    nat: true
```

5. Add policy-based routing for guest network:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: guest-backup-wan
spec:
  description: "Route guest traffic through backup WAN"
  sourceVlan: vlan20
  sourceNetwork: 10.20.20.0/24
  interface: eth1
  table: 200
  priority: 100
```

### Example 2: Home Network with Application-Aware Routing

1. Configure application-based routing policies:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: streaming-policy
spec:
  description: "Route streaming through high-bandwidth connection"
  applications:
    - netflix
    - youtube
    - hulu
    - plex
  interface: eth0
  table: 100
  priority: 50
---
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: gaming-policy
spec:
  description: "Route gaming through low-latency connection"
  applications:
    - steam
    - battle.net
    - ea_origin
    - epic_games
  interface: eth1
  table: 200
  priority: 50
---
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: voip-policy
spec:
  description: "Route VoIP through most reliable connection"
  applications:
    - zoom
    - teams
    - skype
    - voip
  interface: eth0
  table: 300
  priority: 30  # Higher priority (lower number)
```

2. Configure traffic policy with QoS for VoIP:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: voip-priority
spec:
  description: "Prioritize VoIP traffic"
  match:
    applications:
      - zoom
      - teams
      - skype
      - voip
  action:
    dscp: 46  # Expedited Forwarding
    priority: high
    queue: 1
```

### Example 3: BGP Peering with Upstream Provider

1. Configure BGP with an upstream provider:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: FRRouteConfig
metadata:
  name: upstream-bgp
spec:
  bgp:
    enabled: true
    asn: 65000  # Your ASN
    routerId: 203.0.113.1
    neighbors:
      - address: 203.0.113.2
        remoteAsn: 64496  # ISP ASN
        description: "Upstream ISP"
        keepalive: 30
        holdTime: 90
        bfd: true
    networks:
      - 192.168.0.0/16  # Your internal networks
    redistribution:
      - protocol: connected
      - protocol: static
```

2. Configure BFD for fast failover:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: BFDConfig
metadata:
  name: upstream-bfd
spec:
  enabled: true
  intervals:
    minTx: 300
    minRx: 300
    multiplier: 3
  peers:
    - address: 203.0.113.2
      interface: eth0
```