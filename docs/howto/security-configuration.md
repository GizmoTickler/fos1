# Security Configuration Guide

This guide explains how to configure the security features of the Kubernetes-based Router/Firewall system, including firewalls, deep packet inspection (DPI), policy-based routing (PBR), and quality of service (QoS).

## Table of Contents

1. [Firewall Configuration](#firewall-configuration)
2. [Deep Packet Inspection](#deep-packet-inspection)
3. [Policy-Based Routing](#policy-based-routing)
4. [Quality of Service](#quality-of-service)
5. [Integration Between Components](#integration-between-components)
6. [Examples](#examples)

## Firewall Configuration

The firewall in this system is managed through Cilium Network Policies, which are Kubernetes Custom Resources (CRs) that provide Layer 3-7 filtering with eBPF.

### Zone-Based Policies

In Cilium, we implement zone-based firewall using endpoint labels:

```yaml
# Define a policy for traffic from LAN to WAN zone
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: zone-lan-to-wan
spec:
  description: "Allow web traffic from LAN to WAN"
  endpointSelector:
    matchLabels:
      zone: wan
  ingress:
  - fromEndpoints:
    - matchLabels:
        zone: lan
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      - port: "443"
        protocol: TCP
```

### IP-Based Policies

To create IP-based filtering with Cilium:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: trusted-servers
spec:
  description: "Allow traffic to trusted servers"
  endpointSelector:
    matchLabels:
      app: webserver
  ingress:
  - fromCIDR:
    - 192.168.1.10/32
    - 192.168.1.20/32
    - 192.168.2.0/24
```

### L7 Application Filtering

Cilium provides application-layer filtering:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: collaboration-apps
spec:
  description: "Controls for collaboration applications"
  endpointSelector:
    matchLabels:
      app: workstation
  egress:
  - toFQDNs:
    - matchPattern: "*.zoom.us"
    - matchPattern: "*.teams.microsoft.com"
    - matchPattern: "*.webex.com"
  - toEndpoints:
    - matchLabels:
        app: dns
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
```

### Inter-VLAN Traffic Control

To control traffic between VLANs with Cilium:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: vlan10-to-vlan20
spec:
  description: "Allow selected traffic from VLAN10 to VLAN20"
  endpointSelector:
    matchLabels:
      vlan: "20"
  ingress:
  - fromEndpoints:
    - matchLabels:
        vlan: "10"
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      - port: "443"
        protocol: TCP
      - port: "53"
        protocol: UDP
```

### DPI-Based Application Rules

To create rules based on applications detected by DPI using Cilium:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: block-p2p
spec:
  description: "Block P2P traffic with DPI integration"
  endpointSelector:
    matchLabels:
      zone: lan
  egress:
  - toEndpoints:
    - matchLabels: {}
    toPorts:
    - ports:
      - port: "1024-65535"
        protocol: TCP
      rules:
        l7proto: "bittorrent"
    denied: true
  - toEndpoints:
    - matchLabels: {}
    toPorts:
    - ports:
      - port: "6881-6889"
        protocol: TCP
    denied: true
```

## Deep Packet Inspection

DPI enables application-level recognition and control.

### DPI Profiles

DPI profiles define which applications to detect and how:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: DPIProfile
metadata:
  name: standard-inspection
spec:
  name: StandardInspection
  description: "Standard DPI profile"
  enabled: true
  inspectionDepth: 5
  applications:
    - http
    - https
    - ssh
    - dns
    - ftp
  applicationCategories:
    - web
    - email
    - file_transfer
  trafficClasses:
    - name: HighPriority
      applications:
        - voip
        - webex
      applicationCategories:
        - video_conferencing
      dscp: 46
    - name: StandardTraffic
      applications:
        - http
        - https
      applicationCategories:
        - web
      dscp: 0
  logging:
    enabled: true
    logLevel: info
```

### DPI Flows

DPI flows define which traffic should be inspected:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: DPIFlow
metadata:
  name: lan-to-wan-inspection
spec:
  description: "Inspect traffic from LAN to WAN"
  enabled: true
  sourceNetwork: eth1
  destinationNetwork: eth0
  profile: StandardInspection
  bypassRules:
    - match: "ip saddr 192.168.1.10"
      description: "Skip inspection for trusted server"
```

## Policy-Based Routing

Policy-based routing (PBR) directs traffic based on criteria beyond destination address.

### Route Tables

PBR uses multiple routing tables:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RouteTable
metadata:
  name: isp1-routes
spec:
  name: ISP1
  tableId: 100
  defaultRoute:
    gateway: 203.0.113.1
    interface: eth0
  staticRoutes:
    - destination: 10.0.0.0/8
      gateway: 203.0.113.1
      interface: eth0
```

### Routing Policies

Routing policies determine which traffic uses which route table:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: voip-routing
spec:
  name: VoIPRouting
  description: "Route VoIP traffic through ISP1"
  priority: 10
  applicationMatch:
    applications:
      - voip
      - sip
      - rtp
  routeTable: ISP1
```

#### Application-Based Routing

To route traffic based on DPI-detected applications:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: streaming-routing
spec:
  name: StreamingRouting
  description: "Route streaming traffic through ISP2"
  priority: 15
  applicationMatch:
    applications:
      - netflix
      - youtube
    categories:
      - streaming
  routeTable: ISP2
```

## Quality of Service

QoS provides traffic prioritization and bandwidth control.

### QoS Profiles

QoS profiles define traffic classes and their characteristics:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: QoSProfile
metadata:
  name: wan-qos
spec:
  interface: eth0
  uploadBandwidth: 50Mbit
  downloadBandwidth: 200Mbit
  defaultClass: standard
  classes:
    - name: voip
      priority: 1
      minBandwidth: 10Mbit
      maxBandwidth: 20Mbit
      burst: 15kb
      dscp: 46
      applications:
        - voip
        - sip
        - rtp
      applicationCategories:
        - voice
        - video_conferencing
    - name: streaming
      priority: 3
      minBandwidth: 20Mbit
      maxBandwidth: 40%
      dscp: 34
      applications:
        - netflix
        - youtube
      applicationCategories:
        - streaming
    - name: standard
      priority: 5
      minBandwidth: 1Mbit
      maxBandwidth: 30%
      dscp: 0
    - name: bulk
      priority: 7
      maxBandwidth: 10%
      dscp: 8
      applications:
        - bittorrent
        - ftp
      applicationCategories:
        - file_sharing
        - backup
```

#### DPI-Based QoS

QoS profiles can use DPI-detected applications to classify traffic:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: QoSProfile
metadata:
  name: application-aware-qos
spec:
  interface: eth0
  uploadBandwidth: 100Mbit
  downloadBandwidth: 500Mbit
  classes:
    - name: realtime
      priority: 1
      minBandwidth: 20%
      maxBandwidth: 40%
      applications:
        - zoom
        - teams
        - webex
      applicationCategories:
        - video_conferencing
        - voip
      dscp: 46
    - name: interactive
      priority: 3
      minBandwidth: 30%
      maxBandwidth: 50%
      applications:
        - ssh
        - rdp
        - vnc
      applicationCategories:
        - remote_access
        - web
      dscp: 26
    - name: background
      priority: 7
      maxBandwidth: 20%
      applications:
        - bittorrent
        - ftp
      applicationCategories:
        - file_transfer
        - updates
      dscp: 8
```

## Integration Between Components

The security components work together for comprehensive control:

1. **DPI → Firewall**: DPI identifies applications that firewall rules can filter
2. **DPI → QoS**: DPI identifies applications for QoS classification
3. **DPI → PBR**: DPI identifies applications for routing decisions
4. **Firewall → QoS**: Firewall marks packets for QoS
5. **Firewall → PBR**: Firewall can redirect traffic to specific route tables

## Examples

### Example 1: Home Network Security Configuration

A comprehensive configuration for a home network:

1. Define zones:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FirewallZone
metadata:
  name: wan-zone
spec:
  name: WAN
  interfaces:
    - eth0
  defaultAction: drop
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallZone
metadata:
  name: lan-zone
spec:
  name: LAN
  interfaces:
    - eth1
  defaultAction: accept
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallZone
metadata:
  name: iot-zone
spec:
  name: IoT
  interfaces:
    - vlan20
  defaultAction: drop
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallZone
metadata:
  name: guest-zone
spec:
  name: Guest
  interfaces:
    - vlan30
  defaultAction: drop
```

2. Define basic firewall rules:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FirewallRule
metadata:
  name: allow-lan-to-wan
spec:
  name: LAN-to-WAN
  description: "Allow LAN to WAN"
  sourceType: zone
  source: LAN
  destinationType: zone
  destination: WAN
  action: accept
  logging: false
  priority: 10
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallRule
metadata:
  name: allow-iot-limited
spec:
  name: IoT-Limited
  description: "Allow IoT devices limited access"
  sourceType: zone
  source: IoT
  destinationType: zone
  destination: WAN
  protocol: tcp
  destinationPort: "80,443,53,123"
  action: accept
  logging: true
  priority: 20
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallRule
metadata:
  name: allow-guest-web
spec:
  name: Guest-Web
  description: "Allow guest devices web access only"
  sourceType: zone
  source: Guest
  destinationType: zone
  destination: WAN
  protocol: tcp
  destinationPort: "80,443,53"
  action: accept
  logging: true
  priority: 30
```

3. Configure DPI profile:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: DPIProfile
metadata:
  name: home-network-inspection
spec:
  name: HomeNetworkInspection
  description: "Home network DPI profile"
  enabled: true
  inspectionDepth: 5
  applicationCategories:
    - web
    - email
    - streaming
    - gaming
    - file_sharing
    - social_media
  trafficClasses:
    - name: Streaming
      applicationCategories:
        - streaming
      dscp: 34
    - name: Gaming
      applicationCategories:
        - gaming
      dscp: 26
    - name: FileSharing
      applicationCategories:
        - file_sharing
      dscp: 8
  logging:
    enabled: true
    logLevel: info
```

4. Configure QoS for internet connection:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: QoSProfile
metadata:
  name: internet-qos
spec:
  interface: eth0
  uploadBandwidth: 50Mbit
  downloadBandwidth: 200Mbit
  defaultClass: standard
  classes:
    - name: gaming
      priority: 2
      minBandwidth: 10Mbit
      maxBandwidth: 20%
      applicationCategories:
        - gaming
      dscp: 26
    - name: streaming
      priority: 3
      minBandwidth: 20Mbit
      maxBandwidth: 40%
      applicationCategories:
        - streaming
      dscp: 34
    - name: standard
      priority: 5
      minBandwidth: 5Mbit
      maxBandwidth: 30%
      dscp: 0
    - name: bulk
      priority: 7
      maxBandwidth: 10%
      applicationCategories:
        - file_sharing
        - updates
      dscp: 8
```

### Example 2: Small Business Configuration

A configuration for a small business with separate VLANs for different departments:

1. Define zones:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FirewallZone
metadata:
  name: wan-zone
spec:
  name: WAN
  interfaces:
    - eth0
  defaultAction: drop
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallZone
metadata:
  name: mgmt-zone
spec:
  name: Management
  interfaces:
    - vlan10
  defaultAction: accept
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallZone
metadata:
  name: staff-zone
spec:
  name: Staff
  interfaces:
    - vlan20
  defaultAction: drop
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallZone
metadata:
  name: servers-zone
spec:
  name: Servers
  interfaces:
    - vlan30
  defaultAction: drop
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallZone
metadata:
  name: guest-zone
spec:
  name: Guest
  interfaces:
    - vlan40
  defaultAction: drop
```

2. Define inter-VLAN rules:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FirewallRule
metadata:
  name: mgmt-to-servers
spec:
  name: Mgmt-to-Servers
  description: "Allow management access to servers"
  sourceType: zone
  source: Management
  destinationType: zone
  destination: Servers
  action: accept
  priority: 10
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallRule
metadata:
  name: staff-to-servers
spec:
  name: Staff-to-Servers
  description: "Allow staff access to servers"
  sourceType: zone
  source: Staff
  destinationType: zone
  destination: Servers
  protocol: tcp
  destinationPort: "80,443,389,636"
  action: accept
  priority: 20
---
apiVersion: security.fos1.io/v1alpha1
kind: FirewallRule
metadata:
  name: guest-isolation
spec:
  name: Guest-Isolation
  description: "Isolate guest network"
  sourceType: zone
  source: Guest
  destinationType: any
  destination: WAN
  protocol: tcp
  destinationPort: "80,443,53"
  action: accept
  priority: 100
```

3. Configure application-aware DPI and PBR:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: DPIProfile
metadata:
  name: business-inspection
spec:
  name: BusinessInspection
  description: "Business DPI profile"
  enabled: true
  inspectionDepth: 7
  applicationCategories:
    - web
    - email
    - file_transfer
    - database
    - remote_access
    - collaboration
  trafficClasses:
    - name: Collaboration
      applicationCategories:
        - collaboration
        - video_conferencing
      dscp: 46
    - name: BusinessApps
      applicationCategories:
        - database
        - erp
        - crm
      dscp: 26
---
apiVersion: network.fos1.io/v1alpha1
kind: RoutingPolicy
metadata:
  name: voip-routing
spec:
  name: VoIPRouting
  description: "Route VoIP traffic through MPLS"
  priority: 10
  applicationMatch:
    categories:
      - voip
      - video_conferencing
  routeTable: MPLS
```

4. Configure QoS for business traffic:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: QoSProfile
metadata:
  name: business-qos
spec:
  interface: eth0
  uploadBandwidth: 100Mbit
  downloadBandwidth: 500Mbit
  classes:
    - name: voip
      priority: 1
      minBandwidth: 20Mbit
      maxBandwidth: 30%
      applications:
        - voip
        - webex
        - teams
      applicationCategories:
        - video_conferencing
      dscp: 46
    - name: business
      priority: 3
      minBandwidth: 50Mbit
      maxBandwidth: 60%
      applicationCategories:
        - database
        - erp
        - crm
      dscp: 26
    - name: web
      priority: 5
      minBandwidth: 20Mbit
      maxBandwidth: 40%
      applicationCategories:
        - web
      dscp: 0
    - name: bulk
      priority: 7
      maxBandwidth: 10%
      applicationCategories:
        - file_transfer
        - updates
      dscp: 8
```