# Network Configuration Guide

This guide explains how to configure the network interfaces, VLANs, subnets, and other network settings in the Kubernetes-based Router/Firewall system.

## Table of Contents

1. [Basic Concepts](#basic-concepts)
2. [Physical Interface Configuration](#physical-interface-configuration)
3. [VLAN Configuration](#vlan-configuration)
4. [Subnet Configuration](#subnet-configuration)
5. [IPv6 Configuration](#ipv6-configuration)
6. [NAT and NAT66 Configuration](#nat-and-nat66-configuration)
7. [DHCP and DHCPv6 Configuration](#dhcp-and-dhcpv6-configuration)
8. [Router Advertisements Configuration](#router-advertisements-configuration)
9. [Examples](#examples)

## Basic Concepts

The network configuration in this system is managed through Kubernetes Custom Resources (CRs). There are two main types of resources:

- **NetworkInterface**: Defines physical interfaces, bridges, bonds, and VLANs
- **Subnet**: Defines IP subnets, DHCP settings, and routing for interfaces

## Physical Interface Configuration

To configure a physical interface, create a `NetworkInterface` resource:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: wan
spec:
  name: eth0
  type: physical
  dhcp: true  # Use DHCP for IPv4
  dhcp6: true  # Use DHCPv6 for IPv6
  mtu: 1500
```

For a static IP configuration:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: lan
spec:
  name: eth1
  type: physical
  addresses:
    - 192.168.1.1/24
    - 2001:db8:1::1/64
  mtu: 1500
```

## VLAN Configuration

To create a VLAN interface, you need to define a parent interface first, then create a VLAN interface:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: vlan10
spec:
  name: vlan10
  type: vlan
  parent: eth1  # The parent physical interface
  vlanId: 10
  addresses:
    - 192.168.10.1/24
    - 2001:db8:10::1/64
  mtu: 1500
```

## Subnet Configuration

After defining interfaces, you can configure subnets with DHCP and routing:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: lan-subnet
spec:
  name: LAN
  network: 192.168.1.0/24
  interface: eth1
  dhcp:
    enabled: true
    rangeStart: 192.168.1.100
    rangeEnd: 192.168.1.200
    leaseTime: 86400  # 24 hours
    options:
      router: 192.168.1.1
      domain-name-servers: 192.168.1.1
  routing:
    nat: true  # Enable NAT for this subnet
  dns:
    domain: lan.local
    servers:
      - 192.168.1.1
    searchDomains:
      - lan.local
```

## IPv6 Configuration

For IPv6 configuration, you need to define both the subnet and the router advertisements:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: lan-ipv6-subnet
spec:
  name: LAN-IPv6
  network: 2001:db8:1::/64
  interface: eth1
  dhcpv6:
    enabled: true
    mode: stateless  # Use stateless DHCPv6
    prefixDelegation: false
  routerAdvertisement:
    enabled: true
    managed: false  # M-bit set to false
    other: true  # O-bit set to true
    prefixAutonomous: true  # A-bit set to true
    prefixOnLink: true  # L-bit set to true
    prefixValidLifetime: 86400  # 24 hours
    prefixPreferredLifetime: 43200  # 12 hours
  routing:
    nat66: true  # Enable NAT66 for this subnet
  dns:
    servers:
      - 2001:db8:1::1
```

## NAT and NAT66 Configuration

NAT for IPv4 and NAT66 for IPv6 can be enabled in the subnet configuration. These are implemented using Cilium's eBPF-based NAT capabilities:

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
```

For IPv6 NAT66:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: vlan20-ipv6-subnet
spec:
  name: VLAN20-IPv6
  network: 2001:db8:20::/64
  interface: vlan20
  routing:
    nat66: true  # Enable Cilium NAT66 for IPv6
```

This creates Cilium network policies with masquerading rules, providing high-performance NAT through eBPF.

## DHCP and DHCPv6 Configuration

DHCP for IPv4 is configured in the subnet definition:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: vlan30-subnet
spec:
  name: VLAN30
  network: 192.168.30.0/24
  interface: vlan30
  dhcp:
    enabled: true
    rangeStart: 192.168.30.100
    rangeEnd: 192.168.30.200
    leaseTime: 86400
    options:
      router: 192.168.30.1
      domain-name-servers: 192.168.30.1
      domain-name: vlan30.local
```

DHCPv6 configuration:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: vlan30-ipv6-subnet
spec:
  name: VLAN30-IPv6
  network: 2001:db8:30::/64
  interface: vlan30
  dhcpv6:
    enabled: true
    mode: stateful  # Use stateful DHCPv6
    prefixDelegation: true
    prefixLength: 64
```

## Router Advertisements Configuration

Router advertisements for IPv6 autoconfig:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: vlan40-ipv6-subnet
spec:
  name: VLAN40-IPv6
  network: 2001:db8:40::/64
  interface: vlan40
  routerAdvertisement:
    enabled: true
    managed: true  # M-bit set to true for DHCPv6
    other: true  # O-bit set to true
    prefixAutonomous: true
    prefixOnLink: true
    prefixValidLifetime: 86400
    prefixPreferredLifetime: 43200
```

## Examples

### Example 1: Home Network with Multiple VLANs

This example shows a home network with WAN, LAN, IoT, and Guest VLANs:

1. Define physical interfaces:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: wan-interface
spec:
  name: eth0
  type: physical
  dhcp: true
  dhcp6: true
---
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: lan-interface
spec:
  name: eth1
  type: physical
  addresses:
    - 192.168.1.1/24
    - 2001:db8:1::1/64
```

2. Define VLANs for IoT and Guest networks:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: iot-vlan
spec:
  name: vlan20
  type: vlan
  parent: eth1
  vlanId: 20
  addresses:
    - 192.168.20.1/24
    - 2001:db8:20::1/64
---
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: guest-vlan
spec:
  name: vlan30
  type: vlan
  parent: eth1
  vlanId: 30
  addresses:
    - 192.168.30.1/24
    - 2001:db8:30::1/64
```

3. Configure subnets with DHCP and routing:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: lan-subnet
spec:
  name: LAN
  network: 192.168.1.0/24
  interface: eth1
  dhcp:
    enabled: true
    rangeStart: 192.168.1.100
    rangeEnd: 192.168.1.200
  routing:
    nat: true
---
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: iot-subnet
spec:
  name: IoT
  network: 192.168.20.0/24
  interface: vlan20
  dhcp:
    enabled: true
    rangeStart: 192.168.20.100
    rangeEnd: 192.168.20.200
  routing:
    nat: true
---
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: guest-subnet
spec:
  name: Guest
  network: 192.168.30.0/24
  interface: vlan30
  dhcp:
    enabled: true
    rangeStart: 192.168.30.100
    rangeEnd: 192.168.30.200
  routing:
    nat: true
```

4. Configure IPv6 subnets with router advertisements:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: lan-ipv6-subnet
spec:
  name: LAN-IPv6
  network: 2001:db8:1::/64
  interface: eth1
  dhcpv6:
    enabled: true
    mode: stateless
  routerAdvertisement:
    enabled: true
    managed: false
    other: true
  routing:
    nat66: true
---
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: iot-ipv6-subnet
spec:
  name: IoT-IPv6
  network: 2001:db8:20::/64
  interface: vlan20
  dhcpv6:
    enabled: true
    mode: stateless
  routerAdvertisement:
    enabled: true
    managed: false
    other: true
  routing:
    nat66: true
---
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: guest-ipv6-subnet
spec:
  name: Guest-IPv6
  network: 2001:db8:30::/64
  interface: vlan30
  dhcpv6:
    enabled: true
    mode: stateless
  routerAdvertisement:
    enabled: true
    managed: false
    other: true
  routing:
    nat66: true
```

### Example 2: Small Business Network

This example shows a business network with separate VLANs for management, staff, and servers:

1. Define VLANs:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: mgmt-vlan
spec:
  name: vlan10
  type: vlan
  parent: eth1
  vlanId: 10
  addresses:
    - 10.0.10.1/24
    - 2001:db8:10::1/64
---
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: staff-vlan
spec:
  name: vlan20
  type: vlan
  parent: eth1
  vlanId: 20
  addresses:
    - 10.0.20.1/24
    - 2001:db8:20::1/64
---
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: server-vlan
spec:
  name: vlan30
  type: vlan
  parent: eth1
  vlanId: 30
  addresses:
    - 10.0.30.1/24
    - 2001:db8:30::1/64
```

2. Configure subnet with DHCP reservations:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: Subnet
metadata:
  name: server-subnet
spec:
  name: Servers
  network: 10.0.30.0/24
  interface: vlan30
  dhcp:
    enabled: true
    rangeStart: 10.0.30.100
    rangeEnd: 10.0.30.200
    options:
      router: 10.0.30.1
      domain-name-servers: 10.0.30.1
    # DHCP reservations would be handled by controller
  routing:
    nat: true
```