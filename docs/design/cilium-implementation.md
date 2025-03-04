# Cilium Implementation Design

## Overview

This document outlines the comprehensive design for Cilium integration within our Kubernetes-based router/firewall system. Cilium serves as the foundation of our networking architecture, providing high-performance packet processing through eBPF, unified policy enforcement, and integration with security components.

## Design Goals

1. **Unified Network Layer**: Provide a consistent packet processing pipeline for all traffic
2. **High Performance**: Leverage eBPF for kernel-level packet processing
3. **Comprehensive Visibility**: Enable detailed traffic monitoring and analysis
4. **Flexible Policy Model**: Support advanced filtering from L3-L7
5. **Integration Platform**: Serve as the integration point for all networking components

## System Architecture

### Cilium as the Central CNI

Cilium serves as the central CNI (Container Network Interface) provider for the entire system with:

1. **Deployment Strategy**:
   - Deployed as a DaemonSet on all nodes
   - Hubble for flow visibility
   - Cilium Operator for cluster-wide management

2. **Core Configuration**:
   - IPv4/IPv6 dual-stack support
   - VXLAN tunnel for overlay networking
   - Direct routing for native performance where possible
   - Host firewall for system protection
   - Bandwidth manager for QoS

3. **Component Integration**:
   - Custom controllers to extend Cilium functionality
   - API integration for programmatic control
   - Synchronization mechanisms with other subsystems

### Packet Processing Pipeline

The unified processing pipeline managed by Cilium consists of:

1. **Packet Ingress**:
   - XDP programs for early packet processing (DDoS protection)
   - TC ingress hooks for stateful filtering

2. **Central Processing**:
   - Cilium eBPF for policy enforcement
   - Connection tracking
   - NAT/Routing decisions
   - Application layer (L7) visibility

3. **Packet Egress**:
   - TC egress hooks for QoS and traffic shaping
   - Final packet modifications

## Integration Components

### 1. Cilium Network Controller

The `NetworkController` serves as the primary integration point between our custom logic and Cilium:

```go
// NetworkController manages all networking functionality through Cilium
type NetworkController struct {
    ciliumClient CiliumClient
    // Additional components for routing, firewall, etc.
}
```

Key responsibilities:
- Translate high-level configurations into Cilium policies
- Synchronize network state with Cilium
- Manage Cilium-specific features

Implementation components:
- `pkg/cilium/network_controller.go`: Core controller logic
- `pkg/cilium/client.go`: Client interface to Cilium API
- `cmd/cilium-controller/main.go`: Service entrypoint

### 2. Cilium Client Interface

The Cilium client provides an abstraction layer for interacting with Cilium:

```go
// CiliumClient represents the interface to Cilium's API
type CiliumClient interface {
    ApplyNetworkPolicy(ctx context.Context, policy *NetworkPolicy) error
    CreateNAT(ctx context.Context, config *NATConfig) error
    ConfigureVLANRouting(ctx context.Context, config *VLANRoutingConfig) error
    ConfigureDPIIntegration(ctx context.Context, config *DPIIntegrationConfig) error
}
```

This interface allows for:
- Testing with mock implementations
- Potentially supporting alternative backends
- Abstracting Cilium API changes

### 3. Cilium CRD Controllers

Custom CRD controllers translate our domain-specific resources into Cilium policies:

1. **Network Interface Controller**:
   - Watches `NetworkInterface` CRDs
   - Creates corresponding Cilium endpoints
   - Applies appropriate Cilium policies

2. **Firewall Controller**:
   - Watches `FirewallRule` and `FirewallZone` CRDs
   - Translates to Cilium Network Policies
   - Manages zone-based and rule-based firewall configurations

3. **Routing Controller**:
   - Synchronizes routes with Cilium's eBPF maps
   - Implements policy-based routing through Cilium policies
   - Manages VRF isolation

4. **DPI Controller**:
   - Integrates DPI results with Cilium policies
   - Creates application-aware filtering rules

## Network Feature Implementation

### 1. VLAN Support

VLANs are integrated with Cilium through:

1. **Host-level VLAN Interfaces**:
   - VLANs created using host networking
   - Cilium sees each VLAN as distinct network interface

2. **VLAN Policy Enforcement**:
   - Cilium policies target specific VLANs
   - Inter-VLAN routing controlled through policies

Example configuration:
```yaml
kind: VLANPolicy
spec:
  fromVLAN: 10
  toVLAN: 20
  allowAll: false
  rules:
    - protocol: tcp
      port: 80
      allow: true
```

Implementation:
- `pkg/network/vlan/manager.go`: VLAN interface management
- `pkg/cilium/network_controller.go`: VLAN policy translation

### 2. Routing System

Routing is implemented through Cilium using:

1. **Route Synchronization**:
   - Routes installed in kernel tables
   - Cilium Synchronizer propagates to Cilium
   - eBPF maps store routing information

2. **Policy-Based Routing**:
   - Complex routing decisions implemented as Cilium policies
   - Source/destination matching with priority

3. **VRF Support**:
   - Isolation through Cilium policies
   - Independent routing tables per VRF

Implementation:
- `pkg/network/routing/manager.go`: Routing core functionality
- `pkg/cilium/route_sync.go`: Route synchronization with Cilium

### 3. NAT and NAT66

Cilium provides NAT capabilities for both IPv4 and IPv6:

1. **Implementation Approach**:
   - Utilize Cilium's built-in NAT capabilities
   - Configure through NetworkController

2. **Configuration Options**:
   - Source network specification
   - Destination interface
   - IPv4/IPv6 support

Example:
```go
// ConfigureNAT configures NAT for IPv4 or IPv6
func (c *NetworkController) ConfigureNAT(ctx context.Context, sourceNetwork, outInterface string, ipv6 bool) error {
    config := &NATConfig{
        SourceNetwork:    sourceNetwork,
        DestinationIface: outInterface,
        IPv6:             ipv6,
    }
    
    return c.ciliumClient.CreateNAT(ctx, config)
}
```

### 4. Security Integration

Cilium integrates with security components through:

1. **DPI Integration**:
   - Cilium's L7 visibility feeds DPI engines
   - DPI results translated to Cilium policies

2. **IDS/IPS Integration**:
   - Suricata integrated with Cilium's traffic flow
   - Alerts generate dynamic policies

3. **Application-Layer Filtering**:
   - L7 (HTTP, DNS, etc.) filtering through Cilium proxies
   - Protocol-aware rule enforcement

Implementation:
- `pkg/security/dpi/manager.go`: DPI integration
- `pkg/security/ids/manager.go`: IDS/IPS integration

## eBPF Program Integration

### 1. Custom eBPF Programs

Custom eBPF programs coexist with Cilium's programs:

1. **Program Types**:
   - XDP programs for early packet processing
   - TC programs for advanced traffic control
   - Socket operations for connection monitoring

2. **Integration Points**:
   - Map sharing between custom programs and Cilium
   - Coordination of program execution

3. **Program Loading**:
   - Custom eBPF program manager
   - Hook selection based on processing needs

### 2. Map Sharing Strategy

eBPF maps are shared between Cilium and custom programs:

1. **Map Types**:
   - Global maps for routing, policy
   - Functional maps for specific features
   - Local maps for program-specific state

2. **Sharing Mechanism**:
   - Maps pinned to filesystem
   - Permission management
   - Versioning for compatibility

## CRD-Based Configuration

### 1. Network Interface CRD

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: lan1
spec:
  type: physical
  device: eth1
  vlan:
    enabled: true
    id: 10
  cilium:
    labels:
      zone: lan
      interface: lan1
```

### 2. Firewall Rule CRD

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FirewallRule
metadata:
  name: allow-web-from-lan-to-wan
spec:
  fromZone: lan
  toZone: wan
  protocol: tcp
  ports: [80, 443]
  action: allow
```

### 3. DPI Profile CRD

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: DPIProfile
metadata:
  name: detect-web-traffic
spec:
  applications:
    - http
    - https
  actions:
    allow:
      - http
    block:
      - bittorrent
```

## Implementation Phases

### Phase 1: Core CNI Integration
- Base Cilium deployment with optimized configuration
- Integration with Talos Linux networking
- Basic CRD controllers

### Phase 2: Advanced Networking Features
- VLAN integration
- Routing system with Cilium synchronization
- NAT/NAT66 implementation

### Phase 3: Security Components
- DPI engine integration
- IDS/IPS integration with Suricata
- Application-aware filtering

### Phase 4: Performance Optimization
- Custom eBPF programs for router-specific features
- Advanced QoS implementation
- Performance testing and tuning

## Security Considerations

1. **Policy Enforcement**:
   - Default-deny approach for network policies
   - Comprehensive policy validation
   - Audit logging for policy changes

2. **Privileged Access**:
   - RBAC for CRD access
   - Secured API endpoints
   - Principle of least privilege

3. **Data Security**:
   - Encryption for sensitive traffic
   - Certificate management
   - Secrets protection

## Observability

### 1. Hubble Integration

Cilium's Hubble provides comprehensive flow visibility:

1. **Flow Data Collection**:
   - Per-connection metadata
   - Policy decisions
   - Performance metrics

2. **Integration Points**:
   - Hubble Relay for centralized collection
   - API for programmatic access
   - Prometheus metrics

### 2. Custom Metrics

Additional metrics are collected for router-specific functionality:

1. **Performance Metrics**:
   - Throughput per interface/VLAN
   - Policy processing time
   - Connection tracking table utilization

2. **Security Metrics**:
   - Policy violations
   - IDS/IPS alerts
   - Anomaly detection

## Conclusion

This Cilium implementation design serves as the foundation for our Kubernetes-based router/firewall system. By leveraging Cilium's eBPF capabilities and extending them with custom controllers and integrations, we can provide a high-performance, feature-rich networking platform that unifies routing, security, and traffic management functions.

The implementation follows a phased approach, starting with core CNI functionality and progressively adding more advanced features while maintaining backward compatibility and ensuring high performance throughout.