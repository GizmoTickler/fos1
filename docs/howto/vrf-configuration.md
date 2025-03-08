# VRF Configuration Guide

This document provides in-depth guidance on configuring and managing Virtual Routing and Forwarding (VRF) instances in the Cilium-based networking system.

## Table of Contents

- [VRF Overview](#vrf-overview)
- [VRF Architecture](#vrf-architecture)
- [VRF Configuration](#vrf-configuration)
  - [Basic Configuration](#basic-configuration)
  - [Advanced Configuration](#advanced-configuration)
- [Managing VRF Routes](#managing-vrf-routes)
- [VRF Isolation](#vrf-isolation)
- [VRF-Aware Services](#vrf-aware-services)
- [Multi-tenant Networking with VRFs](#multi-tenant-networking-with-vrfs)
- [VRF Operations and Maintenance](#vrf-operations-and-maintenance)
- [Integration with External Systems](#integration-with-external-systems)
- [Troubleshooting VRFs](#troubleshooting-vrfs)

## VRF Overview

Virtual Routing and Forwarding (VRF) is a technology that allows multiple routing tables to exist on the same network device simultaneously. This enables network segmentation at the Layer 3 level, providing logical isolation between different network domains while sharing the same physical infrastructure.

Key benefits of VRFs include:

- **Network Isolation**: Separate routing tables for different tenants or applications
- **Address Space Reuse**: Overlapping IP addresses can be used in different VRFs
- **Security Segmentation**: Traffic from one VRF cannot reach another VRF unless explicitly permitted
- **Resource Optimization**: Better utilization of physical network resources

## VRF Architecture

In our Cilium-based implementation, VRFs are implemented using the following components:

1. **VRF Objects**: Each VRF has a unique identifier, name, and associated routing tables
2. **Interface Association**: Network interfaces are assigned to specific VRFs
3. **eBPF Maps**: Cilium uses eBPF maps to implement VRF functionality at the kernel level
4. **Routing Tables**: Each VRF maintains its own independent set of routing tables

The architecture follows this hierarchical model:
```
Router
├── VRF 0 (Default)
│   ├── Tables: [254]
│   └── Interfaces: [eth0]
├── VRF 1 (Red)
│   ├── Tables: [100]
│   └── Interfaces: [eth1]
└── VRF 2 (Blue)
    ├── Tables: [200]
    └── Interfaces: [eth2]
```

## VRF Configuration

### Basic Configuration

To create a basic VRF using Kubernetes CRDs, apply the following manifest:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: VRF
metadata:
  name: red
  namespace: default
spec:
  tables:
    - 100
  interfaces:
    - eth1
```

This creates a VRF named "red" with a single routing table (ID 100) and assigns interface eth1 to this VRF.

### Advanced Configuration

For more advanced configurations, you can specify additional parameters:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: VRF
metadata:
  name: production
  namespace: default
  labels:
    environment: production
    criticality: high
spec:
  tables:
    - 100  # Main table for this VRF
    - 101  # Secondary table for policy routing
  interfaces:
    - name: eth1
      properties:
        mtu: 9000
        promiscuous: false
    - name: eth2
      properties:
        mtu: 1500
        promiscuous: true
  routing:
    ecmp: true
    gracefulRestart: true
    bfd: true
  security:
    isolation: strict  # Options: strict, relaxed, none
    encryption: true
```

## Managing VRF Routes

### Adding Routes to a VRF

To add a route to a specific VRF, include the VRF name in the route definition:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: Route
metadata:
  name: internal-service
  namespace: default
spec:
  destination: "10.1.0.0/24"
  gateway: "192.168.1.2"
  interface: "eth1"
  vrf: "red"
  table: "100"
  metric: 100
  type: "static"
```

### Route Redistribution

For route redistribution between VRFs, use a RouteDistribution CRD:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: RouteDistribution
metadata:
  name: shared-services
  namespace: default
spec:
  sourceVRF: "red"
  destinationVRF: "blue"
  routes:
    - "10.0.0.0/24"  # Redistribute this specific network
  filters:
    prefixList: "allowed-prefixes"
    routeMap: "redistribute-map"
```

## VRF Isolation

VRF isolation controls how traffic flows between different VRFs. Three isolation modes are supported:

1. **Strict**: No traffic can pass between VRFs unless explicitly permitted via route leaking
2. **Relaxed**: Traffic can pass between VRFs if there are matching routes in both VRFs
3. **None**: No isolation, traffic can freely flow between VRFs (not recommended for production)

Configure isolation in the VRF CRD:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: VRF
metadata:
  name: secure
  namespace: default
spec:
  # ... other configuration ...
  security:
    isolation: strict
```

## VRF-Aware Services

To create services that are aware of VRF boundaries, use the VRF annotation in Service objects:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  namespace: default
  annotations:
    networking.cilium.io/vrf: "red"
spec:
  selector:
    app: backend
  ports:
    - port: 80
      targetPort: 8080
  type: ClusterIP
```

## Multi-tenant Networking with VRFs

VRFs are ideal for implementing multi-tenant networking. Each tenant can be assigned their own VRF:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: VRF
metadata:
  name: tenant-a
  namespace: tenant-a
spec:
  tables:
    - 100
  interfaces:
    - name: tenant-a-if
  security:
    isolation: strict
    encryption: true
```

And tenant-specific routes:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: Route
metadata:
  name: tenant-a-route
  namespace: tenant-a
spec:
  destination: "10.1.0.0/24"
  gateway: "192.168.1.2"
  vrf: "tenant-a"
```

## VRF Operations and Maintenance

### Monitoring VRF Status

Check the status of VRFs:

```bash
kubectl get vrfs -A
```

Get detailed information about a specific VRF:

```bash
kubectl describe vrf red -n default
```

### VRF Metrics

The system exposes the following VRF-related metrics:

- `cilium_vrf_route_count`: Number of routes in each VRF
- `cilium_vrf_interface_count`: Number of interfaces associated with each VRF
- `cilium_vrf_drop_count`: Number of packets dropped due to VRF isolation policies
- `cilium_vrf_crossover_count`: Number of packets that crossed VRF boundaries

These metrics can be collected by Prometheus and visualized in Grafana dashboards.

## Integration with External Systems

### BGP Integration

To integrate VRFs with BGP routing, use the BGP configuration in the VRF CRD:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: VRF
metadata:
  name: external
  namespace: default
spec:
  # ... other configuration ...
  bgp:
    enabled: true
    localAS: 65001
    neighbors:
      - address: "192.168.1.1"
        remoteAS: 65002
    announcements:
      - "10.0.0.0/16"
```

### MPLS Integration

For MPLS VPN integration:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: VRF
metadata:
  name: mpls-vpn
  namespace: default
spec:
  # ... other configuration ...
  mpls:
    enabled: true
    label: 100
    exportRoutes: true
    importRoutes: true
```

## Troubleshooting VRFs

### Common VRF Issues

1. **Cross-VRF Communication Issues**:
   - Check isolation settings
   - Verify route leaking configuration
   - Ensure interfaces are assigned to the correct VRFs

2. **VRF Route Propagation Problems**:
   - Check routing tables for the specific VRF
   - Verify route redistribution settings
   - Check for conflicts in routing entries

3. **Interface Assignment Issues**:
   - Verify interface exists
   - Check for conflicting interface assignments
   - Validate MTU and other interface settings

### Debugging Commands

Debug VRF routing tables:

```bash
cilium vrf list
cilium vrf routes <vrf-name>
```

Check VRF interface assignments:

```bash
cilium vrf interfaces <vrf-name>
```

Trace packet path with VRF awareness:

```bash
cilium trace --src-vrf <vrf-name> --src <source-ip> --dst <destination-ip>
```

### Logging

Enable verbose logging for VRF-related operations:

```bash
kubectl patch configmap cilium-config -n kube-system --type merge -p '{"data":{"debug":"true","debug-verbose":"vrf,routing"}}'
```

This will increase log verbosity specifically for VRF and routing components.
