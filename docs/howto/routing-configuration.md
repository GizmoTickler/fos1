# Routing Configuration Guide

This guide provides comprehensive information on configuring routing in the Cilium-based networking system. It covers the creation and management of routes, Virtual Routing and Forwarding (VRF) instances, and policy-based routing.

## Table of Contents

- [Route Configuration](#route-configuration)
  - [Route CRD Specification](#route-crd-specification)
  - [Creating Routes](#creating-routes)
  - [Updating Routes](#updating-routes)
  - [Deleting Routes](#deleting-routes)
- [VRF Configuration](#vrf-configuration)
  - [VRF Basics](#vrf-basics)
  - [Creating VRFs](#creating-vrfs)
  - [Adding Routes to VRFs](#adding-routes-to-vrfs)
  - [Deleting VRFs](#deleting-vrfs)
- [Policy-Based Routing](#policy-based-routing)
  - [Creating Policy Rules](#creating-policy-rules)
  - [Routing Tables](#routing-tables)
  - [Deleting Policy Rules](#deleting-policy-rules)
- [Integration with Cilium](#integration-with-cilium)
  - [eBPF Maps](#ebpf-maps)
  - [Route Synchronization](#route-synchronization)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Debugging Tools](#debugging-tools)

## Route Configuration

Routes are defined using Kubernetes Custom Resource Definitions (CRDs). The routing controller watches for changes to Route CRDs and synchronizes them with Cilium's eBPF maps.

### Route CRD Specification

A Route CRD is defined with the following specification:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: Route
metadata:
  name: example-route
  namespace: default
spec:
  destination: "10.0.0.0/24"  # Required: The destination CIDR
  gateway: "192.168.1.1"      # Optional: The next-hop gateway IP
  interface: "eth0"           # Optional: The output interface
  metric: 100                 # Optional: The route's priority/metric (default: 100)
  table: "main"               # Optional: The routing table (default: main table)
  vrf: "red"                  # Optional: The VRF name
  type: "static"              # Optional: Route type (static, dynamic, policy)
```

### Creating Routes

To create a route, apply a Route CRD manifest:

```bash
kubectl apply -f route.yaml
```

The routing controller will detect the new Route CRD and synchronize it with Cilium.

### Updating Routes

To update a route, modify your Route CRD manifest and apply it:

```bash
kubectl apply -f updated-route.yaml
```

The routing controller will detect the changes and update the route accordingly.

### Deleting Routes

To delete a route, delete the Route CRD:

```bash
kubectl delete route example-route -n default
```

The routing controller will detect the deletion and remove the route from Cilium.

## VRF Configuration

Virtual Routing and Forwarding (VRF) instances provide network virtualization by creating multiple routing tables that can coexist on the same physical infrastructure.

### VRF Basics

A VRF consists of:
- A unique identifier (ID)
- A name for easier reference
- A set of routing tables
- A set of network interfaces

Each VRF maintains its own routing table, allowing for overlapping IP address spaces across different VRFs.

### Creating VRFs

VRFs can be created using the Router API:

```go
vrfID, err := router.AddVRF("red", []int{100}, []string{"eth1"})
if err != nil {
    // Handle error
}
```

Alternatively, you can create VRFs using a VRF CRD:

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

### Adding Routes to VRFs

Routes can be added to a specific VRF by setting the `vrf` field in the Route CRD:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: Route
metadata:
  name: vrf-route
  namespace: default
spec:
  destination: "10.1.0.0/24"
  gateway: "192.168.1.2"
  interface: "eth1"
  vrf: "red"
  table: "100"
```

### Deleting VRFs

To delete a VRF using the Router API:

```go
err := router.DeleteVRF(vrfID)
if err != nil {
    // Handle error
}
```

Or by deleting the VRF CRD:

```bash
kubectl delete vrf red -n default
```

## Policy-Based Routing

Policy-Based Routing (PBR) allows routing decisions based on criteria other than the destination address, such as source address, incoming interface, or other packet attributes.

### Creating Policy Rules

Policy rules can be created using the Router API:

```go
rule := PolicyRule{
    Priority:       100,
    Table:          100,
    SourceIP:       sourceNet,  // *net.IPNet
    DestinationIP:  destNet,    // *net.IPNet
    InputInterface: "eth1",
}
err := router.AddPolicyRule(rule)
if err != nil {
    // Handle error
}
```

Alternatively, you can create policy rules using a PolicyRule CRD:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: PolicyRule
metadata:
  name: example-rule
  namespace: default
spec:
  priority: 100
  table: 100
  sourceIP: "192.168.1.0/24"
  destinationIP: "10.0.0.0/24"
  inputInterface: "eth1"
```

### Routing Tables

Each policy rule refers to a routing table. The system supports multiple routing tables, including:

- `main` (table ID 254): The default routing table
- `local` (table ID 255): Reserved for local routes
- Custom tables (table IDs 1-252): Available for user-defined routes

### Deleting Policy Rules

To delete a policy rule using the Router API:

```go
err := router.DeletePolicyRule(priority)
if err != nil {
    // Handle error
}
```

Or by deleting the PolicyRule CRD:

```bash
kubectl delete policyrule example-rule -n default
```

## Integration with Cilium

### eBPF Maps

Cilium uses eBPF maps to implement routing functionality. The routing controller synchronizes routes with these eBPF maps.

The key eBPF maps for routing include:
- `cilium_lxc`: Maps endpoints to their IP addresses
- `cilium_lb4_services_v2`: IPv4 load balancing services
- `cilium_lb6_services_v2`: IPv6 load balancing services
- `cilium_ipcache`: IP address to identity mapping

### Route Synchronization

The route synchronizer ensures that routes are properly synchronized between kernel routing tables and Cilium's eBPF maps. This synchronization happens:

- When routes are created, updated, or deleted through the Route CRDs
- Periodically to ensure consistency

## Troubleshooting

### Common Issues

1. **Routes not taking effect:**
   - Check that the Route CRD is correctly defined
   - Verify that the destination CIDR is valid
   - Check for conflicting routes in the same VRF

2. **VRF issues:**
   - Ensure that the VRF exists
   - Verify that the interfaces are correctly assigned to the VRF
   - Check that the routing tables are properly configured

3. **Policy-based routing not working:**
   - Verify the priority of the policy rule
   - Check that the routing table referenced by the rule exists
   - Ensure that the source and destination IP addresses are correctly specified

### Debugging Tools

Use these commands to debug routing issues:

1. **Check CRDs:**
   ```bash
   kubectl get routes -A
   kubectl get vrfs -A
   kubectl get policyrules -A
   ```

2. **Describe a specific resource:**
   ```bash
   kubectl describe route example-route -n default
   ```

3. **Check Cilium status:**
   ```bash
   cilium status
   ```

4. **Check Cilium eBPF maps:**
   ```bash
   cilium bpf routes list
   ```

5. **Check controller logs:**
   ```bash
   kubectl logs -n kube-system -l app=cilium -c cilium-agent
   ```
