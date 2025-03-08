# Policy-Based Routing Guide

This document provides detailed information on configuring and using Policy-Based Routing (PBR) in the Cilium-based networking system.

## Table of Contents

- [Introduction to Policy-Based Routing](#introduction-to-policy-based-routing)
- [How Policy-Based Routing Works](#how-policy-based-routing-works)
- [Policy Rule Structure](#policy-rule-structure)
- [Configuring Policy Rules](#configuring-policy-rules)
  - [Basic Policy Rules](#basic-policy-rules)
  - [Advanced Policy Rules](#advanced-policy-rules)
- [Routing Tables](#routing-tables)
- [Common Use Cases](#common-use-cases)
  - [Multi-ISP Connectivity](#multi-isp-connectivity)
  - [Quality of Service](#quality-of-service)
  - [Traffic Engineering](#traffic-engineering)
  - [Security Segregation](#security-segregation)
- [Integration with VRFs](#integration-with-vrfs)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Introduction to Policy-Based Routing

Policy-Based Routing (PBR) allows network traffic to be routed based on policies other than the destination address. This enables more flexible routing decisions based on criteria such as:

- Source IP address or subnet
- Input interface
- Protocol type
- Packet size
- Any combination of these factors

With PBR, you can implement sophisticated traffic management and traffic engineering solutions that would not be possible with traditional destination-based routing.

## How Policy-Based Routing Works

In our Cilium-based implementation, PBR works through the following process:

1. **Policy Rule Evaluation**: When a packet enters the system, it is evaluated against policy rules in order of priority (lower values have higher priority).

2. **Rule Matching**: If a packet matches a policy rule, the rule directs the packet to a specific routing table.

3. **Route Lookup**: The routing table contains routes that determine the next-hop for the packet.

4. **Table Selection**: If no policy rule matches, the packet uses the default routing table (usually the main table).

This mechanism leverages Linux's policy routing framework and extends it through Cilium's eBPF implementation for better performance and scalability.

## Policy Rule Structure

A policy rule consists of the following components:

- **Priority**: A numeric value defining the order of rule evaluation (lower values are processed first)
- **Table**: The routing table to use if the rule matches
- **Match Criteria**: What traffic should match the rule
  - Source IP address/prefix
  - Destination IP address/prefix
  - Input interface
  - Output interface
  - Other criteria specific to your implementation

## Configuring Policy Rules

### Basic Policy Rules

To create a basic policy rule using Kubernetes CRDs, apply the following manifest:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: PolicyRule
metadata:
  name: route-by-source
  namespace: default
spec:
  priority: 100
  table: 100
  sourceIP: "192.168.1.0/24"
```

This rule directs all traffic from the 192.168.1.0/24 subnet to routing table 100.

### Advanced Policy Rules

For more complex rules, you can specify multiple match criteria:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: PolicyRule
metadata:
  name: complex-rule
  namespace: default
spec:
  priority: 50
  table: 200
  sourceIP: "10.1.0.0/24"
  destinationIP: "10.2.0.0/24"
  inputInterface: "eth1"
  protocol: "tcp"
  ports:
    - 80
    - 443
  tos: 0x10
  mark: 0x1
```

This rule matches TCP traffic from 10.1.0.0/24 to 10.2.0.0/24 coming in through eth1 on ports 80 or 443, and routes it according to table 200.

## Routing Tables

Each policy rule directs matching traffic to a specific routing table. The system supports the following routing tables:

- **Main Table (254)**: The default routing table
- **Local Table (255)**: Used for local and broadcast addresses
- **Custom Tables (1-252)**: Available for user-defined routes

To create a routing table for use with policy-based routing:

```yaml
apiVersion: networking.cilium.io/v1alpha1
kind: RoutingTable
metadata:
  name: isp1-routes
  namespace: default
spec:
  id: 100
  routes:
    - destination: "0.0.0.0/0"
      gateway: "203.0.113.1"
      interface: "eth1"
    - destination: "10.0.0.0/8"
      gateway: "10.0.0.1"
      interface: "eth0"
```

## Common Use Cases

### Multi-ISP Connectivity

One of the most common use cases for PBR is managing traffic across multiple Internet Service Providers:

```yaml
# Route traffic from the engineering department through ISP 1
apiVersion: networking.cilium.io/v1alpha1
kind: PolicyRule
metadata:
  name: engineering-traffic
  namespace: default
spec:
  priority: 100
  table: 100  # ISP 1 routing table
  sourceIP: "10.1.0.0/24"  # Engineering department subnet

---
# Route traffic from the marketing department through ISP 2
apiVersion: networking.cilium.io/v1alpha1
kind: PolicyRule
metadata:
  name: marketing-traffic
  namespace: default
spec:
  priority: 100
  table: 200  # ISP 2 routing table
  sourceIP: "10.2.0.0/24"  # Marketing department subnet
```

### Quality of Service

PBR can be used to implement Quality of Service (QoS) by routing different types of traffic through different paths:

```yaml
# Route real-time traffic (VoIP, video conferencing) through a low-latency path
apiVersion: networking.cilium.io/v1alpha1
kind: PolicyRule
metadata:
  name: realtime-traffic
  namespace: default
spec:
  priority: 50
  table: 100  # Low-latency path
  tос: 0x10   # DSCP value for Expedited Forwarding
```

### Traffic Engineering

Direct traffic based on application or service requirements:

```yaml
# Route backup traffic through a high-bandwidth, non-critical path
apiVersion: networking.cilium.io/v1alpha1
kind: PolicyRule
metadata:
  name: backup-traffic
  namespace: default
spec:
  priority: 200
  table: 300  # High-bandwidth path
  destinationIP: "10.5.0.0/24"  # Backup servers
```

### Security Segregation

PBR can help implement security policies:

```yaml
# Route all traffic from guest network through security inspection
apiVersion: networking.cilium.io/v1alpha1
kind: PolicyRule
metadata:
  name: guest-traffic
  namespace: default
spec:
  priority: 10  # High priority for security
  table: 400    # Table with routes going through security appliances
  sourceIP: "10.10.0.0/24"  # Guest network
```

## Integration with VRFs

Policy-based routing can be integrated with VRFs for even more granular control:

```yaml
# Policy rule within a specific VRF
apiVersion: networking.cilium.io/v1alpha1
kind: PolicyRule
metadata:
  name: vrf-specific-rule
  namespace: default
spec:
  priority: 100
  table: 100
  sourceIP: "192.168.1.0/24"
  vrf: "red"  # This rule applies only in the "red" VRF
```

This allows you to have different policy-based routing behaviors in different VRFs, which is crucial for multi-tenant environments.

## Best Practices

1. **Use Meaningful Priorities**:
   - Use priority ranges for different types of policies (e.g., 10-99 for security, 100-199 for QoS)
   - Leave gaps between priorities to allow for future insertions

2. **Document Your Routing Tables**:
   - Keep clear documentation of what each routing table is used for
   - Use consistent table IDs across your infrastructure

3. **Verify Rule Ordering**:
   - Remember that rules are evaluated in order of priority
   - Test rule interactions to ensure the expected behavior

4. **Avoid Too Many Rules**:
   - Keep the number of rules manageable
   - Combine rules where possible to improve performance

5. **Default Routes**:
   - Always have a default route in each routing table
   - Consider what happens if no rule matches

## Troubleshooting

### Common Issues

1. **Rules Not Being Applied**:
   - Check rule priorities to ensure they are being evaluated in the correct order
   - Verify that the matching criteria are correct
   - Check for syntax errors in the rule definition

2. **Unexpected Routing Behavior**:
   - Trace the packet path using debugging tools
   - Check all matching rules to see which one is being applied
   - Verify the contents of the routing table being used

3. **Performance Issues**:
   - Too many complex rules can impact performance
   - Consider consolidating rules where possible
   - Use more specific match criteria to reduce evaluation time

### Debugging Commands

List all policy rules:

```bash
cilium policy-route list
```

Test which rule matches a specific packet:

```bash
cilium policy-route match --src 10.1.0.5 --dst 8.8.8.8
```

View the routing table for a specific rule:

```bash
cilium route table show 100
```

Trace a packet's path through the policy-based routing system:

```bash
cilium trace --from-source 10.1.0.5 --to-destination 8.8.8.8
```

This will show the complete path, including which policy rule matched and which routing table was used.
