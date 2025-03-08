# eBPF Programs Management Using CRDs

This guide explains how to create, configure, and manage eBPF programs in the FOS1 platform using Kubernetes Custom Resource Definitions (CRDs).

## Table of Contents

- [Overview](#overview)
- [Available CRDs](#available-crds)
- [Getting Started](#getting-started)
- [EBPFProgram Resource](#ebpfprogram-resource)
- [EBPFMap Resource](#ebpfmap-resource)
- [EBPFNetworkPolicy Resource](#ebpfnetworkpolicy-resource)
- [EBPFTrafficControl Resource](#ebpftrafficcontrol-resource)
- [EBPFNATPolicy Resource](#ebpfnatpolicy-resource)
- [EBPFContainerPolicy Resource](#ebpfcontainerpolicy-resource)
- [Common Use Cases](#common-use-cases)
- [Troubleshooting](#troubleshooting)

## Overview

FOS1 leverages eBPF (extended Berkeley Packet Filter) technology to provide high-performance, programmable networking capabilities. eBPF programs run in the kernel and can intercept and modify network traffic, collect metrics, and implement complex networking features with minimal overhead.

Rather than requiring you to write eBPF code directly, FOS1 provides a set of CRDs that abstract the underlying eBPF implementation. These CRDs allow you to declare the desired behavior in a Kubernetes-native way, and the system will automatically translate these declarations into optimized eBPF programs.

## Available CRDs

FOS1 provides the following CRDs for managing eBPF-based functionality:

1. **EBPFProgram** - Defines an eBPF program to be loaded into the kernel
2. **EBPFMap** - Defines a data structure shared between kernel and user space
3. **EBPFNetworkPolicy** - Defines network access control and routing policies
4. **EBPFTrafficControl** - Defines QoS and traffic shaping rules
5. **EBPFNATPolicy** - Defines Network Address Translation policies
6. **EBPFContainerPolicy** - Defines network policies for containers/pods

## Getting Started

To use the eBPF CRDs, ensure you have:

1. A running Kubernetes cluster with the FOS1 components installed
2. The `kubectl` command-line tool configured to communicate with your cluster
3. Administrative access to create and manage custom resources

You can deploy the CRDs by applying the base Kustomize configuration:

```bash
kubectl apply -k manifests/base/ebpf
```

## EBPFProgram Resource

The `EBPFProgram` resource defines an eBPF program that will be loaded into the kernel. FOS1 supports several types of eBPF programs, each attaching to different kernel hooks.

### Program Types

- **xdp** - XDP (eXpress Data Path) programs that run at the earliest possible point in the network stack
- **tc-ingress** - Traffic Control programs for ingress traffic (after XDP but before the network stack)
- **tc-egress** - Traffic Control programs for egress traffic (after the network stack but before transmission)
- **sockops** - Socket operations programs for monitoring and optimizing socket operations
- **cgroup** - Programs attached to cgroups for container-level policies

### Example: XDP Packet Filtering Program

```yaml
apiVersion: networking.fos1.io/v1alpha1
kind: EBPFProgram
metadata:
  name: xdp-packet-filter
  namespace: default
spec:
  description: "XDP program for packet filtering and DDoS protection"
  type: xdp
  interface: eth0
  settings:
    rateLimiting:
      enabled: true
      packetsPerSecond: 10000
    blacklist:
      enabled: true
      ips:
        - "192.168.1.100"
        - "10.10.10.0/24"
    stateful: true
```

### Monitoring Program Status

Check the status of your eBPF program:

```bash
kubectl get ebpfprograms
kubectl describe ebpfprogram xdp-packet-filter
```

The status section will show whether the program was successfully loaded and any relevant metrics.

## EBPFMap Resource

The `EBPFMap` resource defines a data structure shared between the kernel (eBPF programs) and user space. Maps store data that can be accessed and modified by eBPF programs and user-space applications.

### Map Types

- **hash** - Hash table with key/value pairs
- **array** - Simple array indexed by integers
- **lru_hash** - Least-Recently-Used hash table that automatically evicts old entries
- **lpm_trie** - Longest Prefix Match trie, ideal for IP matching
- **percpu_hash/percpu_array** - Per-CPU variants that avoid contention
- **ringbuf** - Ring buffer for efficient data sharing
- **perf_event_array** - For sending events from kernel to user space

### Example: Blacklist Map

```yaml
apiVersion: networking.fos1.io/v1alpha1
kind: EBPFMap
metadata:
  name: blacklist-map
  namespace: default
spec:
  description: "Map for storing blacklisted IP addresses"
  type: lpm_trie
  maxEntries: 1024
  keySize: 8  # IPv4 prefix in trie format
  valueSize: 4  # Action value
  pinPath: "/sys/fs/bpf/blacklist"
  accessedBy:
    - "xdp-packet-filter"
  initData:
    - key: "0x0a0a0a00/24"  # 10.10.10.0/24 in hex
      value: "0x00000001"   # Block action code
```

## EBPFNetworkPolicy Resource

The `EBPFNetworkPolicy` resource defines network access control rules similar to Kubernetes NetworkPolicy but with extended functionality. It can filter traffic based on various criteria and apply actions like allowing, denying, logging, or marking packets.

### Example: API Server Protection Policy

```yaml
apiVersion: networking.fos1.io/v1alpha1
kind: EBPFNetworkPolicy
metadata:
  name: api-server-protection
  namespace: default
spec:
  description: "Network policy to protect API server"
  policyType: filtering
  priority: 100
  selector:
    podSelector:
      matchLabels:
        app: api-server
  ingress:
    - description: "Allow incoming HTTPS traffic"
      ports:
        - protocol: TCP
          port: 443
      action: allow
    - description: "Rate limit incoming API requests"
      ports:
        - protocol: TCP
          port: 8080
      action: allow
      rateLimit:
        bitsPerSecond: 1000000  # 1Mbps
        burstSize: 32768  # 32KB burst
  egress:
    - description: "Allow outgoing DB traffic"
      to:
        - ipBlock:
            cidr: "10.0.0.0/8"
      ports:
        - protocol: TCP
          port: 5432
      action: allow
    - description: "Default deny all other outgoing traffic"
      action: deny
```

## EBPFTrafficControl Resource

The `EBPFTrafficControl` resource defines Quality of Service (QoS) and traffic shaping rules. It can be used to prioritize certain types of traffic, limit bandwidth, and enforce fair sharing of network resources.

### Example: Egress QoS Policy

```yaml
apiVersion: networking.fos1.io/v1alpha1
kind: EBPFTrafficControl
metadata:
  name: egress-quality-of-service
  namespace: default
spec:
  description: "QoS policy for egress traffic"
  interface: eth0
  direction: egress
  queueingDiscipline:
    type: htb
    rate: "1Gbit"
    burst: "15kb"
  filters:
    - description: "Prioritize VoIP traffic"
      priority: 10
      protocol: udp
      match:
        dstPort: "5060-5080"
      action:
        type: mark
        mark: 46  # DSCP EF (Expedited Forwarding)
      classID: 10
    - description: "Limit video streaming"
      priority: 20
      match:
        dstPort: 443
      action:
        type: police
        police:
          rate: "5Mbit"
          burst: "50kb"
          exceed: "drop"
  classes:
    - id: 10
      rate: "100Mbit"
      priority: 1
      burst: "15kb"
    - id: 20
      rate: "10Mbit"
      priority: 2
      burst: "50kb"
```

## EBPFNATPolicy Resource

The `EBPFNATPolicy` resource defines Network Address Translation policies. It supports Source NAT (SNAT), Destination NAT (DNAT), and Masquerading to enable scenarios like load balancing, port forwarding, and internet access sharing.

### Example: Outbound NAT (Masquerading)

```yaml
apiVersion: networking.fos1.io/v1alpha1
kind: EBPFNATPolicy
metadata:
  name: outbound-nat
  namespace: default
spec:
  description: "NAT policy for outbound traffic"
  type: masquerade
  interface: eth0
  sourceAddresses:
    - "10.0.0.0/8"
  enableTracking: true
```

### Example: Port Forwarding (DNAT)

```yaml
apiVersion: networking.fos1.io/v1alpha1
kind: EBPFNATPolicy
metadata:
  name: web-server-dnat
  namespace: default
spec:
  description: "DNAT policy for web servers"
  type: dnat
  interface: eth0
  externalIP: "203.0.113.10"
  portMappings:
    - protocol: tcp
      externalPort: 80
      internalIP: "10.0.0.10"
      internalPort: 8080
      description: "HTTP traffic to web server"
    - protocol: tcp
      externalPort: 443
      internalIP: "10.0.0.10"
      internalPort: 8443
      description: "HTTPS traffic to web server"
```

## EBPFContainerPolicy Resource

The `EBPFContainerPolicy` resource defines network policies specifically for containers/pods. It provides granular control over container network access, resource usage limits, and monitoring.

### Example: Database Container Policy

```yaml
apiVersion: networking.fos1.io/v1alpha1
kind: EBPFContainerPolicy
metadata:
  name: database-network-policy
  namespace: default
spec:
  description: "Network policy for database containers"
  selector:
    podSelector:
      matchLabels:
        app: database
  resourceLimits:
    enableAccounting: true
    bandwidthLimits:
      egressBitsPerSecond: 100000000  # 100Mbps
      ingressBitsPerSecond: 200000000  # 200Mbps
    connectionLimits:
      maxConnections: 100
  networkControls:
    enableEgressControl: true
    enableIngressControl: true
    defaultEgressAction: deny
    defaultIngressAction: deny
    ingressRules:
      - description: "Allow database client connections"
        ports:
          - protocol: TCP
            port: 5432
        action: allow
    egressRules:
      - description: "Allow DNS lookups"
        ports:
          - protocol: UDP
            port: 53
        action: allow
      - description: "Allow NTP"
        ports:
          - protocol: UDP
            port: 123
        action: allow
```

## Common Use Cases

### DDoS Protection

To implement DDoS protection, combine an XDP-type `EBPFProgram` with an `EBPFMap` for storing blacklisted IP addresses:

1. Create an `EBPFMap` for the blacklist
2. Create an `EBPFProgram` of type `xdp` with rate limiting and blacklist settings
3. Reference the map in the program

### Traffic Shaping and QoS

To prioritize certain types of traffic:

1. Create an `EBPFTrafficControl` resource
2. Define classes with different priorities and bandwidth allocations
3. Create filters to match and classify traffic

### Secure Pod Networking

To implement secure networking for pods:

1. Create an `EBPFContainerPolicy` resource
2. Define the selector to target specific pods
3. Configure ingress and egress rules
4. Set appropriate resource limits

## Troubleshooting

### Checking Resource Status

All eBPF CRDs include a status field that provides information about the current state:

```bash
kubectl get ebpfprograms -o wide
kubectl describe ebpfprogram <name>
```

### Common Issues

1. **Program failed to load**
   - Check kernel compatibility
   - Verify that the interface exists and is up
   - Check for syntax errors in the CRD definition

2. **Map creation failed**
   - Verify the map type is supported
   - Check if the keySize and valueSize are appropriate
   - Ensure the pinPath is accessible

3. **Policy not applying**
   - Check if the selectors match the intended targets
   - Verify priority values (lower values have higher priority)
   - Look for conflicting policies

### Viewing Logs

Check the logs of the eBPF controller:

```bash
kubectl logs -n kube-system -l app=fos1-ebpf-controller
```

### Getting Support

If you encounter issues that you cannot resolve, please:

1. Gather the output of `kubectl describe` for the relevant resources
2. Collect logs from the eBPF controller
3. Contact the FOS1 support team with this information

## Conclusion

The eBPF CRDs in FOS1 provide a powerful and flexible way to implement advanced networking features using a declarative, Kubernetes-native approach. By abstracting the complexity of eBPF programming, these CRDs allow you to focus on defining the desired behavior rather than low-level implementation details.

For more advanced use cases or custom eBPF program development, refer to the [eBPF Implementation Guide](/docs/design/ebpf-implementation.md).
