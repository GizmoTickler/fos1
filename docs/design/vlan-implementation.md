# VLAN Implementation Design

## Overview

This document describes the design for the VLAN implementation in the Kubernetes-based Router/Firewall system. The VLAN implementation will provide support for IEEE 802.1Q Virtual LANs, allowing logical network segmentation and traffic isolation.

## Goals

- Support VLAN interfaces on physical, bridge, and bond interfaces
- Enable VLAN trunking (multiple VLANs on a single interface)
- Configure MTU settings and QoS priorities for VLANs
- Manage VLANs through both CRDs and API calls
- Provide proper state reporting and error handling

## Non-Goals

- Support for Q-in-Q (802.1ad) double VLAN tagging
- Automatic VLAN provisioning
- Dynamic VLAN assignment

## Design Details

### VLAN Interface Management

#### VLAN Custom Resource Definition

VLANs will be managed through a `NetworkInterface` CRD with a type field set to `vlan`:

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: vlan-interface-100
spec:
  name: vlan100
  type: vlan
  parent: eth0  # The parent physical, bridge, or bond interface
  vlanId: 100   # Valid range: 1-4094
  addresses:
    - 192.168.100.1/24
    - 2001:db8:100::1/64
  mtu: 1500     # Optional, defaults to parent MTU - 4
  qos:
    priority: 3 # 802.1p priority (0-7)
    dscp: 46    # DSCP value for QoS marking
  state: up     # Desired state (up or down)
status:
  operationalState: up  # Current state (up, down, pending)
  actualMtu: 1496
  addresses:
    - 192.168.100.1/24
    - 2001:db8:100::1/64
  parent: eth0
  errorMessage: ""
```

#### API Interface

In addition to the CRD, a Go interface will be provided for programmatic management:

```go
type VLANManager interface {
    // CreateVLAN creates a new VLAN interface
    CreateVLAN(parent string, vlanID int, name string, config VLANConfig) (*VLANInterface, error)
    
    // DeleteVLAN removes a VLAN interface
    DeleteVLAN(name string) error
    
    // GetVLAN retrieves information about a VLAN interface
    GetVLAN(name string) (*VLANInterface, error)
    
    // ListVLANs returns all configured VLAN interfaces
    ListVLANs() ([]*VLANInterface, error)
    
    // UpdateVLAN modifies a VLAN interface configuration
    UpdateVLAN(name string, config VLANConfig) (*VLANInterface, error)
}

type VLANConfig struct {
    MTU        int
    Addresses  []string
    QoSPriority int
    DSCP       int
    State      string // "up" or "down"
}

type VLANInterface struct {
    Name            string
    Parent          string
    VLANID          int
    OperationalState string // "up", "down", "pending"
    Config          VLANConfig
    ActualMTU       int
    ErrorMessage    string
}
```

### VLAN Configuration Options

#### Naming Convention

VLAN interfaces will follow the `vlanXXX` naming pattern where XXX is the VLAN ID. For example, VLAN 100 on interface eth0 would be named `vlan100`. This naming is preferred for clarity and consistency.

#### MTU Settings

The MTU of a VLAN interface will default to the parent interface's MTU minus 4 bytes (to account for the VLAN header). The MTU can be explicitly configured if needed. The system will validate that the VLAN MTU does not exceed the parent MTU minus 4.

#### QoS Configuration

QoS for VLANs will support both:

1. 802.1p priorities (0-7) for Layer 2 QoS
2. DSCP markings for Layer 3 QoS

The CRD will include fields for both. The controller will configure:
- egress_qos_map for outgoing traffic
- ingress_qos_map for incoming traffic

#### Parent Interface Handling

When a VLAN is configured on a parent that doesn't exist, the system will:
1. Create the VLAN configuration
2. Set the operational state to "pending"
3. Wait for the parent interface to appear
4. Apply the configuration once the parent is available

If the parent interface disappears after the VLAN is created, the VLAN will be marked as "down" but not removed. It will be automatically brought back up when the parent reappears.

#### VLAN ID Validation

VLAN IDs will be validated against the standard range of 1-4094. No other restrictions will be applied.

### VLAN Trunking

Any physical, bridge, or bond interface can function as a trunk by having multiple VLAN interfaces attached to it. The system will not have a specific "trunk" interface type. Instead, an interface becomes a trunk automatically when multiple VLANs are configured on it.

For bridge interfaces:
- VLAN filtering will be disabled by default, allowing all traffic to pass
- The bridge will pass VLAN tagged and untagged traffic without filtering

### Cilium Integration

The VLAN implementation will work with Cilium in transparent mode, where Cilium will operate on traffic within each VLAN as if it were a separate network. The controller will:

1. Create the VLAN interfaces at the host level
2. Configure IP addressing for each VLAN
3. Allow Cilium to see each VLAN interface as a distinct network endpoint
4. Enable Cilium to apply network policies to traffic on specific VLANs

### Implementation Components

The VLAN implementation will consist of:

1. **VLAN Controller**: Watches for NetworkInterface CRDs with type "vlan" and manages the VLAN interfaces
2. **VLAN Manager**: Provides the implementation of the VLANManager interface
3. **VLAN Configurator**: Handles the actual netlink calls to create, delete, and configure VLAN interfaces
4. **VLAN Status Reporter**: Updates the status of VLAN interfaces in the CRD

```go
// High-level flowchart
CRD Controller -> VLAN Manager -> VLAN Configurator -> netlink
                                                     -> sysfs
                      ^                                  |
                      |                                  v
                 Status Reporter <----------------------
```

### State and Error Handling

VLAN interfaces will report their state as:
- "up": Interface is operational
- "down": Interface is administratively down
- "pending": Interface is waiting for parent to become available

Error conditions will be reported through:
- Status field in the CRD
- Error messages in logs
- Events in Kubernetes

### Performance Considerations

1. VLAN creation/deletion is relatively inexpensive but should be rate-limited to avoid overwhelming the system
2. MTU settings should be properly calculated to avoid fragmentation
3. QoS configurations should be applied efficiently to minimize overhead

### Monitoring and Metrics

The system will expose standard network interface metrics for each VLAN interface, including:
- Traffic statistics (bytes/packets in/out)
- Error counters
- Interface status

These metrics will be exposed via Prometheus integration.

## Example Configurations

### Basic VLAN Interface

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: vlan-100
spec:
  name: vlan100
  type: vlan
  parent: eth0
  vlanId: 100
  addresses:
    - 192.168.100.1/24
```

### VLAN with QoS Configuration

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: vlan-200-qos
spec:
  name: vlan200
  type: vlan
  parent: eth0
  vlanId: 200
  addresses:
    - 192.168.200.1/24
  qos:
    priority: 5  # Voice traffic
    dscp: 46     # EF (Expedited Forwarding)
```

### Multiple VLANs on a Bridge (Trunk)

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: bridge-0
spec:
  name: br0
  type: bridge
  interfaces:
    - eth0
    - eth1
---
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: vlan-100-on-bridge
spec:
  name: vlan100
  type: vlan
  parent: br0
  vlanId: 100
  addresses:
    - 192.168.100.1/24
---
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: vlan-200-on-bridge
spec:
  name: vlan200
  type: vlan
  parent: br0
  vlanId: 200
  addresses:
    - 192.168.200.1/24
```