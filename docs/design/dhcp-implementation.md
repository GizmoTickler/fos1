# DHCP Service Implementation Design

## Overview

This document outlines the design and implementation of the DHCP service for the Kubernetes-based router/firewall system. The service will provide DHCP functionality across multiple VLANs with tight integration to the DNS system.

## Design Goals

- Provide complete DHCP services for both IPv4 and IPv6
- Configure DHCP servers per VLAN with appropriate subnet and gateway configuration
- Support static IP reservations for specific devices
- Enable dynamic DNS updates based on DHCP leases
- Support configurable DHCP options per VLAN
- Ensure persistence of DHCP leases

## Architecture

### Components

1. **Kea DHCP Server**: The core DHCP engine providing the actual DHCP service.
2. **DHCP Controller**: A Kubernetes controller that translates CRDs to Kea configuration.
3. **DHCP-DNS Connector**: Component that sends lease information to the DNS system.
4. **Database**: PostgreSQL database for lease persistence (if supported by Kea).

### Deployment Model

- One Kea DHCP instance per VLAN, configured to listen on the gateway IP address
- Each instance runs as a separate pod in the Kubernetes cluster
- Controller monitors CRDs and reconfigures Kea instances as needed
- Configuration is driven entirely through Kubernetes CRDs

## Custom Resource Definitions

### DHCPv4Service

```yaml
apiVersion: network.fos.io/v1
kind: DHCPv4Service
metadata:
  name: vlan-10-dhcp
spec:
  vlanRef: vlan-10   # Reference to a VLAN CRD
  
  # DHCP settings
  leaseTime: 86400   # Default lease time in seconds (1 day)
  maxLeaseTime: 604800  # Maximum lease time in seconds (7 days)
  
  # Range of addresses to allocate dynamically
  range:
    start: 192.168.10.100
    end: 192.168.10.200
  
  # Domain name to provide to clients
  domain: vlan10.local
  
  # DHCP options to provide
  options:
    - code: 6    # DNS servers
      value: 192.168.10.1, 192.168.10.2
    - code: 42   # NTP servers
      value: 192.168.10.1
    # Additional options as needed
  
  # Static reservations
  reservations:
    - hostname: printer
      macAddress: 00:11:22:33:44:55
      ipAddress: 192.168.10.50
    - hostname: nas
      clientId: client-id-123
      ipAddress: 192.168.10.51
  
  # DNS integration
  dnsIntegration:
    enabled: true
    forwardUpdates: true
    reverseUpdates: true
    ttl: 3600
```

### DHCPv6Service

```yaml
apiVersion: network.fos.io/v1
kind: DHCPv6Service
metadata:
  name: vlan-10-dhcpv6
spec:
  vlanRef: vlan-10   # Reference to a VLAN CRD
  
  # DHCP settings
  leaseTime: 86400   # Default lease time in seconds (1 day)
  maxLeaseTime: 604800  # Maximum lease time in seconds (7 days)
  
  # Range of addresses to allocate dynamically
  range:
    start: 2001:db8:10::100
    end: 2001:db8:10::200
  
  # Domain name to provide to clients
  domain: vlan10.local
  
  # DHCP options to provide
  options:
    - code: 23    # DNS recursive servers
      value: 2001:db8:10::1, 2001:db8:10::2
    # Additional options as needed
  
  # Static reservations
  reservations:
    - hostname: printer
      duid: 00:03:00:01:00:11:22:33:44:55
      ipAddress: 2001:db8:10::50
    - hostname: nas
      hwAddress: 00:11:22:33:44:55
      ipAddress: 2001:db8:10::51
  
  # DNS integration
  dnsIntegration:
    enabled: true
    forwardUpdates: true
    reverseUpdates: true
    ttl: 3600
```

## Integration with VLANs and DNS

### VLAN Integration

- The DHCP service references VLAN CRDs to determine subnet information
- Gateway IP is automatically determined from the VLAN interface configuration
- DHCP server listens on the gateway IP for the VLAN

### DNS Integration

- When a DHCP lease is issued or renewed, DNS records are updated
- Forward DNS records are created for all clients with hostnames
- Reverse DNS records are created for all assigned IPs
- When leases expire, DNS records are automatically removed
- Domain suffixes are configurable per VLAN

## Implementation Components

### DHCP Controller

The controller watches for changes to DHCP CRDs and translates them into Kea configuration:

```go
package dhcp

import (
    "context"
    // Other imports
)

// Controller watches DHCP CRDs and manages Kea configuration
type Controller struct {
    client        kubernetes.Interface
    dhcpv4Lister  listers.DHCPv4ServiceLister
    dhcpv6Lister  listers.DHCPv6ServiceLister
    vlanLister    listers.VLANLister
    keaManager    *KeaManager
    dnsConnector  *DNSConnector
}

// Run starts the controller
func (c *Controller) Run(ctx context.Context) error {
    // Controller implementation
}

// syncDHCPv4Service syncs a DHCPv4Service CRD to Kea configuration
func (c *Controller) syncDHCPv4Service(key string) error {
    // Implementation details
}

// syncDHCPv6Service syncs a DHCPv6Service CRD to Kea configuration
func (c *Controller) syncDHCPv6Service(key string) error {
    // Implementation details
}
```

### Kea Manager

Manages Kea configuration and instances:

```go
package dhcp

// KeaManager handles the management of Kea DHCP server instances
type KeaManager struct {
    configDir  string
    keaCommand string
}

// UpdateConfig updates the Kea configuration file for a specific VLAN
func (m *KeaManager) UpdateConfig(vlanID string, config *KeaConfig) error {
    // Implementation details
}

// RestartService restarts the Kea service for a specific VLAN
func (m *KeaManager) RestartService(vlanID string) error {
    // Implementation details
}

// KeaConfig represents the configuration for a Kea DHCP server
type KeaConfig struct {
    // Configuration structure matching Kea's configuration format
}
```

### DNS Connector

Handles DNS updates based on DHCP leases:

```go
package dhcp

// DNSConnector manages the connection between DHCP and DNS
type DNSConnector struct {
    dnsManager dns.Manager
}

// UpdateLease updates DNS records for a DHCP lease
func (c *DNSConnector) UpdateLease(lease *Lease) error {
    // Implementation details
}

// RemoveLease removes DNS records for an expired DHCP lease
func (c *DNSConnector) RemoveLease(lease *Lease) error {
    // Implementation details
}

// Lease represents a DHCP lease
type Lease struct {
    IP        string
    Hostname  string
    MAC       string
    VLANRef   string
    ExpiresAt time.Time
    // Other lease details
}
```

## Database Design

If Kea supports PostgreSQL, we will configure it to use a PostgreSQL database for lease persistence. The database will be deployed as part of the Kubernetes setup and will store:

- Active DHCP leases
- Lease history
- Static reservations

## Testing and Validation

Testing will include:

1. Unit tests for the controller and connector components
2. Integration tests for DHCP-DNS integration
3. End-to-end tests with actual DHCP clients

## Deployment Considerations

- Each VLAN's DHCP server must be able to listen on the gateway IP for that VLAN
- Network configuration must allow DHCP broadcasts to reach the appropriate server
- Kea configuration must be properly persisted and backed up
- Database must be properly secured and backed up

## Implementation Plan

1. Create CRDs for DHCPv4Service and DHCPv6Service
2. Implement DHCP controller
3. Add Kea configuration generator
4. Develop DNS connector
5. Configure database integration
6. Create Kubernetes manifests for deployment
7. Implement monitoring and metrics
8. Write documentation and examples

## References

- [Kea DHCP Documentation](https://kea.readthedocs.io/)
- DNS Implementation Design (internal document)
- VLAN Implementation Design (internal document)