# DHCP Subsystem

## Overview

The DHCP Subsystem provides dynamic host configuration services for both IPv4 and IPv6 networks. It's designed to integrate seamlessly with the DNS subsystem for automatic DNS record management based on DHCP leases.

## Architecture

The DHCP subsystem consists of the following core components:

1. **DHCP Manager**: Central coordinator for all DHCP services
2. **Kea Controller**: Manages the ISC Kea DHCP server
3. **DNS Connector**: Integrates with the DNS subsystem
4. **Lease Database**: Stores and manages lease information

![DHCP Architecture](../images/dhcp-architecture.png)

## Features

- DHCPv4 and DHCPv6 server functionality
- Subnet and pool configuration
- Reservation management
- Option configuration
- High availability
- Dynamic DNS integration
- Lease tracking and management
- Client classification
- Kubernetes-native deployment

## Custom Resources

The DHCP subsystem defines the following Custom Resource Definitions (CRDs):

### DHCPv4Service

Defines a DHCPv4 service with subnets, pools, and options.

```yaml
apiVersion: dhcp.fos1.io/v1alpha1
kind: DHCPv4Service
metadata:
  name: main-network
spec:
  subnets:
    - subnet: 192.168.1.0/24
      pools:
        - start: 192.168.1.100
          end: 192.168.1.200
      options:
        - name: routers
          value: 192.168.1.1
        - name: domain-name-servers
          value: 192.168.1.1, 8.8.8.8
  reservations:
    - identifier-type: hw-address
      identifier: 00:11:22:33:44:55
      ip-address: 192.168.1.50
      hostname: reserved-host
  dnsupdates:
    enabled: true
    domain: example.local
```

### DHCPv6Service

Defines a DHCPv6 service with subnets, pools, and options.

```yaml
apiVersion: dhcp.fos1.io/v1alpha1
kind: DHCPv6Service
metadata:
  name: ipv6-network
spec:
  subnets:
    - subnet: 2001:db8::/64
      pools:
        - start: 2001:db8::100
          end: 2001:db8::200
      options:
        - name: dns-servers
          value: 2001:db8::1, 2001:4860:4860::8888
  reservations:
    - identifier-type: duid
      identifier: 00:03:00:01:00:11:22:33:44:55
      ip-addresses:
        - 2001:db8::50
      hostname: reserved-host-v6
  dnsupdates:
    enabled: true
    domain: example.local
```

## Installation

### Prerequisites

- Kubernetes cluster
- kubectl
- kustomize

### Deploy DHCP Components

```bash
kubectl apply -k manifests/base/dhcp
```

## Configuration

### DHCPv4 Configuration

The DHCP controller supports a wide range of DHCPv4 options and configurations:

```yaml
options:
  - name: routers
    value: 192.168.1.1
  - name: domain-name-servers
    value: 192.168.1.1, 8.8.8.8
  - name: domain-name
    value: example.local
  - name: domain-search
    value: example.local, example.com
  - name: ntp-servers
    value: 192.168.1.1, 0.pool.ntp.org
  - name: time-offset
    value: -18000
```

### DHCPv6 Configuration

The DHCP controller supports DHCPv6-specific options:

```yaml
options:
  - name: dns-servers
    value: 2001:db8::1, 2001:4860:4860::8888
  - name: domain-search
    value: example.local, example.com
  - name: sntp-servers
    value: 2001:db8::1, 2001:db8:0:1::123
```

### Reservations

You can create static reservations for specific clients:

```yaml
reservations:
  - identifier-type: hw-address
    identifier: 00:11:22:33:44:55
    ip-address: 192.168.1.50
    hostname: printer
    options:
      - name: default-time-to-live
        value: 7200
  - identifier-type: client-id
    identifier: 01:02:03:04:05:06
    ip-address: 192.168.1.51
    hostname: desktop
```

### DNS Updates

The DHCP subsystem can automatically update DNS records:

```yaml
dnsupdates:
  enabled: true
  domain: example.local
  reverseZones:
    - 1.168.192.in-addr.arpa
  ttl: 3600
  forwardUpdates: true
  reverseUpdates: true
```

## Integration with DNS

The DHCP subsystem integrates with the DNS subsystem through the DNS connector:

1. When a DHCP lease is assigned:
   - Forward (A/AAAA) records are created
   - Reverse (PTR) records are created

2. When a DHCP lease is renewed:
   - DNS record TTLs are updated

3. When a DHCP lease expires or is released:
   - Forward records are removed
   - Reverse records are removed

## API Reference

### DHCP Manager

| Method | Description |
|--------|-------------|
| `ConfigureService` | Configures a DHCP service based on CRD |
| `AddSubnet` | Adds a subnet to a DHCP service |
| `RemoveSubnet` | Removes a subnet from a DHCP service |
| `AddReservation` | Adds a reservation for a specific client |
| `RemoveReservation` | Removes a client reservation |
| `GetLease` | Gets information about a specific lease |
| `GetLeases` | Gets all active leases |
| `ReleaseLease` | Manually releases a lease |
| `Sync` | Forces a synchronization of DHCP configuration |
| `Status` | Returns the status of the DHCP service |

### Kea Controller

| Method | Description |
|--------|-------------|
| `Configure` | Applies a configuration to the Kea server |
| `AddSubnet` | Adds a subnet to the configuration |
| `RemoveSubnet` | Removes a subnet from the configuration |
| `AddReservation` | Adds a client reservation |
| `RemoveReservation` | Removes a client reservation |
| `GetLease` | Gets information about a specific lease |
| `GetLeases` | Gets all active leases |
| `ReleaseLease` | Manually releases a lease |
| `Restart` | Restarts the Kea server |
| `Status` | Returns the status of the Kea server |

### DNS Connector

| Method | Description |
|--------|-------------|
| `Initialize` | Initializes the DNS connector |
| `ProcessLeaseAdd` | Processes a lease addition event |
| `ProcessLeaseUpdate` | Processes a lease update event |
| `ProcessLeaseDelete` | Processes a lease deletion event |
| `AddForwardRecord` | Adds a forward DNS record |
| `AddReverseRecord` | Adds a reverse DNS record |
| `RemoveForwardRecord` | Removes a forward DNS record |
| `RemoveReverseRecord` | Removes a reverse DNS record |

## Troubleshooting

### Common Issues

#### DHCP Server Not Starting

1. Check if the DHCP pods are running:
   ```bash
   kubectl get pods -n dhcp-system
   ```

2. Check the DHCP manager logs:
   ```bash
   kubectl logs -n dhcp-system dhcp-manager-0
   ```

3. Verify the DHCP CRD is correctly defined:
   ```bash
   kubectl get dhcpv4service -A
   ```

#### DHCP Leases Not Being Assigned

1. Check the DHCP server logs:
   ```bash
   kubectl logs -n dhcp-system kea-dhcp4-0
   ```

2. Verify subnet and pool configuration:
   ```bash
   kubectl describe dhcpv4service -n dhcp-system main-network
   ```

3. Check for IP conflicts or exhausted pools:
   ```bash
   kubectl exec -it -n dhcp-system kea-dhcp4-0 -- keactrl leases
   ```

#### DNS Updates Not Working

1. Check the DNS connector logs:
   ```bash
   kubectl logs -n dhcp-system dhcp-manager-0 | grep dns-connector
   ```

2. Verify that DNS updates are enabled in the DHCP configuration:
   ```bash
   kubectl get dhcpv4service -o yaml
   ```

3. Check the DNS manager logs:
   ```bash
   kubectl logs -n dns-system dns-manager-0
   ```

## Example Use Cases

### Setting Up a DHCP Service for a LAN

1. Create a DHCPv4Service resource:
   ```yaml
   apiVersion: dhcp.fos1.io/v1alpha1
   kind: DHCPv4Service
   metadata:
     name: lan-network
   spec:
     subnets:
       - subnet: 192.168.1.0/24
         pools:
           - start: 192.168.1.50
             end: 192.168.1.200
         options:
           - name: routers
             value: 192.168.1.1
           - name: domain-name-servers
             value: 192.168.1.1, 8.8.8.8
           - name: domain-name
             value: home.lan
     dnsupdates:
       enabled: true
       domain: home.lan
   ```

### Configuring Multiple Subnets with Different Options

1. Create a DHCPv4Service resource with multiple subnets:
   ```yaml
   apiVersion: dhcp.fos1.io/v1alpha1
   kind: DHCPv4Service
   metadata:
     name: multi-network
   spec:
     subnets:
       - subnet: 192.168.1.0/24
         pools:
           - start: 192.168.1.50
             end: 192.168.1.200
         options:
           - name: routers
             value: 192.168.1.1
       - subnet: 10.0.0.0/24
         pools:
           - start: 10.0.0.50
             end: 10.0.0.200
         options:
           - name: routers
             value: 10.0.0.1
     dnsupdates:
       enabled: true
       domain: example.local
   ```

### Setting Up DHCP with Client Classification

1. Create a DHCPv4Service resource with client classes:
   ```yaml
   apiVersion: dhcp.fos1.io/v1alpha1
   kind: DHCPv4Service
   metadata:
     name: classified-network
   spec:
     clientClasses:
       - name: voip-devices
         test: option[60].text == 'VoIP'
       - name: printers
         test: substring(option[60].hex,0,6) == 'HP-Printer'
     subnets:
       - subnet: 192.168.1.0/24
         pools:
           - start: 192.168.1.50
             end: 192.168.1.150
             clientClass: default
           - start: 192.168.1.151
             end: 192.168.1.180
             clientClass: voip-devices
           - start: 192.168.1.181
             end: 192.168.1.200
             clientClass: printers
     options:
       - name: voip-servers
         value: 192.168.1.10
         clientClass: voip-devices
   ```

## References

- [ISC Kea Documentation](https://kb.isc.org/docs/kea-administrator-reference-manual)
- [DHCP Options Reference](https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml)
- [DHCPv6 Options Reference](https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml)
- [DDNS Integration Guide](https://kb.isc.org/docs/kea-administrator-reference-manual-d2-dhcp-ddns)
