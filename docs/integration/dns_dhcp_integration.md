# DNS and DHCP Integration

## Overview

This document outlines the integration between the DNS and DHCP subsystems in the FOS1 project. The integration ensures that DNS records are automatically created, updated, and removed based on DHCP lease events.

## Architecture

The integration is structured around the following components:

1. **DHCP Manager**: Coordinates DHCP services and lease management
2. **DNS Manager**: Coordinates DNS services and record management
3. **DNS Connector**: Provides the integration between DHCP and DNS subsystems

![DNS-DHCP Integration](../images/dns-dhcp-integration.png)

## Components Implemented

### Custom Resource Definitions (CRDs)

#### DNS CRDs
- **DNSFilterList**: For managing DNS filtering rules and custom lists
- **DNSClient**: For client-specific DNS configurations and filtering
- **PTRZone**: For managing reverse DNS lookups and associated records

#### DHCP CRDs
- **DHCPv4Service**: For managing DHCPv4 services, subnets, and options
- **DHCPv6Service**: For managing DHCPv6 services, subnets, and options

### Controllers

- **CoreDNS Controller**: Manages standard DNS zones and records
- **AdGuard Controller**: Provides DNS filtering capabilities
- **mDNS Controller**: Enables multicast DNS reflection

### Integration Components

- **DNS Connector**: Links DHCP lease events to DNS record management

## Integration Flow

### Lease Creation and DNS Record Creation

1. DHCP server assigns a lease to a client
2. DHCP manager detects the lease event
3. DHCP manager calls DNS connector's `UpdateLease` method
4. DNS connector calls DNS manager to create forward and reverse records
5. DNS manager updates the appropriate DNS zones via the CoreDNS controller

### Lease Renewal

1. DHCP server renews a client lease
2. DHCP manager detects the renewal event
3. DHCP manager calls DNS connector's `UpdateLease` method
4. DNS connector calls DNS manager to update TTL values if needed

### Lease Expiration and DNS Record Removal

1. DHCP lease expires
2. DNS connector's scheduled task triggers at expiration time
3. DNS connector calls DNS manager to remove forward and reverse records
4. DNS manager updates the appropriate DNS zones via the CoreDNS controller

## Testing

### Unit Tests

#### DNS Manager Tests
- Test adding DNS records
- Test removing DNS records
- Test adding reverse records
- Test removing reverse records

#### CoreDNS Controller Tests
- Test zone file manipulation
- Test zone synchronization
- Test DNS record management

#### DNS Connector Tests
- Test lease update handling
- Test lease removal handling
- Test scheduled lease removal

### Integration Tests

- Test end-to-end lease creation and DNS record creation
- Test end-to-end lease expiration and DNS record removal
- Test handling of multiple simultaneous leases
- Test error handling and recovery

## Deployment

The DNS and DHCP components are deployed as part of the network management stack in Kubernetes:

```bash
kubectl apply -k manifests/base/dns
kubectl apply -k manifests/base/dhcp
```

## Configuration Examples

### DNS Zone Example

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: DNSZone
metadata:
  name: example-zone
spec:
  domain: example.com
  ttl: 3600
  records:
    - name: www
      type: A
      value: 192.168.1.10
```

### DHCPv4 Service Example

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
  dnsupdates:
    enabled: true
    domain: example.local
```

## Completed Work

1. Created DNS CRDs:
   - DNSFilterList
   - DNSClient
   - PTRZone

2. Implemented controllers:
   - CoreDNS Controller
   - AdGuard Controller
   - mDNS Controller

3. Created unit tests:
   - DNS Manager tests
   - CoreDNS Controller tests
   - DNS Connector tests

4. Created example manifests:
   - DNS CRD examples
   - DHCP configuration examples

5. Created documentation:
   - DNS subsystem documentation
   - DHCP subsystem documentation
   - Integration documentation

## Next Steps

1. **Complete Kubernetes Client Libraries**:
   - Generate client code for the CRDs
   - Implement informers and listers

2. **Finalize Integration Tests**:
   - Set up test environment with DNS and DHCP components
   - Implement end-to-end tests

3. **Implement Monitoring**:
   - Add metrics collection for DNS records
   - Add metrics collection for DHCP leases
   - Create dashboards for DNS-DHCP integration monitoring

4. **Implement High Availability**:
   - Set up redundant DNS servers with synchronized zones
   - Set up DHCP failover configuration

5. **Create Operator Documentation**:
   - Write detailed operational guides
   - Create troubleshooting documentation

## Conclusion

The DNS and DHCP integration provides a robust foundation for network management. By automatically synchronizing DNS records with DHCP leases, network administrators can ensure that DNS always reflects the current state of the network.
