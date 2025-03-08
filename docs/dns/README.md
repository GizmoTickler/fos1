# DNS Subsystem

## Overview

The DNS Subsystem provides comprehensive DNS management capabilities, including forward and reverse DNS, filtering, and mDNS reflection. It integrates closely with the DHCP subsystem for automatic DNS record management based on DHCP leases.

## Architecture

The DNS subsystem consists of the following core components:

1. **DNS Manager**: Central coordinator for all DNS services
2. **CoreDNS Controller**: Manages standard DNS zones and records
3. **AdGuard Controller**: Provides DNS filtering capabilities
4. **mDNS Controller**: Enables multicast DNS reflection across networks

![DNS Architecture](../images/dns-architecture.png)

## Features

- Forward and reverse DNS zone management
- Dynamic DNS updates from DHCP
- DNS filtering and security
- Parental controls
- Client-specific filtering rules
- mDNS reflection for service discovery
- Metrics collection
- Kubernetes-native deployment

## Custom Resources

The DNS subsystem defines the following Custom Resource Definitions (CRDs):

### DNSZone

Defines a forward DNS zone with associated records.

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
    - name: mail
      type: A
      value: 192.168.1.20
```

### PTRZone

Defines a reverse DNS zone with associated PTR records.

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: PTRZone
metadata:
  name: internal-network
spec:
  network: "192.168.1.0/24"
  syncWithDHCP: true
  defaultDomain: example.local
  records:
    - ip: 192.168.1.1
      target: router.example.local
```

### DNSFilterList

Defines DNS filtering lists and rules.

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: DNSFilterList
metadata:
  name: default-filtering
spec:
  name: "Default DNS Filtering"
  enabled: true
  categories:
    - ads
    - trackers
    - malware
```

### DNSClient

Defines client-specific DNS filtering rules.

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: DNSClient
metadata:
  name: family-laptop
spec:
  name: "Family Laptop"
  addresses:
    - "192.168.1.150"
  filteringEnabled: true
  safesearch: true
```

### MDNSReflection

Defines mDNS reflection rules between networks.

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: MDNSReflection
metadata:
  name: home-reflection
spec:
  name: "Home Network Reflection"
  sourceVLANs: [10, 20]
  destinationVLANs: [30, 40]
  serviceTypes:
    - airplay
    - homekit
```

## Installation

### Prerequisites

- Kubernetes cluster
- kubectl
- kustomize

### Deploy DNS Components

```bash
kubectl apply -k manifests/base/dns
```

## Configuration

### CoreDNS Configuration

The CoreDNS controller uses a CoreFile format for configuration. Example:

```
. {
    errors
    health
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        upstream
        fallthrough in-addr.arpa ip6.arpa
    }
    hosts /etc/coredns/hosts {
        reload 60s
        fallthrough
    }
    file /etc/coredns/zones/example.com example.com {
        reload 60s
    }
    prometheus :9153
    forward . /etc/resolv.conf
    cache 30
    loop
    reload
    loadbalance
}
```

### AdGuard Configuration

The AdGuard controller can be configured with various filtering options:

```yaml
filterCategories:
  - ads
  - malware
  - phishing
customLists:
  - name: "Custom Block List"
    url: "https://example.com/blocklist.txt"
```

### mDNS Configuration

mDNS reflection can be configured to relay multicast DNS traffic between VLANs:

```yaml
reflection:
  enabled: true
  allowedServices:
    - _airplay._tcp.local.
    - _googlecast._tcp.local.
```

## Integration with DHCP

The DNS subsystem integrates with the DHCP subsystem to automatically create and remove DNS records based on DHCP leases.

When a DHCP lease is created, the following actions occur:
1. Forward (A/AAAA) records are created
2. Reverse (PTR) records are created
3. Client information is registered for filtering

When a DHCP lease expires, the corresponding DNS records are automatically removed.

## API Reference

### DNS Manager

| Method | Description |
|--------|-------------|
| `AddRecord` | Adds a DNS record to the appropriate zone |
| `RemoveRecord` | Removes a DNS record from the appropriate zone |
| `AddReverseRecord` | Adds a reverse (PTR) DNS record |
| `RemoveReverseRecord` | Removes a reverse (PTR) DNS record |
| `Sync` | Forces a synchronization of all DNS services |
| `Status` | Returns the status of all DNS services |

### CoreDNS Controller

| Method | Description |
|--------|-------------|
| `AddRecord` | Adds a DNS record to a zone |
| `RemoveRecord` | Removes a DNS record from a zone |
| `AddPTRRecord` | Adds a PTR record to a reverse zone |
| `RemovePTRRecord` | Removes a PTR record from a reverse zone |
| `Sync` | Forces a synchronization of all CoreDNS zones |
| `Status` | Returns the status of CoreDNS |

### AdGuard Controller

| Method | Description |
|--------|-------------|
| `UpdateFilterList` | Updates or adds a DNS filter list |
| `RemoveFilterList` | Removes a DNS filter list |
| `UpdateClientRule` | Updates or adds a client filtering rule |
| `RemoveClientRule` | Removes a client filtering rule |
| `Sync` | Forces a synchronization of AdGuard Home configuration |
| `Status` | Returns the status of AdGuard Home |

### mDNS Controller

| Method | Description |
|--------|-------------|
| `UpdateReflectionRule` | Updates or adds a mDNS reflection rule |
| `RemoveReflectionRule` | Removes a mDNS reflection rule |
| `EnableReflection` | Enables or disables mDNS reflection globally |
| `AddServiceType` | Adds or updates a supported mDNS service type |
| `RemoveServiceType` | Removes a supported mDNS service type |
| `Sync` | Forces a synchronization of mDNS reflection |
| `Status` | Returns the status of mDNS reflection |

## Troubleshooting

### Common Issues

#### DNS Records Not Being Created

1. Check that the DNS Manager is running:
   ```bash
   kubectl get pods -n dns-system
   ```

2. Check the DNS Manager logs:
   ```bash
   kubectl logs -n dns-system dns-manager-0
   ```

3. Verify the DNSZone resource is correctly defined:
   ```bash
   kubectl get dnszone -A
   ```

#### DNS Filtering Not Working

1. Check that the AdGuard controller is running:
   ```bash
   kubectl get pods -n dns-system
   ```

2. Check the AdGuard controller logs:
   ```bash
   kubectl logs -n dns-system adguard-controller-0
   ```

3. Verify the DNSFilterList resource is correctly defined:
   ```bash
   kubectl get dnsfilterlist -A
   ```

## Example Use Cases

### Setting Up a New Domain with Forward and Reverse DNS

1. Create a DNSZone resource:
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

2. Create a PTRZone resource:
   ```yaml
   apiVersion: dns.fos1.io/v1alpha1
   kind: PTRZone
   metadata:
     name: internal-network
   spec:
     network: "192.168.1.0/24"
     syncWithDHCP: true
   ```

### Implementing DNS Filtering for a Network

1. Create a DNSFilterList resource:
   ```yaml
   apiVersion: dns.fos1.io/v1alpha1
   kind: DNSFilterList
   metadata:
     name: default-filtering
   spec:
     name: "Default DNS Filtering"
     enabled: true
     categories:
       - ads
       - trackers
       - malware
   ```

2. Apply client-specific rules:
   ```yaml
   apiVersion: dns.fos1.io/v1alpha1
   kind: DNSClient
   metadata:
     name: family-laptop
   spec:
     name: "Family Laptop"
     addresses:
       - "192.168.1.150"
     filteringEnabled: true
     filterLists:
       - name: default-filtering
   ```

### Setting Up mDNS Reflection Between VLANs

1. Create an MDNSReflection resource:
   ```yaml
   apiVersion: dns.fos1.io/v1alpha1
   kind: MDNSReflection
   metadata:
     name: home-reflection
   spec:
     name: "Home Network Reflection"
     sourceVLANs: [10, 20]
     destinationVLANs: [30, 40]
     serviceTypes:
       - airplay
       - homekit
   ```

## References

- [CoreDNS Documentation](https://coredns.io/manual/toc/)
- [AdGuard Home Documentation](https://github.com/AdguardTeam/AdGuardHome/wiki)
- [mDNS Specification](https://tools.ietf.org/html/rfc6762)
- [DNS Records Types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
