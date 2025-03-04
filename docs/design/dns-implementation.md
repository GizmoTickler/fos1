# DNS Implementation Design

## Overview

This document outlines the design for a comprehensive DNS services implementation for the Kubernetes-based router/firewall system. The design focuses on three primary components: CoreDNS for authoritative internal DNS, AdGuard Home for DNS filtering, and mDNS for service discovery across VLANs.

## Design Goals

1. **Authoritative DNS**: Provide authoritative DNS for internal zones with comprehensive record type support
2. **DNS Filtering**: Implement content and security filtering through AdGuard Home
3. **Cross-VLAN Service Discovery**: Enable configurable mDNS reflection between VLANs
4. **Dynamic DNS**: Automatically create DNS records from DHCP leases
5. **Unified Management**: Provide consistent management interface while maintaining separate deployments
6. **Metrics and Monitoring**: Integrate with Prometheus and Grafana for observability
7. **Kubernetes Native**: Use CRDs for configuration and management

## System Architecture

### Core Components

1. **CoreDNS**:
   - Authoritative DNS server for internal zones
   - Recursive resolver for specified domains
   - Managed through Kubernetes CRDs

2. **AdGuard Home**:
   - Client-facing DNS server
   - Content and security filtering
   - Forwards internal queries to CoreDNS

3. **mDNS Reflector**:
   - Cross-VLAN service discovery
   - Rule-based reflection configuration
   - Integration with network components

4. **DNS Manager**:
   - Unified API for DNS configuration
   - Orchestrates CoreDNS, AdGuard, and mDNS
   - Handles integration with other services

### Component Relationships

```
┌───────────────────────────────────────────────────────────────┐
│                       Clients                                 │
│  (All clients use AdGuard as their DNS server)                │
└────────────────┬───────────────────────────────┬──────────────┘
                 │                               │
                 ▼                               ▼
┌────────────────────────────┐    ┌───────────────────────────┐
│    AdGuard Home            │    │    mDNS Reflector         │
│  - DNS filtering           │    │  - Service discovery      │
│  - DoH/DoT for clients     │    │  - Cross-VLAN reflection  │
└────────────┬───────────────┘    └───────────────────────────┘
             │                        
             │ (internal domains)
             ▼                                                  
┌────────────────────────────┐    ┌───────────────────────────┐
│    CoreDNS                 │◄───┤    DNS Manager            │
│  - Authoritative DNS       │    │  - Unified API            │
│  - Internal zones          │    │  - DHCP integration       │
└────────────────────────────┘    └───────────────────────────┘
```

### DNS Query Flow

1. **Client Query**:
   - Client sends DNS query to AdGuard Home
   - AdGuard processes request through filter lists

2. **Internal Domain Resolution**:
   - For internal zones, AdGuard forwards to CoreDNS
   - CoreDNS resolves from Kubernetes CRD-defined zones

3. **External Domain Resolution**:
   - For external domains, AdGuard performs filtering
   - If allowed, AdGuard forwards to configured upstream DNS

4. **mDNS Discovery**:
   - mDNS queries are captured by mDNS reflector
   - Reflected across VLANs based on configured rules

## Component Design

### CoreDNS Implementation

CoreDNS will serve as the authoritative DNS server for internal domains.

#### Zone Management with CRDs

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: DNSZone
metadata:
  name: home-local
spec:
  domain: home.local
  ttl: 3600
  soa:
    refresh: 7200
    retry: 3600
    expire: 1209600
    minimum: 3600
  records:
  - name: "@"
    type: A
    value: 192.168.1.1
    ttl: 3600  # Optional override of zone TTL
  - name: router
    type: A
    value: 192.168.1.1
  - name: printer
    type: A
    value: 192.168.1.100
  - name: server
    type: A
    value: 192.168.1.200
  - name: www
    type: CNAME
    value: server.home.local.
  - name: _http._tcp
    type: SRV
    value: "10 10 80 server.home.local."
  - name: server
    type: TXT
    value: "v=info owner=admin"
```

#### Record Type Support

CoreDNS will support all common record types:
- **A/AAAA Records**: IPv4 and IPv6 addresses
- **CNAME Records**: Canonical names
- **MX Records**: Mail exchange servers
- **SRV Records**: Service location
- **TXT Records**: Text information
- **PTR Records**: Reverse DNS entries
- **NS Records**: Nameserver definitions
- **SOA Records**: Start of authority

#### PTR Zone Management

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: PTRZone
metadata:
  name: 1-168-192-in-addr-arpa
spec:
  network: 192.168.1.0/24
  ttl: 3600
  soa:
    refresh: 7200
    retry: 3600
    expire: 1209600
    minimum: 3600
  # Static PTR records (optional, most will be from DHCP)
  records:
  - ip: 192.168.1.1
    hostname: router.home.local.
  - ip: 192.168.1.100
    hostname: printer.home.local.
```

#### CoreDNS Configuration

CoreDNS will be configured through a ConfigMap, managed by the DNS Manager:

```yaml
Corefile: |
  # Internal zones
  home.local:53 {
    errors
    kubernetes_crd dns.fos1.io/v1alpha1 DNSZone
    cache 30
    prometheus
    forward . /etc/resolv.conf
    log
  }
  
  # PTR zones for reverse lookups
  1.168.192.in-addr.arpa:53 {
    errors
    kubernetes_crd dns.fos1.io/v1alpha1 PTRZone
    cache 30
    prometheus
    log
  }
```

### AdGuard Home Implementation

AdGuard Home will serve as the client-facing DNS server with filtering capabilities.

#### Integration with CoreDNS

AdGuard will be configured to forward internal domain queries to CoreDNS:

```yaml
upstream_dns:
  - '[/home.local/]127.0.0.1:5053'  # CoreDNS service for internal zones
  - '[/168.192.in-addr.arpa/]127.0.0.1:5053'  # CoreDNS for reverse lookup
  - '1.1.1.1'  # Cloudflare for external domains
  - '9.9.9.9'  # Quad9 for external domains
```

#### Client Management CRD

Client management for filtering exceptions:

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: DNSClient
metadata:
  name: home-servers
spec:
  description: "Home servers with filtering exceptions"
  identifiers:
    - type: ip
      value: 192.168.1.200
    - type: ip
      value: 192.168.1.201
    - type: ip
      value: 192.168.1.202
    - type: mac
      value: "00:11:22:33:44:55"
  filtering:
    enabled: true
    exceptions:
      - "*.github.com"
      - "*.docker.com"
      - "download.example.com"
```

#### Filter Lists Management

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: DNSFilterList
metadata:
  name: security-filters
spec:
  enabled: true
  categories:
    - malware
    - phishing
    - ads
  customLists:
    - name: Company Blocklist
      url: https://internal.example.com/blocklist.txt
      enabled: true
  allowLists:
    - name: False Positives
      domains:
        - safe-site.example.com
        - legitimate-tool.example.org
```

### mDNS Reflector Implementation

The mDNS reflector enables service discovery across VLANs with rule-based controls.

#### mDNS Reflection Rules CRD

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: MDNSReflection
metadata:
  name: home-vlans
spec:
  enabled: true
  reflectionRules:
    - name: "Media Devices"
      sourceVLANs: 
        - 10  # Main network
        - 20  # IoT network
      destinationVLANs:
        - 10  # Main network
        - 20  # IoT network
      serviceTypes:
        - "_airplay._tcp"
        - "_googlecast._tcp"
        - "_spotify-connect._tcp"
      
    - name: "Print Services"
      sourceVLANs: 
        - 10  # Main network
        - 30  # Guest network
      destinationVLANs:
        - 10  # Main network
      serviceTypes:
        - "_ipp._tcp"
        - "_printer._tcp"
        - "_scanner._tcp"
      
    - name: "Home Automation"
      sourceVLANs: 
        - 10  # Main network
      destinationVLANs:
        - 10  # Main network
        - 20  # IoT network
      serviceTypes:
        - "_hue._tcp"
        - "_homekit._tcp"
        - "_matter._tcp"
```

#### Avahi Configuration

The Avahi daemon will be configured through a ConfigMap created by the DNS Manager:

```ini
[server]
domain-name=local
use-ipv4=yes
use-ipv6=yes
allow-interfaces=eth*,br*,vlan*
ratelimit-interval-usec=1000000
ratelimit-burst=1000

[reflector]
enable-reflector=yes
reflect-ipv=yes

[reflect-filters]
# Generated from MDNSReflection CRD
```

#### Service Type Management

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: MDNSServiceType
metadata:
  name: smart-home
spec:
  description: "Smart Home Device Services"
  types:
    - name: "_hue._tcp"
      description: "Philips Hue Bridge"
      defaultPorts: [80, 443]
    - name: "_homekit._tcp"
      description: "Apple HomeKit Devices"
      defaultPorts: [8080, 8443]
    - name: "_wemo._tcp"
      description: "Belkin WeMo Devices"
      defaultPorts: [49153]
```

### DNS Manager Implementation

The DNS Manager provides a unified API and coordinates all DNS components.

#### Manager Architecture

```go
// Manager manages all DNS services
type Manager struct {
    // Component controllers
    coreDNSController   *CoreDNSController
    adGuardController   *AdGuardController
    mDNSController      *MDNSController
    
    // Integration
    dhcpIntegration     *DHCPIntegration
    metricsCollector    *MetricsCollector
    
    // API and status
    apiServer          *APIServer
    
    // Control
    k8sClient          kubernetes.Interface
    ctx                context.Context
    cancel             context.CancelFunc
}
```

#### DHCP Integration

The DNS Manager integrates with DHCP for dynamic DNS updates:

```go
// DHCPIntegration handles DHCP lease events
type DHCPIntegration struct {
    dnsManager       *Manager
    leaseWatcher     *LeaseWatcher
    recordGenerator  *DNSRecordGenerator
}

// ProcessLeaseEvent processes a DHCP lease event
func (d *DHCPIntegration) ProcessLeaseEvent(event LeaseEvent) error {
    // For new or updated leases
    if event.Type == LeaseCreated || event.Type == LeaseUpdated {
        return d.createOrUpdateDNSRecords(event.Lease)
    }
    
    // For expired or deleted leases
    if event.Type == LeaseExpired || event.Type == LeaseDeleted {
        return d.removeDNSRecords(event.Lease)
    }
    
    return nil
}

// createOrUpdateDNSRecords creates or updates DNS records for a lease
func (d *DHCPIntegration) createOrUpdateDNSRecords(lease Lease) error {
    // Create forward (A/AAAA) record
    if err := d.recordGenerator.CreateForwardRecord(lease); err != nil {
        return err
    }
    
    // Create reverse (PTR) record
    if err := d.recordGenerator.CreateReverseRecord(lease); err != nil {
        return err
    }
    
    return nil
}
```

#### Dynamic Record Management

For dynamic DNS records from DHCP:

```yaml
apiVersion: dns.fos1.io/v1alpha1
kind: DynamicDNSConfig
metadata:
  name: dhcp-integration
spec:
  enabled: true
  # Base domain for dynamically created records
  baseDomain: home.local
  # TTL for dynamic records (should be related to lease time)
  ttl: 3600
  # Whether to create reverse (PTR) records
  createReverse: true
  # Whether to use client-provided hostnames
  useClientHostname: true
  # Hostname pattern if client doesn't provide one
  hostnamePattern: "host-{ip}"
  # Cleanup grace period after lease expiration
  cleanupGracePeriod: 86400  # 24 hours
```

## Kubernetes CRD Architecture

### CRD Types

The system will implement the following CRDs:

1. **DNSZone**: Defines forward lookup zones
2. **PTRZone**: Defines reverse lookup zones
3. **DNSClient**: Defines client groups with specific filtering rules
4. **DNSFilterList**: Defines filter lists for AdGuard
5. **MDNSReflection**: Defines rules for mDNS reflection
6. **MDNSServiceType**: Defines mDNS service types
7. **DynamicDNSConfig**: Configures dynamic DNS from DHCP

### Example CRD Deployment

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: dnszones.dns.fos1.io
spec:
  group: dns.fos1.io
  names:
    kind: DNSZone
    plural: dnszones
    singular: dnszone
    shortNames:
      - dz
  scope: Namespaced
  versions:
  - name: v1alpha1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        required:
          - spec
        properties:
          spec:
            type: object
            required:
              - domain
            properties:
              domain:
                type: string
                pattern: '^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\\.)+[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$'
              ttl:
                type: integer
                default: 3600
              soa:
                type: object
                properties:
                  refresh:
                    type: integer
                    default: 7200
                  retry:
                    type: integer
                    default: 3600
                  expire:
                    type: integer
                    default: 1209600
                  minimum:
                    type: integer
                    default: 3600
              records:
                type: array
                items:
                  type: object
                  required:
                    - name
                    - type
                    - value
                  properties:
                    name:
                      type: string
                    type:
                      type: string
                      enum:
                        - A
                        - AAAA
                        - CNAME
                        - MX
                        - SRV
                        - TXT
                        - NS
                    value:
                      type: string
                    ttl:
                      type: integer
```

## Integration with Network Components

### VLAN Integration

mDNS reflection rules will be aligned with VLAN definitions:

```go
// UpdateMDNSRulesForVLANs updates mDNS reflection rules based on VLAN changes
func (m *MDNSController) UpdateMDNSRulesForVLANs(vlans []*network.VLAN) error {
    // Get current mDNS reflection rules
    reflectionRules, err := m.GetMDNSReflectionRules()
    if err != nil {
        return err
    }
    
    // Update rules based on VLAN changes
    for _, rule := range reflectionRules {
        // Update source VLANs if needed
        updateSourceVLANs(rule, vlans)
        
        // Update destination VLANs if needed
        updateDestinationVLANs(rule, vlans)
    }
    
    // Apply updated rules
    return m.ApplyMDNSReflectionRules(reflectionRules)
}
```

### Cilium Integration

DNS services will integrate with Cilium for enhanced security:

1. **DNS-based Policies**:
   - Allow Cilium to enforce policies based on DNS names
   - Enable visibility of DNS queries in Cilium

2. **Service Discovery**:
   - Utilize DNS for service discovery in Cilium
   - Map DNS names to Cilium endpoints

## Monitoring and Metrics

### Prometheus Integration

Each DNS component will expose Prometheus metrics:

1. **CoreDNS Metrics**:
   - Query rates by zone and record type
   - Cache hit/miss rates
   - Query response times

2. **AdGuard Metrics**:
   - Filtering statistics (blocked/allowed)
   - Query rates by client
   - Filter list effectiveness

3. **mDNS Metrics**:
   - Reflection counts by service type
   - Discovery rates
   - Rule match statistics

### Grafana Dashboards

Pre-configured Grafana dashboards will include:

1. **DNS Overview Dashboard**:
   - Overall query rates
   - Error rates
   - Cache performance

2. **Security Dashboard**:
   - Blocked domain statistics
   - Top clients with blocked requests
   - Filter list effectiveness

3. **Service Discovery Dashboard**:
   - mDNS service discovery rates
   - Cross-VLAN reflection activity
   - Service type distribution

## Deployment Architecture

### CoreDNS Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: network
spec:
  replicas: 2  # For redundancy
  selector:
    matchLabels:
      app: coredns
  template:
    metadata:
      labels:
        app: coredns
    spec:
      containers:
      - name: coredns
        image: coredns/coredns:1.10.0
        args: ["-conf", "/etc/coredns/Corefile"]
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        - containerPort: 9153
          name: metrics
          protocol: TCP
        volumeMounts:
        - name: config-volume
          mountPath: /etc/coredns
      volumes:
      - name: config-volume
        configMap:
          name: coredns-config
---
apiVersion: v1
kind: Service
metadata:
  name: coredns
  namespace: network
spec:
  selector:
    app: coredns
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
  - name: metrics
    port: 9153
    protocol: TCP
```

### AdGuard Home Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: adguard-home
  namespace: network
spec:
  replicas: 1
  selector:
    matchLabels:
      app: adguard-home
  template:
    metadata:
      labels:
        app: adguard-home
    spec:
      containers:
      - name: adguard-home
        image: adguard/adguardhome:latest
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        - containerPort: 3000
          name: ui
          protocol: TCP
        - containerPort: 443
          name: tls
          protocol: TCP
        volumeMounts:
        - name: config-volume
          mountPath: /opt/adguardhome/conf
        - name: work-volume
          mountPath: /opt/adguardhome/work
      volumes:
      - name: config-volume
        configMap:
          name: adguard-config
      - name: work-volume
        persistentVolumeClaim:
          claimName: adguard-work
---
apiVersion: v1
kind: Service
metadata:
  name: adguard-home
  namespace: network
spec:
  selector:
    app: adguard-home
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
  - name: ui
    port: 3000
    protocol: TCP
  - name: tls
    port: 443
    protocol: TCP
```

### mDNS Reflector Deployment

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: mdns-reflector
  namespace: network
spec:
  selector:
    matchLabels:
      app: mdns-reflector
  template:
    metadata:
      labels:
        app: mdns-reflector
    spec:
      hostNetwork: true
      containers:
      - name: avahi
        image: mvance/avahi:latest
        securityContext:
          capabilities:
            add: ["NET_ADMIN"]
        volumeMounts:
        - name: config-volume
          mountPath: /etc/avahi/avahi-daemon.conf
          subPath: avahi-daemon.conf
        - name: filters-volume
          mountPath: /etc/avahi/reflect-filters.conf
          subPath: reflect-filters.conf
      volumes:
      - name: config-volume
        configMap:
          name: avahi-config
      - name: filters-volume
        configMap:
          name: avahi-filters
```

## Implementation Plan

### Phase 1: Core DNS Infrastructure
- Implement DNS CRD definitions
- Create CoreDNS controller
- Set up basic zone management
- Implement DNS Manager framework

### Phase 2: Client-Facing DNS
- Implement AdGuard Home integration
- Configure filtering and forwarding
- Create client management
- Set up Prometheus metrics

### Phase 3: mDNS and Service Discovery
- Implement mDNS reflector
- Develop reflection rule management
- Create service type definitions
- Configure cross-VLAN reflection

### Phase 4: Integration and Automation
- Implement DHCP integration
- Set up dynamic DNS
- Create unified management API
- Develop Grafana dashboards

## Conclusion

This DNS implementation design provides a comprehensive solution for the router/firewall platform with:

1. Authoritative DNS for internal zones via CoreDNS, managed through Kubernetes CRDs
2. Client-facing DNS filtering via AdGuard Home
3. Flexible mDNS reflection across VLANs for service discovery
4. Dynamic DNS updates from DHCP leases
5. Comprehensive monitoring via Prometheus and Grafana
6. A unified management API while maintaining separate service deployments

The design prioritizes home network use cases while remaining flexible enough for small business and enterprise environments. The integration with other system components ensures a cohesive networking solution that aligns with the overall router/firewall architecture.