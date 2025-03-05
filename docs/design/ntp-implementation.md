# NTP Implementation Design

## Overview

This document outlines the design and implementation of the Network Time Protocol (NTP) service for the Kubernetes-based router/firewall system. The service provides accurate time synchronization across all network segments, supporting multiple time sources and security features.

## Design Goals

1. **Time Synchronization**: Provide accurate and reliable time synchronization for all network devices
2. **Multiple Source Support**: Support diverse time sources including public NTP pools, GPS, PPS, and atomic clocks
3. **Security**: Implement security features including NTS (Network Time Security), authentication, and access controls 
4. **Per-VLAN Policies**: Enable configurable NTP services per VLAN with appropriate access controls
5. **Monitoring**: Provide comprehensive metrics for time synchronization status and quality
6. **Kubernetes Native**: Use CRDs for configuration and management
7. **Integration**: Seamless integration with DHCP, DNS, and security components

## System Architecture

### Core Components

1. **Chrony NTP Server**:
   - Primary NTP engine providing time synchronization services
   - Deployed as a privileged container with host network access
   - Configured through Kubernetes CRDs

2. **NTP Controller**:
   - Translates CRDs to Chrony configuration
   - Manages NTP server instances
   - Handles component lifecycle

3. **NTP Exporter**:
   - Collects metrics from Chrony
   - Exposes Prometheus-compatible metrics
   - Provides monitoring and alerting data

4. **NTP Manager**:
   - Unified API for NTP configuration
   - Coordinates all NTP components
   - Handles integration with other services

### Component Relationships

```
┌───────────────────────────────────────────────────────────────┐
│                       Clients                                 │
│  (All network devices synchronize with NTP service)           │
└────────────────┬───────────────────────────────┬──────────────┘
                 │                               │
                 ▼                               ▼
┌────────────────────────────┐    ┌───────────────────────────┐
│    Chrony NTP Server       │    │    NTP Controller         │
│  - Time synchronization    │◄───┤  - Configuration          │
│  - Multiple source support │    │  - Instance management    │
└────────────┬───────────────┘    └───────────────┬───────────┘
             │                                    │
             │                                    │
             ▼                                    ▼
┌────────────────────────────┐    ┌───────────────────────────┐
│    NTP Exporter            │    │    NTP Manager            │
│  - Metrics collection      │◄───┤  - Unified API            │
│  - Prometheus integration  │    │  - Integration with DHCP  │
└────────────────────────────┘    └───────────────────────────┘
```

### Time Synchronization Flow

1. **NTP Sources**:
   - Chrony obtains time from configured sources (pools, direct servers, hardware)
   - Sources are prioritized based on stratum and reliability
   - Chrony maintains statistics on source quality

2. **Local Time Maintenance**:
   - Chrony disciplines the local system clock
   - Adjusts clock frequency and offset to maintain accuracy
   - Monitors drift and stability

3. **Client Synchronization**:
   - Network clients request time from Chrony
   - Requests are authenticated if configured
   - Responses include accuracy information

4. **Monitoring**:
   - NTP Exporter collects performance and status metrics
   - Metrics are exposed for Prometheus
   - Alerts are configured for abnormal conditions

## Component Design

### NTP Service CRD

The NTP service is configured through a dedicated CRD:

```yaml
apiVersion: ntp.fos1.io/v1alpha1
kind: NTPService
metadata:
  name: main-ntp
spec:
  enabled: true
  
  # Time sources configuration
  sources:
    pools:
      - name: "pool.ntp.org"
        servers: 4  # Number of servers to use from pool
        iburst: true  # Fast initial synchronization
        prefer: false
      - name: "time.cloudflare.com"
        servers: 2
        iburst: true
        prefer: true
    
    servers:
      - address: "192.168.1.100"  # Local reference server
        iburst: true
        prefer: true
        minpoll: 4
        maxpoll: 10
    
    # Hardware clock sources (if available)
    hardware:
      pps:
        enabled: false
        device: "/dev/pps0"
        prefer: true
      gps:
        enabled: false
        device: "/dev/ttyS0"
        refclock: true
        prefer: true
  
  # Server configuration
  server:
    stratum: 2  # Stratum level for this server
    driftfile: "/var/lib/chrony/drift"
    makestep: 
      threshold: 1.0  # Step if offset larger than 1 second
      limit: 3  # Allow stepping in first 3 clock updates
    
    # Local clock as fallback reference
    local:
      enabled: true
      stratum: 10  # High stratum means low priority
  
  # Security settings
  security:
    nts:
      enabled: true  # Network Time Security
    authentication:
      enabled: true
      keys:
        - id: 1
          type: "SHA256"
          value: "AVerySecureKeyString"  # Should be in a Kubernetes Secret
    
    ratelimit:
      enabled: true
      interval: 3  # Seconds
      burst: 8  # Packets
    
    # Access controls
    access:
      - network: "192.168.0.0/16"
        permission: "allow"
      - network: "10.0.0.0/8"
        permission: "allow"
      - network: "0.0.0.0/0"
        permission: "deny"
  
  # VLAN-specific configuration
  vlanConfig:
    - vlanRef: vlan-10  # Main network
      enabled: true
      broadcast: true
      clientsOnly: false
    - vlanRef: vlan-20  # IoT network
      enabled: true
      broadcast: false
      clientsOnly: true
    - vlanRef: vlan-30  # Guest network
      enabled: true
      broadcast: false
      clientsOnly: true
  
  # Monitoring configuration
  monitoring:
    enabled: true
    offset:
      warningThreshold: 100  # milliseconds
      criticalThreshold: 1000  # milliseconds
    sourcesMinimum: 3  # Minimum number of valid sources
```

### Chrony Configuration Generator

The NTP Controller will translate the CRD into Chrony configuration:

```go
// ConfigGenerator generates Chrony configuration from NTP Service CRD
type ConfigGenerator struct {
    // Dependencies
}

// Generate creates a Chrony configuration file from the NTP Service spec
func (g *ConfigGenerator) Generate(service *v1alpha1.NTPService) (string, error) {
    var config strings.Builder
    
    // Add server and pool directives for time sources
    for _, pool := range service.Spec.Sources.Pools {
        fmt.Fprintf(&config, "pool %s iburst %t maxsources %d\n", 
                   pool.Name, pool.IBurst, pool.Servers)
    }
    
    for _, server := range service.Spec.Sources.Servers {
        fmt.Fprintf(&config, "server %s iburst %t prefer %t minpoll %d maxpoll %d\n",
                   server.Address, server.IBurst, server.Prefer, 
                   server.MinPoll, server.MaxPoll)
    }
    
    // Hardware time sources if available
    if service.Spec.Sources.Hardware.PPS.Enabled {
        fmt.Fprintf(&config, "refclock PPS /dev/pps0 prefer\n")
    }
    
    if service.Spec.Sources.Hardware.GPS.Enabled {
        fmt.Fprintf(&config, "refclock SHM 0 refid GPS prefer\n")
    }
    
    // Server configuration
    fmt.Fprintf(&config, "driftfile %s\n", service.Spec.Server.Driftfile)
    fmt.Fprintf(&config, "makestep %f %d\n", 
               service.Spec.Server.MakeStep.Threshold,
               service.Spec.Server.MakeStep.Limit)
    
    // Local clock fallback
    if service.Spec.Server.Local.Enabled {
        fmt.Fprintf(&config, "local stratum %d\n", service.Spec.Server.Local.Stratum)
    }
    
    // Security configuration
    if service.Spec.Security.NTS.Enabled {
        fmt.Fprintln(&config, "ntsdumpdir /var/lib/chrony")
        fmt.Fprintln(&config, "ntsservercert /etc/chrony/cert.pem")
        fmt.Fprintln(&config, "ntsserverkey /etc/chrony/key.pem")
    }
    
    // Authentication keys
    if service.Spec.Security.Authentication.Enabled {
        fmt.Fprintln(&config, "keyfile /etc/chrony/chrony.keys")
    }
    
    // Rate limiting
    if service.Spec.Security.RateLimit.Enabled {
        fmt.Fprintf(&config, "ratelimit interval %d burst %d\n",
                   service.Spec.Security.RateLimit.Interval,
                   service.Spec.Security.RateLimit.Burst)
    }
    
    // Access controls
    for _, access := range service.Spec.Security.Access {
        fmt.Fprintf(&config, "%s %s\n", access.Permission, access.Network)
    }
    
    // VLAN-specific settings handled through firewall rules
    
    // Logging and statistics
    fmt.Fprintln(&config, "logdir /var/log/chrony")
    fmt.Fprintln(&config, "log measurements statistics tracking")
    
    // Enable serving time
    fmt.Fprintln(&config, "allow all")
    
    return config.String(), nil
}
```

### NTP Controller

The NTP Controller manages the lifecycle of the NTP service:

```go
package ntp

import (
    "context"
    // Other imports
)

// Controller watches NTP CRDs and manages Chrony configuration
type Controller struct {
    client        kubernetes.Interface
    ntpLister     listers.NTPServiceLister
    vlanLister    listers.VLANLister
    chronyManager *ChronyManager
    configGen     *ConfigGenerator
    exporterMgr   *ExporterManager
}

// Run starts the controller
func (c *Controller) Run(ctx context.Context) error {
    // Controller implementation
}

// syncNTPService syncs an NTPService CRD to Chrony configuration
func (c *Controller) syncNTPService(key string) error {
    // Get the NTPService resource
    ntpService, err := c.ntpLister.Get(key)
    if err != nil {
        return err
    }
    
    // Generate Chrony configuration
    config, err := c.configGen.Generate(ntpService)
    if err != nil {
        return err
    }
    
    // Update Chrony configuration
    if err := c.chronyManager.UpdateConfig(config); err != nil {
        return err
    }
    
    // Update firewall rules for VLANs
    if err := c.updateFirewallRules(ntpService); err != nil {
        return err
    }
    
    // Configure exporter
    if err := c.exporterMgr.Configure(ntpService); err != nil {
        return err
    }
    
    // Restart or reload Chrony
    return c.chronyManager.RestartService()
}

// updateFirewallRules creates appropriate firewall rules for NTP access
func (c *Controller) updateFirewallRules(ntpService *v1alpha1.NTPService) error {
    // Implementation
    return nil
}
```

### Chrony Manager

Manages the Chrony NTP server:

```go
package ntp

// ChronyManager handles the management of Chrony NTP server
type ChronyManager struct {
    configFile     string
    keysFile       string
    chronyCommand  string
}

// UpdateConfig updates the Chrony configuration file
func (m *ChronyManager) UpdateConfig(config string) error {
    // Write config to file
    return nil
}

// UpdateKeys updates the Chrony authentication keys
func (m *ChronyManager) UpdateKeys(keys []Key) error {
    // Write keys to file
    return nil
}

// RestartService restarts the Chrony service
func (m *ChronyManager) RestartService() error {
    // Restart service
    return nil
}

// CheckStatus checks the status of the Chrony service
func (m *ChronyManager) CheckStatus() (Status, error) {
    // Check status
    return Status{}, nil
}

// Status represents the status of the Chrony NTP service
type Status struct {
    Running      bool
    Synchronized bool
    Stratum      int
    Sources      []Source
}

// Source represents an NTP time source
type Source struct {
    Name     string
    Type     string  // Server, Pool, PPS, etc.
    Stratum  int
    Offset   float64 // in milliseconds
    Jitter   float64 // in milliseconds
    Reach    int     // Octal value
    Selected bool    // Whether this source is selected
}
```

### NTP Exporter

Collects and exports metrics from Chrony:

```go
package ntp

// ExporterManager manages the NTP metrics exporter
type ExporterManager struct {
    configFile    string
    exporterFlags map[string]string
}

// Configure configures the NTP exporter
func (e *ExporterManager) Configure(ntpService *v1alpha1.NTPService) error {
    // Configure exporter
    return nil
}

// CollectMetrics collects metrics from Chrony
func (e *ExporterManager) CollectMetrics() (Metrics, error) {
    // Collect metrics
    return Metrics{}, nil
}

// Metrics represents NTP metrics
type Metrics struct {
    Offset           float64 // System time offset in milliseconds
    Jitter           float64 // System jitter in milliseconds
    Stratum          int     // Stratum level
    SyncStatus       bool    // Whether system is synchronized
    SourceCount      int     // Number of sources
    SourcesReachable int     // Number of reachable sources
}
```

### NTP Manager

Provides a unified API for NTP management:

```go
package ntp

// Manager manages the NTP service
type Manager struct {
    // Component controllers
    controller     *Controller
    chronyManager  *ChronyManager
    exporterMgr    *ExporterManager
    
    // Integration
    dhcpIntegration *DHCPIntegration
    dnsIntegration  *DNSIntegration
    
    // API and status
    apiServer      *APIServer
    
    // Control
    k8sClient      kubernetes.Interface
    ctx            context.Context
    cancel         context.CancelFunc
}

// Run starts the NTP manager
func (m *Manager) Run() error {
    // Start components
    return nil
}

// GetStatus gets the status of the NTP service
func (m *Manager) GetStatus() (Status, error) {
    // Get status
    return m.chronyManager.CheckStatus()
}

// UpdateConfig updates the NTP service configuration
func (m *Manager) UpdateConfig(config *v1alpha1.NTPService) error {
    // Update configuration
    return nil
}
```

### Integration Components

#### DHCP Integration

Integrates NTP with DHCP services:

```go
package ntp

// DHCPIntegration handles DHCP integration
type DHCPIntegration struct {
    ntpManager *Manager
}

// UpdateDHCPOptions updates DHCP options for NTP
func (d *DHCPIntegration) UpdateDHCPOptions() error {
    // Update DHCP options
    return nil
}
```

#### DNS Integration

Integrates NTP with DNS services:

```go
package ntp

// DNSIntegration handles DNS integration
type DNSIntegration struct {
    ntpManager *Manager
}

// UpdateDNSRecords updates DNS records for NTP
func (d *DNSIntegration) UpdateDNSRecords() error {
    // Update DNS records
    return nil
}
```

## Kubernetes CRD Architecture

### CRD Types

The system will implement the following CRDs:

1. **NTPService**: Defines the main NTP service configuration
2. **NTPClient**: (Optional) Defines client groups with specific NTP policies

### Example CRD Deployment

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: ntpservices.ntp.fos1.io
spec:
  group: ntp.fos1.io
  names:
    kind: NTPService
    plural: ntpservices
    singular: ntpservice
    shortNames:
      - ntp
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
              - enabled
              - sources
              - server
            properties:
              enabled:
                type: boolean
              sources:
                type: object
                properties:
                  pools:
                    type: array
                    items:
                      type: object
                      properties:
                        name:
                          type: string
                        servers:
                          type: integer
                          minimum: 1
                          maximum: 16
                        iburst:
                          type: boolean
                        prefer:
                          type: boolean
                  # Additional properties omitted for brevity
```

## Integration with Network Components

### VLAN Integration

NTP access control will be aligned with VLAN configurations:

```go
// UpdateNTPRulesForVLANs updates NTP access rules based on VLAN changes
func (c *Controller) UpdateNTPRulesForVLANs(vlans []*network.VLAN) error {
    // Get current NTP service configuration
    ntpService, err := c.ntpLister.Get("main-ntp")
    if err != nil {
        return err
    }
    
    // Update VLAN configuration
    updated := false
    for _, vlan := range vlans {
        found := false
        for i, vlanConfig := range ntpService.Spec.VLANConfig {
            if vlanConfig.VLANRef == vlan.Name {
                found = true
                // Update existing configuration if needed
                break
            }
        }
        
        if !found {
            // Add new VLAN configuration
            ntpService.Spec.VLANConfig = append(ntpService.Spec.VLANConfig, v1alpha1.VLANConfig{
                VLANRef:     vlan.Name,
                Enabled:     true,
                Broadcast:   false,
                ClientsOnly: true,
            })
            updated = true
        }
    }
    
    // Apply updated configuration if changed
    if updated {
        // Update the CRD
        return c.updateNTPService(ntpService)
    }
    
    return nil
}
```

### DHCP Option Integration

NTP servers will be provided via DHCP options:

```go
// UpdateDHCPOptions updates DHCP options with NTP server information
func (d *DHCPIntegration) UpdateDHCPOptions() error {
    // Get NTP server status
    status, err := d.ntpManager.GetStatus()
    if err != nil {
        return err
    }
    
    // Only update if NTP is synchronized
    if !status.Synchronized {
        return nil
    }
    
    // Update DHCPv4 option 42 (NTP servers)
    // Implementation details
    
    // Update DHCPv6 option 56 (NTP servers)
    // Implementation details
    
    return nil
}
```

## Monitoring and Metrics

### Prometheus Integration

The NTP exporter will expose the following metrics:

1. **Time Synchronization Metrics**:
   - `ntp_offset_milliseconds`: System clock offset from reference
   - `ntp_jitter_milliseconds`: Clock jitter in milliseconds
   - `ntp_stratum`: NTP stratum level of the system
   - `ntp_sync`: Whether system is in sync (1 or 0)

2. **Source Metrics**:
   - `ntp_source_offset_milliseconds`: Offset from each source
   - `ntp_source_jitter_milliseconds`: Jitter from each source
   - `ntp_source_delay_milliseconds`: Delay to each source
   - `ntp_source_stratum`: Stratum level of each source
   - `ntp_source_reachability`: Reachability score for each source

3. **System Metrics**:
   - `ntp_frequency_drift_ppm`: System clock frequency drift
   - `ntp_client_requests_total`: Number of client requests received
   - `ntp_client_requests_rate`: Rate of client requests

### Grafana Dashboards

Pre-configured Grafana dashboards will include:

1. **NTP Overview Dashboard**:
   - System synchronization status
   - Offset and jitter trends
   - Source quality indicators
   - Client request rates

2. **NTP Sources Dashboard**:
   - Per-source metrics
   - Source selection status
   - Source reachability
   - Offset comparison between sources

3. **NTP Clients Dashboard**:
   - Client request distribution
   - VLAN traffic patterns
   - Top clients by request volume

## Deployment Architecture

### Chrony Deployment

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ntp-chrony
  namespace: network
spec:
  selector:
    matchLabels:
      app: ntp-chrony
  template:
    metadata:
      labels:
        app: ntp-chrony
    spec:
      hostNetwork: true
      containers:
      - name: chrony
        image: custom/chrony:latest
        securityContext:
          capabilities:
            add: ["SYS_TIME", "NET_ADMIN"]
          privileged: true
        ports:
        - containerPort: 123
          name: ntp
          protocol: UDP
        volumeMounts:
        - name: config-volume
          mountPath: /etc/chrony
        - name: drift-volume
          mountPath: /var/lib/chrony
        - name: localtime
          mountPath: /etc/localtime
          readOnly: true
        - name: devices
          mountPath: /dev
        resources:
          limits:
            cpu: 200m
            memory: 256Mi
          requests:
            cpu: 100m
            memory: 128Mi
      - name: exporter
        image: custom/ntp-exporter:latest
        ports:
        - containerPort: 9559
          name: metrics
        volumeMounts:
        - name: config-volume
          mountPath: /etc/chrony
          readOnly: true
      volumes:
      - name: config-volume
        configMap:
          name: chrony-config
      - name: drift-volume
        persistentVolumeClaim:
          claimName: chrony-drift
      - name: localtime
        hostPath:
          path: /etc/localtime
      - name: devices
        hostPath:
          path: /dev
---
apiVersion: v1
kind: Service
metadata:
  name: ntp-chrony
  namespace: network
spec:
  selector:
    app: ntp-chrony
  ports:
  - name: ntp
    port: 123
    protocol: UDP
  - name: metrics
    port: 9559
    protocol: TCP
```

### NTP Controller Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ntp-controller
  namespace: network
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ntp-controller
  template:
    metadata:
      labels:
        app: ntp-controller
    spec:
      containers:
      - name: controller
        image: custom/ntp-controller:latest
        resources:
          limits:
            cpu: 100m
            memory: 128Mi
          requests:
            cpu: 50m
            memory: 64Mi
```

## Implementation Plan

### Phase 1: Core NTP Infrastructure
- Implement NTP CRD definitions
- Create Chrony container and base configuration
- Implement NTP Controller framework
- Set up basic NTP service

### Phase 2: Security and Integration
- Configure authentication and access controls
- Implement NTP-DHCP integration
- Set up NTP-DNS integration
- Configure firewall rules

### Phase 3: Monitoring and Management
- Implement NTP exporter
- Create Prometheus metrics
- Develop Grafana dashboards
- Set up alerting rules

### Phase 4: Advanced Features
- Implement hardware clock support (if available)
- Configure broadcast/multicast modes
- Set up NTS (Network Time Security)
- Develop management API

## Conclusion

This NTP implementation design provides a comprehensive solution for time synchronization in the router/firewall platform with:

1. Accurate and reliable time synchronization via Chrony
2. Support for diverse time sources including public pools and hardware clocks
3. Security features including NTS, authentication, and access controls
4. Per-VLAN NTP services with appropriate access controls
5. Comprehensive monitoring via Prometheus and Grafana
6. Seamless integration with DHCP and DNS services

The design prioritizes accuracy, security, and integration with other system components while remaining flexible for various deployment scenarios.