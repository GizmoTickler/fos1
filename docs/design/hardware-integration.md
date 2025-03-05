# Hardware Integration Design

## Overview

This document outlines the design for low-level hardware integration in the Kubernetes-based Router/Firewall system. It details how the system interacts with physical network interfaces, configures hardware features, and leverages eBPF for high-performance packet processing.

## Design Goals

- Provide direct integration with standard NICs (X540, X550, I225) through Linux kernel drivers
- Leverage selective hardware offloading capabilities (TX checksum, TSO, GRO) while maintaining visibility
- Enable seamless eBPF program loading and updates without downtime
- Support multiple WAN interfaces with failover and load balancing
- Implement IPv4 and IPv6 dual-stack with software-based NAT capabilities (NAT66, NPT) using eBPF
- Provide on-demand packet capture with filtering capabilities
- Configure VLANs with full trunk support and VLAN-specific services
- Support application identification and feed it into firewall rules
- Enable efficient traffic management for gaming and other latency-sensitive traffic types

## System Architecture

The hardware integration layer sits between the physical network hardware and the Kubernetes-based control plane. It consists of several key components:

1. **Network Interface Manager**: Configures and monitors physical network interfaces
2. **eBPF Program Manager**: Loads, updates, and manages eBPF programs for packet processing
3. **Hardware Offload Controller**: Configures hardware offloading features
4. **Packet Capture System**: Provides on-demand packet captures
5. **Multi-WAN Manager**: Handles WAN interface monitoring and failover
6. **Hardware-Accelerated NAT**: Implements NAT, NAT66, and NPT in eBPF

### Architecture Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                     Kubernetes Control Plane                    │
│                                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │NetworkIfaceCRD│  │  VLAN CRD  │  │   DPI CRD  │  │ NAT CRD │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────┬────┘ │
└─────────┼───────────────┼───────────────┼───────────────┼───────┘
          │               │               │               │
┌─────────┼───────────────┼───────────────┼───────────────┼───────┐
│         │               │               │               │       │
│  ┌──────▼──────┐  ┌─────▼─────┐  ┌──────▼──────┐  ┌────▼────┐  │
│  │  Interface  │  │   VLAN    │  │     DPI     │  │   NAT   │  │
│  │ Controller  │  │ Controller│  │  Controller │  │Controller│  │
│  └──────┬──────┘  └─────┬─────┘  └──────┬──────┘  └────┬────┘  │
│         │               │               │               │       │
│      ┌──▼───────────────▼───────────────▼───────────────▼───┐   │
│      │                Low-Level Manager Layer                │   │
│      │                                                       │   │
│      │  ┌───────────┐ ┌────────────┐ ┌─────────────┐        │   │
│      │  │ NIC Manager│ │eBPF Manager│ │Packet Capture│        │   │
│      │  └─────┬─────┘ └──────┬─────┘ └──────┬──────┘        │   │
│      └────────┼──────────────┼──────────────┼────────────────┘   │
│               │              │              │                    │
│   ┌───────────▼──────────────▼──────────────▼─────────────┐      │
│   │                     Cilium CNI                         │      │
│   │  ┌──────────┐   ┌──────────┐   ┌──────────┐           │      │
│   │  │ eBPF Maps │   │ eBPF Progs│   │ Cilium API│           │      │
│   │  └──────────┘   └──────────┘   └──────────┘           │      │
│   └─────────────────────────────────────────┬─────────────┘      │
│                                            │                     │
│                                    ┌───────▼────────┐            │
│                                    │ Linux Networking│            │
│                                    │   Subsystem    │            │
│                                    └───────┬────────┘            │
│                                            │                     │
│                                    ┌───────▼────────┐            │
│                                    │   Netlink API  │            │
│                                    └───────┬────────┘            │
│                                            │                     │
└────────────────────────────────────────────┼─────────────────────┘
                                             │
┌────────────────────────────────────────────┼─────────────────────┐
│                                    ┌───────▼────────┐            │
│                                    │  Hardware NIC  │            │
│                                    │  Drivers       │            │
│                                    └───────┬────────┘            │
│                                            │                     │
│                      ┌─────────────────────┼────────────────┐    │
│                      │                     │                │    │
│                ┌─────▼─────┐         ┌─────▼─────┐    ┌─────▼─────┐
│                │  I225 WAN  │         │  I225 WAN  │    │  X540 LAN  │
│                │ Interfaces │         │ Interfaces │    │ Interfaces │
│                └───────────┘         └───────────┘    └───────────┘
│                                                                    │
│                          Physical Hardware Layer                   │
└────────────────────────────────────────────────────────────────────┘
```

## Component Design

### Network Interface Manager

The Network Interface Manager handles the configuration of physical network interfaces, including:

- Interface state (up/down)
- IP addressing (IPv4 and IPv6)
- MTU configuration
- Hardware offloading features
- Interface statistics collection

```go
// Interface configuration through netlink
type NICManager struct {
    interfaces map[string]*NetworkInterface
    vlanManager *vlan.Manager
}

func (m *NICManager) ConfigureInterface(name string, config InterfaceConfig) error {
    // Create netlink handle
    h, err := netlink.NewHandle()
    if err != nil {
        return fmt.Errorf("failed to create netlink handle: %w", err)
    }
    defer h.Delete()
    
    // Get interface
    link, err := h.LinkByName(name)
    if err != nil {
        return fmt.Errorf("failed to get interface %s: %w", name, err)
    }
    
    // Configure MTU
    if config.MTU > 0 {
        if err := h.LinkSetMTU(link, config.MTU); err != nil {
            return fmt.Errorf("failed to set MTU: %w", err)
        }
    }
    
    // Configure hardware offloading if supported
    if config.EnableOffload {
        // Use ethtool to enable/disable specific offloads
        if err := m.configureOffload(name, config.OffloadFeatures); err != nil {
            return fmt.Errorf("failed to configure offload: %w", err)
        }
    }
    
    // Set interface up/down
    if config.Enabled {
        if err := h.LinkSetUp(link); err != nil {
            return fmt.Errorf("failed to set interface up: %w", err)
        }
    } else {
        if err := h.LinkSetDown(link); err != nil {
            return fmt.Errorf("failed to set interface down: %w", err)
        }
    }
    
    // Configure addresses
    for _, addr := range config.Addresses {
        // Parse CIDR
        ipNet, err := netlink.ParseIPNet(addr)
        if err != nil {
            return fmt.Errorf("failed to parse address %s: %w", addr, err)
        }
        
        // Add address
        nlAddr := &netlink.Addr{IPNet: ipNet}
        if err := h.AddrAdd(link, nlAddr); err != nil {
            return fmt.Errorf("failed to add address %s: %w", addr, err)
        }
    }
    
    return nil
}
```

### eBPF Program Manager

The eBPF Program Manager is responsible for loading, updating, and managing eBPF programs for packet processing:

- Loads pre-built and dynamically generated eBPF programs
- Attaches programs to network interfaces
- Manages eBPF maps for program configuration and state
- Performs atomic program updates for zero-downtime changes

```go
// eBPF program manager
type BPFProgramManager struct {
    // Maps to store loaded programs
    programs map[string]*ebpf.Program
    maps     map[string]*ebpf.Map
    
    // Hooks for program attachments
    xdpLinks map[string]link.Link
    tcLinks  map[string]link.Link
    
    // Mutex for program management
    mu sync.RWMutex
}

// LoadXDPProgram loads and attaches an XDP program to an interface
func (m *BPFProgramManager) LoadXDPProgram(ifName string, programType string, config map[string]interface{}) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // Get program spec based on type and config
    spec, err := m.getProgramSpec(programType, config)
    if err != nil {
        return fmt.Errorf("failed to get program spec: %w", err)
    }
    
    // Load program
    prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
        Logger: logrus.WithField("component", "ebpf-loader"),
    })
    if err != nil {
        return fmt.Errorf("failed to load XDP program: %w", err)
    }
    
    // Find interface
    iface, err := net.InterfaceByName(ifName)
    if err != nil {
        prog.Close()
        return fmt.Errorf("interface %s not found: %w", ifName, err)
    }
    
    // Attach XDP program
    l, err := link.AttachXDP(link.XDPOptions{
        Program:   prog,
        Interface: iface.Index,
        // Don't use XDP_FLAGS_HW_MODE to maintain consistent behavior
        Flags: unix.XDP_FLAGS_DRV_MODE,
    })
    if err != nil {
        prog.Close()
        return fmt.Errorf("failed to attach XDP program: %w", err)
    }
    
    // Store program and link
    progID := fmt.Sprintf("%s-%s", ifName, programType)
    m.programs[progID] = prog
    m.xdpLinks[progID] = l
    
    return nil
}
```

### Hardware Offload Controller

The Hardware Offload Controller configures hardware offloading features while maintaining visibility:

```go
func (m *NICManager) configureOffload(ifName string, features OffloadFeatures) error {
    // Use ethtool to configure hardware offloading
    ethtool := ethtool.New()
    defer ethtool.Close()
    
    // Get supported features
    supportedFeatures, err := ethtool.Features(ifName)
    if err != nil {
        return fmt.Errorf("failed to get supported features: %w", err)
    }
    
    // Configure TX checksum offload
    if _, ok := supportedFeatures["tx-checksumming"]; ok {
        if err := ethtool.Change(ifName, "tx-checksumming", features.TXChecksum); err != nil {
            return fmt.Errorf("failed to configure TX checksum offload: %w", err)
        }
    }
    
    // Configure TSO (TCP Segmentation Offload)
    if _, ok := supportedFeatures["tso"]; ok {
        if err := ethtool.Change(ifName, "tso", features.TSO); err != nil {
            return fmt.Errorf("failed to configure TSO: %w", err)
        }
    }
    
    // Configure GRO (Generic Receive Offload) - keep this enabled for performance
    // but packets will be merged when they reach our stack
    if _, ok := supportedFeatures["gro"]; ok {
        if err := ethtool.Change(ifName, "gro", features.GRO); err != nil {
            return fmt.Errorf("failed to configure GRO: %w", err)
        }
    }
    
    // Configure LRO (Large Receive Offload) - typically disable for visibility
    if _, ok := supportedFeatures["lro"]; ok {
        if err := ethtool.Change(ifName, "lro", features.LRO); err != nil {
            return fmt.Errorf("failed to configure LRO: %w", err)
        }
    }
    
    return nil
}
```

### Packet Capture System

The Packet Capture System provides on-demand packet captures with filtering capabilities:

```go
// Packet capture manager
type PacketCaptureManager struct {
    captureMap  *ebpf.Map
    captureDir  string
    maxCaptures int
    mu          sync.Mutex
    activeCaps  map[string]*Capture
}

// StartCapture starts a packet capture matching the filter
func (m *PacketCaptureManager) StartCapture(req CaptureRequest) (*Capture, error) {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // Check if we've reached max captures
    if len(m.activeCaps) >= m.maxCaptures {
        return nil, errors.New("maximum number of concurrent captures reached")
    }
    
    // Create capture ID
    captureID := uuid.New().String()
    
    // Create capture file
    captureFile := filepath.Join(m.captureDir, captureID+".pcap")
    f, err := os.Create(captureFile)
    if err != nil {
        return nil, fmt.Errorf("failed to create capture file: %w", err)
    }
    
    // Create pcap writer
    writer, err := pcapgo.NewWriter(f)
    if err != nil {
        f.Close()
        os.Remove(captureFile)
        return nil, fmt.Errorf("failed to create pcap writer: %w", err)
    }
    
    // Write pcap header
    if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
        f.Close()
        os.Remove(captureFile)
        return nil, fmt.Errorf("failed to write pcap header: %w", err)
    }
    
    // Convert filter to BPF filter program
    filter, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, req.Filter)
    if err != nil {
        f.Close()
        os.Remove(captureFile)
        return nil, fmt.Errorf("invalid capture filter: %w", err)
    }
    
    // Update capture map with filter program
    key := captureID
    if err := m.captureMap.Update(key, filter, ebpf.UpdateAny); err != nil {
        f.Close()
        os.Remove(captureFile)
        return nil, fmt.Errorf("failed to update capture map: %w", err)
    }
    
    // Create capture object
    cap := &Capture{
        ID:       captureID,
        File:     f,
        Writer:   writer,
        Request:  req,
        StartTime: time.Now(),
    }
    
    // Store capture
    m.activeCaps[captureID] = cap
    
    // Start background goroutine to enforce max duration
    go func() {
        timer := time.NewTimer(req.MaxDuration)
        defer timer.Stop()
        
        <-timer.C
        m.StopCapture(captureID)
    }()
    
    return cap, nil
}
```

### Multi-WAN Manager

The Multi-WAN Manager handles WAN interface monitoring and failover:

```go
// WAN manager for multi-WAN management
type WANManager struct {
    wanInterfaces map[string]*WANInterface
    mu            sync.RWMutex
    routeManager  *RouteManager
}

// WANInterface represents a WAN interface
type WANInterface struct {
    Name          string
    Weight        int
    Online        bool
    LastChecked   time.Time
    MonitorConfig WANMonitorConfig
}

// WANMonitorConfig defines how to monitor a WAN interface
type WANMonitorConfig struct {
    PingHosts     []string
    PingInterval  time.Duration
    FailureThreshold int
    RecoveryThreshold int
}

// StartMonitoring begins monitoring all WAN interfaces
func (m *WANManager) StartMonitoring(ctx context.Context) {
    for _, iface := range m.wanInterfaces {
        go m.monitorWANInterface(ctx, iface)
    }
}

// monitorWANInterface monitors a single WAN interface
func (m *WANManager) monitorWANInterface(ctx context.Context, iface *WANInterface) {
    ticker := time.NewTicker(iface.MonitorConfig.PingInterval)
    defer ticker.Stop()
    
    failures := 0
    recoveries := 0
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            // Check WAN connectivity
            online := m.checkWANConnectivity(iface)
            
            m.mu.Lock()
            
            if online {
                // Interface is online
                recoveries++
                failures = 0
                
                if !iface.Online && recoveries >= iface.MonitorConfig.RecoveryThreshold {
                    // Interface has recovered
                    iface.Online = true
                    m.updateRouting()
                }
            } else {
                // Interface is offline
                failures++
                recoveries = 0
                
                if iface.Online && failures >= iface.MonitorConfig.FailureThreshold {
                    // Interface has failed
                    iface.Online = false
                    m.updateRouting()
                }
            }
            
            iface.LastChecked = time.Now()
            m.mu.Unlock()
        }
    }
}
```

### eBPF-Based NAT System

The eBPF-Based NAT system implements NAT, NAT66, and NPT in eBPF for high-performance software-based network address translation:

```go
// Create NAT configuration with NAT66 support
func (m *NATManager) ConfigureNAT66(config NAT66Config) error {
    // Create NAT66 maps - using LRU_HASH for efficient memory usage
    natMap, err := ebpf.NewMap(&ebpf.MapSpec{
        Type:       ebpf.BPF_MAP_TYPE_LRU_HASH,
        KeySize:    sizeof(nat.IPv6Key),
        ValueSize:  sizeof(nat.IPv6Value),
        MaxEntries: config.MaxEntries,
        Flags:      0,
        Name:       "nat66_map",
    })
    if err != nil {
        return fmt.Errorf("failed to create NAT66 map: %w", err)
    }
    
    // Create NAT66 program at TC hook for better integration with connection tracking
    // Using TC instead of XDP for stateful NAT functionality
    natProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
        Name:    "nat66",
        Type:    ebpf.SchedCLS, // TC classifier for stateful NAT
        License: "GPL",
        Instructions: generateNAT66Instructions(config),
    })
    if err != nil {
        natMap.Close()
        return fmt.Errorf("failed to create NAT66 program: %w", err)
    }
    
    // Create connection tracking map for stateful NAT
    ctMap, err := ebpf.NewMap(&ebpf.MapSpec{
        Type:       ebpf.BPF_MAP_TYPE_LRU_HASH,
        KeySize:    sizeof(nat.ConnectionKey),
        ValueSize:  sizeof(nat.ConnectionInfo),
        MaxEntries: config.MaxConnections,
        Flags:      0,
        Name:       "nat66_ct_map",
    })
    if err != nil {
        natProg.Close()
        natMap.Close()
        return fmt.Errorf("failed to create connection tracking map: %w", err)
    }
    
    // Configure NAT66 translation entries
    for _, entry := range config.Translations {
        key := nat.IPv6Key{
            Src: net.ParseIP(entry.SourcePrefix),
            Dst: net.ParseIP(entry.DestinationIP),
        }
        
        value := nat.IPv6Value{
            TranslatedSrc: net.ParseIP(entry.TranslatedSourcePrefix),
            TranslatedDst: net.ParseIP(entry.TranslatedDestinationIP),
        }
        
        if err := natMap.Update(key, value, ebpf.UpdateAny); err != nil {
            ctMap.Close()
            natProg.Close()
            natMap.Close()
            return fmt.Errorf("failed to update NAT66 map: %w", err)
        }
    }
    
    // Store NAT66 program and maps
    m.nat66Program = natProg
    m.nat66Map = natMap
    m.nat66CTMap = ctMap
    
    return nil
}
```

## Integration with Existing Components

### Cilium Integration

The hardware integration layer integrates closely with Cilium:

- Uses Cilium's eBPF library for program and map management
- Leverages Cilium's XDP and TC hooks for packet processing
- Integrates with Cilium's Network Policy engine for firewall rules
- Uses Cilium's Hubble for network flow monitoring

```go
// Cilium-based hardware integration
type CiliumHardwareManager struct {
    client   cilium.Client
    nodeName string
    config   *HardwareConfig
}

// Initialize Cilium with hardware awareness
func (m *CiliumHardwareManager) Initialize() error {
    // Detect hardware capabilities for X540/X550 and I225 NICs
    capabilities, err := m.detectHardwareCapabilities()
    if err != nil {
        return fmt.Errorf("failed to detect hardware capabilities: %w", err)
    }
    
    // Configure Cilium CNI with hardware-specific settings
    ciliumConfig := cilium.Config{
        // Base configuration
        TunnelMode: "disabled", // Use native routing
        
        // XDP for packet processing
        EnableXDPPrefilter: true, // Intel NICs support XDP
        PrefilterDevices:   m.config.XDPDevices,
        
        // Software-based packet processing
        EnableBPFTProxy:       true,
        EnableHostReachableServices: true,
        
        // Software NAT configuration
        EnableIPv4Masquerade: true, 
        EnableIPv6Masquerade: true,
        EnableNAT46:          m.config.EnableNAT46,
        EnableNAT64:          m.config.EnableNAT64,
        
        // Multi-queue support for X540/X550 (up to 64 queues)
        DevicePreFilter: capabilities.SupportsDevicePreFilter,
        
        // Use all available queues
        MaxQueueSize: 65535,
        NumQueues:    capabilities.MaxQueues, // Up to 64 for X540/X550
        
        // Datapath configuration
        DatapathMode:  "native",
        ProcFs:        "/proc",
    }
    
    // Create node-specific configuration
    return m.client.ConfigureNode(m.nodeName, ciliumConfig)
}
```

### DPI Integration

The hardware integration connects with the DPI system to enable application-aware policies:

```go
// DPI-aware Firewall Program Generator
type DPIFirewallGenerator struct {
    dpiManager *dpi.Manager
    cilium     cilium.Client
}

// Generate a firewall policy based on DPI results
func (g *DPIFirewallGenerator) GeneratePolicy(appID string, action string) (*cilium.NetworkPolicy, error) {
    // Get application info from DPI manager
    app, err := g.dpiManager.GetApplicationInfo(appID)
    if err != nil {
        return nil, fmt.Errorf("failed to get application info: %w", err)
    }
    
    // Create policy name
    policyName := fmt.Sprintf("app-%s", appID)
    
    // Create policy
    policy := &cilium.NetworkPolicy{
        Name: policyName,
        Labels: map[string]string{
            "app":         appID,
            "category":    app.Category,
            "generated":   "true",
            "auto-policy": "true",
        },
    }
    
    // Configure policy based on action
    switch action {
    case "allow":
        // Create allow policy
        policy.Ingress = []cilium.IngressRule{
            {
                ToPorts: []cilium.PortRule{
                    {
                        Ports: []cilium.PortProtocol{
                            {
                                Port:     "*",
                                Protocol: "TCP",
                            },
                            {
                                Port:     "*",
                                Protocol: "UDP",
                            },
                        },
                        Rules: map[string][]string{
                            "l7proto": {appID},
                        },
                    },
                },
            },
        }
        
    case "block":
        // Create block policy
        policy.Ingress = []cilium.IngressRule{
            {
                ToPorts: []cilium.PortRule{
                    {
                        Ports: []cilium.PortProtocol{
                            {
                                Port:     "*",
                                Protocol: "TCP",
                            },
                            {
                                Port:     "*",
                                Protocol: "UDP",
                            },
                        },
                        Rules: map[string][]string{
                            "l7proto": {appID},
                        },
                    },
                },
                Denied: true,
            },
        }
        
    case "qos":
        // Create QoS policy
        policy.Ingress = []cilium.IngressRule{
            {
                ToPorts: []cilium.PortRule{
                    {
                        Ports: []cilium.PortProtocol{
                            {
                                Port:     "*",
                                Protocol: "TCP",
                            },
                            {
                                Port:     "*",
                                Protocol: "UDP",
                            },
                        },
                        Rules: map[string][]string{
                            "l7proto": {appID},
                        },
                    },
                },
                DSCP: app.DefaultDSCP,
            },
        }
        
    default:
        return nil, fmt.Errorf("unknown action: %s", action)
    }
    
    return policy, nil
}
```

## Kubernetes Integration

The hardware integration exposes its capabilities through Kubernetes CRDs:

### NetworkInterface CRD

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NetworkInterface
metadata:
  name: wan1
spec:
  name: "enp1s0" # The I225 interface 
  type: "physical"
  enabled: true
  mtu: 1500
  addresses:
    - "192.168.1.2/24"
    - "2001:db8::2/64"
  offload:
    enabled: true
    features:
      txChecksumming: true
      tso: true
      gro: true
      lro: false
  wan:
    enabled: true
    weight: 100
    monitor:
      pingHosts:
        - "8.8.8.8"
        - "1.1.1.1"
      pingInterval: "5s"
      failureThreshold: 3
      recoveryThreshold: 2
```

### VLANInterface CRD

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: VLANInterface
metadata:
  name: vlan10
spec:
  parent: "enp7s0" # X540 interface
  vlanID: 10
  name: "vlan10"
  enabled: true
  mtu: 1500
  addresses:
    - "10.10.0.1/24"
    - "fd00:10::1/64"
  services:
    dhcp:
      enabled: true
      ipv4Range:
        start: "10.10.0.100"
        end: "10.10.0.200"
      ipv6Prefix: "fd00:10::/64"
      dynamicDns: true
    dns:
      enabled: true
      domain: "vlan10.local"
```

### NATConfig CRD

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: NATConfig
metadata:
  name: ipv6-nat
spec:
  type: "nat66"
  enabled: true
  sourceNetwork: "fd00:1::/64"
  externalPrefix: "2001:db8::/64"
  translations:
    - sourcePrefix: "fd00:1::/64"
      translatedSourcePrefix: "2001:db8::/64"
  stateful: true
```

### PacketCapture CRD

```yaml
apiVersion: network.fos1.io/v1alpha1
kind: PacketCapture
metadata:
  name: http-capture
spec:
  interface: "vlan10"
  filter: "tcp port 80"
  maxDuration: "5m"
  maxSize: "100MB"
```

## Controller Design

Controllers watch the CRDs and translate them into low-level configurations:

```go
// NetworkInterfaceController watches NetworkInterface CRDs and configures hardware
type NetworkInterfaceController struct {
    client        kubernetes.Interface
    informer      cache.SharedIndexInformer
    nicManager    *NICManager
    bpfManager    *BPFProgramManager
    wanManager    *WANManager
}

// Run starts the controller
func (c *NetworkInterfaceController) Run(stopCh <-chan struct{}) error {
    // Start informer
    go c.informer.Run(stopCh)
    
    // Wait for cache sync
    if !cache.WaitForCacheSync(stopCh, c.informer.HasSynced) {
        return errors.New("failed to sync cache")
    }
    
    // Start processing events
    go c.processNetworkInterfaceEvents()
    
    return nil
}

// processNetworkInterfaceEvents processes NetworkInterface events
func (c *NetworkInterfaceController) processNetworkInterfaceEvents() {
    // Add event handlers
    c.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(obj interface{}) {
            c.handleNetworkInterfaceAdd(obj)
        },
        UpdateFunc: func(oldObj, newObj interface{}) {
            c.handleNetworkInterfaceUpdate(oldObj, newObj)
        },
        DeleteFunc: func(obj interface{}) {
            c.handleNetworkInterfaceDelete(obj)
        },
    })
}
```

## Performance Considerations

1. **Selective Hardware Offloading**
   - Enable hardware offloading for TX checksum, TSO, and GRO based on tested compatibility
   - Disable LRO to maintain packet visibility for DPI
   - Use XDP in driver mode for consistent behavior across your Intel NICs
   - Utilize NIC multi-queue capabilities (X540/X550 supports up to 64 queues)

2. **eBPF Optimization**
   - Use pre-compiled programs for performance-critical paths
   - Use dynamic configuration through eBPF maps
   - Perform atomic program replacements for zero-downtime updates
   - Place NAT functionality in TC hooks rather than XDP for stateful operations

3. **Memory and CPU Optimization**
   - Size eBPF maps based on expected traffic patterns
   - Use LRU maps for connection tracking to limit memory usage
   - Implement dynamic scaling of map sizes based on load
   - Distribute processing across CPU cores using RSS (Receive Side Scaling)

4. **Specialized Traffic Handling**
   - Configure software-based QoS for gaming traffic with low latency priority
   - Utilize multiple hardware queues for traffic separation
   - Implement fast-path processing for established connections
   - Use appropriate DSCP markings for traffic classification

## Monitoring and Observability

1. **eBPF Program Metrics**
   - Packet counts and byte counts per program
   - Program run time and errors
   - Map usage statistics

2. **Interface Metrics**
   - Link status and bandwidth usage
   - Error counts and buffer status
   - Hardware offload statistics

3. **Flow Monitoring**
   - Use Hubble for detailed flow visibility
   - Track connection statistics per application
   - Monitor geolocation-based traffic patterns

## Implementation Plan

1. **Phase 1: Core Hardware Integration**
   - Implement Network Interface Manager
   - Develop eBPF Program Manager
   - Create basic CRDs and controllers

2. **Phase 2: Advanced Features**
   - Implement Packet Capture System
   - Develop Multi-WAN Manager
   - Create Hardware-Accelerated NAT

3. **Phase 3: Integration and Testing**
   - Integrate with Cilium and DPI components
   - Perform performance testing
   - Optimize for target hardware

4. **Phase 4: Documentation and Deployment**
   - Document hardware requirements
   - Create deployment guides
   - Develop troubleshooting procedures

## Security Considerations

1. **Access Control**
   - CRDs protected by Kubernetes RBAC
   - Privileged operations require elevated permissions
   - Audit logging for all hardware configuration changes

2. **Packet Processing Security**
   - eBPF programs verified by kernel verifier
   - Hardened default configurations
   - Secure defaults for interfaces and services