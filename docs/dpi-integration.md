# Deep Packet Inspection (DPI) Integration

This document details the integration of Deep Packet Inspection capabilities with the Kubernetes-based router/firewall system, including its interaction with firewall rules, Quality of Service (QoS), and Policy-Based Routing (PBR).

## Overview

DPI provides visibility into application-layer traffic, enabling the system to make intelligent decisions based on traffic content rather than just headers. This capability is essential for advanced security, traffic management, and application-specific routing.

## DPI Components

### Primary DPI Technologies

1. **nProbe**
   - Application recognition and fingerprinting
   - NetFlow/IPFIX export for traffic analysis
   - Traffic classification for QoS and policy enforcement
   - Flow collection for long-term traffic analysis

2. **Suricata**
   - Signature-based traffic inspection
   - Protocol analysis and anomaly detection
   - Intrusion detection and prevention capabilities
   - High-performance packet capture and analysis

3. **Zeek** (formerly Bro)
   - Deep protocol analysis for common services
   - Behavioral anomaly detection
   - Session tracking and connection analysis
   - Event-based programming model for custom analysis

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                Packet Processing Pipeline                  │
└───────────┬───────────────────────────────┬───────────────┘
            │                               │
            ▼                               ▼
┌───────────────────────┐      ┌───────────────────────────┐
│   Fast Path (XDP/eBPF) │      │    Slow Path (Detailed)   │
│                        │      │                           │
│ - Header-based routing │      │ - Full packet inspection  │
│ - Basic packet filters │      │ - Signature matching      │
│ - Performance-critical │      │ - Protocol analysis       │
└────────────┬───────────┘      └─────────────┬─────────────┘
             │                                │
             ▼                                ▼
┌──────────────────────────────────────────────────────────┐
│                    Integration Layer                      │
│                                                          │
│  ┌───────────────┐   ┌───────────────┐  ┌──────────────┐ │
│  │ Event Streams │   │ Flow Records  │  │ Rule Updates │ │
│  └───────┬───────┘   └───────┬───────┘  └──────┬───────┘ │
│          │                   │                  │         │
└──────────┼───────────────────┼──────────────────┼─────────┘
           │                   │                  │
           ▼                   ▼                  ▼
┌──────────────────┐  ┌────────────────┐  ┌────────────────┐
│ Security Systems │  │ Traffic Mgmt.  │  │ Policy Engine  │
│  - Firewall      │  │  - QoS         │  │  - Routing     │
│  - IDS/IPS       │  │  - Shaping     │  │  - NAT         │
└──────────────────┘  └────────────────┘  └────────────────┘
```

## Integration with System Components

### 1. Firewall Integration

#### Data Flow
- DPI engines analyze traffic and generate events
- Events are processed by the integration layer
- Firewall rules are dynamically updated based on traffic analysis

#### Implementation Details
- **Rule Generation**: DPI results trigger dynamic firewall rule creation
- **Connection Tracking**: Stateful inspection combined with application awareness
- **Threat Response**: Automatic blocking of malicious traffic identified by signatures
- **Application Control**: Allow/deny rules based on recognized applications

#### Technical Approach
```go
// Example Go code for firewall integration
type DPIEvent struct {
    Protocol    string
    Application string
    Risk        int
    Signature   string
    SessionID   string
}

func ProcessDPIEvent(event DPIEvent) {
    if event.Risk > THRESHOLD {
        // Create firewall rule to block traffic
        rule := CreateFirewallRule(event)
        ApplyFirewallRule(rule)
    }
}
```

### 2. QoS Integration

#### Data Flow
- nProbe classifies traffic by application type
- Classification data is fed to QoS engine
- Traffic is queued and prioritized based on application type

#### Implementation Details
- **Traffic Classification**: Application-aware traffic categorization
- **Bandwidth Allocation**: Per-application bandwidth guarantees or limits
- **Priority Queuing**: Higher priority for critical applications
- **DSCP Marking**: Setting appropriate DSCP values based on traffic type

#### Technical Approach
- Traffic classes defined in ConfigMap
- nProbe exports classifications to etcd
- QoS controller watches for changes and updates tc (traffic control) rules
- eBPF programs enforce QoS at high speed

```yaml
# Example QoS configuration with DPI integration
apiVersion: networking.fos1.io/v1
kind: QoSPolicy
metadata:
  name: default-qos-policy
spec:
  classes:
    - name: voip
      applications: ["sip", "rtp", "skype", "teams", "zoom"]
      priority: high
      bandwidth:
        min: 20%
        max: 40%
    - name: web
      applications: ["http", "https"]
      priority: medium
      bandwidth:
        min: 10%
        max: 60%
    - name: bulk
      applications: ["bittorrent", "ftp", "storage"]
      priority: low
      bandwidth:
        max: 20%
```

### 3. Policy-Based Routing Integration

#### Data Flow
- DPI identifies application or protocol
- Policy engine evaluates routing rules
- Packets are marked for specific routing decisions

#### Implementation Details
- **Application-Aware Routing**: Direct specific applications through preferred paths
- **Multi-WAN Management**: Use specific uplinks for certain applications
- **VPN Selection**: Route sensitive applications through secure tunnels
- **Traffic Steering**: Direct traffic to inspection devices based on content

#### Technical Approach
- Cilium's Layer 7 visibility provides application identification
- Custom CRDs define application-based routing policies
- eBPF maps store routing decisions for high-performance lookups

```yaml
# Example PBR configuration with DPI integration
apiVersion: networking.fos1.io/v1
kind: RoutingPolicy
metadata:
  name: application-routing
spec:
  rules:
    - name: streaming-via-isp2
      applications: ["netflix", "youtube", "spotify"]
      action:
        routeVia: isp2
    - name: business-via-mpls
      applications: ["salesforce", "office365", "webex"]
      action:
        routeVia: mpls
    - name: guest-via-internet
      networkSegment: guest
      action:
        routeVia: default-internet
```

## Implementation Strategy

### Phase 1: Infrastructure Setup
1. Deploy base packet capture infrastructure
2. Implement nProbe, Suricata, and Zeek containers
3. Configure basic event collection and storage

### Phase 2: Event Integration
1. Develop common event format for all DPI components
2. Create integration layer in Go for event processing
3. Implement etcd-based state synchronization

### Phase 3: Firewall Integration
1. Develop dynamic rule generation from DPI events
2. Implement connection tracking with application awareness
3. Create threat intelligence integration

### Phase 4: QoS Integration
1. Implement traffic classification based on nProbe data
2. Develop QoS controller for managing tc rules
3. Configure DSCP marking based on application type

### Phase 5: Policy-Based Routing
1. Develop application-aware routing infrastructure
2. Implement multi-WAN routing based on DPI data
3. Create path selection logic for different applications

## Performance Considerations

### Fast Path vs. Slow Path
- Use eBPF/XDP for high-performance, basic classification
- Selectively forward traffic for detailed inspection
- Maintain state between fast and slow paths

### Scaling Strategy
- Horizontally scale DPI components for higher throughput
- Use packet sampling for high-volume traffic
- Cache DPI results for similar flows

### Resource Utilization
- Monitor CPU and memory usage of DPI components
- Implement adaptive sampling based on system load
- Optimize packet capture and processing pipeline

## Operational Aspects

### Monitoring
- Dashboards for DPI performance and detection metrics
- Alerts for significant detection events
- Statistics on application distribution

### Management
- APIs for managing DPI rule sets
- Integration with GitOps workflow
- Configuration versioning and rollback

## Conclusion

This integrated DPI approach provides deep visibility into network traffic while enabling intelligent security, QoS, and routing decisions. The layered architecture separates high-performance packet processing from detailed inspection, ensuring both security and performance goals are met.

Future enhancements may include machine learning-based traffic analysis, encrypted traffic inspection capabilities, and integration with external threat intelligence platforms.