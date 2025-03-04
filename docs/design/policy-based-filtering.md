# Policy-Based Filtering System Design

## Overview

This document outlines the design for a Policy-Based Filtering (PBF) system that leverages Cilium's capabilities to provide comprehensive network traffic filtering. The system extends Cilium's native policy model with additional abstraction layers that support hierarchical policies, application-aware filtering, and integration with other security components.

## Design Goals

1. **Comprehensive Filtering**: Support both L3/L4 filtering and L7 application filtering
2. **Hierarchical Policies**: Implement multi-level policy inheritance and composition
3. **Cilium Integration**: Extend Cilium using custom CRDs that translate to CiliumNetworkPolicies
4. **Application Awareness**: Enable filtering based on application properties and metadata
5. **Simplified Management**: Provide intuitive policy abstractions for complex filtering requirements
6. **Component Integration**: Integrate with the DPI system and security orchestration framework
7. **Detailed Logging**: Provide comprehensive, centralized logging of policy decisions

## System Architecture

### Core Components

1. **Policy Controller** (`pkg/security/policy/controller.go`):
   - Watches for custom policy CRDs
   - Validates policy definitions
   - Translates custom policies to CiliumNetworkPolicies
   - Manages policy lifecycle

2. **Policy Resolver** (`pkg/security/policy/resolver.go`):
   - Resolves hierarchical policy dependencies
   - Handles policy inheritance and overrides
   - Manages policy conflict resolution
   - Generates effective policies

3. **Policy Translator** (`pkg/security/policy/translator.go`):
   - Converts resolved policies to Cilium policies
   - Maps custom abstractions to Cilium constructs
   - Handles L7 policy translation
   - Optimizes generated policies

4. **Policy Monitor** (`pkg/security/policy/monitor.go`):
   - Tracks policy application status
   - Collects policy match statistics
   - Provides logging and alerting
   - Offers policy analysis tools

### Integration with Existing Components

The PBF system integrates with several existing components:

1. **Security Orchestration System**:
   - Policy Controller is implemented as part of the Security Coordinator
   - Shares the event bus for policy-related events
   - Uses the security system's logging infrastructure
   - Participates in security workflows

2. **DPI System**:
   - Uses application detection results for filtering
   - Filters based on application metadata
   - Applies policies based on DPI classification

3. **Cilium Integration**:
   - Extends Cilium's policy model
   - Uses CiliumNetworkPolicies for enforcement
   - Leverages Cilium's eBPF capabilities
   - Utilizes Cilium's L7 proxy for application filtering

## Policy Model

### Hierarchical Policy Framework

The system implements a hierarchical policy model with five levels:

1. **Global Policies**: System-wide policies that apply to all traffic
2. **Zone Policies**: Policies for specific security zones (e.g., DMZ, Internal)
3. **Network Policies**: Policies for specific networks or subnets
4. **Host Policies**: Policies for specific hosts or workloads
5. **Application Policies**: Policies for specific applications

Each level can inherit from and override higher levels, with clear precedence rules:

```
Application > Host > Network > Zone > Global
```

### Policy Inheritance and Overrides

Policies follow an inheritance model where:

1. Child policies inherit rules from parent policies
2. Child policies can override specific inherited rules
3. Child policies can add new rules specific to their scope
4. Conflicts are resolved based on explicit priorities

The system supports both:
- **Explicit inheritance**: Policies directly reference parent policies
- **Implicit inheritance**: Policies automatically inherit based on scope

### Custom Resource Definitions

#### 1. FilterPolicy CRD

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FilterPolicy
metadata:
  name: example-policy
spec:
  # Policy metadata
  description: "Example filtering policy"
  scope: "global"  # global, zone, network, host, application
  enabled: true
  priority: 100
  
  # Parent policies (for inheritance)
  inherits:
    - name: base-policy
      overrideStrategy: merge  # merge, replace, append
  
  # Matching criteria
  selectors:
    # Network selectors
    sources:
      - type: cidr
        values: ["10.0.0.0/8", "192.168.1.0/24"]
      - type: zone
        values: ["internal"]
    
    destinations:
      - type: cidr
        values: ["0.0.0.0/0"]
      - type: service
        values: ["web-servers"]
    
    # Application selectors
    applications:
      - type: protocol
        values: ["HTTP", "HTTPS"]
      - type: metadata
        key: "tls.sni"
        operator: "contains"
        values: ["example.com"]
    
    # Additional selectors
    ports:
      - protocol: tcp
        ports: [80, 443]
    
    # Time-based selectors (optional)
    timeWindows:
      - days: ["monday", "tuesday", "wednesday", "thursday", "friday"]
        startTime: "09:00"
        endTime: "17:00"
        timezone: "UTC"
  
  # Actions to take on matched traffic
  actions:
    - type: allow  # allow, deny, log, ratelimit, dscp
      parameters:
        log: true
        logLevel: "info"
    
    - type: ratelimit
      parameters:
        rate: 100
        burst: 20
        per: "source.ip"
```

#### 2. FilterZone CRD

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FilterZone
metadata:
  name: internal-zone
spec:
  description: "Internal network zone"
  
  # Zone membership criteria
  networks:
    - cidr: "10.0.0.0/8"
    - cidr: "172.16.0.0/12"
  
  # Interface definitions (optional)
  interfaces:
    - name: "eth1"
      description: "Internal interface"
  
  # Trust level (used for default policies)
  trustLevel: high  # high, medium, low, untrusted
  
  # Default action for inter-zone traffic
  defaultIngressAction: deny
  defaultEgressAction: allow
  
  # Zone-specific policy references
  policies:
    - name: "internal-base-policy"
    - name: "internal-app-policy"
```

#### 3. FilterPolicyGroup CRD

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FilterPolicyGroup
metadata:
  name: web-access-policies
spec:
  description: "Grouped policies for web access"
  
  # Member policies
  policies:
    - name: "web-allow-internal"
    - name: "web-restrict-external"
  
  # Group-wide settings
  enabled: true
  priority: 50
  
  # Override settings
  overrides:
    - policyName: "web-allow-internal"
      enabled: true
      priority: 60
```

### Policy Rules and Actions

The system supports a variety of rules and actions:

1. **Network Rules**:
   - Source/destination IP/CIDR matching
   - Protocol/port matching
   - Zone-based matching
   - Interface-based matching

2. **Application Rules**:
   - Protocol identification (HTTP, DNS, etc.)
   - Metadata matching (headers, SNI, etc.)
   - Application categorization
   - Application properties

3. **Actions**:
   - Allow/Deny: Basic allow or deny traffic
   - Log: Record matching traffic
   - Rate Limit: Apply bandwidth or request limits
   - DSCP: Mark traffic for QoS handling
   - Redirect: Send traffic to another destination
   - Monitor: Track traffic without filtering

## Policy Translation

### Translation Process

The translation process converts custom policies to Cilium policies:

1. **Policy Resolution**:
   - Resolve hierarchical dependencies
   - Apply inheritance and overrides
   - Resolve conflicts
   - Generate effective policies

2. **Policy Normalization**:
   - Convert complex selectors to basic selectors
   - Normalize actions
   - Optimize rule combinations
   - Prepare for translation

3. **Cilium Translation**:
   - Map selectors to Cilium selectors
   - Convert rules to Cilium rules
   - Map actions to Cilium policy elements
   - Generate CiliumNetworkPolicy objects

4. **Policy Application**:
   - Apply generated policies to Kubernetes
   - Monitor application status
   - Handle errors and retries
   - Update policy status

### Example Translation

A high-level policy like:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FilterPolicy
metadata:
  name: web-access
spec:
  scope: "zone"
  selectors:
    sources:
      - type: zone
        values: ["internal"]
    destinations:
      - type: service
        values: ["web-servers"]
    applications:
      - type: protocol
        values: ["HTTP", "HTTPS"]
  actions:
    - type: allow
      parameters:
        log: true
```

Would translate to a CiliumNetworkPolicy like:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: web-access
spec:
  description: "Allow internal access to web servers"
  endpointSelector:
    matchLabels:
      app: web-servers
  ingress:
    - fromEndpoints:
        - matchLabels:
            zone: internal
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
            - port: "443"
              protocol: TCP
          rules:
            http:
              - {}  # Allow all HTTP
  egress: []
```

## L7 Application Filtering

### Application Property Filtering

The system supports filtering based on application properties without content inspection:

1. **HTTP Properties**:
   - Method (GET, POST, etc.)
   - Path/URL patterns
   - Headers (without inspecting values)
   - Query parameters (existence, not values)

2. **DNS Properties**:
   - Query type (A, AAAA, MX, etc.)
   - Domain patterns
   - Response code

3. **TLS Properties**:
   - SNI (Server Name Indication)
   - Certificate attributes
   - Protocol version
   - Cipher suites

Example application policy:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FilterPolicy
metadata:
  name: http-filtering
spec:
  scope: "application"
  selectors:
    applications:
      - type: protocol
        values: ["HTTP"]
      - type: properties
        key: "http.method"
        operator: "in"
        values: ["GET", "HEAD"]
      - type: properties
        key: "http.path"
        operator: "startsWith"
        values: ["/api/", "/public/"]
  actions:
    - type: allow
```

### Metadata-Based Filtering

For encrypted traffic, the system offers metadata-based filtering:

1. **TLS SNI Filtering**:
   - Filter based on requested domain
   - Domain pattern matching
   - Whitelist/blacklist approach

2. **Certificate Filtering**:
   - Issuer attributes
   - Certificate validity
   - Public key properties

Example TLS metadata policy:

```yaml
apiVersion: security.fos1.io/v1alpha1
kind: FilterPolicy
metadata:
  name: tls-filtering
spec:
  scope: "application"
  selectors:
    applications:
      - type: protocol
        values: ["TLS"]
      - type: metadata
        key: "tls.sni"
        operator: "endsWith"
        values: [".example.com", ".trusted-domain.org"]
      - type: metadata
        key: "tls.cert.issuer"
        operator: "contains"
        values: ["Let's Encrypt", "DigiCert"]
  actions:
    - type: allow
```

## Integration with DPI System

### Leveraging DPI Results

The policy system integrates with the DPI system by:

1. **Application-Based Filtering**:
   - Using DPI application identification results
   - Filtering based on detected applications
   - Applying application-specific policies

2. **Metadata Utilization**:
   - Using protocol metadata extracted by DPI
   - Applying metadata-based rules
   - Enhancing filtering precision

Example integration flow:

1. Packet enters the system
2. DPI identifies the application and extracts metadata
3. Policy engine evaluates policies using DPI results
4. Matching policy actions are applied

### Integration Interface

```go
// DPIIntegration manages integration with the DPI system
type DPIIntegration struct {
    dpiManager     *dpi.Manager
    policyResolver *PolicyResolver
    
    // Cache for DPI results
    appCache       *cache.Cache
    metadataCache  *cache.Cache
}

// GetApplicationInfo gets application info for filtering
func (d *DPIIntegration) GetApplicationInfo(flow *FlowContext) (*AppInfo, error) {
    // Check cache
    if app, found := d.appCache.Get(flow.ID); found {
        return app.(*AppInfo), nil
    }
    
    // Get from DPI manager
    app, err := d.dpiManager.GetDetectedApplication(flow.SrcIP, flow.DstIP, 
                                                   flow.SrcPort, flow.DstPort,
                                                   flow.Protocol)
    if err != nil {
        return nil, err
    }
    
    // Cache result
    d.appCache.Set(flow.ID, app, cache.DefaultExpiration)
    
    return app, nil
}

// GetMetadata gets metadata for the application
func (d *DPIIntegration) GetMetadata(flow *FlowContext, app string) (map[string]interface{}, error) {
    // Similar implementation for metadata
    // ...
}
```

## Policy Resolution and Conflict Handling

### Hierarchical Resolution

The system resolves hierarchical policies with these steps:

1. **Collection**: Gather all applicable policies based on scope
2. **Dependency Resolution**: Build dependency tree of policies
3. **Inheritance Application**: Apply inheritance rules
4. **Conflict Resolution**: Resolve conflicting rules
5. **Effective Policy Generation**: Generate final effective policies

### Conflict Resolution

Conflicts are resolved automatically using these strategies:

1. **Priority-Based Resolution**:
   - Higher priority policies override lower priority ones
   - Explicit priorities take precedence

2. **Scope-Based Resolution**:
   - More specific scope overrides more general scope
   - Application > Host > Network > Zone > Global

3. **First-Matching Rule**:
   - For policies with equal priority and scope
   - First matching rule applies

4. **Alert Generation**:
   - Generate alerts for significant conflicts
   - Log conflict resolution decisions
   - Provide context for manual review

```go
// ConflictResolver resolves policy conflicts
type ConflictResolver struct {
    config         *ResolverConfig
    alerter        *AlertGenerator
    logger         *Logger
}

// ResolveConflicts resolves conflicts between policies
func (r *ConflictResolver) ResolveConflicts(policies []*FilterPolicy) ([]*FilterPolicy, error) {
    // Implement conflict resolution logic
    // ...
    
    // Generate alerts for significant conflicts
    if conflict != nil && conflict.Significance > r.config.AlertThreshold {
        r.alerter.GenerateAlert(conflict)
    }
    
    // Log all conflict resolutions
    r.logger.LogConflictResolution(conflict)
    
    return resolvedPolicies, nil
}
```

## Logging and Monitoring

### Centralized Logging

The system implements centralized logging for policy decisions:

1. **Log Collection**:
   - Collect logs from all policy enforcement points
   - Standardize log format
   - Include detailed context

2. **Log Storage**:
   - Centralized log storage
   - Configurable retention
   - Secure access controls

3. **Log Analysis**:
   - Query capabilities
   - Aggregation and summarization
   - Trend analysis

### Log Contents

Each policy decision log includes:

1. **Policy Information**:
   - Policy name, ID, and version
   - Matched rule details
   - Applied actions

2. **Traffic Information**:
   - Source/destination addresses
   - Protocol and ports
   - Application identification
   - Relevant metadata

3. **Context Information**:
   - Timestamp and duration
   - Processing node
   - Related events
   - Decision latency

Example log entry:

```json
{
  "timestamp": "2025-03-04T12:34:56.789Z",
  "level": "info",
  "message": "Policy decision applied",
  "policy": {
    "id": "web-access-123",
    "name": "web-access",
    "version": 5,
    "rule": "allow-internal-web-traffic"
  },
  "traffic": {
    "source": {
      "ip": "10.1.2.3",
      "port": 45678,
      "zone": "internal"
    },
    "destination": {
      "ip": "192.168.5.6",
      "port": 443,
      "service": "web-servers"
    },
    "protocol": "TCP",
    "application": "HTTPS",
    "metadata": {
      "tls.sni": "example.com",
      "tls.version": "1.3"
    }
  },
  "decision": {
    "action": "allow",
    "latency": 0.25,
    "reason": "Matched rule: allow-internal-web-traffic"
  },
  "node": "worker-3",
  "correlationId": "flow-12345"
}
```

## Implementation Plan

### Phase 1: Core Framework
- Define CRDs for policy resources
- Implement basic Policy Controller
- Create simple policy translation to Cilium
- Setup integration with Security Orchestration

### Phase 2: Hierarchical Policies
- Implement policy inheritance
- Add policy conflict resolution
- Create zone-based policies
- Develop policy groups

### Phase 3: Application Integration
- Integrate with DPI for application awareness
- Implement L7 filtering capabilities
- Add metadata-based filtering
- Develop application policies

### Phase 4: Advanced Features
- Implement advanced logging and monitoring
- Add policy analysis tools
- Create policy simulation
- Develop policy templates

### Phase 5: Optimization and Scaling
- Optimize policy resolution
- Improve translation performance
- Enhance conflict resolution
- Scale for large policy sets

## Conclusion

The Policy-Based Filtering system extends Cilium's capabilities with a hierarchical policy model that supports both L3/L4 and L7 application filtering. By integrating with the DPI system and security orchestration framework, it enables sophisticated filtering based on application properties and metadata without requiring content inspection.

The custom CRDs provide an intuitive abstraction that simplifies policy management while leveraging Cilium's powerful eBPF-based enforcement. The hierarchical model with automatic conflict resolution ensures consistent policy application across the system, while comprehensive logging provides visibility into policy decisions.

This design meets the requirements for a flexible, powerful filtering system that integrates seamlessly with the existing components of the router/firewall architecture.