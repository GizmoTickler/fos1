# Security Orchestration System Design

## Overview

This document outlines the design for the Security Orchestration System, which coordinates all security components in our Kubernetes-based router/firewall architecture. The system provides a unified framework for security policy management, threat detection, and automated response across all security domains.

## Design Goals

1. **Unified Security Management**: Provide a single control point for all security components
2. **Automated Response**: Enable policy-driven responses to security events
3. **Cross-Component Correlation**: Correlate events across different security components
4. **Extensible Architecture**: Support integration of new security capabilities
5. **Policy Enforcement**: Ensure consistent policy application across components
6. **Compliance Monitoring**: Track and report on security posture and compliance

## System Architecture

### Core Components

1. **Security Coordinator** (`pkg/security/coordinator.go`):
   - Central orchestration component
   - Manages communication between security subsystems
   - Implements security workflows
   - Handles event correlation

2. **Event Bus** (`pkg/security/eventbus.go`):
   - Distributes security events between components
   - Implements publish-subscribe pattern
   - Provides filtering and routing capabilities
   - Ensures reliable event delivery

3. **Policy Manager** (`pkg/security/policy/manager.go`):
   - Manages security policies across components
   - Translates high-level policies to component-specific configurations
   - Handles policy validation and conflict resolution
   - Enforces policy consistency

4. **Threat Intelligence** (`pkg/security/threatintel/manager.go`):
   - Integrates with threat intelligence sources
   - Manages indicators of compromise (IoCs)
   - Provides reputation services
   - Updates security components with threat data

5. **Response Engine** (`pkg/security/response/engine.go`):
   - Implements automated response workflows
   - Executes remediation actions
   - Manages response policies
   - Tracks incident lifecycle

### Integration Architecture

The Security Orchestration System integrates with the following components:

1. **DPI System**:
   - Receives application detection results
   - Configures inspection profiles
   - Controls inspection depth and focus

2. **Firewall System**:
   - Updates firewall rules based on threat intelligence
   - Applies dynamic blocking rules
   - Correlates firewall events with other security events

3. **IDS/IPS Components**:
   - Manages Suricata rules and configurations
   - Processes IDS/IPS alerts
   - Controls IPS actions

4. **Cilium Network Policies**:
   - Translates security events to network policies
   - Applies dynamic access controls
   - Integrates application-aware filtering

5. **Authentication Systems**:
   - Integrates user identity information
   - Applies user-based security policies
   - Correlates authentication events with network activity

## Detailed Component Design

### Security Coordinator

The Security Coordinator serves as the central orchestration point:

```go
// SecurityCoordinator manages all security components
type SecurityCoordinator struct {
    // Core components
    eventBus       *EventBus
    policyManager  *policy.Manager
    threatIntel    *threatintel.Manager
    responseEngine *response.Engine
    
    // Component managers
    dpiManager     *dpi.Manager
    firewallManager *firewall.Manager
    idsManager     *ids.Manager
    
    // Integration
    k8sClient      kubernetes.Interface
    ciliumClient   cilium.CiliumClient
    
    // Control
    ctx            context.Context
    cancel         context.CancelFunc
    config         *CoordinatorConfig
}
```

Key responsibilities:
- Initialize and manage all security subsystems
- Coordinate cross-component workflows
- Handle system-wide configuration
- Provide APIs for security management

### Event Bus

The Event Bus enables communication between security components:

```go
// EventBus manages security event distribution
type EventBus struct {
    subscribers    map[string][]EventSubscriber
    eventQueue     chan SecurityEvent
    eventHistory   *EventStore
    filterEngine   *EventFilter
    ctx            context.Context
    cancel         context.CancelFunc
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
    ID            string
    Type          string
    Source        string
    Timestamp     time.Time
    Severity      EventSeverity
    Description   string
    Attributes    map[string]interface{}
    RelatedEvents []string
}

// EventSubscriber receives events from the event bus
type EventSubscriber interface {
    HandleEvent(ctx context.Context, event SecurityEvent) error
    GetSubscriptionFilters() []EventFilter
}
```

Features:
- Topic-based event routing
- Event persistence for historical analysis
- Event correlation and enrichment
- Backpressure handling and delivery guarantees

### Policy Manager

The Policy Manager handles all security policies:

```go
// Manager manages security policies
type Manager struct {
    policies        map[string]*SecurityPolicy
    policyVersions  map[string]int
    components      map[string]PolicyConsumer
    validator       *PolicyValidator
    compiler        *PolicyCompiler
    store           PolicyStore
}

// SecurityPolicy represents a high-level security policy
type SecurityPolicy struct {
    ID           string
    Name         string
    Description  string
    Version      int
    Enabled      bool
    Priority     int
    Rules        []PolicyRule
    Actions      []PolicyAction
    Dependencies []string
    Tags         []string
    Metadata     map[string]interface{}
}

// PolicyConsumer implements component-specific policy application
type PolicyConsumer interface {
    ApplyPolicy(ctx context.Context, policy *SecurityPolicy) error
    ValidatePolicy(policy *SecurityPolicy) (bool, []PolicyValidationError)
    GetCapabilities() []PolicyCapability
}
```

Features:
- Hierarchical policy model
- Version control and change tracking
- Policy inheritance and composition
- Component-specific policy translation

### Threat Intelligence

The Threat Intelligence system manages security intelligence:

```go
// Manager manages threat intelligence
type Manager struct {
    sources         map[string]ThreatIntelSource
    indicators      map[string]*Indicator
    reputationDB    *ReputationDatabase
    updateScheduler *UpdateScheduler
    cache           *ThreatIntelCache
}

// Indicator represents an indicator of compromise
type Indicator struct {
    ID           string
    Type         string
    Value        string
    Source       string
    FirstSeen    time.Time
    LastSeen     time.Time
    Confidence   float64
    Severity     string
    Tags         []string
    Context      map[string]interface{}
}

// ThreatIntelSource provides threat intelligence data
type ThreatIntelSource interface {
    GetName() string
    GetIndicators(ctx context.Context, types []string) ([]Indicator, error)
    GetLastUpdate() time.Time
    Update(ctx context.Context) error
}
```

Features:
- Integration with multiple threat intelligence sources
- Indicator management and correlation
- Reputation scoring system
- Automated updates and synchronization

### Response Engine

The Response Engine handles automated security responses:

```go
// Engine manages automated responses to security events
type Engine struct {
    workflows      map[string]*ResponseWorkflow
    actions        map[string]ResponseAction
    triggers       map[string][]ResponseTrigger
    executionLog   *ExecutionLog
    actionRunners  map[string]ActionRunner
}

// ResponseWorkflow defines a sequence of response actions
type ResponseWorkflow struct {
    ID           string
    Name         string
    Description  string
    Triggers     []ResponseTrigger
    Actions      []WorkflowAction
    Conditions   []WorkflowCondition
    MaxDuration  time.Duration
    Approval     ApprovalRequirement
}

// ResponseAction represents a security response action
type ResponseAction interface {
    Execute(ctx context.Context, params map[string]interface{}) (ActionResult, error)
    Validate(params map[string]interface{}) error
    GetCapabilities() []ActionCapability
}
```

Features:
- Workflow-based response automation
- Conditional execution based on event context
- Approval workflows for critical actions
- Rollback capabilities for failed actions

## Security Event Processing

### Event Flow

1. **Event Generation**:
   - Security components generate events
   - Events are published to the Event Bus

2. **Event Enrichment**:
   - Add context from threat intelligence
   - Correlate with related events
   - Add asset and user information

3. **Policy Evaluation**:
   - Match events against security policies
   - Determine required actions

4. **Response Execution**:
   - Trigger appropriate response workflows
   - Execute actions across security components
   - Log and track execution

5. **Feedback Loop**:
   - Monitor response effectiveness
   - Update policies based on outcomes
   - Generate reports and metrics

### Event Correlation

The system implements sophisticated event correlation:

```go
// Correlator correlates security events
type Correlator struct {
    rules           []CorrelationRule
    eventStore      *EventStore
    patternMatcher  *PatternMatcher
    alertGenerator  *AlertGenerator
}

// CorrelationRule defines how to correlate events
type CorrelationRule struct {
    ID              string
    Name            string
    EventPattern    EventPattern
    TimeWindow      time.Duration
    MinMatches      int
    MaxMatches      int
    GenerateAlert   bool
    AlertSeverity   AlertSeverity
    AlertTemplate   string
}
```

Correlation methods:
1. Pattern-based correlation
2. Temporal correlation
3. Statistical correlation
4. Entity-based correlation

## Security Policies

### Policy Model

The system uses a hierarchical policy model:

1. **Global Policies**:
   - Apply across all security domains
   - Define baseline security requirements
   - Control system-wide security behavior

2. **Domain Policies**:
   - Apply to specific security domains (firewall, DPI, etc.)
   - Define domain-specific controls
   - Inherit from global policies

3. **Component Policies**:
   - Apply to specific security components
   - Define detailed technical controls
   - Translated from domain policies

### Policy Translation

The system translates high-level policies to component-specific configurations:

```go
// PolicyCompiler translates security policies
type PolicyCompiler struct {
    translators     map[string]PolicyTranslator
    ruleEngine      *RuleEngine
    optimizers      []PolicyOptimizer
}

// PolicyTranslator translates policies for specific components
type PolicyTranslator interface {
    TranslatePolicy(policy *SecurityPolicy) (interface{}, error)
    GetTargetComponent() string
    GetCapabilities() []TranslationCapability
}
```

Translation process:
1. Parse high-level policy
2. Map to component capabilities
3. Generate component-specific configurations
4. Validate translated policies
5. Apply optimizations

## Custom Resources

1. **SecurityPolicy CR**:
```yaml
apiVersion: security.fos1.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: web-server-protection
spec:
  description: "Security policy for web servers"
  enabled: true
  priority: 100
  rules:
  - name: "Allow HTTP/HTTPS"
    match:
      destination:
        portRanges: ["80", "443"]
    action: allow
  - name: "Block Suspicious Web Traffic"
    match:
      application: "http"
      attributes:
        suricata.signature.tags: ["web-attack", "sqli", "xss"]
    action: block
  actions:
  - event: "repeated_attack"
    type: "blacklist_source"
    parameters:
      duration: "1h"
```

2. **ThreatIntelFeed CR**:
```yaml
apiVersion: security.fos1.io/v1alpha1
kind: ThreatIntelFeed
metadata:
  name: malware-domains
spec:
  description: "Malware domain blacklist"
  source:
    type: "url"
    url: "https://example.com/malware-domains.txt"
    format: "domain"
    auth:
      secretRef:
        name: "ti-feed-credentials"
  update:
    schedule: "0 */6 * * *"
    retry:
      count: 3
      interval: "10m"
  integration:
    dnsFilter: true
    firewallBlock: true
    dpiInspection: true
```

3. **ResponseWorkflow CR**:
```yaml
apiVersion: security.fos1.io/v1alpha1
kind: ResponseWorkflow
metadata:
  name: malware-containment
spec:
  description: "Automated response to malware detection"
  triggers:
  - type: "event"
    eventType: "suricata.alert"
    conditions:
    - field: "alert.signature_severity"
      operator: "gte"
      value: "high"
    - field: "alert.signature_category"
      operator: "eq"
      value: "malware"
  actions:
  - name: "isolate-host"
    type: "network.quarantine"
    parameters:
      target: "{{ event.src_ip }}"
      allowDns: true
  - name: "notify-admin"
    type: "notification.email"
    parameters:
      to: "security@example.com"
      subject: "Malware detected from {{ event.src_ip }}"
```

## Integration with Cilium

The Security Orchestration System integrates with Cilium through:

1. **Dynamic Policy Generation**:
   - Create Cilium Network Policies from security events
   - Apply application-aware filtering

2. **Flow Visibility**:
   - Consume flow data from Hubble
   - Correlate flows with security events

3. **Endpoint Identity**:
   - Map security policies to Cilium endpoints
   - Apply identity-based security controls

Integration interface:
```go
// CiliumIntegration manages integration with Cilium
type CiliumIntegration struct {
    ciliumClient       cilium.CiliumClient
    policyTranslator   *CiliumPolicyTranslator
    flowMonitor        *CiliumFlowMonitor
    endpointManager    *CiliumEndpointManager
}
```

## Security Dashboard

The Security Orchestration System includes a management dashboard:

1. **Security Posture Overview**:
   - Real-time security status
   - Compliance metrics
   - Threat indicators

2. **Event Monitoring**:
   - Real-time event display
   - Filtering and search
   - Correlation visualization

3. **Policy Management**:
   - Policy editor and validator
   - Deployment status
   - Impact analysis

4. **Response Management**:
   - Workflow editor
   - Execution monitoring
   - Incident tracking

## Deployment Model

### Kubernetes Architecture

1. **Core Components**:
   - Security Coordinator: Deployment (1 replica)
   - Event Bus: Deployment with Redis backend
   - Policy Manager: Part of Coordinator
   - Response Engine: Part of Coordinator

2. **Data Storage**:
   - Events: Persistent volume for event storage
   - Policies: Kubernetes CRDs
   - Threat Intelligence: Configurable storage backend

3. **Integration Components**:
   - Component-specific deployments
   - Shared ConfigMaps for configuration
   - Secret management for sensitive settings

### Resource Requirements

1. **Security Coordinator**:
   - CPU: 1-2 cores
   - Memory: 2-4 GB
   - Storage: 10 GB for operating state

2. **Event Bus**:
   - CPU: 2-4 cores
   - Memory: 4-8 GB
   - Storage: 100+ GB for event history

3. **Threat Intelligence**:
   - CPU: 1-2 cores
   - Memory: 2-4 GB
   - Storage: 20+ GB for indicator database

## Implementation Plan

### Phase 1: Core Framework
- Implement Security Coordinator
- Develop Event Bus
- Create basic Policy Manager
- Establish component interfaces

### Phase 2: Integration
- Integrate with DPI System
- Integrate with Firewall components
- Integrate with Cilium
- Implement basic response capabilities

### Phase 3: Advanced Features
- Implement Threat Intelligence
- Develop correlation engine
- Create advanced response workflows
- Implement compliance reporting

### Phase 4: Management
- Develop security dashboard
- Implement comprehensive API
- Create management tools
- Add reporting and analytics

## Conclusion

The Security Orchestration System provides a unified framework for managing security across the router/firewall architecture. By coordinating multiple security components, correlating events, and automating responses, the system enhances security effectiveness while simplifying management and ensuring consistent policy enforcement.