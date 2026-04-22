# Threat Intelligence System Design

> **Implementation status (Sprint 30 / Ticket 44):** v0 is shipped. The
> `ThreatFeed` CRD (cluster-scoped, `security.fos1.io/v1alpha1`) drives a
> polling controller in `pkg/security/threatintel/` that fetches abuse.ch
> URLhaus CSV, translates each URL indicator into a Cilium `toFQDNs` deny
> policy (or `toCIDR` for IP literals), and expires the applied policy once
> the indicator has not been seen in a successful fetch newer than
> `spec.maxAge`.
>
> **v0 scope:** URLhaus CSV ingestion only, polling-based, one feed per CR.
> **Non-goals for v0:** MISP, STIX/TAXII, confidence scoring, feed
> authentication, ETag/If-Modified-Since caching, and the rich indicator
> database / reputation engine described below. Those remain design-stage
> aspirations and will land in later sprints.

## Overview

This document outlines the design for the Threat Intelligence System, a key security component in our Kubernetes-based router/firewall architecture. The system aggregates, processes, and distributes threat intelligence to enable proactive defense against known threats and malicious activities.

## v0 Implementation (Sprint 30 / Ticket 44)

The first working slice ships a deliberately narrow pipeline. The CRD, the
fetcher, the translator, and the controller are concrete and tested; the
broader multi-source / reputation / distribution framework described in the
rest of this document remains aspirational.

### CRD

```
apiVersion: security.fos1.io/v1alpha1
kind: ThreatFeed
metadata:
  name: urlhaus
spec:
  url: https://urlhaus.abuse.ch/downloads/csv/
  format: urlhaus-csv      # only supported format in v0
  refreshInterval: 15m
  maxAge: 24h              # indicator TTL after last-seen
  enabled: true
status:
  lastFetchTime: ...
  lastFetchError: ""
  entryCount: 1342          # rows parsed (post-filter)
  activeIndicators: 1341    # unique domains currently enforced
  conditions: [...]
```

### Runtime pipeline

1. Controller lists ThreatFeed CRs (`pkg/security/threatintel/controller.go`).
2. For each enabled feed, if `now >= nextFetch`, run
   `Manager.Refresh(ctx)`.
3. `URLhausFetcher.Fetch` HTTPs the feed, drops comments, and parses the
   CSV. `url_status="offline"` and empty URLs are filtered out.
4. `Translator.Translate` converts each Indicator into a Cilium
   `CiliumPolicy` whose single rule is a deny on `toFQDNs` (domain) or
   `toCIDR` (IP literal). Policy names are stable
   (`fos1-threatintel-<feed>-<hash>`) so repeated fetches are idempotent.
5. The Manager applies newly-seen indicators and refreshes the last-seen
   time for ones it already tracks.
6. Expiry: on every Refresh (and on off-cycle ExpireStale calls), any
   indicator whose LastSeen is older than `spec.maxAge` has its Cilium
   policy deleted and is removed from the in-memory active set.
7. Status is written back via the `status` subresource — entry count,
   active indicator count, last-fetch time/error, and `Ready` /
   `FetchSucceeded` conditions.

### Deduplication and TTL semantics

- Duplicate URLs inside a single fetch collapse to one policy per unique
  host (after lower-casing and port stripping).
- Across fetches, an indicator still present in the feed is "refreshed"
  (LastSeen moves forward, no re-apply needed).
- `maxAge` measures time since last successful fetch included the
  indicator, **not** time since creation. A feed that keeps an indicator
  published keeps the policy in place indefinitely.
- A failed fetch does not mutate active indicator state; transient upstream
  failures never cause enforcement to disappear on their own. `maxAge`
  expiry continues to run off-cycle so truly stale entries eventually drop.

### CI harness

The hermetic proof (`scripts/harness-threatintel.sh`) runs the build-tagged
`TestHarness_EndToEnd` test behind `-tags=harness`. It boots an in-process
HTTP server that serves a canned URLhaus CSV, drives a full controller
reconcile, asserts the expected Cilium policies are applied, advances a
synthetic clock past `maxAge`, and asserts the same set of policies is
deleted on the next reconcile. An in-cluster analogue
(`manifests/examples/security/threatfeed-urlhaus.yaml`) deploys an nginx
pod that serves the same CSV from a ConfigMap.

### Explicit non-goals for v0

- MISP integration
- STIX/TAXII ingestion
- Confidence scoring and reputation models
- Feed authentication (Basic/Bearer/Secret-ref)
- ETag / `If-Modified-Since` caching
- The full Indicator / Reputation / Distribution framework described below

## Design Goals

1. **Comprehensive Coverage**: Integrate multiple intelligence sources for broad threat coverage
2. **Real-Time Updates**: Provide timely threat information to security components
3. **Actionable Intelligence**: Focus on information that can drive automated actions
4. **Flexible Integration**: Easily integrate with all security subsystems
5. **Performance Efficiency**: Minimize performance impact while providing valuable intelligence
6. **Privacy Compliance**: Ensure all intelligence processing complies with privacy requirements

## System Architecture

### Core Components

1. **Threat Intelligence Manager** (`pkg/security/threatintel/manager.go`):
   - Central coordination component
   - Manages intelligence sources
   - Handles indicator processing
   - Provides lookups and queries

2. **Intelligence Sources** (`pkg/security/threatintel/sources/`):
   - Open-source feed connectors
   - Commercial feed integrations
   - Internal intelligence generators
   - OSINT collectors

3. **Indicator Database** (`pkg/security/threatintel/indicators/`):
   - Stores and indexes threat indicators
   - Provides fast lookup capabilities
   - Manages indicator lifecycle
   - Handles indicator relationships

4. **Reputation Engine** (`pkg/security/threatintel/reputation/`):
   - Calculates entity reputation scores
   - Applies confidence and severity models
   - Provides reputation lookups
   - Manages reputation history

5. **Intelligence Distribution** (`pkg/security/threatintel/distribution/`):
   - Publishes intelligence updates
   - Manages subscriptions
   - Handles targeted distribution
   - Supports pull and push models

### Data Flow

1. **Intelligence Collection**:
   - Scheduled fetching from external sources
   - Real-time streaming from premium sources
   - System-generated indicators
   - Manual intelligence input

2. **Processing Pipeline**:
   - Deduplication and normalization
   - Enrichment with context
   - Confidence scoring
   - Classification and tagging

3. **Storage and Indexing**:
   - Optimized storage by indicator type
   - Multi-level indexing for fast lookups
   - Time-based partitioning
   - Expiration management

4. **Distribution to Consumers**:
   - Component-specific formatting
   - Filtering by relevance
   - Batched or real-time distribution
   - Targeted distribution based on component needs

## Detailed Component Design

### Threat Intelligence Manager

The Threat Intelligence Manager orchestrates the entire system:

```go
// Manager manages threat intelligence
type Manager struct {
    // Core components
    sources         map[string]Source
    indicatorDB     *IndicatorDatabase
    reputationEngine *ReputationEngine
    distributor     *Distributor
    
    // Configuration and control
    config          *ManagerConfig
    updateScheduler *UpdateScheduler
    ctx             context.Context
    cancel          context.CancelFunc
    
    // Integration
    securityCoordinator *coordinator.SecurityCoordinator
    eventBus           *eventbus.EventBus
}

// ManagerConfig contains configuration for the manager
type ManagerConfig struct {
    UpdateInterval    time.Duration
    RetentionPolicy   RetentionPolicy
    ConfidenceThreshold float64
    EnabledSources    []string
    EnabledTypes      []string
    CacheSize         int
    StoragePath       string
}
```

Key responsibilities:
- Initialize and manage all threat intelligence components
- Coordinate updates from intelligence sources
- Provide query interfaces to security components
- Handle system-wide intelligence configuration

### Intelligence Sources

The system supports multiple intelligence source types:

```go
// Source provides threat intelligence data
type Source interface {
    GetName() string
    GetDescription() string
    GetTypes() []string
    GetLastUpdate() time.Time
    
    Update(ctx context.Context) (SourceUpdateStats, error)
    GetIndicators(ctx context.Context, filter IndicatorFilter) ([]Indicator, error)
    GetCapabilities() SourceCapabilities
}

// SourceUpdateStats contains statistics about an update
type SourceUpdateStats struct {
    NewIndicators     int
    UpdatedIndicators int
    ExpiredIndicators int
    Duration          time.Duration
    Timestamp         time.Time
    Errors            []error
}
```

Source implementations:
1. **URLSource**: Fetches from HTTP/HTTPS URLs
2. **FileSource**: Reads from local files
3. **APISource**: Connects to REST APIs
4. **TAXIISource**: Fetches from TAXII servers
5. **MISPSource**: Connects to MISP instances
6. **STIXSource**: Processes STIX-formatted data
7. **CustomSource**: Supports custom source logic

### Indicator Database

The Indicator Database efficiently stores and indexes threat indicators:

```go
// IndicatorDatabase manages threat indicators
type IndicatorDatabase struct {
    indicators      map[string]*Indicator
    ipv4Store       *IPStore
    ipv6Store       *IPStore
    domainStore     *DomainStore
    urlStore        *URLStore
    hashStore       *HashStore
    fileStore       *FileStore
    
    indexManager    *IndexManager
    storageManager  *StorageManager
    expiryManager   *ExpiryManager
}

// Indicator represents a threat indicator
type Indicator struct {
    ID             string
    Type           string
    Value          string
    Sources        []IndicatorSource
    FirstSeen      time.Time
    LastSeen       time.Time
    Confidence     float64
    Severity       string
    Tags           []string
    Context        map[string]interface{}
    RelatedIDs     []string
    Metadata       map[string]interface{}
}
```

Features:
- Type-specific optimized storage
- Fast prefix and pattern matching
- CIDR range support for IP indicators
- Hierarchical matching for domains

### Reputation Engine

The Reputation Engine calculates and manages entity reputation:

```go
// ReputationEngine calculates entity reputation
type ReputationEngine struct {
    reputationDB    map[string]*ReputationEntry
    scoringModel    *ScoringModel
    thresholds      map[string]float64
    historyManager  *HistoryManager
}

// ReputationEntry represents an entity's reputation
type ReputationEntry struct {
    Entity          string
    Score           float64
    Category        string
    FirstSeen       time.Time
    LastUpdated     time.Time
    Sources         []string
    Factors         map[string]float64
    Context         map[string]interface{}
    History         []ReputationChange
}

// ScoringModel calculates reputation scores
type ScoringModel struct {
    Weights         map[string]float64
    Categories      map[float64]string
    DecayFunction   DecayFunction
    AggregateMethod string
}
```

Scoring factors:
1. Source credibility
2. Indicator confidence
3. Recency of observations
4. Severity of associated threats
5. Historical behavior patterns

### Intelligence Distribution

The Distribution system manages intelligence delivery:

```go
// Distributor manages intelligence distribution
type Distributor struct {
    subscribers       map[string]Subscriber
    distributionQueue chan DistributionPackage
    packager          *PackageGenerator
    deliveryManager   *DeliveryManager
}

// Subscriber receives threat intelligence
type Subscriber interface {
    GetName() string
    GetSupportedTypes() []string
    GetDistributionPreferences() DistributionPreferences
    ReceiveIntelligence(ctx context.Context, pkg DistributionPackage) error
    Acknowledge(packageID string) error
}

// DistributionPackage contains packaged intelligence
type DistributionPackage struct {
    ID             string
    Timestamp      time.Time
    Types          []string
    Format         string
    Indicators     []Indicator
    ExpiryTime     time.Time
    TargetComponent string
}
```

Distribution methods:
1. Push-based real-time updates
2. Pull-based scheduled polling
3. Bulk exports for batch processing
4. Differential updates to minimize traffic

## Indicator Types and Processing

### Supported Indicator Types

1. **Network Indicators**:
   - IP addresses (IPv4/IPv6)
   - CIDR ranges
   - Domain names
   - URLs
   - SSL/TLS certificates

2. **File Indicators**:
   - File hashes (MD5, SHA1, SHA256)
   - File names
   - YARA rules
   - File entropy patterns

3. **Behavioral Indicators**:
   - TTPs (Tactics, Techniques, Procedures)
   - Attack patterns
   - Behavioral signatures

4. **Entity Indicators**:
   - User accounts
   - Email addresses
   - Application identifiers

### Processing Pipeline

Each indicator goes through a processing pipeline:

1. **Validation**:
   - Format verification
   - Value normalization
   - Deduplication checking

2. **Enrichment**:
   - Context addition
   - Relationship discovery
   - Metadata enhancement

3. **Scoring**:
   - Confidence calculation
   - Severity assignment
   - Reputation impact

4. **Indexing**:
   - Type-specific storage
   - Multi-dimensional indexing
   - Expiration scheduling

## Integration with Security Components

### Firewall Integration

The Threat Intelligence System integrates with the firewall:

1. **IP Block Lists**:
   - Malicious IP addresses
   - Botnet command and control servers
   - DDoS sources

2. **Domain Filtering**:
   - Malware distribution domains
   - Phishing sites
   - Command and control domains

3. **URL Categories**:
   - Malicious content categories
   - Policy-based filtering

Implementation:
```go
// FirewallIntegration manages firewall intelligence
type FirewallIntegration struct {
    firewallManager *firewall.Manager
    ipBlocklist     *IPBlocklist
    domainFilter    *DomainFilter
    urlCategories   *URLCategories
}
```

### DPI Integration

Integration with the DPI system:

1. **Signature Generation**:
   - Convert indicators to detection signatures
   - Apply to Suricata/Zeek

2. **Application Classification**:
   - Identify malicious applications
   - Flag suspicious behaviors

3. **Protocol Analysis**:
   - Identify abused protocols
   - Detect protocol anomalies

Implementation:
```go
// DPIIntegration manages DPI intelligence
type DPIIntegration struct {
    dpiManager      *dpi.Manager
    signatureGen    *SignatureGenerator
    behaviorAnalyzer *BehaviorAnalyzer
}
```

### Cilium Integration

Integration with Cilium:

1. **Network Policies**:
   - Generate Cilium NetworkPolicies from threat intelligence
   - Apply application-layer filtering

2. **Identity-Based Controls**:
   - Apply rules based on Cilium identities
   - Map threat intel to workload context

Implementation:
```go
// CiliumIntegration manages Cilium intelligence
type CiliumIntegration struct {
    ciliumClient    cilium.CiliumClient
    policyGenerator *NetworkPolicyGenerator
}
```

## Custom Resources

1. **ThreatIntelFeed CR**:
```yaml
apiVersion: security.fos1.io/v1alpha1
kind: ThreatIntelFeed
metadata:
  name: emerging-threats
spec:
  description: "Emerging Threats Open Ruleset"
  enabled: true
  source:
    type: "url"
    url: "https://rules.emergingthreats.net/open/suricata/rules/emerging-malware.rules"
    format: "suricata"
    auth:
      secretRef:
        name: "et-credentials"
  update:
    schedule: "0 */4 * * *"
    retry:
      count: 3
      interval: "10m"
  processing:
    confidenceThreshold: 0.7
    severityLevels:
      - critical
      - high
    expiryPeriod: "720h"  # 30 days
  distribution:
    targets:
      - component: "suricata"
        format: "rules"
      - component: "firewall"
        format: "ipset"
```

2. **ThreatIntelConfig CR**:
```yaml
apiVersion: security.fos1.io/v1alpha1
kind: ThreatIntelConfig
metadata:
  name: default-config
spec:
  retention:
    defaultPeriod: "720h"  # 30 days
    byType:
      ip: "168h"           # 7 days
      domain: "720h"       # 30 days
      url: "168h"          # 7 days
      hash: "2160h"        # 90 days
  thresholds:
    minConfidence: 0.6
    criticalSeverity: 0.9
    highSeverity: 0.7
    mediumSeverity: 0.4
  reputation:
    badReputation: -0.7
    suspiciousReputation: -0.3
    decay:
      method: "linear"
      halfLife: "168h"     # 7 days
  storage:
    persistentVolumeClaim: "threat-intel-storage"
    maxSize: "10Gi"
```

3. **ThreatIntelLookup CR**:
```yaml
apiVersion: security.fos1.io/v1alpha1
kind: ThreatIntelLookup
metadata:
  name: ip-lookup-example
spec:
  indicator:
    type: "ip"
    value: "203.0.113.1"
  includeRelated: true
  includeHistory: true
  responseFormat: "full"
```

## Operational Considerations

### Performance Optimization

1. **Efficient Lookups**:
   - Optimized data structures for each indicator type
   - In-memory caching for frequent lookups
   - Bloom filters for negative caching

2. **Storage Efficiency**:
   - Compression for historical data
   - Time-based pruning of expired indicators
   - Incremental updates to minimize storage needs

3. **Distribution Efficiency**:
   - Differential updates
   - Component-specific filtering
   - Batched distribution

### Privacy and Compliance

1. **Data Handling**:
   - Minimization of personal data
   - Anonymization where appropriate
   - Clear retention policies

2. **Auditability**:
   - Track intelligence origins
   - Log access and usage
   - Document handling processes

3. **Ethical Use**:
   - Verification before blocking
   - False positive management
   - Appeal processes

## Future Enhancements

1. **Machine Learning**:
   - Predictive threat intelligence
   - Anomaly-based detection
   - Confidence scoring models

2. **Community Sharing**:
   - Contribute intelligence back to community
   - Collaborative threat defense
   - Anonymized local discoveries

3. **Advanced Correlation**:
   - Graph-based indicator relationships
   - Campaign tracking
   - Actor attribution

## Implementation Plan

### Phase 1: Core Framework
- Implement Threat Intelligence Manager
- Develop basic source integrations
- Create indicator database
- Establish distribution system

### Phase 2: Integration
- Integrate with Firewall components
- Integrate with DPI System
- Integrate with Cilium
- Implement basic reputation system

### Phase 3: Advanced Features
- Add advanced indicator processing
- Implement comprehensive reputation engine
- Create sophisticated distribution system
- Develop custom source support

### Phase 4: Management and Analytics
- Add management interface
- Implement analytics capabilities
- Create intelligence dashboard
- Develop reporting mechanisms

## Conclusion

The Threat Intelligence System provides a comprehensive framework for aggregating, processing, and distributing threat intelligence throughout the router/firewall architecture. By integrating with multiple security components and providing actionable intelligence, the system enhances the overall security posture and enables proactive defense against emerging threats.