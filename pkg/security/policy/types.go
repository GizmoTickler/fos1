package policy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Condition type constants for FilterPolicy status, mirroring the NAT
// controller condition set at pkg/network/nat/types.go:11-29 so operators
// see a consistent status surface across Cilium-backed controllers.
const (
	// ConditionApplied indicates the FilterPolicy has been successfully
	// translated into CiliumNetworkPolicy objects and applied via the
	// Cilium client.
	ConditionApplied = "Applied"

	// ConditionDegraded indicates the policy was partially applied;
	// some translated rules succeeded but at least one Cilium apply
	// call failed.
	ConditionDegraded = "Degraded"

	// ConditionInvalid indicates the FilterPolicy spec failed validation
	// or the translator rejected the input. No retry is attempted until
	// the spec changes.
	ConditionInvalid = "Invalid"

	// ConditionRemoved indicates all applied Cilium policies for this
	// FilterPolicy have been deleted (disable or delete path).
	ConditionRemoved = "Removed"
)

// Condition status values
const (
	ConditionStatusTrue  = "True"
	ConditionStatusFalse = "False"
)

// FilterPolicy defines a policy for network traffic filtering
type FilterPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Policy specification
	Spec FilterPolicySpec `json:"spec"`

	// Policy status
	Status FilterPolicyStatus `json:"status,omitempty"`

	// Fields below are not part of the CRD but used internally
	Name     string `json:"-"`
	Enabled  bool   `json:"-"`
	Priority int    `json:"-"`
}

// FilterPolicySpec defines the specification for a filtering policy
type FilterPolicySpec struct {
	// Policy metadata
	Description string `json:"description,omitempty"`
	Scope       string `json:"scope"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`

	// Parent policies (for inheritance)
	Inherits []PolicyInheritance `json:"inherits,omitempty"`

	// Matching criteria
	Selectors FilterSelectors `json:"selectors"`

	// Actions to take on matched traffic
	Actions []PolicyAction `json:"actions"`

	// Additional metadata
	Tags []string `json:"tags,omitempty"`
}

// PolicyInheritance defines inheritance from a parent policy
type PolicyInheritance struct {
	Name             string `json:"name"`
	OverrideStrategy string `json:"overrideStrategy,omitempty"`
}

// FilterSelectors defines the selectors for matching traffic
type FilterSelectors struct {
	Sources      []Selector     `json:"sources,omitempty"`
	Destinations []Selector     `json:"destinations,omitempty"`
	Applications []Selector     `json:"applications,omitempty"`
	Ports        []PortSelector `json:"ports,omitempty"`
	TimeWindows  []TimeWindow   `json:"timeWindows,omitempty"`
}

// Selector defines a generic selector for matching traffic
type Selector struct {
	Type     string        `json:"type"`
	Key      string        `json:"key,omitempty"`
	Operator string        `json:"operator,omitempty"`
	Values   []interface{} `json:"values"`
}

// PortSelector defines a selector for matching ports
type PortSelector struct {
	Protocol string  `json:"protocol"`
	Ports    []int32 `json:"ports"`
}

// TimeWindow defines a time-based selector
type TimeWindow struct {
	Days      []string `json:"days"`
	StartTime string   `json:"startTime"`
	EndTime   string   `json:"endTime"`
	Timezone  string   `json:"timezone,omitempty"`
}

// PolicyAction defines an action to take on matched traffic
type PolicyAction struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// FilterPolicyStatus defines the status of a filtering policy
type FilterPolicyStatus struct {
	// Status of policy application
	Applied     bool      `json:"applied"`
	LastApplied time.Time `json:"lastApplied,omitempty"`

	// Error information if application failed
	Error string `json:"error,omitempty"`

	// Corresponding Cilium policies
	CiliumPolicies []string `json:"ciliumPolicies,omitempty"`

	// LastAppliedHash is the deterministic spec hash last used to apply the
	// policy. The controller skips re-apply when the current spec hash
	// matches, mirroring the NAT controller idempotency contract.
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// Conditions reports the transitional state of the policy
	// (Applied / Degraded / Invalid / Removed). See the Condition
	// constants above for semantics.
	Conditions []PolicyCondition `json:"conditions,omitempty"`

	// Statistics
	MatchCount int64     `json:"matchCount"`
	LastMatch  time.Time `json:"lastMatch,omitempty"`
}

// PolicyCondition captures a single transitional condition in
// FilterPolicyStatus.Conditions. Its shape mirrors the NAT condition type
// (pkg/network/nat/types.go) so dashboards and alerts can treat the two
// controllers uniformly.
type PolicyCondition struct {
	// Type is one of the Condition* constants above.
	Type string `json:"type"`

	// Status is one of ConditionStatusTrue / ConditionStatusFalse.
	Status string `json:"status"`

	// LastTransitionTime is when this condition last changed.
	LastTransitionTime time.Time `json:"lastTransitionTime"`

	// Reason is a machine-readable CamelCase token describing why the
	// condition has its current status.
	Reason string `json:"reason,omitempty"`

	// Message is a human-readable description of the condition.
	Message string `json:"message,omitempty"`
}

// FilterPolicyGroup defines a group of related policies
type FilterPolicyGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Policy group specification
	Spec FilterPolicyGroupSpec `json:"spec"`

	// Fields below are not part of the CRD but used internally
	Name    string `json:"-"`
	Enabled bool   `json:"-"`
}

// FilterPolicyGroupSpec defines the specification for a policy group
type FilterPolicyGroupSpec struct {
	// Group metadata
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority,omitempty"`

	// Member policies
	Policies []string `json:"policies"`

	// Default action for this group
	DefaultAction string `json:"defaultAction,omitempty"`

	// Override settings for member policies
	Overrides []PolicyOverride `json:"overrides,omitempty"`
}

// PolicyOverride defines overrides for a specific policy
type PolicyOverride struct {
	PolicyName string `json:"policyName"`
	Enabled    *bool  `json:"enable,omitempty"`
	Priority   *int   `json:"priority,omitempty"`
}

// FilterZone defines a security zone for filtering
type FilterZone struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Zone specification
	Spec FilterZoneSpec `json:"spec"`

	// Fields below are not part of the CRD but used internally
	Name                 string   `json:"-"`
	TrustLevel           string   `json:"-"`
	DefaultIngressAction string   `json:"-"`
	DefaultEgressAction  string   `json:"-"`
	Policies             []string `json:"-"`
}

// FilterZoneSpec defines the specification for a security zone
type FilterZoneSpec struct {
	// Zone metadata
	Description string `json:"description,omitempty"`

	// Zone membership criteria
	Networks []NetworkDefinition `json:"networks"`

	// Interface definitions
	Interfaces []InterfaceDefinition `json:"interfaces,omitempty"`

	// Security settings
	TrustLevel string `json:"trustLevel"`

	// Default actions
	DefaultIngressAction string `json:"defaultIngressAction"`
	DefaultEgressAction  string `json:"defaultEgressAction"`

	// Zone-specific policies
	Policies []string `json:"policies,omitempty"`
}

// NetworkDefinition defines a network for zone membership
type NetworkDefinition struct {
	CIDR string `json:"cidr"`
}

// InterfaceDefinition defines a network interface
type InterfaceDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// FilterPolicyTemplate defines a template for generating policies
type FilterPolicyTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Template specification
	Spec FilterPolicyTemplateSpec `json:"spec"`
}

// FilterPolicyTemplateSpec defines the specification for a policy template
type FilterPolicyTemplateSpec struct {
	// Template metadata
	Description string `json:"description,omitempty"`

	// Template parameters
	Parameters []TemplateParameter `json:"parameters"`

	// Template policy
	Template map[string]interface{} `json:"template"`
}

// TemplateParameter defines a parameter for a policy template
type TemplateParameter struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Type        string      `json:"type,omitempty"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
}

// PolicyLogger implements logging for the policy system
type PolicyLogger struct {
	DetailedLogging bool
}

// NewPolicyLogger creates a new policy logger
func NewPolicyLogger(detailedLogging bool) *PolicyLogger {
	return &PolicyLogger{
		DetailedLogging: detailedLogging,
	}
}

// LogPolicyEvent logs a policy-related event
func (l *PolicyLogger) LogPolicyEvent(policy string, event string, details map[string]interface{}) {
	// In a real implementation, would log to a central logging system
}

// LogPolicyDecision logs a policy decision
func (l *PolicyLogger) LogPolicyDecision(policy string, match bool, action string, details map[string]interface{}) {
	// In a real implementation, would log to a central logging system
}

// LogConflictResolution logs a conflict resolution decision
func (l *PolicyLogger) LogConflictResolution(conflict *PolicyConflict) {
	// In a real implementation, would log to a central logging system
}

// PolicyConflict represents a conflict between policies
type PolicyConflict struct {
	PolicyA      string
	PolicyB      string
	ConflictType string
	Resolution   string
	Significance int
	Details      map[string]interface{}
}

// PolicyResolver resolves policy dependencies and conflicts
type PolicyResolver struct {
	logger *PolicyLogger
}

// NewPolicyResolver creates a new policy resolver
func NewPolicyResolver(logger *PolicyLogger) *PolicyResolver {
	return &PolicyResolver{
		logger: logger,
	}
}

// ResolvePolicy resolves a policy's dependencies
func (r *PolicyResolver) ResolvePolicy(policy *FilterPolicy, policies map[string]*FilterPolicy) (*FilterPolicy, error) {
	// In a real implementation, would resolve inheritance and conflicts
	// For now, just return the original policy
	return policy, nil
}

// PolicyMonitor monitors policy application and status
type PolicyMonitor struct {
	logger *PolicyLogger
}

// NewPolicyMonitor creates a new policy monitor
func NewPolicyMonitor(logger *PolicyLogger) *PolicyMonitor {
	return &PolicyMonitor{
		logger: logger,
	}
}

// Start starts the policy monitor
func (m *PolicyMonitor) Start(ctx interface{}) {
	// In a real implementation, would start monitoring
}

// RegisterPolicy registers a policy for monitoring
func (m *PolicyMonitor) RegisterPolicy(name string, namespace string) {
	// In a real implementation, would register for monitoring
}

// UnregisterPolicy unregisters a policy from monitoring
func (m *PolicyMonitor) UnregisterPolicy(name string, namespace string) {
	// In a real implementation, would unregister from monitoring
}

// ciliumPolicyName returns the deterministic CiliumNetworkPolicy name for a
// FilterPolicy. The scheme is `fos1-filter-<namespace>-<name>`; it is stable
// across controller restarts and uniquely scoped by the FilterPolicy's
// namespace and name so multiple FilterPolicy CRs do not collide.
func ciliumPolicyName(policy *FilterPolicy) string {
	name := policyObjectName(policy)
	if namespace := policy.ObjectMeta.Namespace; namespace != "" {
		name = namespace + "-" + name
	}
	name = sanitizeKubernetesName(name)
	if name == "" {
		return "fos1-filter-policy"
	}
	return "fos1-filter-" + name
}

// sanitizeKubernetesName lowercases and strips characters so the result is a
// valid RFC 1123 DNS subdomain.
func sanitizeKubernetesName(in string) string {
	in = strings.ToLower(in)
	in = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '.':
			return r
		default:
			return '-'
		}
	}, in)
	return strings.Trim(in, "-.")
}

// specHash computes a deterministic SHA-256 over the FilterPolicySpec so the
// controller can skip a no-op re-apply when the spec is unchanged. Maps and
// slices are ordered before encoding so the hash is stable across JSON
// marshaling order variations. Matches the idempotency idiom at
// pkg/network/nat/types.go:173.
func specHash(spec FilterPolicySpec) string {
	canonical := canonicalizeSpec(spec)
	buf, err := json.Marshal(canonical)
	if err != nil {
		// Fall back to a string dump; we never want a hash panic to take
		// the controller down.
		buf = []byte(fmt.Sprintf("%#v", canonical))
	}
	sum := sha256.Sum256(buf)
	return fmt.Sprintf("%x", sum)
}

// canonicalizeSpec returns a representation of the spec with deterministic
// ordering suitable for hashing.
func canonicalizeSpec(spec FilterPolicySpec) map[string]interface{} {
	out := map[string]interface{}{
		"description": spec.Description,
		"scope":       spec.Scope,
		"enabled":     spec.Enabled,
		"priority":    spec.Priority,
		"tags":        sortedCopy(spec.Tags),
	}

	inherits := make([]map[string]string, 0, len(spec.Inherits))
	for _, inh := range spec.Inherits {
		inherits = append(inherits, map[string]string{
			"name":             inh.Name,
			"overrideStrategy": inh.OverrideStrategy,
		})
	}
	sort.SliceStable(inherits, func(i, j int) bool {
		if inherits[i]["name"] != inherits[j]["name"] {
			return inherits[i]["name"] < inherits[j]["name"]
		}
		return inherits[i]["overrideStrategy"] < inherits[j]["overrideStrategy"]
	})
	out["inherits"] = inherits

	out["selectors"] = canonicalizeSelectors(spec.Selectors)
	out["actions"] = canonicalizeActions(spec.Actions)

	return out
}

func canonicalizeSelectors(sel FilterSelectors) map[string]interface{} {
	return map[string]interface{}{
		"sources":      canonicalizeSelectorList(sel.Sources),
		"destinations": canonicalizeSelectorList(sel.Destinations),
		"applications": canonicalizeSelectorList(sel.Applications),
		"ports":        canonicalizePortSelectors(sel.Ports),
		"timeWindows":  canonicalizeTimeWindows(sel.TimeWindows),
	}
}

func canonicalizeSelectorList(selectors []Selector) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(selectors))
	for _, s := range selectors {
		values := make([]string, 0, len(s.Values))
		for _, v := range s.Values {
			values = append(values, fmt.Sprintf("%v", v))
		}
		sort.Strings(values)
		out = append(out, map[string]interface{}{
			"type":     strings.ToLower(s.Type),
			"key":      s.Key,
			"operator": s.Operator,
			"values":   values,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return fmt.Sprintf("%v", out[i]) < fmt.Sprintf("%v", out[j])
	})
	return out
}

func canonicalizePortSelectors(ports []PortSelector) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(ports))
	for _, p := range ports {
		portsCopy := make([]int32, len(p.Ports))
		copy(portsCopy, p.Ports)
		sort.Slice(portsCopy, func(i, j int) bool { return portsCopy[i] < portsCopy[j] })
		out = append(out, map[string]interface{}{
			"protocol": strings.ToLower(p.Protocol),
			"ports":    portsCopy,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return fmt.Sprintf("%v", out[i]) < fmt.Sprintf("%v", out[j])
	})
	return out
}

func canonicalizeTimeWindows(windows []TimeWindow) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(windows))
	for _, w := range windows {
		days := sortedCopy(w.Days)
		out = append(out, map[string]interface{}{
			"days":      days,
			"startTime": w.StartTime,
			"endTime":   w.EndTime,
			"timezone":  w.Timezone,
		})
	}
	return out
}

func canonicalizeActions(actions []PolicyAction) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(actions))
	for _, a := range actions {
		params := make(map[string]string, len(a.Parameters))
		keys := make([]string, 0, len(a.Parameters))
		for k := range a.Parameters {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			params[k] = fmt.Sprintf("%v", a.Parameters[k])
		}
		out = append(out, map[string]interface{}{
			"type":       strings.ToLower(a.Type),
			"parameters": params,
		})
	}
	return out
}

func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// setCondition upserts a PolicyCondition into the supplied list, preserving
// LastTransitionTime when Status is unchanged. Returns the updated list.
func setCondition(existing []PolicyCondition, cond PolicyCondition) []PolicyCondition {
	for i, e := range existing {
		if e.Type != cond.Type {
			continue
		}
		if e.Status == cond.Status {
			// Preserve the earlier transition time; only reason/message may drift.
			cond.LastTransitionTime = e.LastTransitionTime
		}
		existing[i] = cond
		return existing
	}
	return append(existing, cond)
}
