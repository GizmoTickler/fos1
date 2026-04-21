package dpi

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/security/dpi/common"
	"k8s.io/klog/v2"
)

// PolicyAction defines what action to take when a policy rule matches.
type PolicyAction string

const (
	ActionBlock     PolicyAction = "block"
	ActionRateLimit PolicyAction = "rate-limit"
	ActionLog       PolicyAction = "log"
)

// PolicyRule defines when and how to create firewall policies from DPI events.
type PolicyRule struct {
	Name            string
	MinSeverity     int
	Categories      []string // match on event category; empty = match all
	Action          PolicyAction
	Duration        time.Duration // auto-expiry TTL; 0 = permanent
	AggregateWindow time.Duration // deduplicate events within this window
}

// EnforcementAction records an auditable enforcement action taken by the pipeline.
type EnforcementAction struct {
	Timestamp  time.Time
	ActionType string // "created", "removed", "expired"
	PolicyName string
	NodeName   string
	SourceIP   string
	Rule       string
	Detail     string
}

// ActivePolicy tracks a policy that has been applied to the firewall.
type ActivePolicy struct {
	Name       string
	NodeName   string
	SourceIP   string
	Policy     *cilium.CiliumPolicy
	CreatedAt  time.Time
	ExpiresAt  time.Time
	EventCount int
	Rule       string // name of the PolicyRule that created this

	// Enforcement audit metadata
	TriggerEvent common.DPIEvent     // the event that triggered this policy
	Actions      []EnforcementAction // audit trail of enforcement actions
}

// PolicyPipeline processes DPI events and auto-generates firewall policies
// based on configurable rules with severity thresholds, deduplication, and TTL expiry.
type PolicyPipeline struct {
	ciliumClient   cilium.CiliumClient
	nodeName       string
	rules          []PolicyRule
	activePolicies map[string]*ActivePolicy // key: "rule:sourceIP"
	recentEvents   map[string]time.Time     // deduplication tracking
	mu             sync.RWMutex
}

// NewPolicyPipeline creates a new DPI-to-firewall policy pipeline.
func NewPolicyPipeline(client cilium.CiliumClient, rules []PolicyRule, nodeName ...string) *PolicyPipeline {
	scopeNode := ""
	if len(nodeName) > 0 {
		scopeNode = nodeName[0]
	}

	return &PolicyPipeline{
		ciliumClient:   client,
		nodeName:       scopeNode,
		rules:          rules,
		activePolicies: make(map[string]*ActivePolicy),
		recentEvents:   make(map[string]time.Time),
	}
}

// ProcessEvent evaluates a DPI event against all rules and creates policies as needed.
func (p *PolicyPipeline) ProcessEvent(ctx context.Context, event common.DPIEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, rule := range p.rules {
		if !p.ruleMatches(rule, event) {
			continue
		}

		policyKey := p.policyKey(rule.Name, event.SourceIP)

		// Check deduplication window
		if rule.AggregateWindow > 0 {
			if lastSeen, ok := p.recentEvents[policyKey]; ok {
				if time.Since(lastSeen) < rule.AggregateWindow {
					// Within dedup window — just increment counter
					if ap, exists := p.activePolicies[policyKey]; exists {
						ap.EventCount++
					}
					p.recentEvents[policyKey] = time.Now()
					continue
				}
			}
		}

		// Check if policy already active
		if _, exists := p.activePolicies[policyKey]; exists {
			p.activePolicies[policyKey].EventCount++
			p.recentEvents[policyKey] = time.Now()
			continue
		}

		// Create and apply new policy
		if err := p.createPolicy(ctx, rule, event, policyKey); err != nil {
			klog.Warningf("Failed to create policy for %s: %v", policyKey, err)
			return err
		}

		p.recentEvents[policyKey] = time.Now()
	}

	return nil
}

// ruleMatches checks if a DPI event matches a policy rule.
func (p *PolicyPipeline) ruleMatches(rule PolicyRule, event common.DPIEvent) bool {
	// Check severity threshold
	if event.Severity < rule.MinSeverity {
		return false
	}

	// Check category filter
	if len(rule.Categories) > 0 {
		matched := false
		for _, cat := range rule.Categories {
			if cat == event.Category {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// createPolicy creates and applies a Cilium policy for the matched event.
func (p *PolicyPipeline) createPolicy(ctx context.Context, rule PolicyRule, event common.DPIEvent, policyKey string) error {
	policyName := p.policyName(rule.Name, event.SourceIP)
	description := fmt.Sprintf("Auto-generated from DPI event: %s (severity=%d)", event.Description, event.Severity)
	if p.nodeName != "" {
		description = fmt.Sprintf("%s on node %s", description, p.nodeName)
	}

	policy := &cilium.CiliumPolicy{
		Name:        policyName,
		Description: description,
		Labels: map[string]string{
			"fos1.io/auto-generated": "true",
			"fos1.io/dpi-rule":       rule.Name,
			"fos1.io/source-ip":      event.SourceIP,
			"fos1.io/action":         string(rule.Action),
		},
	}
	if p.nodeName != "" {
		policy.Labels["fos1.io/source-node"] = p.nodeName
		policy.Labels["fos1.io/policy-scope"] = "node-local"
	}

	// Build CIDR for the source IP
	srcCIDR := event.SourceIP
	if srcCIDR != "" && !containsPolicySlash(srcCIDR) {
		srcCIDR = srcCIDR + "/32"
	}

	switch rule.Action {
	case ActionBlock:
		// Create a deny rule that blocks traffic from the source CIDR
		policy.Rules = []cilium.CiliumRule{{
			FromCIDR: []string{srcCIDR},
			Denied:   true,
			Action:   "deny",
		}}
	case ActionLog:
		policy.Rules = []cilium.CiliumRule{{
			FromCIDR: []string{srcCIDR},
			Action:   "log",
		}}
	case ActionRateLimit:
		policy.Rules = []cilium.CiliumRule{{
			FromCIDR: []string{srcCIDR},
			Action:   "allow",
		}}
	}

	if err := p.ciliumClient.ApplyNetworkPolicy(ctx, policy); err != nil {
		return fmt.Errorf("apply policy %s: %w", policyName, err)
	}

	now := time.Now()
	ap := &ActivePolicy{
		Name:         policyName,
		NodeName:     p.nodeName,
		SourceIP:     event.SourceIP,
		Policy:       policy,
		CreatedAt:    now,
		EventCount:   1,
		Rule:         rule.Name,
		TriggerEvent: event,
		Actions: []EnforcementAction{
			{
				Timestamp:  now,
				ActionType: "created",
				PolicyName: policyName,
				NodeName:   p.nodeName,
				SourceIP:   event.SourceIP,
				Rule:       rule.Name,
				Detail:     fmt.Sprintf("node=%s action=%s severity=%d category=%s description=%q", policyScopeNode(p.nodeName), rule.Action, event.Severity, event.Category, event.Description),
			},
		},
	}

	if rule.Duration > 0 {
		ap.ExpiresAt = now.Add(rule.Duration)
	}

	p.activePolicies[policyKey] = ap

	klog.Infof("Created DPI auto-policy %s: node=%s action=%s source=%s severity=%d category=%s",
		policyName, policyScopeNode(p.nodeName), rule.Action, event.SourceIP, event.Severity, event.Category)

	return nil
}

// Start begins the background goroutine for policy expiry cleanup.
func (p *PolicyPipeline) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.cleanupExpired(ctx)
			}
		}
	}()
}

// cleanupExpired removes policies that have exceeded their TTL,
// deleting the corresponding Cilium network policy for each.
func (p *PolicyPipeline) cleanupExpired(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for key, ap := range p.activePolicies {
		if ap.ExpiresAt.IsZero() {
			continue // permanent policy
		}
		if now.After(ap.ExpiresAt) {
			// Delete the Cilium policy from the cluster
			if err := p.ciliumClient.DeleteNetworkPolicy(ctx, ap.Name); err != nil {
				klog.Warningf("Failed to delete expired DPI auto-policy %s: %v", ap.Name, err)
				continue // retry on next tick
			}

			klog.Infof("Expired and removed DPI auto-policy %s (TTL exceeded, was active for %s, triggered %d events)",
				ap.Name, now.Sub(ap.CreatedAt).Round(time.Second), ap.EventCount)

			delete(p.activePolicies, key)
			delete(p.recentEvents, key)
		}
	}
}

// GetActivePolicies returns all active auto-generated policies.
func (p *PolicyPipeline) GetActivePolicies() []*ActivePolicy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*ActivePolicy, 0, len(p.activePolicies))
	for _, ap := range p.activePolicies {
		result = append(result, ap)
	}
	return result
}

// RemovePolicy manually removes an active policy and deletes the corresponding Cilium policy.
func (p *PolicyPipeline) RemovePolicy(ctx context.Context, policyKey string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ap, exists := p.activePolicies[policyKey]
	if !exists {
		return fmt.Errorf("policy %s not found", policyKey)
	}

	// Delete the Cilium policy from the cluster
	if err := p.ciliumClient.DeleteNetworkPolicy(ctx, ap.Name); err != nil {
		return fmt.Errorf("failed to delete Cilium policy %s: %w", ap.Name, err)
	}

	klog.Infof("Manually removed DPI auto-policy %s", ap.Name)

	delete(p.activePolicies, policyKey)
	delete(p.recentEvents, policyKey)
	return nil
}

// ActivePolicyCount returns the number of active policies.
func (p *PolicyPipeline) ActivePolicyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.activePolicies)
}

// containsPolicySlash checks if a string contains a slash (for CIDR notation).
func containsPolicySlash(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}

// sanitizePolicyName converts an IP or string into a valid K8s resource name component.
func sanitizePolicyName(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result = append(result, c)
		} else if c >= 'A' && c <= 'Z' {
			result = append(result, c+32) // lowercase
		} else {
			result = append(result, '-')
		}
	}
	if len(result) > 63 {
		result = result[:63]
	}
	return string(result)
}

func (p *PolicyPipeline) policyKey(ruleName, sourceIP string) string {
	if p.nodeName == "" {
		return fmt.Sprintf("%s:%s", ruleName, sourceIP)
	}
	return fmt.Sprintf("%s:%s:%s", p.nodeName, ruleName, sourceIP)
}

func (p *PolicyPipeline) policyName(ruleName, sourceIP string) string {
	parts := []string{"dpi", "auto", sanitizePolicyName(ruleName)}
	if p.nodeName != "" {
		parts = append(parts, sanitizePolicyName(p.nodeName))
	}
	if sourceIP == "" {
		parts = append(parts, "unknown")
	} else {
		parts = append(parts, sanitizePolicyName(sourceIP))
	}

	base := strings.Trim(strings.Join(parts, "-"), "-")
	suffix := shortPolicyHash(p.policyKey(ruleName, sourceIP))
	if len(base) > 54 {
		base = strings.Trim(base[:54], "-")
	}
	if base == "" {
		base = "dpi-auto"
	}

	return fmt.Sprintf("%s-%s", base, suffix)
}

func shortPolicyHash(value string) string {
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(value))
	return fmt.Sprintf("%08x", hasher.Sum32())
}

func policyScopeNode(nodeName string) string {
	if nodeName == "" {
		return "unknown"
	}
	return nodeName
}
