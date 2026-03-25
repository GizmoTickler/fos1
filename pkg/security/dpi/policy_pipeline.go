package dpi

import (
	"context"
	"fmt"
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

// ActivePolicy tracks a policy that has been applied to the firewall.
type ActivePolicy struct {
	Name       string
	SourceIP   string
	Policy     *cilium.CiliumPolicy
	CreatedAt  time.Time
	ExpiresAt  time.Time
	EventCount int
	Rule       string // name of the PolicyRule that created this
}

// PolicyPipeline processes DPI events and auto-generates firewall policies
// based on configurable rules with severity thresholds, deduplication, and TTL expiry.
type PolicyPipeline struct {
	ciliumClient   cilium.CiliumClient
	rules          []PolicyRule
	activePolicies map[string]*ActivePolicy // key: "rule:sourceIP"
	recentEvents   map[string]time.Time     // deduplication tracking
	mu             sync.RWMutex
}

// NewPolicyPipeline creates a new DPI-to-firewall policy pipeline.
func NewPolicyPipeline(client cilium.CiliumClient, rules []PolicyRule) *PolicyPipeline {
	return &PolicyPipeline{
		ciliumClient:   client,
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

		policyKey := fmt.Sprintf("%s:%s", rule.Name, event.SourceIP)

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
	policyName := fmt.Sprintf("dpi-auto-%s-%s", rule.Name, event.SourceIP)

	policy := &cilium.CiliumPolicy{
		Name:        policyName,
		Description: fmt.Sprintf("Auto-generated from DPI event: %s (severity=%d)", event.Description, event.Severity),
		Labels: map[string]string{
			"fos1.io/auto-generated": "true",
			"fos1.io/dpi-rule":      rule.Name,
			"fos1.io/source-ip":     event.SourceIP,
		},
	}

	switch rule.Action {
	case ActionBlock:
		policy.Rules = []cilium.CiliumRule{{
			Action: "deny",
		}}
	case ActionLog:
		policy.Rules = []cilium.CiliumRule{{
			Action: "log",
		}}
	case ActionRateLimit:
		policy.Rules = []cilium.CiliumRule{{
			Action: "allow",
		}}
	}

	if err := p.ciliumClient.ApplyNetworkPolicy(ctx, policy); err != nil {
		return fmt.Errorf("apply policy %s: %w", policyName, err)
	}

	now := time.Now()
	ap := &ActivePolicy{
		Name:       policyName,
		SourceIP:   event.SourceIP,
		Policy:     policy,
		CreatedAt:  now,
		EventCount: 1,
		Rule:       rule.Name,
	}

	if rule.Duration > 0 {
		ap.ExpiresAt = now.Add(rule.Duration)
	}

	p.activePolicies[policyKey] = ap

	klog.Infof("Created DPI auto-policy %s: action=%s source=%s severity=%d",
		policyName, rule.Action, event.SourceIP, event.Severity)

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

// cleanupExpired removes policies that have exceeded their TTL.
func (p *PolicyPipeline) cleanupExpired(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for key, ap := range p.activePolicies {
		if ap.ExpiresAt.IsZero() {
			continue // permanent policy
		}
		if now.After(ap.ExpiresAt) {
			klog.Infof("Expiring DPI auto-policy %s (TTL exceeded)", ap.Name)
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

// RemovePolicy manually removes an active policy.
func (p *PolicyPipeline) RemovePolicy(policyKey string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.activePolicies[policyKey]; !exists {
		return fmt.Errorf("policy %s not found", policyKey)
	}

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
