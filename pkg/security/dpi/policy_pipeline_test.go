package dpi

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/security/dpi/common"
)

// pipelineMockCiliumClient tracks calls to ApplyNetworkPolicy and DeleteNetworkPolicy.
type pipelineMockCiliumClient struct {
	mu                         sync.Mutex
	ApplyNetworkPolicyCalled   bool
	AppliedPolicies            []*cilium.CiliumPolicy
	DeleteNetworkPolicyCalled  bool
	DeletedPolicyNames         []string
	LastPolicy                 *cilium.CiliumPolicy
}

func (m *pipelineMockCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *cilium.CiliumPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ApplyNetworkPolicyCalled = true
	m.LastPolicy = policy
	m.AppliedPolicies = append(m.AppliedPolicies, policy)
	return nil
}

func (m *pipelineMockCiliumClient) DeleteNetworkPolicy(ctx context.Context, policyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DeleteNetworkPolicyCalled = true
	m.DeletedPolicyNames = append(m.DeletedPolicyNames, policyName)
	return nil
}

func (m *pipelineMockCiliumClient) ConfigureDPIIntegration(ctx context.Context, config *cilium.CiliumDPIIntegrationConfig) error {
	return nil
}
func (m *pipelineMockCiliumClient) CreateNAT(ctx context.Context, config *cilium.CiliumNATConfig) error {
	return nil
}
func (m *pipelineMockCiliumClient) RemoveNAT(ctx context.Context, config *cilium.CiliumNATConfig) error {
	return nil
}
func (m *pipelineMockCiliumClient) CreateNAT64(ctx context.Context, config *cilium.NAT64Config) error {
	return nil
}
func (m *pipelineMockCiliumClient) RemoveNAT64(ctx context.Context, config *cilium.NAT64Config) error {
	return nil
}
func (m *pipelineMockCiliumClient) CreatePortForward(ctx context.Context, config *cilium.PortForwardConfig) error {
	return nil
}
func (m *pipelineMockCiliumClient) RemovePortForward(ctx context.Context, config *cilium.PortForwardConfig) error {
	return nil
}
func (m *pipelineMockCiliumClient) ConfigureVLANRouting(ctx context.Context, config *cilium.CiliumVLANRoutingConfig) error {
	return nil
}

// pipelineErrorCiliumClient always returns errors on ApplyNetworkPolicy.
type pipelineErrorCiliumClient struct {
	pipelineMockCiliumClient
}

func (m *pipelineErrorCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *cilium.CiliumPolicy) error {
	return context.DeadlineExceeded
}

func TestPolicyPipelineBlockOnSeverity(t *testing.T) {
	mock := &pipelineMockCiliumClient{}
	rules := []PolicyRule{
		{
			Name:        "high-severity-block",
			MinSeverity: 3,
			Action:      ActionBlock,
			Duration:    5 * time.Minute,
		},
	}

	pipeline := NewPolicyPipeline(mock, rules)

	// Low severity — should not trigger
	err := pipeline.ProcessEvent(context.Background(), common.DPIEvent{
		SourceIP: "10.0.0.1",
		Severity: 1,
		Category: "malware",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pipeline.ActivePolicyCount() != 0 {
		t.Error("low severity event should not create policy")
	}

	// High severity — should trigger
	err = pipeline.ProcessEvent(context.Background(), common.DPIEvent{
		SourceIP:    "10.0.0.2",
		Severity:    4,
		Category:    "malware",
		Description: "trojan detected",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pipeline.ActivePolicyCount() != 1 {
		t.Errorf("expected 1 active policy, got %d", pipeline.ActivePolicyCount())
	}
	if !mock.ApplyNetworkPolicyCalled {
		t.Error("ApplyNetworkPolicy should have been called")
	}
}

func TestPolicyPipelineCategoryFilter(t *testing.T) {
	mock := &pipelineMockCiliumClient{}
	rules := []PolicyRule{
		{
			Name:        "malware-block",
			MinSeverity: 1,
			Categories:  []string{"malware", "exploit"},
			Action:      ActionBlock,
		},
	}

	pipeline := NewPolicyPipeline(mock, rules)

	// Non-matching category
	pipeline.ProcessEvent(context.Background(), common.DPIEvent{
		SourceIP: "10.0.0.1",
		Severity: 3,
		Category: "normal",
	})
	if pipeline.ActivePolicyCount() != 0 {
		t.Error("non-matching category should not create policy")
	}

	// Matching category
	pipeline.ProcessEvent(context.Background(), common.DPIEvent{
		SourceIP: "10.0.0.1",
		Severity: 3,
		Category: "malware",
	})
	if pipeline.ActivePolicyCount() != 1 {
		t.Errorf("expected 1 policy, got %d", pipeline.ActivePolicyCount())
	}
}

func TestPolicyPipelineDeduplication(t *testing.T) {
	mock := &pipelineMockCiliumClient{}
	rules := []PolicyRule{
		{
			Name:            "dedup-test",
			MinSeverity:     1,
			Action:          ActionBlock,
			AggregateWindow: 1 * time.Hour,
		},
	}

	pipeline := NewPolicyPipeline(mock, rules)

	event := common.DPIEvent{
		SourceIP: "10.0.0.1",
		Severity: 3,
	}

	// First event creates policy
	pipeline.ProcessEvent(context.Background(), event)
	if pipeline.ActivePolicyCount() != 1 {
		t.Fatal("first event should create policy")
	}

	// Second event should just increment counter (dedup)
	pipeline.ProcessEvent(context.Background(), event)

	policies := pipeline.GetActivePolicies()
	if len(policies) != 1 {
		t.Fatal("should still have 1 policy")
	}
	if policies[0].EventCount != 2 {
		t.Errorf("expected event count 2, got %d", policies[0].EventCount)
	}

	// Verify ApplyNetworkPolicy was called only once (not for the dedup event)
	mock.mu.Lock()
	applyCount := len(mock.AppliedPolicies)
	mock.mu.Unlock()
	if applyCount != 1 {
		t.Errorf("expected ApplyNetworkPolicy called once, got %d", applyCount)
	}
}

func TestPolicyPipelineMultipleRules(t *testing.T) {
	mock := &pipelineMockCiliumClient{}
	rules := []PolicyRule{
		{Name: "block-high", MinSeverity: 3, Action: ActionBlock},
		{Name: "log-medium", MinSeverity: 1, Action: ActionLog},
	}

	pipeline := NewPolicyPipeline(mock, rules)

	// Severity 4 matches both rules
	pipeline.ProcessEvent(context.Background(), common.DPIEvent{
		SourceIP: "10.0.0.1",
		Severity: 4,
	})

	if pipeline.ActivePolicyCount() != 2 {
		t.Errorf("expected 2 policies (both rules), got %d", pipeline.ActivePolicyCount())
	}
}

func TestPolicyPipelineRemove(t *testing.T) {
	mock := &pipelineMockCiliumClient{}
	rules := []PolicyRule{
		{Name: "test", MinSeverity: 1, Action: ActionBlock},
	}

	pipeline := NewPolicyPipeline(mock, rules)

	pipeline.ProcessEvent(context.Background(), common.DPIEvent{
		SourceIP: "10.0.0.1",
		Severity: 3,
	})

	err := pipeline.RemovePolicy(context.Background(), "test:10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if pipeline.ActivePolicyCount() != 0 {
		t.Error("policy should be removed")
	}

	// Verify DeleteNetworkPolicy was called
	if !mock.DeleteNetworkPolicyCalled {
		t.Error("DeleteNetworkPolicy should have been called on removal")
	}

	// Remove non-existent
	err = pipeline.RemovePolicy(context.Background(), "nonexistent:1.2.3.4")
	if err == nil {
		t.Error("removing non-existent policy should fail")
	}
}

func TestPolicyPipelineApplyError(t *testing.T) {
	mock := &pipelineErrorCiliumClient{}
	rules := []PolicyRule{
		{Name: "test", MinSeverity: 1, Action: ActionBlock},
	}

	pipeline := NewPolicyPipeline(mock, rules)

	err := pipeline.ProcessEvent(context.Background(), common.DPIEvent{
		SourceIP: "10.0.0.1",
		Severity: 3,
	})

	if err == nil {
		t.Error("should propagate cilium client error")
	}
	if pipeline.ActivePolicyCount() != 0 {
		t.Error("no policy should be created on error")
	}
}

func TestPolicyPipelineBlockCreatesCIDRDenyRule(t *testing.T) {
	mock := &pipelineMockCiliumClient{}
	rules := []PolicyRule{
		{
			Name:        "block-rule",
			MinSeverity: 3,
			Action:      ActionBlock,
			Duration:    10 * time.Minute,
		},
	}

	pipeline := NewPolicyPipeline(mock, rules)

	err := pipeline.ProcessEvent(context.Background(), common.DPIEvent{
		SourceIP:    "192.168.1.100",
		Severity:    4,
		Category:    "malware",
		Description: "trojan callback detected",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the applied policy has CIDR-based deny rules
	mock.mu.Lock()
	defer mock.mu.Unlock()

	if len(mock.AppliedPolicies) != 1 {
		t.Fatalf("expected 1 applied policy, got %d", len(mock.AppliedPolicies))
	}

	policy := mock.AppliedPolicies[0]
	if len(policy.Rules) == 0 {
		t.Fatal("expected at least one rule in the policy")
	}

	rule := policy.Rules[0]
	if !rule.Denied {
		t.Error("block action should produce a denied=true rule")
	}
	if len(rule.FromCIDR) == 0 {
		t.Error("block action should include FromCIDR")
	}
	if rule.FromCIDR[0] != "192.168.1.100/32" {
		t.Errorf("expected FromCIDR 192.168.1.100/32, got %s", rule.FromCIDR[0])
	}

	// Verify labels include action metadata
	if policy.Labels["fos1.io/action"] != "block" {
		t.Errorf("expected action label 'block', got %s", policy.Labels["fos1.io/action"])
	}
}

func TestPolicyPipelineExpiryDeletesCiliumPolicy(t *testing.T) {
	mock := &pipelineMockCiliumClient{}
	rules := []PolicyRule{
		{
			Name:        "expiry-test",
			MinSeverity: 1,
			Action:      ActionBlock,
			Duration:    1 * time.Millisecond, // very short TTL for testing
		},
	}

	pipeline := NewPolicyPipeline(mock, rules)

	err := pipeline.ProcessEvent(context.Background(), common.DPIEvent{
		SourceIP: "10.0.0.50",
		Severity: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pipeline.ActivePolicyCount() != 1 {
		t.Fatal("expected 1 active policy")
	}

	// Wait for TTL to expire
	time.Sleep(10 * time.Millisecond)

	// Manually trigger cleanup
	pipeline.cleanupExpired(context.Background())

	// Policy should be removed
	if pipeline.ActivePolicyCount() != 0 {
		t.Errorf("expected 0 active policies after expiry, got %d", pipeline.ActivePolicyCount())
	}

	// Verify DeleteNetworkPolicy was called
	mock.mu.Lock()
	defer mock.mu.Unlock()
	if !mock.DeleteNetworkPolicyCalled {
		t.Error("DeleteNetworkPolicy should have been called on expiry")
	}
	if len(mock.DeletedPolicyNames) != 1 {
		t.Fatalf("expected 1 deleted policy name, got %d", len(mock.DeletedPolicyNames))
	}
}

func TestPolicyPipelineEnforcementAudit(t *testing.T) {
	mock := &pipelineMockCiliumClient{}
	rules := []PolicyRule{
		{
			Name:        "audit-test",
			MinSeverity: 1,
			Action:      ActionBlock,
		},
	}

	pipeline := NewPolicyPipeline(mock, rules)

	event := common.DPIEvent{
		SourceIP:    "10.0.0.99",
		Severity:    4,
		Category:    "exploit",
		Description: "buffer overflow attempt",
	}

	err := pipeline.ProcessEvent(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}

	policies := pipeline.GetActivePolicies()
	if len(policies) != 1 {
		t.Fatal("expected 1 active policy")
	}

	ap := policies[0]

	// Verify trigger event is recorded
	if ap.TriggerEvent.SourceIP != "10.0.0.99" {
		t.Errorf("expected trigger event source IP 10.0.0.99, got %s", ap.TriggerEvent.SourceIP)
	}
	if ap.TriggerEvent.Description != "buffer overflow attempt" {
		t.Errorf("expected trigger event description, got %s", ap.TriggerEvent.Description)
	}

	// Verify enforcement action is recorded
	if len(ap.Actions) != 1 {
		t.Fatalf("expected 1 enforcement action, got %d", len(ap.Actions))
	}
	if ap.Actions[0].ActionType != "created" {
		t.Errorf("expected action type 'created', got %s", ap.Actions[0].ActionType)
	}
	if ap.Actions[0].SourceIP != "10.0.0.99" {
		t.Errorf("expected action source IP 10.0.0.99, got %s", ap.Actions[0].SourceIP)
	}
}
