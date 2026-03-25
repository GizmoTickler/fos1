package dpi

import (
	"context"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/security/dpi/common"
)

func TestPolicyPipelineBlockOnSeverity(t *testing.T) {
	mock := &MockCiliumClient{}
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
	mock := &MockCiliumClient{}
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
	mock := &MockCiliumClient{}
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
}

func TestPolicyPipelineMultipleRules(t *testing.T) {
	mock := &MockCiliumClient{}
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
	mock := &MockCiliumClient{}
	rules := []PolicyRule{
		{Name: "test", MinSeverity: 1, Action: ActionBlock},
	}

	pipeline := NewPolicyPipeline(mock, rules)

	pipeline.ProcessEvent(context.Background(), common.DPIEvent{
		SourceIP: "10.0.0.1",
		Severity: 3,
	})

	err := pipeline.RemovePolicy("test:10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if pipeline.ActivePolicyCount() != 0 {
		t.Error("policy should be removed")
	}

	// Remove non-existent
	err = pipeline.RemovePolicy("nonexistent:1.2.3.4")
	if err == nil {
		t.Error("removing non-existent policy should fail")
	}
}

func TestPolicyPipelineApplyError(t *testing.T) {
	mock := &errorCiliumClient{}
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

// errorCiliumClient always returns errors.
type errorCiliumClient struct{ MockCiliumClient }

func (m *errorCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *cilium.CiliumPolicy) error {
	return context.DeadlineExceeded
}
