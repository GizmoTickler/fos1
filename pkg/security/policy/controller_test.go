package policy

import (
	"context"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type mockPolicyCiliumClient struct {
	applied []*cilium.CiliumPolicy
	deleted []string
}

func (m *mockPolicyCiliumClient) ApplyNetworkPolicy(_ context.Context, policy *cilium.CiliumPolicy) error {
	copy := *policy
	m.applied = append(m.applied, &copy)
	return nil
}

func (m *mockPolicyCiliumClient) DeleteNetworkPolicy(_ context.Context, policyName string) error {
	m.deleted = append(m.deleted, policyName)
	return nil
}

func (m *mockPolicyCiliumClient) ListRoutes(context.Context) ([]cilium.Route, error) {
	return nil, nil
}

func (m *mockPolicyCiliumClient) ListVRFRoutes(context.Context, int) ([]cilium.Route, error) {
	return nil, nil
}

func (m *mockPolicyCiliumClient) AddRoute(cilium.Route) error {
	return nil
}

func (m *mockPolicyCiliumClient) DeleteRoute(cilium.Route) error {
	return nil
}

func (m *mockPolicyCiliumClient) AddVRFRoute(cilium.Route, int) error {
	return nil
}

func (m *mockPolicyCiliumClient) DeleteVRFRoute(cilium.Route, int) error {
	return nil
}

func (m *mockPolicyCiliumClient) ConfigureVLANRouting(context.Context, *cilium.CiliumVLANRoutingConfig) error {
	return nil
}

func (m *mockPolicyCiliumClient) ConfigureDPIIntegration(context.Context, *cilium.CiliumDPIIntegrationConfig) error {
	return nil
}

func (m *mockPolicyCiliumClient) CreateNAT(context.Context, *cilium.CiliumNATConfig) error {
	return nil
}

func (m *mockPolicyCiliumClient) RemoveNAT(context.Context, *cilium.CiliumNATConfig) error {
	return nil
}

func (m *mockPolicyCiliumClient) CreateNAT64(context.Context, *cilium.NAT64Config) error {
	return nil
}

func (m *mockPolicyCiliumClient) RemoveNAT64(context.Context, *cilium.NAT64Config) error {
	return nil
}

func (m *mockPolicyCiliumClient) CreatePortForward(context.Context, *cilium.PortForwardConfig) error {
	return nil
}

func (m *mockPolicyCiliumClient) RemovePortForward(context.Context, *cilium.PortForwardConfig) error {
	return nil
}

func TestPolicyControllerStartWithoutConfiguredInformers(t *testing.T) {
	controller, err := NewPolicyController(fake.NewSimpleClientset(), &mockPolicyCiliumClient{}, nil, &ControllerConfig{
		ResyncPeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}

	if err := controller.Start(); err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}
	defer controller.Stop()

	if len(controller.informers) != 0 {
		t.Fatalf("expected no informers without explicit wiring, got %d", len(controller.informers))
	}
}

func TestPolicyControllerAppliesUpdatesAndDisablesPoliciesThroughCilium(t *testing.T) {
	client := &mockPolicyCiliumClient{}
	controller, err := NewPolicyController(fake.NewSimpleClientset(), client, nil, &ControllerConfig{
		ResyncPeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-web", Namespace: "team-a"},
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 100,
			Scope:    "ingress",
			Selectors: FilterSelectors{
				Sources: []Selector{{Type: "cidr", Values: []interface{}{"10.0.0.0/8"}}},
				Ports:   []PortSelector{{Protocol: "tcp", Ports: []int32{80}}},
			},
			Actions: []PolicyAction{{Type: "allow"}},
		},
	}

	controller.handlePolicyAdd(policy)

	if len(client.applied) != 1 {
		t.Fatalf("expected 1 apply on add, got %d", len(client.applied))
	}

	updated := policy.DeepCopy()
	updated.Spec.Selectors.Ports = []PortSelector{{Protocol: "tcp", Ports: []int32{443}}}
	controller.handlePolicyUpdate(updated)

	if len(client.applied) != 2 {
		t.Fatalf("expected 2 apply calls after update, got %d", len(client.applied))
	}
	if len(client.deleted) != 1 {
		t.Fatalf("expected 1 delete call before re-apply, got %d", len(client.deleted))
	}

	disabled := updated.DeepCopy()
	disabled.Spec.Enabled = false
	controller.handlePolicyUpdate(disabled)

	if len(client.deleted) != 2 {
		t.Fatalf("expected disabling to delete applied policy, got %d deletes", len(client.deleted))
	}
	if applied := controller.appliedPolicies[policyKey(policy)]; len(applied) != 0 {
		t.Fatalf("expected applied state cleared for disabled policy, got %v", applied)
	}
}

func TestPolicyControllerDeleteRemovesAppliedPolicies(t *testing.T) {
	client := &mockPolicyCiliumClient{}
	controller, err := NewPolicyController(fake.NewSimpleClientset(), client, nil, &ControllerConfig{
		ResyncPeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-db", Namespace: "team-a"},
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 90,
			Scope:    "egress",
			Selectors: FilterSelectors{
				Destinations: []Selector{{Type: "cidr", Values: []interface{}{"192.168.1.0/24"}}},
			},
			Actions: []PolicyAction{{Type: "deny"}},
		},
	}

	controller.handlePolicyAdd(policy)
	controller.handlePolicyDelete(policy)

	if len(client.applied) != 1 {
		t.Fatalf("expected policy apply before delete, got %d applies", len(client.applied))
	}
	if len(client.deleted) != 1 {
		t.Fatalf("expected 1 delete call, got %d", len(client.deleted))
	}
	if _, exists := controller.policies[policyKey(policy)]; exists {
		t.Fatalf("expected policy to be removed from controller cache")
	}
	if _, exists := controller.appliedPolicies[policyKey(policy)]; exists {
		t.Fatalf("expected applied policy state to be removed")
	}
}
