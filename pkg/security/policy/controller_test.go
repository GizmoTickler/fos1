package policy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type mockPolicyCiliumClient struct {
	applied []*cilium.CiliumPolicy
	deleted []string

	// applyErrOn makes ApplyNetworkPolicy return an error when the target
	// policy name matches. Used to simulate partial-apply (Degraded).
	applyErrOn map[string]error
}

func (m *mockPolicyCiliumClient) ApplyNetworkPolicy(_ context.Context, policy *cilium.CiliumPolicy) error {
	if err, ok := m.applyErrOn[policy.Name]; ok && err != nil {
		return err
	}
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

// TestPolicyControllerIdempotentNoop verifies that re-processing the same
// spec does not re-issue ApplyNetworkPolicy calls once LastAppliedHash is
// recorded, matching the NAT controller's SpecHash-based idempotency
// (pkg/controllers/nat_controller.go:82).
func TestPolicyControllerIdempotentNoop(t *testing.T) {
	client := &mockPolicyCiliumClient{}
	controller, err := NewPolicyController(fake.NewSimpleClientset(), client, nil, &ControllerConfig{
		ResyncPeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-http", Namespace: "team-b"},
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 100,
			Scope:    "ingress",
			Selectors: FilterSelectors{
				Ports: []PortSelector{{Protocol: "tcp", Ports: []int32{80}}},
			},
			Actions: []PolicyAction{{Type: "allow"}},
		},
	}

	controller.handlePolicyAdd(policy)
	if len(client.applied) != 1 {
		t.Fatalf("expected 1 apply on first reconcile, got %d", len(client.applied))
	}

	stored, ok := controller.policies[policyKey(policy)]
	if !ok {
		t.Fatal("expected policy to be cached after first reconcile")
	}
	firstHash := stored.Status.LastAppliedHash
	if firstHash == "" {
		t.Fatal("expected LastAppliedHash to be recorded after apply")
	}

	// Second reconcile with identical spec — must be a no-op.
	controller.handlePolicyUpdate(stored.DeepCopy())
	if len(client.applied) != 1 {
		t.Fatalf("expected applies to stay at 1 for idempotent reconcile, got %d", len(client.applied))
	}
	if len(client.deleted) != 0 {
		t.Fatalf("expected no delete calls on idempotent reconcile, got %d", len(client.deleted))
	}

	stored = controller.policies[policyKey(policy)]
	if stored.Status.LastAppliedHash != firstHash {
		t.Fatalf("expected LastAppliedHash unchanged across idempotent reconcile, got %q -> %q",
			firstHash, stored.Status.LastAppliedHash)
	}
	if !hasCondition(stored.Status.Conditions, ConditionApplied, ConditionStatusTrue) {
		t.Fatalf("expected Applied=True condition, got %+v", stored.Status.Conditions)
	}
}

// TestPolicyControllerConditionsAppliedAndRemoved walks through the full
// add -> disable lifecycle and asserts the condition transitions mirror the
// NAT controller's (Applied -> Removed).
func TestPolicyControllerConditionsAppliedAndRemoved(t *testing.T) {
	client := &mockPolicyCiliumClient{}
	controller, err := NewPolicyController(fake.NewSimpleClientset(), client, nil, &ControllerConfig{
		ResyncPeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "block-db", Namespace: "team-c"},
		Spec: FilterPolicySpec{
			Enabled: true,
			Scope:   "egress",
			Selectors: FilterSelectors{
				Destinations: []Selector{{Type: "cidr", Values: []interface{}{"10.0.0.0/8"}}},
			},
			Actions: []PolicyAction{{Type: "deny"}},
		},
	}

	controller.handlePolicyAdd(policy)

	stored := controller.policies[policyKey(policy)]
	if !hasCondition(stored.Status.Conditions, ConditionApplied, ConditionStatusTrue) {
		t.Fatalf("expected Applied=True after add, got %+v", stored.Status.Conditions)
	}
	if hasCondition(stored.Status.Conditions, ConditionRemoved, ConditionStatusTrue) {
		t.Fatalf("did not expect Removed=True immediately after add, got %+v", stored.Status.Conditions)
	}

	disabled := stored.DeepCopy()
	disabled.Spec.Enabled = false
	controller.handlePolicyUpdate(disabled)

	stored = controller.policies[policyKey(policy)]
	if !hasCondition(stored.Status.Conditions, ConditionRemoved, ConditionStatusTrue) {
		t.Fatalf("expected Removed=True after disable, got %+v", stored.Status.Conditions)
	}
	if !hasCondition(stored.Status.Conditions, ConditionApplied, ConditionStatusFalse) {
		t.Fatalf("expected Applied=False after disable, got %+v", stored.Status.Conditions)
	}
	if stored.Status.LastAppliedHash != "" {
		t.Fatalf("expected LastAppliedHash cleared after disable, got %q", stored.Status.LastAppliedHash)
	}
}

// TestPolicyControllerDegradedOnCiliumApplyError simulates an apply failure
// and asserts Degraded=True is set. The current translator emits one
// CiliumPolicy per FilterPolicy, so a single-policy apply error fully
// triggers the Degraded branch.
func TestPolicyControllerDegradedOnCiliumApplyError(t *testing.T) {
	client := &mockPolicyCiliumClient{
		applyErrOn: map[string]error{
			"fos1-filter-team-d-half-broken": fmt.Errorf("simulated cilium apply failure"),
		},
	}
	controller, err := NewPolicyController(fake.NewSimpleClientset(), client, nil, &ControllerConfig{
		ResyncPeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "half-broken", Namespace: "team-d"},
		Spec: FilterPolicySpec{
			Enabled: true,
			Scope:   "ingress",
			Selectors: FilterSelectors{
				Sources: []Selector{{Type: "cidr", Values: []interface{}{"172.16.0.0/12"}}},
			},
			Actions: []PolicyAction{{Type: "allow"}},
		},
	}

	controller.handlePolicyAdd(policy)

	stored := controller.policies[policyKey(policy)]
	if !hasCondition(stored.Status.Conditions, ConditionDegraded, ConditionStatusTrue) {
		t.Fatalf("expected Degraded=True after cilium apply error, got %+v", stored.Status.Conditions)
	}
	if stored.Status.LastAppliedHash != "" {
		t.Fatalf("expected LastAppliedHash cleared on degraded apply, got %q", stored.Status.LastAppliedHash)
	}
	if len(client.applied) != 0 {
		t.Fatalf("expected no successful applies, got %d", len(client.applied))
	}
	if stored.Status.Applied {
		t.Fatalf("expected Status.Applied=false on full apply failure, got true")
	}
}

// TestPolicyControllerRejectsInvalidSpec exercises the translator-error path
// via a test double whose TranslatePolicy always fails; verifies the
// Invalid condition is set and no Cilium calls are issued.
func TestPolicyControllerRejectsInvalidSpec(t *testing.T) {
	client := &mockPolicyCiliumClient{}
	controller, err := NewPolicyController(fake.NewSimpleClientset(), client, nil, &ControllerConfig{
		ResyncPeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}

	// Replace translator with one that always fails so the Invalid branch
	// is deterministically reached.
	controller.translator = &invalidTranslator{}

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-spec", Namespace: "team-e"},
		Spec: FilterPolicySpec{
			Enabled: true,
			Scope:   "ingress",
			Actions: []PolicyAction{{Type: "allow"}},
		},
	}

	controller.handlePolicyAdd(policy)

	stored := controller.policies[policyKey(policy)]
	if !hasCondition(stored.Status.Conditions, ConditionInvalid, ConditionStatusTrue) {
		t.Fatalf("expected Invalid=True on translator error, got %+v", stored.Status.Conditions)
	}
	if !hasCondition(stored.Status.Conditions, ConditionApplied, ConditionStatusFalse) {
		t.Fatalf("expected Applied=False on translator error, got %+v", stored.Status.Conditions)
	}
	if len(client.applied) != 0 {
		t.Fatalf("expected no Cilium apply calls on invalid spec, got %d", len(client.applied))
	}
}

// invalidTranslator is a test double whose TranslatePolicy always returns
// an error so the controller exercises its Invalid branch.
type invalidTranslator struct{}

func (invalidTranslator) TranslatePolicy(*FilterPolicy, map[string]*FilterZone) ([]*cilium.CiliumPolicy, error) {
	return nil, fmt.Errorf("translator rejected spec for test")
}

// hasCondition returns true if conditions contains a PolicyCondition with
// matching type and status.
func hasCondition(conds []PolicyCondition, condType, status string) bool {
	for _, c := range conds {
		if c.Type == condType && c.Status == status {
			return true
		}
	}
	return false
}
