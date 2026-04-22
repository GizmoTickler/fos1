package policy

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
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

// newFakeDynamicClientForFilterPolicy returns a FakeDynamicClient wired to
// accept UpdateStatus calls on the filterpolicies resource without requiring
// the object to exist in the tracker. Mirrors the NAT controller's test
// helper at pkg/controllers/nat_controller_test.go:204.
func newFakeDynamicClientForFilterPolicy() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	c := dynamicfake.NewSimpleDynamicClient(scheme)
	c.PrependReactor("update", "filterpolicies", func(action clienttesting.Action) (bool, runtime.Object, error) {
		upd, ok := action.(clienttesting.UpdateAction)
		if !ok {
			return false, nil, nil
		}
		return true, upd.GetObject(), nil
	})
	return c
}

// TestPolicyControllerPersistsStatusToCRD closes the Sprint-29 / Ticket-33
// follow-up: after a successful reconcile, the controller must push the
// computed FilterPolicy.Status back to the CRD status subresource via the
// shared pkg/controllers/status.Writer helper. Asserts (a) exactly one
// update/status action is recorded against the correct GVR, and (b) the
// payload contains the Applied=True condition and the expected
// lastAppliedHash — i.e. status survives a controller restart because it
// is now persisted server-side rather than only in the in-memory cache.
func TestPolicyControllerPersistsStatusToCRD(t *testing.T) {
	ciliumMock := &mockPolicyCiliumClient{}
	dynFake := newFakeDynamicClientForFilterPolicy()

	controller, err := NewPolicyController(fake.NewSimpleClientset(), ciliumMock, nil, &ControllerConfig{
		ResyncPeriod:  time.Second,
		DynamicClient: dynFake,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-http", Namespace: "team-a"},
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

	actions := dynFake.Actions()
	if len(actions) != 1 {
		t.Fatalf("expected 1 dynamic-client action (update/status), got %d: %v",
			len(actions), dumpVerbs(actions))
	}
	act := actions[0]
	if act.GetVerb() != "update" || act.GetSubresource() != "status" {
		t.Fatalf("expected update on status subresource, got %s/%s",
			act.GetVerb(), act.GetSubresource())
	}
	if act.GetResource().Resource != "filterpolicies" {
		t.Fatalf("expected filterpolicies resource, got %s", act.GetResource().Resource)
	}

	written := act.(clienttesting.UpdateAction).GetObject().(*unstructured.Unstructured)
	if got := written.GetNamespace(); got != "team-a" {
		t.Fatalf("expected written object namespace=team-a, got %q", got)
	}
	if got := written.GetName(); got != "allow-http" {
		t.Fatalf("expected written object name=allow-http, got %q", got)
	}

	applied, found, err := unstructured.NestedBool(written.Object, "status", "applied")
	if err != nil || !found {
		t.Fatalf("expected status.applied field on written object, found=%v err=%v", found, err)
	}
	if !applied {
		t.Fatalf("expected status.applied=true on written object, got false")
	}

	hash, found, err := unstructured.NestedString(written.Object, "status", "lastAppliedHash")
	if err != nil || !found || hash == "" {
		t.Fatalf("expected non-empty status.lastAppliedHash, found=%v hash=%q err=%v",
			found, hash, err)
	}

	conds, found, err := unstructured.NestedSlice(written.Object, "status", "conditions")
	if err != nil || !found {
		t.Fatalf("expected status.conditions, found=%v err=%v", found, err)
	}
	if !hasUnstructuredCondition(conds, "Applied", "True") {
		t.Fatalf("expected Applied=True condition in written status, got: %+v", conds)
	}
}

// TestPolicyControllerPersistsStatusAcrossRestart simulates the
// "controller-restart" scenario that Ticket 33 flagged: if we tear down
// the controller and start a new one without seeding the in-memory cache,
// the only way the restarted controller can recover the previously-
// applied status is for it to have been written to the CRD on the prior
// reconcile. This test asserts the status payload written by the prior
// reconcile carries all the fields a fresh controller would need to
// rehydrate (Applied, LastAppliedHash, Conditions).
func TestPolicyControllerPersistsStatusAcrossRestart(t *testing.T) {
	ciliumMock := &mockPolicyCiliumClient{}
	dynFake := newFakeDynamicClientForFilterPolicy()

	controller, err := NewPolicyController(fake.NewSimpleClientset(), ciliumMock, nil, &ControllerConfig{
		ResyncPeriod:  time.Second,
		DynamicClient: dynFake,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "persist-me", Namespace: "team-restart"},
		Spec: FilterPolicySpec{
			Enabled: true,
			Scope:   "ingress",
			Selectors: FilterSelectors{
				Sources: []Selector{{Type: "cidr", Values: []interface{}{"10.0.0.0/8"}}},
			},
			Actions: []PolicyAction{{Type: "allow"}},
		},
	}

	controller.handlePolicyAdd(policy)

	actions := dynFake.Actions()
	if len(actions) == 0 {
		t.Fatal("expected a status write on first reconcile; got none")
	}
	last := actions[len(actions)-1]
	written := last.(clienttesting.UpdateAction).GetObject().(*unstructured.Unstructured)

	// Every status field the controller's recovery path would need to
	// prove it need not re-apply must be present.
	applied, _, _ := unstructured.NestedBool(written.Object, "status", "applied")
	hash, _, _ := unstructured.NestedString(written.Object, "status", "lastAppliedHash")
	conds, _, _ := unstructured.NestedSlice(written.Object, "status", "conditions")
	if !applied || hash == "" || !hasUnstructuredCondition(conds, "Applied", "True") {
		t.Fatalf("restart-safety check: expected applied=true, non-empty hash, Applied=True condition; got applied=%v hash=%q conds=%+v",
			applied, hash, conds)
	}
}

// TestPolicyControllerStatusWriteRetriesOnConflict exercises the retry
// path end-to-end from the controller: the dynamic fake returns a single
// Conflict on the first UpdateStatus, the Writer re-fetches and tries
// again, and the second attempt wins. Confirms the FilterPolicy controller
// does not silently swallow status conflicts.
func TestPolicyControllerStatusWriteRetriesOnConflict(t *testing.T) {
	ciliumMock := &mockPolicyCiliumClient{}
	scheme := runtime.NewScheme()

	// Seed the fake with an existing FilterPolicy so the re-fetch on
	// conflict can succeed.
	seed := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.fos1.io/v1alpha1",
			"kind":       "FilterPolicy",
			"metadata": map[string]interface{}{
				"name":            "racy",
				"namespace":       "team-race",
				"resourceVersion": "7",
			},
		},
	}
	dynFake := dynamicfake.NewSimpleDynamicClient(scheme, seed)

	// Return one Conflict, then fall through.
	var conflicts int32
	dynFake.PrependReactor("update", "filterpolicies", func(action clienttesting.Action) (bool, runtime.Object, error) {
		upd, ok := action.(clienttesting.UpdateAction)
		if !ok || upd.GetSubresource() != "status" {
			return false, nil, nil
		}
		if atomic.AddInt32(&conflicts, 1) == 1 {
			return true, nil, apierrors.NewConflict(
				filterPolicyGVR.GroupResource(),
				"racy",
				errors.New("simulated conflict"),
			)
		}
		return true, upd.GetObject(), nil
	})

	controller, err := NewPolicyController(fake.NewSimpleClientset(), ciliumMock, nil, &ControllerConfig{
		ResyncPeriod:  time.Second,
		DynamicClient: dynFake,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "racy", Namespace: "team-race"},
		Spec: FilterPolicySpec{
			Enabled: true,
			Scope:   "ingress",
			Selectors: FilterSelectors{
				Sources: []Selector{{Type: "cidr", Values: []interface{}{"10.0.0.0/8"}}},
			},
			Actions: []PolicyAction{{Type: "allow"}},
		},
	}

	controller.handlePolicyAdd(policy)

	// Expect at least: update (conflict) -> get -> update (ok).
	verbs := dumpVerbs(dynFake.Actions())
	if len(verbs) < 3 {
		t.Fatalf("expected >=3 actions (update/status, get, update/status), got %v", verbs)
	}
	if verbs[0] != "update/status" {
		t.Fatalf("expected first action update/status, got %s", verbs[0])
	}
	if verbs[1] != "get" {
		t.Fatalf("expected second action get (re-fetch after conflict), got %s", verbs[1])
	}
	if verbs[2] != "update/status" {
		t.Fatalf("expected third action update/status, got %s", verbs[2])
	}
	if atomic.LoadInt32(&conflicts) < 2 {
		t.Fatalf("expected at least 2 update attempts (one conflict + one retry), got %d",
			atomic.LoadInt32(&conflicts))
	}
}

// TestPolicyControllerWithoutDynamicClientSkipsWriteback confirms the
// backward-compat contract: a controller built without a dynamic client
// does not attempt any status writes, and reconciles still run to
// completion. This is the pre-Ticket-40 behaviour and must be preserved
// for callers (and tests) that have not migrated to dynamic-client
// wiring.
func TestPolicyControllerWithoutDynamicClientSkipsWriteback(t *testing.T) {
	ciliumMock := &mockPolicyCiliumClient{}
	controller, err := NewPolicyController(fake.NewSimpleClientset(), ciliumMock, nil, &ControllerConfig{
		ResyncPeriod: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected controller error: %v", err)
	}
	if controller.statusWriter != nil {
		t.Fatalf("expected statusWriter to be nil when DynamicClient is not provided")
	}

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "no-writeback", Namespace: "team-z"},
		Spec: FilterPolicySpec{
			Enabled:   true,
			Scope:     "ingress",
			Selectors: FilterSelectors{Sources: []Selector{{Type: "cidr", Values: []interface{}{"0.0.0.0/0"}}}},
			Actions:   []PolicyAction{{Type: "allow"}},
		},
	}
	controller.handlePolicyAdd(policy)

	stored := controller.policies[policyKey(policy)]
	if !hasCondition(stored.Status.Conditions, ConditionApplied, ConditionStatusTrue) {
		t.Fatalf("in-memory status still expected to update when writeback is disabled; got %+v",
			stored.Status.Conditions)
	}
}

// TestFilterPolicyStatusMutatorIncludesAllFields guards the field list in
// buildFilterPolicyStatusMutator — if a new status field is added to
// FilterPolicyStatus, this test should be updated and the mutator
// extended. Fails loudly so the writeback stays in sync with the type.
func TestFilterPolicyStatusMutatorIncludesAllFields(t *testing.T) {
	statusSnapshot := FilterPolicyStatus{
		Applied:         true,
		LastApplied:     time.Unix(1_700_000_000, 0).UTC(),
		Error:           "partial",
		CiliumPolicies:  []string{"fos1-filter-a", "fos1-filter-b"},
		LastAppliedHash: "deadbeef",
		Conditions: []PolicyCondition{
			{Type: ConditionApplied, Status: ConditionStatusTrue, LastTransitionTime: time.Unix(1, 0), Reason: "ok", Message: "reconciled"},
			{Type: ConditionDegraded, Status: ConditionStatusFalse, LastTransitionTime: time.Unix(2, 0)},
		},
	}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "security.fos1.io/v1alpha1",
		"kind":       "FilterPolicy",
		"metadata": map[string]interface{}{
			"name":      "x",
			"namespace": "y",
		},
	}}
	if err := buildFilterPolicyStatusMutator(statusSnapshot)(obj); err != nil {
		t.Fatalf("mutator error: %v", err)
	}

	applied, _, _ := unstructured.NestedBool(obj.Object, "status", "applied")
	if !applied {
		t.Error("expected status.applied=true in mutated object")
	}
	hash, _, _ := unstructured.NestedString(obj.Object, "status", "lastAppliedHash")
	if hash != "deadbeef" {
		t.Errorf("expected status.lastAppliedHash=deadbeef, got %q", hash)
	}
	errMsg, _, _ := unstructured.NestedString(obj.Object, "status", "error")
	if errMsg != "partial" {
		t.Errorf("expected status.error=partial, got %q", errMsg)
	}
	policies, _, _ := unstructured.NestedStringSlice(obj.Object, "status", "ciliumPolicies")
	if len(policies) != 2 || policies[0] != "fos1-filter-a" || policies[1] != "fos1-filter-b" {
		t.Errorf("expected status.ciliumPolicies=[fos1-filter-a fos1-filter-b], got %+v", policies)
	}
	conds, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if len(conds) != 2 {
		t.Errorf("expected 2 conditions, got %d: %+v", len(conds), conds)
	}
	if !hasUnstructuredCondition(conds, "Applied", "True") {
		t.Errorf("expected Applied=True condition, got %+v", conds)
	}
}

// hasUnstructuredCondition is a test-only helper that checks whether a
// conditions slice — as encoded by buildFilterPolicyStatusMutator — has a
// condition of the given type and status.
func hasUnstructuredCondition(conds []interface{}, condType, status string) bool {
	for _, entry := range conds {
		m, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		if m["type"] == condType && m["status"] == status {
			return true
		}
	}
	return false
}

// dumpVerbs returns a compact list of action verbs (with subresource
// appended) used in assertion failure messages.
func dumpVerbs(actions []clienttesting.Action) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		sr := a.GetSubresource()
		if sr == "" {
			out[i] = a.GetVerb()
		} else {
			out[i] = a.GetVerb() + "/" + sr
		}
	}
	return out
}
