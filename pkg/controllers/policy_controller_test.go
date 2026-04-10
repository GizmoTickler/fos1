package controllers

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/GizmoTickler/fos1/pkg/network/routing/policy"
)

// fakePolicyManager implements policy.Manager for testing
type fakePolicyManager struct {
	applyCalls  int
	removeCalls int
	policies    map[string]policy.RoutingPolicy
	shouldError bool
}

func newFakePolicyManager() *fakePolicyManager {
	return &fakePolicyManager{
		policies: make(map[string]policy.RoutingPolicy),
	}
}

func (f *fakePolicyManager) ApplyPolicy(p policy.RoutingPolicy) error {
	f.applyCalls++
	if f.shouldError {
		return fmt.Errorf("mock error: apply policy")
	}
	key := fmt.Sprintf("%s/%s", p.Namespace, p.Name)
	f.policies[key] = p
	return nil
}

func (f *fakePolicyManager) RemovePolicy(name, namespace string) error {
	f.removeCalls++
	if f.shouldError {
		return fmt.Errorf("mock error: remove policy")
	}
	key := fmt.Sprintf("%s/%s", namespace, name)
	delete(f.policies, key)
	return nil
}

func (f *fakePolicyManager) GetPolicyStatus(name, namespace string) (*policy.PolicyStatus, error) {
	if f.shouldError {
		return nil, fmt.Errorf("mock error: get policy status")
	}
	return &policy.PolicyStatus{
		Active:      true,
		MatchCount:  42,
		LastMatched: time.Now(),
	}, nil
}

func (f *fakePolicyManager) ListPolicies() ([]policy.RoutingPolicy, error) {
	policies := make([]policy.RoutingPolicy, 0, len(f.policies))
	for _, p := range f.policies {
		policies = append(policies, p)
	}
	return policies, nil
}

func (f *fakePolicyManager) EvaluatePacket(packet policy.PacketInfo) (*policy.PolicyAction, error) {
	return nil, nil
}

// makePolicyCRD creates an unstructured RoutingPolicy CRD for testing
func makePolicyCRD(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "RoutingPolicy",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"description": "Test routing policy",
				"priority":    int64(100),
				"match": map[string]interface{}{
					"source": map[string]interface{}{
						"networks": []interface{}{
							"10.0.0.0/24",
						},
						"interfaces": []interface{}{
							"eth0",
						},
					},
					"destination": map[string]interface{}{
						"networks": []interface{}{
							"192.168.0.0/16",
						},
					},
					"protocol": "tcp",
					"ports": []interface{}{
						map[string]interface{}{
							"start": int64(80),
							"end":   int64(443),
						},
					},
				},
				"action": map[string]interface{}{
					"type":    "route",
					"nextHop": "10.0.0.1",
					"table":   "custom-table",
				},
				"vrf": "test-vrf",
			},
		},
	}
}

func newPolicyFakeDynamicClient() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme)
	client.PrependReactor("update", "routingpolicies", func(action clienttesting.Action) (bool, runtime.Object, error) {
		updateAction := action.(clienttesting.UpdateActionImpl)
		return true, updateAction.GetObject(), nil
	})
	return client
}

func TestPolicyController_HandleCreateOrUpdate_Success(t *testing.T) {
	polMgr := newFakePolicyManager()
	fakeClient := newPolicyFakeDynamicClient()

	controller := &PolicyController{
		dynamicClient: fakeClient,
		policyManager: polMgr,
	}

	obj := makePolicyCRD("test-policy", "default")

	err := controller.handlePolicyCreateOrUpdate(obj)
	require.NoError(t, err)

	assert.Equal(t, 1, polMgr.applyCalls)
	p, exists := polMgr.policies["default/test-policy"]
	require.True(t, exists)

	assert.Equal(t, "test-policy", p.Name)
	assert.Equal(t, "default", p.Namespace)
	assert.Equal(t, 100, p.Priority)
	assert.Equal(t, "route", p.Action.Type)
	assert.Equal(t, "10.0.0.1", p.Action.NextHop)
	assert.Equal(t, "test-vrf", p.VRF)
	require.Len(t, p.Match.Source.Networks, 1)
	assert.Equal(t, "10.0.0.0/24", p.Match.Source.Networks[0])
	require.Len(t, p.Match.Ports, 1)
	assert.Equal(t, 80, p.Match.Ports[0].Start)
	assert.Equal(t, 443, p.Match.Ports[0].End)
}

func TestPolicyController_HandleCreateOrUpdate_MissingPriority(t *testing.T) {
	polMgr := newFakePolicyManager()
	fakeClient := newPolicyFakeDynamicClient()

	controller := &PolicyController{
		dynamicClient: fakeClient,
		policyManager: polMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "RoutingPolicy",
			"metadata": map[string]interface{}{
				"name":      "bad-policy",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				// Missing priority
				"match": map[string]interface{}{},
				"action": map[string]interface{}{
					"type": "route",
				},
			},
		},
	}

	err := controller.handlePolicyCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "priority not found")
	assert.Equal(t, 0, polMgr.applyCalls)
}

func TestPolicyController_HandleCreateOrUpdate_ApplyError(t *testing.T) {
	polMgr := newFakePolicyManager()
	polMgr.shouldError = true
	fakeClient := newPolicyFakeDynamicClient()

	controller := &PolicyController{
		dynamicClient: fakeClient,
		policyManager: polMgr,
	}

	obj := makePolicyCRD("test-policy", "default")

	err := controller.handlePolicyCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply policy")
}

func TestPolicyController_HandleDelete(t *testing.T) {
	polMgr := newFakePolicyManager()

	controller := &PolicyController{
		policyManager: polMgr,
	}

	err := controller.handlePolicyDelete("default/test-policy")
	require.NoError(t, err)
	assert.Equal(t, 1, polMgr.removeCalls)
}

func TestPolicyController_HandleDelete_Error(t *testing.T) {
	polMgr := newFakePolicyManager()
	polMgr.shouldError = true

	controller := &PolicyController{
		policyManager: polMgr,
	}

	err := controller.handlePolicyDelete("default/test-policy")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove policy")
}

func TestPolicyController_HandleCreateOrUpdate_MissingMatch(t *testing.T) {
	polMgr := newFakePolicyManager()
	fakeClient := newPolicyFakeDynamicClient()

	controller := &PolicyController{
		dynamicClient: fakeClient,
		policyManager: polMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "RoutingPolicy",
			"metadata": map[string]interface{}{
				"name":      "no-match",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"priority": int64(100),
				// Missing match
				"action": map[string]interface{}{
					"type": "route",
				},
			},
		},
	}

	err := controller.handlePolicyCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "match not found")
}

func TestPolicyController_HandleCreateOrUpdate_MissingAction(t *testing.T) {
	polMgr := newFakePolicyManager()
	fakeClient := newPolicyFakeDynamicClient()

	controller := &PolicyController{
		dynamicClient: fakeClient,
		policyManager: polMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "RoutingPolicy",
			"metadata": map[string]interface{}{
				"name":      "no-action",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"priority": int64(100),
				"match":    map[string]interface{}{},
				// Missing action
			},
		},
	}

	err := controller.handlePolicyCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "action not found")
}
