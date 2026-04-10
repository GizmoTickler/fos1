package controllers

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/GizmoTickler/fos1/pkg/network/nat"
)

// fakeNATManager implements nat.Manager for controller tests
type fakeNATManager struct {
	applyCalls  int
	removeCalls int
	configs     map[string]nat.Config
	statuses    map[string]*nat.Status

	applyResult *nat.ApplyResult
	applyErr    error
	removeErr   error
}

func newFakeNATManager() *fakeNATManager {
	return &fakeNATManager{
		configs:  make(map[string]nat.Config),
		statuses: make(map[string]*nat.Status),
	}
}

func (f *fakeNATManager) ApplyNATPolicy(config nat.Config) (*nat.ApplyResult, error) {
	f.applyCalls++
	key := fmt.Sprintf("%s/%s", config.Namespace, config.Name)
	f.configs[key] = config

	if f.applyErr != nil {
		// Store a failure status
		f.statuses[key] = &nat.Status{
			Conditions: []nat.Condition{
				{
					Type:               nat.ConditionApplied,
					Status:             nat.ConditionStatusFalse,
					LastTransitionTime: time.Now(),
					Reason:             "ApplyFailed",
					Message:            f.applyErr.Error(),
				},
			},
		}
		return nil, f.applyErr
	}

	now := time.Now()
	result := f.applyResult
	if result == nil {
		result = &nat.ApplyResult{Applied: true}
	}

	status := &nat.Status{
		LastAppliedHash: config.SpecHash(),
		LastAppliedTime: now,
		Conditions: []nat.Condition{
			{
				Type:               nat.ConditionApplied,
				Status:             nat.ConditionStatusTrue,
				LastTransitionTime: now,
				Reason:             "PolicyApplied",
				Message:            "NAT policy has been enforced via Cilium",
			},
			{
				Type:               nat.ConditionInvalid,
				Status:             nat.ConditionStatusFalse,
				LastTransitionTime: now,
				Reason:             "Valid",
				Message:            "config passed validation",
			},
			{
				Type:               nat.ConditionDegraded,
				Status:             nat.ConditionStatusFalse,
				LastTransitionTime: now,
				Reason:             "FullyApplied",
				Message:            "all rules applied successfully",
			},
		},
	}

	if result.Degraded {
		status.Conditions[0].Status = nat.ConditionStatusFalse
		status.Conditions[0].Reason = "PartialApply"
		status.Conditions[2].Status = nat.ConditionStatusTrue
		status.Conditions[2].Reason = "PartialFailure"
		status.Conditions[2].Message = result.Error
		status.LastAppliedHash = ""
	}

	f.statuses[key] = status
	return result, nil
}

func (f *fakeNATManager) RemoveNATPolicy(name, namespace string) error {
	f.removeCalls++
	key := fmt.Sprintf("%s/%s", namespace, name)
	if f.removeErr != nil {
		return f.removeErr
	}
	delete(f.configs, key)
	delete(f.statuses, key)
	return nil
}

func (f *fakeNATManager) GetNATPolicyStatus(name, namespace string) (*nat.Status, error) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	status, exists := f.statuses[key]
	if !exists {
		return nil, fmt.Errorf("NAT policy %s does not exist", key)
	}
	return status, nil
}

func (f *fakeNATManager) ListNATPolicies() ([]nat.Config, error) {
	policies := make([]nat.Config, 0, len(f.configs))
	for _, p := range f.configs {
		policies = append(policies, p)
	}
	return policies, nil
}

// makeSNATPolicy creates an unstructured SNAT policy for testing
func makeSNATPolicy(name, namespace string, generation int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "EBPFNATPolicy",
			"metadata": map[string]interface{}{
				"name":       name,
				"namespace":  namespace,
				"generation": generation,
			},
			"spec": map[string]interface{}{
				"type":            "snat",
				"interface":       "eth0",
				"externalIP":      "203.0.113.1",
				"sourceAddresses": []interface{}{"10.0.0.0/24"},
				"enableTracking":  true,
			},
		},
	}
}

// makeDNATPolicy creates an unstructured DNAT policy for testing
func makeDNATPolicy(name, namespace string, generation int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "EBPFNATPolicy",
			"metadata": map[string]interface{}{
				"name":       name,
				"namespace":  namespace,
				"generation": generation,
			},
			"spec": map[string]interface{}{
				"type":       "dnat",
				"interface":  "eth0",
				"externalIP": "203.0.113.1",
				"portMappings": []interface{}{
					map[string]interface{}{
						"protocol":     "tcp",
						"externalPort": int64(8080),
						"internalIP":   "10.0.0.5",
						"internalPort": int64(80),
						"description":  "HTTP",
					},
				},
			},
		},
	}
}

// makeInvalidPolicy creates an unstructured policy with invalid spec
func makeInvalidPolicy(name, namespace string, generation int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "EBPFNATPolicy",
			"metadata": map[string]interface{}{
				"name":       name,
				"namespace":  namespace,
				"generation": generation,
			},
			"spec": map[string]interface{}{
				// Missing "type" field -> extraction failure
				"interface": "eth0",
			},
		},
	}
}

func newFakeDynamicClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme, objects...)
	// Add a reactor that accepts all status updates without requiring the object to exist
	client.PrependReactor("update", "ebpfnatpolicies", func(action clienttesting.Action) (bool, runtime.Object, error) {
		updateAction := action.(clienttesting.UpdateActionImpl)
		return true, updateAction.GetObject(), nil
	})
	return client
}

func TestHandleNATPolicyCreateOrUpdate_Applied(t *testing.T) {
	fakeMgr := newFakeNATManager()
	fakeClient := newFakeDynamicClient()

	controller := &NATController{
		dynamicClient: fakeClient,
		natManager:    fakeMgr,
	}

	obj := makeSNATPolicy("test-snat", "default", 1)

	err := controller.handleNATPolicyCreateOrUpdate(obj)
	require.NoError(t, err)

	assert.Equal(t, 1, fakeMgr.applyCalls)

	// Verify the status update was attempted (checking the fake client actions)
	actions := fakeClient.Actions()
	require.Len(t, actions, 1)
	assert.Equal(t, "update", actions[0].GetVerb())
	assert.Equal(t, "ebpfnatpolicies", actions[0].GetResource().Resource)
	assert.Equal(t, "status", actions[0].GetSubresource())
}

func TestHandleNATPolicyCreateOrUpdate_InvalidSpec(t *testing.T) {
	fakeMgr := newFakeNATManager()
	fakeClient := newFakeDynamicClient()

	controller := &NATController{
		dynamicClient: fakeClient,
		natManager:    fakeMgr,
	}

	obj := makeInvalidPolicy("bad-policy", "default", 1)

	err := controller.handleNATPolicyCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract NAT configuration")

	// Manager should NOT have been called
	assert.Equal(t, 0, fakeMgr.applyCalls)

	// Status update with Invalid condition should have been attempted
	actions := fakeClient.Actions()
	require.Len(t, actions, 1)
	assert.Equal(t, "update", actions[0].GetVerb())
	assert.Equal(t, "status", actions[0].GetSubresource())
}

func TestHandleNATPolicyCreateOrUpdate_ApplyFailure(t *testing.T) {
	fakeMgr := newFakeNATManager()
	fakeMgr.applyErr = fmt.Errorf("cilium unreachable")
	fakeClient := newFakeDynamicClient()

	controller := &NATController{
		dynamicClient: fakeClient,
		natManager:    fakeMgr,
	}

	obj := makeSNATPolicy("test-snat", "default", 1)

	err := controller.handleNATPolicyCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply NAT policy")
	assert.Equal(t, 1, fakeMgr.applyCalls)

	// Status update should have been attempted with failure status
	actions := fakeClient.Actions()
	require.Len(t, actions, 1)
	assert.Equal(t, "update", actions[0].GetVerb())
	assert.Equal(t, "status", actions[0].GetSubresource())
}

func TestHandleNATPolicyCreateOrUpdate_Degraded(t *testing.T) {
	fakeMgr := newFakeNATManager()
	fakeMgr.applyResult = &nat.ApplyResult{Applied: true, Degraded: true, Error: "DNAT partial failure"}
	fakeClient := newFakeDynamicClient()

	controller := &NATController{
		dynamicClient: fakeClient,
		natManager:    fakeMgr,
	}

	obj := makeSNATPolicy("test-snat", "default", 2)

	err := controller.handleNATPolicyCreateOrUpdate(obj)
	require.NoError(t, err, "degraded is not a reconcile error")
	assert.Equal(t, 1, fakeMgr.applyCalls)

	// Status should be written
	actions := fakeClient.Actions()
	require.Len(t, actions, 1)
}

func TestHandleNATPolicyDelete_Success(t *testing.T) {
	fakeMgr := newFakeNATManager()
	fakeClient := newFakeDynamicClient()

	controller := &NATController{
		dynamicClient: fakeClient,
		natManager:    fakeMgr,
	}

	err := controller.handleNATPolicyDelete("default/test-snat")
	require.NoError(t, err)
	assert.Equal(t, 1, fakeMgr.removeCalls)
}

func TestHandleNATPolicyDelete_Failure(t *testing.T) {
	fakeMgr := newFakeNATManager()
	fakeMgr.removeErr = fmt.Errorf("cleanup failed")
	fakeClient := newFakeDynamicClient()

	controller := &NATController{
		dynamicClient: fakeClient,
		natManager:    fakeMgr,
	}

	err := controller.handleNATPolicyDelete("default/test-snat")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cleanup failed")
}

func TestExtractConfig_SNAT(t *testing.T) {
	controller := &NATController{}
	obj := makeSNATPolicy("test", "ns", 1)

	config, err := controller.extractConfig(obj)
	require.NoError(t, err)
	assert.Equal(t, "test", config.Name)
	assert.Equal(t, "ns", config.Namespace)
	assert.Equal(t, nat.TypeSNAT, config.Type)
	assert.Equal(t, "eth0", config.Interface)
	assert.Equal(t, "203.0.113.1", config.ExternalIP)
	assert.Equal(t, []string{"10.0.0.0/24"}, config.SourceAddresses)
	assert.True(t, config.EnableTracking)
}

func TestExtractConfig_DNAT(t *testing.T) {
	controller := &NATController{}
	obj := makeDNATPolicy("test", "ns", 1)

	config, err := controller.extractConfig(obj)
	require.NoError(t, err)
	assert.Equal(t, nat.TypeDNAT, config.Type)
	require.Len(t, config.PortMappings, 1)
	assert.Equal(t, "tcp", config.PortMappings[0].Protocol)
	assert.Equal(t, 8080, config.PortMappings[0].ExternalPort)
	assert.Equal(t, "10.0.0.5", config.PortMappings[0].InternalIP)
	assert.Equal(t, 80, config.PortMappings[0].InternalPort)
}

func TestExtractConfig_MissingType(t *testing.T) {
	controller := &NATController{}
	obj := makeInvalidPolicy("bad", "ns", 1)

	_, err := controller.extractConfig(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type not found")
}

func TestWriteStatusToCRD_SetsAllFields(t *testing.T) {
	fakeClient := newFakeDynamicClient()
	controller := &NATController{
		dynamicClient: fakeClient,
	}

	obj := makeSNATPolicy("test", "default", 3)
	now := time.Now()

	status := &nat.Status{
		ObservedGeneration: 3,
		ActiveConnections:  42,
		LastAppliedHash:    "abc123",
		LastAppliedTime:    now,
		Metrics: nat.Metrics{
			Packets:      100,
			Bytes:        5000,
			Translations: 50,
		},
		Conditions: []nat.Condition{
			{
				Type:               nat.ConditionApplied,
				Status:             nat.ConditionStatusTrue,
				LastTransitionTime: now,
				Reason:             "PolicyApplied",
				Message:            "applied",
			},
		},
	}

	err := controller.writeStatusToCRD(obj, status)
	require.NoError(t, err)

	actions := fakeClient.Actions()
	require.Len(t, actions, 1)

	updateAction := actions[0]
	assert.Equal(t, "update", updateAction.GetVerb())
	assert.Equal(t, "status", updateAction.GetSubresource())
	assert.Equal(t, schema.GroupVersionResource{
		Group:    "networking.fos1.io",
		Version:  "v1alpha1",
		Resource: "ebpfnatpolicies",
	}, updateAction.GetResource())
}

func TestUpdateNATPolicyStatusInvalid_SetsConditions(t *testing.T) {
	fakeClient := newFakeDynamicClient()
	controller := &NATController{
		dynamicClient: fakeClient,
	}

	obj := makeSNATPolicy("test", "default", 5)
	validationErr := fmt.Errorf("interface is required")

	err := controller.updateNATPolicyStatusInvalid(obj, validationErr)
	require.NoError(t, err)

	actions := fakeClient.Actions()
	require.Len(t, actions, 1)

	// Verify the updated object has Invalid=True and Applied=False conditions
	updateAction, ok := actions[0].(clienttesting.UpdateActionImpl)
	require.True(t, ok, "action should be an UpdateAction")
	updatedObj := updateAction.GetObject().(*unstructured.Unstructured)

	conditions, found, err := unstructured.NestedSlice(updatedObj.Object, "status", "conditions")
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, conditions, 2)

	// Check Invalid condition
	invalidCond := conditions[0].(map[string]interface{})
	assert.Equal(t, nat.ConditionInvalid, invalidCond["type"])
	assert.Equal(t, nat.ConditionStatusTrue, invalidCond["status"])
	assert.Equal(t, "ExtractionFailed", invalidCond["reason"])
	assert.Contains(t, invalidCond["message"], "interface is required")

	// Check Applied=False condition
	appliedCond := conditions[1].(map[string]interface{})
	assert.Equal(t, nat.ConditionApplied, appliedCond["type"])
	assert.Equal(t, nat.ConditionStatusFalse, appliedCond["status"])

	// Check observedGeneration
	observedGen, found, err := unstructured.NestedInt64(updatedObj.Object, "status", "observedGeneration")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, int64(5), observedGen)
}
