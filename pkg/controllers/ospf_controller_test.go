package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/GizmoTickler/fos1/pkg/network/routing"
)

// makeOSPFConfigCRD creates an unstructured OSPFConfig CRD for testing
func makeOSPFConfigCRD(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "OSPFConfig",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"routerId": "10.0.0.1",
				"areas": []interface{}{
					map[string]interface{}{
						"areaId": "0.0.0.0",
						"interfaces": []interface{}{
							map[string]interface{}{
								"name":        "eth0",
								"networkType": "broadcast",
								"cost":        int64(10),
							},
						},
					},
				},
				"redistributions": []interface{}{
					map[string]interface{}{
						"protocol":    "connected",
						"routeMapRef": "connected-map",
					},
				},
			},
		},
	}
}

func newOSPFFakeDynamicClient() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme)
	client.PrependReactor("update", "ospfconfigs", func(action clienttesting.Action) (bool, runtime.Object, error) {
		updateAction := action.(clienttesting.UpdateActionImpl)
		return true, updateAction.GetObject(), nil
	})
	return client
}

func TestOSPFController_HandleCreateOrUpdate_Success(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	protoMgr.status.Name = "ospf"
	fakeClient := newOSPFFakeDynamicClient()

	controller := &OSPFController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := makeOSPFConfigCRD("test-ospf", "default")

	err := controller.handleOSPFConfigCreateOrUpdate(obj)
	require.NoError(t, err)

	assert.Equal(t, 1, protoMgr.startCalls)
	config, exists := protoMgr.configs["ospf"]
	require.True(t, exists)

	ospfConfig, ok := config.(routing.OSPFConfig)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.1", ospfConfig.RouterID)
	require.Len(t, ospfConfig.Areas, 1)
	assert.Equal(t, "0.0.0.0", ospfConfig.Areas[0].AreaID)
	require.Len(t, ospfConfig.Areas[0].Interfaces, 1)
	assert.Equal(t, "eth0", ospfConfig.Areas[0].Interfaces[0].Name)
	assert.Equal(t, "broadcast", ospfConfig.Areas[0].Interfaces[0].NetworkType)
	assert.Equal(t, 10, ospfConfig.Areas[0].Interfaces[0].Cost)
	require.Len(t, ospfConfig.Redistributions, 1)
	assert.Equal(t, "connected", ospfConfig.Redistributions[0].Protocol)

	// Verify status update was attempted
	actions := fakeClient.Actions()
	require.Len(t, actions, 1)
	assert.Equal(t, "update", actions[0].GetVerb())
	assert.Equal(t, "status", actions[0].GetSubresource())
}

func TestOSPFController_HandleCreateOrUpdate_MissingRouterID(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	fakeClient := newOSPFFakeDynamicClient()

	controller := &OSPFController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "OSPFConfig",
			"metadata": map[string]interface{}{
				"name":      "bad-ospf",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				// Missing routerId
			},
		},
	}

	err := controller.handleOSPFConfigCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "routerId not found")
	assert.Equal(t, 0, protoMgr.startCalls)
}

func TestOSPFController_HandleCreateOrUpdate_StartProtocolError(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	protoMgr.shouldError = true
	fakeClient := newOSPFFakeDynamicClient()

	controller := &OSPFController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := makeOSPFConfigCRD("test-ospf", "default")

	err := controller.handleOSPFConfigCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start OSPF")
}

func TestOSPFController_HandleDelete(t *testing.T) {
	protoMgr := newFakeProtocolManager()

	controller := &OSPFController{
		protocolManager: protoMgr,
	}

	err := controller.handleOSPFConfigDelete("default/test-ospf")
	require.NoError(t, err)
	assert.Equal(t, 1, protoMgr.stopCalls)
}

func TestOSPFController_HandleDelete_Error(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	protoMgr.shouldError = true

	controller := &OSPFController{
		protocolManager: protoMgr,
	}

	err := controller.handleOSPFConfigDelete("default/test-ospf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stop OSPF")
}

func TestOSPFController_UpdateStatus(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	protoMgr.status.Name = "ospf"
	fakeClient := newOSPFFakeDynamicClient()

	controller := &OSPFController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := makeOSPFConfigCRD("test-ospf", "default")

	err := controller.updateOSPFConfigStatus(obj)
	require.NoError(t, err)

	actions := fakeClient.Actions()
	require.Len(t, actions, 1)

	updateAction, ok := actions[0].(clienttesting.UpdateActionImpl)
	require.True(t, ok)
	assert.Equal(t, "status", updateAction.GetSubresource())
	assert.Equal(t, schema.GroupVersionResource{
		Group:    "networking.fos1.io",
		Version:  "v1alpha1",
		Resource: "ospfconfigs",
	}, updateAction.GetResource())

	updatedObj := updateAction.GetObject().(*unstructured.Unstructured)
	state, found, err := unstructured.NestedString(updatedObj.Object, "status", "state")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "running", state)
}

func TestOSPFController_HandleCreateOrUpdate_MissingSpec(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	fakeClient := newOSPFFakeDynamicClient()

	controller := &OSPFController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "OSPFConfig",
			"metadata": map[string]interface{}{
				"name":      "no-spec",
				"namespace": "default",
			},
		},
	}

	err := controller.handleOSPFConfigCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec not found")
}

func TestOSPFController_HandleCreateOrUpdate_StubAndNSSA(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	protoMgr.status.Name = "ospf"
	fakeClient := newOSPFFakeDynamicClient()

	controller := &OSPFController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "OSPFConfig",
			"metadata": map[string]interface{}{
				"name":      "stub-ospf",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"routerId": "10.0.0.1",
				"areas": []interface{}{
					map[string]interface{}{
						"areaId":   "0.0.0.1",
						"stubArea": true,
					},
					map[string]interface{}{
						"areaId":   "0.0.0.2",
						"nssaArea": true,
					},
				},
				"vrf":                "custom-vrf",
				"referenceBandwidth": int64(1000),
			},
		},
	}

	err := controller.handleOSPFConfigCreateOrUpdate(obj)
	require.NoError(t, err)

	config := protoMgr.configs["ospf"].(routing.OSPFConfig)
	assert.True(t, config.Areas[0].StubArea)
	assert.True(t, config.Areas[1].NSSAArea)
	assert.Equal(t, "custom-vrf", config.VRF)
	assert.Equal(t, 1000, config.ReferenceBandwidth)
}
