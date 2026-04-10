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

	"github.com/GizmoTickler/fos1/pkg/network/routing"
)

// fakeProtocolManager implements routing.ProtocolManager for testing
type fakeProtocolManager struct {
	startCalls  int
	stopCalls   int
	configs     map[string]routing.ProtocolConfig
	shouldError bool
	status      *routing.ProtocolStatus
}

func newFakeProtocolManager() *fakeProtocolManager {
	return &fakeProtocolManager{
		configs: make(map[string]routing.ProtocolConfig),
		status: &routing.ProtocolStatus{
			Name:   "bgp",
			State:  "running",
			Uptime: 5 * time.Minute,
			Neighbors: []routing.NeighborStatus{
				{
					Address:          "10.0.0.2",
					State:            "established",
					Uptime:           3 * time.Minute,
					PrefixesReceived: 10,
					PrefixesSent:     5,
				},
			},
		},
	}
}

func (f *fakeProtocolManager) StartProtocol(name string, config routing.ProtocolConfig) error {
	f.startCalls++
	if f.shouldError {
		return fmt.Errorf("mock error: start protocol %s", name)
	}
	f.configs[name] = config
	return nil
}

func (f *fakeProtocolManager) StopProtocol(name string) error {
	f.stopCalls++
	if f.shouldError {
		return fmt.Errorf("mock error: stop protocol %s", name)
	}
	delete(f.configs, name)
	return nil
}

func (f *fakeProtocolManager) RestartProtocol(name string) error {
	if f.shouldError {
		return fmt.Errorf("mock error: restart protocol %s", name)
	}
	return nil
}

func (f *fakeProtocolManager) GetProtocolStatus(name string) (*routing.ProtocolStatus, error) {
	if f.shouldError {
		return nil, fmt.Errorf("mock error: get protocol status %s", name)
	}
	return f.status, nil
}

func (f *fakeProtocolManager) ListProtocols() ([]string, error) {
	names := make([]string, 0, len(f.configs))
	for name := range f.configs {
		names = append(names, name)
	}
	return names, nil
}

func (f *fakeProtocolManager) UpdateProtocolConfig(name string, config routing.ProtocolConfig) error {
	if f.shouldError {
		return fmt.Errorf("mock error: update protocol config %s", name)
	}
	f.configs[name] = config
	return nil
}

func (f *fakeProtocolManager) GetProtocolRoutes(name string) ([]*routing.Route, error) {
	return nil, nil
}

// makeBGPConfigCRD creates an unstructured BGPConfig CRD for testing
func makeBGPConfigCRD(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "BGPConfig",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"asNumber": int64(65001),
				"routerId": "192.168.1.1",
				"neighbors": []interface{}{
					map[string]interface{}{
						"address":        "10.0.0.2",
						"remoteAsNumber": int64(65002),
						"description":    "peer-1",
					},
				},
				"addressFamilies": []interface{}{
					map[string]interface{}{
						"type":    "ipv4-unicast",
						"enabled": true,
						"networks": []interface{}{
							"10.0.0.0/24",
						},
					},
				},
			},
		},
	}
}

func newBGPFakeDynamicClient() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme)
	client.PrependReactor("update", "bgpconfigs", func(action clienttesting.Action) (bool, runtime.Object, error) {
		updateAction := action.(clienttesting.UpdateActionImpl)
		return true, updateAction.GetObject(), nil
	})
	return client
}

func TestBGPController_HandleCreateOrUpdate_Success(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	fakeClient := newBGPFakeDynamicClient()

	controller := &BGPController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := makeBGPConfigCRD("test-bgp", "default")

	err := controller.handleBGPConfigCreateOrUpdate(obj)
	require.NoError(t, err)

	assert.Equal(t, 1, protoMgr.startCalls)
	config, exists := protoMgr.configs["bgp"]
	require.True(t, exists)

	bgpConfig, ok := config.(routing.BGPConfig)
	require.True(t, ok)
	assert.Equal(t, 65001, bgpConfig.ASNumber)
	assert.Equal(t, "192.168.1.1", bgpConfig.RouterID)
	require.Len(t, bgpConfig.Neighbors, 1)
	assert.Equal(t, "10.0.0.2", bgpConfig.Neighbors[0].Address)
	assert.Equal(t, 65002, bgpConfig.Neighbors[0].RemoteASNumber)
	require.Len(t, bgpConfig.AddressFamilies, 1)
	assert.Equal(t, "ipv4-unicast", bgpConfig.AddressFamilies[0].Type)

	// Verify status update was attempted
	actions := fakeClient.Actions()
	require.Len(t, actions, 1)
	assert.Equal(t, "update", actions[0].GetVerb())
	assert.Equal(t, "status", actions[0].GetSubresource())
}

func TestBGPController_HandleCreateOrUpdate_MissingASNumber(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	fakeClient := newBGPFakeDynamicClient()

	controller := &BGPController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "BGPConfig",
			"metadata": map[string]interface{}{
				"name":      "bad-bgp",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				// Missing asNumber
				"routerId": "192.168.1.1",
			},
		},
	}

	err := controller.handleBGPConfigCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "asNumber not found")
	assert.Equal(t, 0, protoMgr.startCalls)
}

func TestBGPController_HandleCreateOrUpdate_StartProtocolError(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	protoMgr.shouldError = true
	fakeClient := newBGPFakeDynamicClient()

	controller := &BGPController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := makeBGPConfigCRD("test-bgp", "default")

	err := controller.handleBGPConfigCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start BGP")
}

func TestBGPController_HandleCreateOrUpdate_DisabledBGP(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	fakeClient := newBGPFakeDynamicClient()

	controller := &BGPController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "BGPConfig",
			"metadata": map[string]interface{}{
				"name":      "disabled-bgp",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"enabled":  false,
				"asNumber": int64(65001),
				"routerId": "192.168.1.1",
			},
		},
	}

	err := controller.handleBGPConfigCreateOrUpdate(obj)
	require.NoError(t, err)
	assert.Equal(t, 0, protoMgr.startCalls)
	assert.Equal(t, 1, protoMgr.stopCalls)
}

func TestBGPController_HandleDelete(t *testing.T) {
	protoMgr := newFakeProtocolManager()

	controller := &BGPController{
		protocolManager: protoMgr,
	}

	err := controller.handleBGPConfigDelete("default/test-bgp")
	require.NoError(t, err)
	assert.Equal(t, 1, protoMgr.stopCalls)
}

func TestBGPController_HandleDelete_Error(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	protoMgr.shouldError = true

	controller := &BGPController{
		protocolManager: protoMgr,
	}

	err := controller.handleBGPConfigDelete("default/test-bgp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stop BGP")
}

func TestBGPController_UpdateStatus(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	fakeClient := newBGPFakeDynamicClient()

	controller := &BGPController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := makeBGPConfigCRD("test-bgp", "default")

	err := controller.updateBGPConfigStatus(obj)
	require.NoError(t, err)

	actions := fakeClient.Actions()
	require.Len(t, actions, 1)

	updateAction, ok := actions[0].(clienttesting.UpdateActionImpl)
	require.True(t, ok)
	assert.Equal(t, "status", updateAction.GetSubresource())
	assert.Equal(t, schema.GroupVersionResource{
		Group:    "networking.fos1.io",
		Version:  "v1alpha1",
		Resource: "bgpconfigs",
	}, updateAction.GetResource())

	updatedObj := updateAction.GetObject().(*unstructured.Unstructured)
	state, found, err := unstructured.NestedString(updatedObj.Object, "status", "state")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "running", state)
}

func TestBGPController_HandleCreateOrUpdate_MissingSpec(t *testing.T) {
	protoMgr := newFakeProtocolManager()
	fakeClient := newBGPFakeDynamicClient()

	controller := &BGPController{
		dynamicClient:   fakeClient,
		protocolManager: protoMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1alpha1",
			"kind":       "BGPConfig",
			"metadata": map[string]interface{}{
				"name":      "no-spec",
				"namespace": "default",
			},
			// No spec field
		},
	}

	err := controller.handleBGPConfigCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec not found")
}
