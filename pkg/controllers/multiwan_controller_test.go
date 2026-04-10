package controllers

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/GizmoTickler/fos1/pkg/network/routing/multiwan"
)

// fakeMultiWANManager implements multiwan.Manager for testing
type fakeMultiWANManager struct {
	applyCalls  int
	removeCalls int
	configs     map[string]multiwan.Configuration
	shouldError bool
}

func newFakeMultiWANManager() *fakeMultiWANManager {
	return &fakeMultiWANManager{
		configs: make(map[string]multiwan.Configuration),
	}
}

func (f *fakeMultiWANManager) ApplyConfiguration(config multiwan.Configuration) error {
	f.applyCalls++
	if f.shouldError {
		return fmt.Errorf("mock error: apply configuration")
	}
	f.configs[config.Name] = config
	return nil
}

func (f *fakeMultiWANManager) RemoveConfiguration(name string) error {
	f.removeCalls++
	if f.shouldError {
		return fmt.Errorf("mock error: remove configuration")
	}
	delete(f.configs, name)
	return nil
}

func (f *fakeMultiWANManager) GetStatus(name string) (*multiwan.Status, error) {
	if f.shouldError {
		return nil, fmt.Errorf("mock error: get status")
	}
	return &multiwan.Status{
		ActiveWANs: []multiwan.WANStatus{
			{
				Name:       "wan1",
				State:      "up",
				RTT:        5,
				PacketLoss: 0.0,
			},
		},
		CurrentPrimary:  "wan1",
		LastStateChange: "2025-01-01T00:00:00Z",
	}, nil
}

func (f *fakeMultiWANManager) ListConfigurations() ([]multiwan.Configuration, error) {
	configs := make([]multiwan.Configuration, 0, len(f.configs))
	for _, c := range f.configs {
		configs = append(configs, c)
	}
	return configs, nil
}

// makeMultiWANCRD creates an unstructured MultiWAN CRD for testing
func makeMultiWANCRD(name, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "MultiWAN",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"description": "Test multi-WAN config",
				"wanInterfaces": []interface{}{
					map[string]interface{}{
						"name":      "wan1",
						"interface": "eth0",
						"weight":    int64(100),
						"priority":  int64(1),
						"gateway":   "192.168.1.1",
						"monitoring": map[string]interface{}{
							"targets":  []interface{}{"8.8.8.8"},
							"method":   "ping",
							"interval": int64(5),
						},
					},
					map[string]interface{}{
						"name":      "wan2",
						"interface": "eth1",
						"weight":    int64(50),
						"priority":  int64(2),
						"gateway":   "192.168.2.1",
					},
				},
				"loadBalancing": map[string]interface{}{
					"enabled": true,
					"method":  "weighted",
					"sticky":  true,
				},
				"failover": map[string]interface{}{
					"enabled": true,
					"preempt": true,
				},
			},
		},
	}
}

func newMultiWANFakeDynamicClient() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme)
	client.PrependReactor("update", "multiwans", func(action clienttesting.Action) (bool, runtime.Object, error) {
		updateAction := action.(clienttesting.UpdateActionImpl)
		return true, updateAction.GetObject(), nil
	})
	return client
}

func TestMultiWANController_HandleCreateOrUpdate_Success(t *testing.T) {
	wanMgr := newFakeMultiWANManager()
	fakeClient := newMultiWANFakeDynamicClient()

	controller := &MultiWANController{
		dynamicClient: fakeClient,
		wanManager:    wanMgr,
	}

	obj := makeMultiWANCRD("test-wan", "default")

	err := controller.handleMultiWANCreateOrUpdate(obj)
	require.NoError(t, err)

	assert.Equal(t, 1, wanMgr.applyCalls)
	config, exists := wanMgr.configs["test-wan"]
	require.True(t, exists)

	assert.Equal(t, "test-wan", config.Name)
	assert.Equal(t, "default", config.Namespace)
	require.Len(t, config.WANInterfaces, 2)
	assert.Equal(t, "wan1", config.WANInterfaces[0].Name)
	assert.Equal(t, "eth0", config.WANInterfaces[0].Interface)
	assert.Equal(t, 100, config.WANInterfaces[0].Weight)
	assert.Equal(t, "192.168.1.1", config.WANInterfaces[0].Gateway)
	assert.True(t, config.LoadBalancing.Enabled)
	assert.Equal(t, "weighted", config.LoadBalancing.Method)
	assert.True(t, config.Failover.Enabled)
	assert.True(t, config.Failover.Preempt)
}

func TestMultiWANController_HandleCreateOrUpdate_MissingWANInterfaces(t *testing.T) {
	wanMgr := newFakeMultiWANManager()
	fakeClient := newMultiWANFakeDynamicClient()

	controller := &MultiWANController{
		dynamicClient: fakeClient,
		wanManager:    wanMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "MultiWAN",
			"metadata": map[string]interface{}{
				"name":      "bad-wan",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				// Missing wanInterfaces
			},
		},
	}

	err := controller.handleMultiWANCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wanInterfaces not found")
	assert.Equal(t, 0, wanMgr.applyCalls)
}

func TestMultiWANController_HandleCreateOrUpdate_ApplyError(t *testing.T) {
	wanMgr := newFakeMultiWANManager()
	wanMgr.shouldError = true
	fakeClient := newMultiWANFakeDynamicClient()

	controller := &MultiWANController{
		dynamicClient: fakeClient,
		wanManager:    wanMgr,
	}

	obj := makeMultiWANCRD("test-wan", "default")

	err := controller.handleMultiWANCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply MultiWAN configuration")
}

func TestMultiWANController_HandleDelete(t *testing.T) {
	wanMgr := newFakeMultiWANManager()

	controller := &MultiWANController{
		wanManager: wanMgr,
	}

	err := controller.handleMultiWANDelete("default/test-wan")
	require.NoError(t, err)
	assert.Equal(t, 1, wanMgr.removeCalls)
}

func TestMultiWANController_HandleDelete_Error(t *testing.T) {
	wanMgr := newFakeMultiWANManager()
	wanMgr.shouldError = true

	controller := &MultiWANController{
		wanManager: wanMgr,
	}

	err := controller.handleMultiWANDelete("default/test-wan")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove MultiWAN configuration")
}

func TestMultiWANController_HandleCreateOrUpdate_MissingGateway(t *testing.T) {
	wanMgr := newFakeMultiWANManager()
	fakeClient := newMultiWANFakeDynamicClient()

	controller := &MultiWANController{
		dynamicClient: fakeClient,
		wanManager:    wanMgr,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "MultiWAN",
			"metadata": map[string]interface{}{
				"name":      "no-gw",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"wanInterfaces": []interface{}{
					map[string]interface{}{
						"name":      "wan1",
						"interface": "eth0",
						// Missing gateway
					},
				},
			},
		},
	}

	err := controller.handleMultiWANCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway not found")
}
