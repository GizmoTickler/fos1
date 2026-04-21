package controllers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// testCiliumClient implements cilium.CiliumClient for controller tests
type testCiliumClient struct {
	policies    map[string]*cilium.CiliumPolicy
	dpiConfigs  []*cilium.CiliumDPIIntegrationConfig
	shouldError bool
}

func newTestCiliumClient() *testCiliumClient {
	return &testCiliumClient{
		policies: make(map[string]*cilium.CiliumPolicy),
	}
}

func (c *testCiliumClient) ApplyNetworkPolicy(_ context.Context, policy *cilium.CiliumPolicy) error {
	if c.shouldError {
		return fmt.Errorf("mock error: apply network policy")
	}
	c.policies[policy.Name] = policy
	return nil
}

func (c *testCiliumClient) DeleteNetworkPolicy(_ context.Context, policyName string) error {
	if c.shouldError {
		return fmt.Errorf("mock error: delete network policy")
	}
	delete(c.policies, policyName)
	return nil
}

func (c *testCiliumClient) ListRoutes(_ context.Context) ([]cilium.Route, error)                        { return nil, nil }
func (c *testCiliumClient) ListVRFRoutes(_ context.Context, _ int) ([]cilium.Route, error)              { return nil, nil }
func (c *testCiliumClient) AddRoute(_ cilium.Route) error                                               { return nil }
func (c *testCiliumClient) DeleteRoute(_ cilium.Route) error                                            { return nil }
func (c *testCiliumClient) AddVRFRoute(_ cilium.Route, _ int) error                                     { return nil }
func (c *testCiliumClient) DeleteVRFRoute(_ cilium.Route, _ int) error                                  { return nil }
func (c *testCiliumClient) CreateNAT(_ context.Context, _ *cilium.CiliumNATConfig) error                { return nil }
func (c *testCiliumClient) RemoveNAT(_ context.Context, _ *cilium.CiliumNATConfig) error                { return nil }
func (c *testCiliumClient) CreateNAT64(_ context.Context, _ *cilium.NAT64Config) error                  { return nil }
func (c *testCiliumClient) RemoveNAT64(_ context.Context, _ *cilium.NAT64Config) error                  { return nil }
func (c *testCiliumClient) CreatePortForward(_ context.Context, _ *cilium.PortForwardConfig) error       { return nil }
func (c *testCiliumClient) RemovePortForward(_ context.Context, _ *cilium.PortForwardConfig) error       { return nil }
func (c *testCiliumClient) ConfigureVLANRouting(_ context.Context, _ *cilium.CiliumVLANRoutingConfig) error { return nil }

func (c *testCiliumClient) ConfigureDPIIntegration(_ context.Context, config *cilium.CiliumDPIIntegrationConfig) error {
	if c.shouldError {
		return fmt.Errorf("mock error: configure DPI integration")
	}
	c.dpiConfigs = append(c.dpiConfigs, config)
	return nil
}

func newControllerFakeDynamicClient() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClient(scheme)
}

// FirewallController tests removed in sprint 29 ticket 33: FirewallRule is a
// non-goal per ADR-0001 (Cilium-first). FilterPolicy is the authoritative
// surface; its tests live in pkg/security/policy/controller_test.go.

// --- DPIController tests ---

func TestDPIController_HandleCreateOrUpdate_Success(t *testing.T) {
	client := newTestCiliumClient()
	fakeClient := newControllerFakeDynamicClient()

	controller := &DPIController{
		dynamicClient: fakeClient,
		ciliumClient:  client,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.fos1.io/v1alpha1",
			"kind":       "DPIPolicy",
			"metadata": map[string]interface{}{
				"name":      "test-dpi",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"enabled":         true,
				"enforcementMode": "block",
				"applications": []interface{}{
					"bittorrent",
					"tiktok",
				},
				"targetInterfaces": []interface{}{
					"eth0",
					"eth1",
				},
			},
		},
	}

	err := controller.handleDPIPolicyCreateOrUpdate(obj)
	require.NoError(t, err)

	require.Len(t, client.dpiConfigs, 1)
	dpiConfig := client.dpiConfigs[0]
	assert.True(t, dpiConfig.Enabled)
	assert.Equal(t, "block", dpiConfig.EnforcementMode)
	assert.Equal(t, []string{"bittorrent", "tiktok"}, dpiConfig.ApplicationsToMonitor)
	assert.Equal(t, []string{"eth0", "eth1"}, dpiConfig.TargetInterfaces)
}

func TestDPIController_HandleCreateOrUpdate_Disabled(t *testing.T) {
	client := newTestCiliumClient()
	fakeClient := newControllerFakeDynamicClient()

	controller := &DPIController{
		dynamicClient: fakeClient,
		ciliumClient:  client,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.fos1.io/v1alpha1",
			"kind":       "DPIPolicy",
			"metadata": map[string]interface{}{
				"name":      "disabled-dpi",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"enabled": false,
				"applications": []interface{}{
					"bittorrent",
				},
			},
		},
	}

	err := controller.handleDPIPolicyCreateOrUpdate(obj)
	require.NoError(t, err)
	assert.Len(t, client.dpiConfigs, 0, "No DPI config should be applied when disabled")
}

func TestDPIController_HandleCreateOrUpdate_CiliumError(t *testing.T) {
	client := newTestCiliumClient()
	client.shouldError = true
	fakeClient := newControllerFakeDynamicClient()

	controller := &DPIController{
		dynamicClient: fakeClient,
		ciliumClient:  client,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.fos1.io/v1alpha1",
			"kind":       "DPIPolicy",
			"metadata": map[string]interface{}{
				"name":      "test-dpi",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"enabled": true,
				"applications": []interface{}{
					"bittorrent",
				},
			},
		},
	}

	err := controller.handleDPIPolicyCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error configuring DPI integration")
}

func TestDPIController_HandleCreateOrUpdate_MissingSpec(t *testing.T) {
	client := newTestCiliumClient()
	fakeClient := newControllerFakeDynamicClient()

	controller := &DPIController{
		dynamicClient: fakeClient,
		ciliumClient:  client,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.fos1.io/v1alpha1",
			"kind":       "DPIPolicy",
			"metadata": map[string]interface{}{
				"name":      "no-spec",
				"namespace": "default",
			},
		},
	}

	err := controller.handleDPIPolicyCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error getting spec")
}

func TestDPIController_HandleDelete(t *testing.T) {
	client := newTestCiliumClient()

	controller := &DPIController{
		ciliumClient: client,
	}

	err := controller.handleDPIPolicyDelete("default/test-dpi")
	require.NoError(t, err)
}

// --- NetworkInterfaceController tests ---

func TestNetworkInterfaceController_HandleCreateOrUpdate_Physical(t *testing.T) {
	fakeClient := newControllerFakeDynamicClient()

	controller := &NetworkInterfaceController{
		dynamicClient: fakeClient,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "NetworkInterface",
			"metadata": map[string]interface{}{
				"name":      "test-nic",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"type":   "physical",
				"name":   "eth0",
				"device": "enp0s31f6",
			},
		},
	}

	err := controller.handleNetworkInterfaceCreateOrUpdate(obj)
	require.NoError(t, err)
}

func TestNetworkInterfaceController_HandleCreateOrUpdate_VLAN(t *testing.T) {
	fakeClient := newControllerFakeDynamicClient()

	controller := &NetworkInterfaceController{
		dynamicClient: fakeClient,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "NetworkInterface",
			"metadata": map[string]interface{}{
				"name":      "vlan100",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"type":   "vlan",
				"name":   "vlan100",
				"parent": "eth0",
				"vlanId": float64(100),
			},
		},
	}

	err := controller.handleNetworkInterfaceCreateOrUpdate(obj)
	require.NoError(t, err)
}

func TestNetworkInterfaceController_HandleCreateOrUpdate_UnsupportedType(t *testing.T) {
	fakeClient := newControllerFakeDynamicClient()

	controller := &NetworkInterfaceController{
		dynamicClient: fakeClient,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "NetworkInterface",
			"metadata": map[string]interface{}{
				"name":      "test-nic",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"type": "unsupported-type",
				"name": "test",
			},
		},
	}

	err := controller.handleNetworkInterfaceCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported interface type")
}

func TestNetworkInterfaceController_HandleCreateOrUpdate_MissingType(t *testing.T) {
	fakeClient := newControllerFakeDynamicClient()

	controller := &NetworkInterfaceController{
		dynamicClient: fakeClient,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "NetworkInterface",
			"metadata": map[string]interface{}{
				"name":      "test-nic",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				// Missing type
				"name": "test",
			},
		},
	}

	err := controller.handleNetworkInterfaceCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error getting interface type")
}

func TestNetworkInterfaceController_HandleDelete(t *testing.T) {
	controller := &NetworkInterfaceController{}

	err := controller.handleNetworkInterfaceDelete("default/test-nic")
	require.NoError(t, err)
}

// --- Routing controller tests ---

func TestCiliumRoutingController_HandleCreateOrUpdate_MissingSpec(t *testing.T) {
	fakeClient := newControllerFakeDynamicClient()

	controller := &RoutingController{
		dynamicClient: fakeClient,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1",
			"kind":       "Route",
			"metadata": map[string]interface{}{
				"name":      "bad-route",
				"namespace": "default",
			},
		},
	}

	err := controller.handleRouteCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec not found")
}

func TestCiliumRoutingController_HandleCreateOrUpdate_MissingDestination(t *testing.T) {
	fakeClient := newControllerFakeDynamicClient()

	controller := &RoutingController{
		dynamicClient: fakeClient,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1",
			"kind":       "Route",
			"metadata": map[string]interface{}{
				"name":      "bad-route",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				// Missing destination
				"gateway": "10.0.0.1",
			},
		},
	}

	err := controller.handleRouteCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destination not found")
}

func TestCiliumRoutingController_HandleCreateOrUpdate_InvalidCIDR(t *testing.T) {
	fakeClient := newControllerFakeDynamicClient()

	controller := &RoutingController{
		dynamicClient: fakeClient,
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.fos1.io/v1",
			"kind":       "Route",
			"metadata": map[string]interface{}{
				"name":      "bad-route",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"destination": "not-a-cidr",
			},
		},
	}

	err := controller.handleRouteCreateOrUpdate(obj)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid destination CIDR")
}

// --- Helper function tests ---

// TestGetCiliumRuleNameForFirewallRule removed in sprint 29 ticket 33 per ADR-0001.

func TestGetCiliumDPIPolicyName(t *testing.T) {
	name := GetCiliumDPIPolicyName("ns", "policy1")
	assert.Equal(t, "dpi-ns-policy1", name)
}

func TestGetCiliumRouteLabelForRoute(t *testing.T) {
	label := GetCiliumRouteLabelForRoute("ns", "route1")
	assert.Equal(t, "route-ns-route1", label)
}

// --- ControllerManager tests ---

func TestControllerManager_NewControllerManager(t *testing.T) {
	fakeClient := newControllerFakeDynamicClient()
	ciliumClient := newTestCiliumClient()

	mgr := NewControllerManager(fakeClient, ciliumClient, nil, nil)
	require.NotNil(t, mgr)
	assert.Equal(t, fakeClient, mgr.dynamicClient)
	assert.Equal(t, ciliumClient, mgr.ciliumClient)
}

// Firewall L7 rule tests removed in sprint 29 ticket 33 per ADR-0001.

// Suppress unused import warnings for clienttesting
var _ clienttesting.Action
