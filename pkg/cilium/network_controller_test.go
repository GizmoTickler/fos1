package cilium

import (
	"context"
	"fmt"
	"testing"
)

// Define error constants for testing
var (
	errTestOperationFailed = fmt.Errorf("operation failed")
)

// MockNetworkCiliumClient is a mock implementation of the network controller client.
type MockNetworkCiliumClient struct {
	// Track calls to methods
	ApplyNetworkPolicyCalled   bool
	CreateNATCalled            bool
	ConfigureVLANRoutingCalled bool
	ConfigureDPICalled         bool

	// Store parameters for verification
	LastNetworkPolicy *CiliumPolicy
	LastNATConfig     *CiliumNATConfig
	LastVLANConfig    *CiliumVLANRoutingConfig
	LastDPIConfig     *CiliumDPIIntegrationConfig

	// Configure responses
	ShouldError bool
}

// ApplyNetworkPolicy mocks applying a network policy
func (m *MockNetworkCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *CiliumPolicy) error {
	m.ApplyNetworkPolicyCalled = true
	m.LastNetworkPolicy = policy
	if m.ShouldError {
		return errTestOperationFailed
	}
	return nil
}

// CreateNAT mocks creating NAT rules
func (m *MockNetworkCiliumClient) CreateNAT(ctx context.Context, config *CiliumNATConfig) error {
	m.CreateNATCalled = true
	m.LastNATConfig = config
	if m.ShouldError {
		return errTestOperationFailed
	}
	return nil
}

// ConfigureVLANRouting mocks configuring VLAN routing
func (m *MockNetworkCiliumClient) ConfigureVLANRouting(ctx context.Context, config *CiliumVLANRoutingConfig) error {
	m.ConfigureVLANRoutingCalled = true
	m.LastVLANConfig = config
	if m.ShouldError {
		return errTestOperationFailed
	}
	return nil
}

// ConfigureDPIIntegration mocks configuring DPI integration
func (m *MockNetworkCiliumClient) ConfigureDPIIntegration(ctx context.Context, config *CiliumDPIIntegrationConfig) error {
	m.ConfigureDPICalled = true
	m.LastDPIConfig = config
	if m.ShouldError {
		return errTestOperationFailed
	}
	return nil
}

func (m *MockNetworkCiliumClient) ListRoutes(ctx context.Context) ([]Route, error)              { return nil, nil }
func (m *MockNetworkCiliumClient) ListVRFRoutes(ctx context.Context, vrfID int) ([]Route, error) { return nil, nil }
func (m *MockNetworkCiliumClient) AddRoute(route Route) error                                    { return nil }
func (m *MockNetworkCiliumClient) DeleteRoute(route Route) error                                 { return nil }
func (m *MockNetworkCiliumClient) AddVRFRoute(route Route, vrfID int) error                      { return nil }
func (m *MockNetworkCiliumClient) DeleteVRFRoute(route Route, vrfID int) error                   { return nil }
func (m *MockNetworkCiliumClient) RemoveNAT(ctx context.Context, config *CiliumNATConfig) error  { return nil }
func (m *MockNetworkCiliumClient) CreateNAT64(ctx context.Context, config *NAT64Config) error    { return nil }
func (m *MockNetworkCiliumClient) RemoveNAT64(ctx context.Context, config *NAT64Config) error    { return nil }
func (m *MockNetworkCiliumClient) CreatePortForward(ctx context.Context, config *PortForwardConfig) error { return nil }
func (m *MockNetworkCiliumClient) RemovePortForward(ctx context.Context, config *PortForwardConfig) error { return nil }

// TestNetworkController_ConfigureNAT tests the ConfigureNAT method
func TestNetworkController_ConfigureNAT(t *testing.T) {
	// Create a mock client
	mockClient := &MockNetworkCiliumClient{}

	// Create a network controller with the mock client
	controller := NewNetworkController(mockClient)

	// Test IPv4 NAT
	ctx := context.Background()
	err := controller.ConfigureNAT(ctx, "192.168.1.0/24", "eth0", false)
	if err != nil {
		t.Errorf("ConfigureNAT returned error: %v", err)
	}

	// Verify the client was called with the correct parameters
	if !mockClient.CreateNATCalled {
		t.Error("CreateNAT was not called")
	}

	if mockClient.LastNATConfig.SourceNetwork != "192.168.1.0/24" {
		t.Errorf("Unexpected source network: got %s, want %s", mockClient.LastNATConfig.SourceNetwork, "192.168.1.0/24")
	}

	if mockClient.LastNATConfig.DestinationIface != "eth0" {
		t.Errorf("Unexpected destination interface: got %s, want %s", mockClient.LastNATConfig.DestinationIface, "eth0")
	}

	if mockClient.LastNATConfig.IPv6 {
		t.Error("IPv6 flag should be false for IPv4 NAT")
	}

	// Test IPv6 NAT (NAT66)
	mockClient = &MockNetworkCiliumClient{}
	controller = NewNetworkController(mockClient)

	err = controller.ConfigureNAT(ctx, "2001:db8::/64", "eth0", true)
	if err != nil {
		t.Errorf("ConfigureNAT returned error: %v", err)
	}

	// Verify the client was called with the correct parameters
	if !mockClient.CreateNATCalled {
		t.Error("CreateNAT was not called")
	}

	if mockClient.LastNATConfig.SourceNetwork != "2001:db8::/64" {
		t.Errorf("Unexpected source network: got %s, want %s", mockClient.LastNATConfig.SourceNetwork, "2001:db8::/64")
	}

	if mockClient.LastNATConfig.DestinationIface != "eth0" {
		t.Errorf("Unexpected destination interface: got %s, want %s", mockClient.LastNATConfig.DestinationIface, "eth0")
	}

	if !mockClient.LastNATConfig.IPv6 {
		t.Error("IPv6 flag should be true for IPv6 NAT")
	}

	// Test error case
	mockClient = &MockNetworkCiliumClient{ShouldError: true}
	controller = NewNetworkController(mockClient)

	err = controller.ConfigureNAT(ctx, "192.168.1.0/24", "eth0", false)
	if err == nil {
		t.Error("ConfigureNAT should return an error when the client fails")
	}
}

// TestNetworkController_ConfigureInterVLANRouting tests the ConfigureInterVLANRouting method
func TestNetworkController_ConfigureInterVLANRouting(t *testing.T) {
	// Create a mock client
	mockClient := &MockNetworkCiliumClient{}

	// Create a network controller with the mock client
	controller := NewNetworkController(mockClient)

	// Test VLAN routing
	ctx := context.Background()
	vlans := []uint16{10, 20, 30}
	err := controller.ConfigureInterVLANRouting(ctx, vlans, true)
	if err != nil {
		t.Errorf("ConfigureInterVLANRouting returned error: %v", err)
	}

	// Verify the client was called with the correct parameters
	if !mockClient.ConfigureVLANRoutingCalled {
		t.Error("ConfigureVLANRouting was not called")
	}

	if len(mockClient.LastVLANConfig.VLANs) != len(vlans) {
		t.Errorf("Unexpected VLANs: got %v, want %v", mockClient.LastVLANConfig.VLANs, vlans)
	}

	for _, vlan := range vlans {
		config, exists := mockClient.LastVLANConfig.VLANs[int(vlan)]
		if !exists {
			t.Errorf("Expected VLAN %d to exist", vlan)
			continue
		}
		if config.Name != fmt.Sprintf("vlan-%d", vlan) {
			t.Errorf("Unexpected VLAN name for %d: got %s", vlan, config.Name)
		}
	}

	// Test error case
	mockClient = &MockNetworkCiliumClient{ShouldError: true}
	controller = NewNetworkController(mockClient)

	err = controller.ConfigureInterVLANRouting(ctx, vlans, true)
	if err == nil {
		t.Error("ConfigureInterVLANRouting should return an error when the client fails")
	}
}

// TestNetworkController_AddVLANPolicy tests the AddVLANPolicy method
func TestNetworkController_AddVLANPolicy(t *testing.T) {
	// Create a mock client
	mockClient := &MockNetworkCiliumClient{}

	// Create a network controller with the mock client
	controller := NewNetworkController(mockClient)

	// Test VLAN policy
	ctx := context.Background()
	rules := []NetworkVLANRule{
		{
			Protocol: "tcp",
			Port:     80,
			Allow:    true,
		},
		{
			Protocol: "udp",
			Port:     53,
			Allow:    true,
		},
	}
	err := controller.AddVLANPolicy(ctx, 10, 20, false, rules)
	if err != nil {
		t.Errorf("AddVLANPolicy returned error: %v", err)
	}

	// Verify the client was called with the correct parameters
	if !mockClient.ConfigureVLANRoutingCalled {
		t.Error("ConfigureVLANRouting was not called")
	}

	if len(mockClient.LastVLANConfig.VLANs) != 2 {
		t.Errorf("Unexpected VLANs count: got %d, want %d", len(mockClient.LastVLANConfig.VLANs), 2)
	}

	policyKey := "10-20"
	policy, exists := mockClient.LastVLANConfig.Policies[policyKey]
	if !exists {
		t.Errorf("Expected policy with key %s to exist", policyKey)
	}

	if policy.FromVLAN != 10 {
		t.Errorf("Unexpected FromVLAN: got %d, want %d", policy.FromVLAN, 10)
	}

	if policy.ToVLAN != 20 {
		t.Errorf("Unexpected ToVLAN: got %d, want %d", policy.ToVLAN, 20)
	}

	if policy.AllowAll {
		t.Error("AllowAll should be false")
	}

	if len(policy.Rules) != len(rules) {
		t.Errorf("Unexpected rule count: got %d, want %d", len(policy.Rules), len(rules))
	}

	// Test error case
	mockClient = &MockNetworkCiliumClient{ShouldError: true}
	controller = NewNetworkController(mockClient)

	err = controller.AddVLANPolicy(ctx, 10, 20, false, rules)
	if err == nil {
		t.Error("AddVLANPolicy should return an error when the client fails")
	}
}

// TestNetworkController_IntegrateDPI tests the IntegrateDPI method
func TestNetworkController_IntegrateDPI(t *testing.T) {
	// Create a mock client
	mockClient := &MockNetworkCiliumClient{}

	// Create a network controller with the mock client
	controller := NewNetworkController(mockClient)

	// Test DPI integration
	ctx := context.Background()
	appPolicies := map[string]AppPolicy{
		"http": {
			Application: "http",
			Action:      "allow",
			Priority:    1,
			DSCP:        0,
		},
		"ssh": {
			Application: "ssh",
			Action:      "deny",
			Priority:    2,
			DSCP:        0,
		},
	}
	err := controller.IntegrateDPI(ctx, appPolicies)
	if err != nil {
		t.Errorf("IntegrateDPI returned error: %v", err)
	}

	// Verify the client was called with the correct parameters
	if !mockClient.ConfigureDPICalled {
		t.Error("ConfigureDPIIntegration was not called")
	}

	if !mockClient.LastDPIConfig.Enabled {
		t.Error("Enabled should be true")
	}

	if len(mockClient.LastDPIConfig.ApplicationsToMonitor) != len(appPolicies) {
		t.Errorf("Unexpected application count: got %d, want %d", len(mockClient.LastDPIConfig.ApplicationsToMonitor), len(appPolicies))
	}

	appsSeen := make(map[string]bool, len(mockClient.LastDPIConfig.ApplicationsToMonitor))
	for _, app := range mockClient.LastDPIConfig.ApplicationsToMonitor {
		appsSeen[app] = true
	}
	for app := range appPolicies {
		if !appsSeen[app] {
			t.Errorf("Expected application %s to be monitored", app)
		}
	}
	if mockClient.LastDPIConfig.EnforcementMode != "log" {
		t.Errorf("Unexpected enforcement mode: got %s, want log", mockClient.LastDPIConfig.EnforcementMode)
	}

	// Test error case
	mockClient = &MockNetworkCiliumClient{ShouldError: true}
	controller = NewNetworkController(mockClient)

	err = controller.IntegrateDPI(ctx, appPolicies)
	if err == nil {
		t.Error("IntegrateDPI should return an error when the client fails")
	}
}

// TestNetworkController_ApplyDynamicPolicy tests the ApplyDynamicPolicy method
func TestNetworkController_ApplyDynamicPolicy(t *testing.T) {
	// Create a mock client
	mockClient := &MockNetworkCiliumClient{}

	// Create a network controller with the mock client
	controller := NewNetworkController(mockClient)

	// Test applying a dynamic policy
	ctx := context.Background()
	err := controller.ApplyDynamicPolicy(ctx, "http", "allow")
	if err != nil {
		t.Errorf("ApplyDynamicPolicy returned error: %v", err)
	}

	// Verify the client was called with the correct parameters
	if !mockClient.ApplyNetworkPolicyCalled {
		t.Error("ApplyNetworkPolicy was not called")
	}

	expectedName := "dpi-app-http"
	if mockClient.LastNetworkPolicy.Name != expectedName {
		t.Errorf("Unexpected policy name: got %s, want %s", mockClient.LastNetworkPolicy.Name, expectedName)
	}

	app, exists := mockClient.LastNetworkPolicy.Labels["app"]
	if !exists {
		t.Error("Expected 'app' label to exist")
	} else if app != "http" {
		t.Errorf("Unexpected app label value: got %s, want %s", app, "http")
	}

	// Test error case
	mockClient = &MockNetworkCiliumClient{ShouldError: true}
	controller = NewNetworkController(mockClient)

	err = controller.ApplyDynamicPolicy(ctx, "http", "allow")
	if err == nil {
		t.Error("ApplyDynamicPolicy should return an error when the client fails")
	}
}
