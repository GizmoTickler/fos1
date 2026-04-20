package cilium

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

var errRouteTestFailed = fmt.Errorf("operation failed")

// MockCiliumClientForRouting is a mock implementation for testing the RouteSynchronizer
type MockCiliumClientForRouting struct {
	// Track calls to methods
	routesAdded    []Route
	routesRemoved  []Route
	vrfRoutesAdded map[int][]Route
	listRoutes     []Route
	listVRFRoutes  map[int][]Route

	// Configure responses
	shouldError bool
}

// NewMockCiliumClientForRouting creates a new mock client for routing tests
func NewMockCiliumClientForRouting(shouldError bool) *MockCiliumClientForRouting {
	return &MockCiliumClientForRouting{
		routesAdded:    make([]Route, 0),
		routesRemoved:  make([]Route, 0),
		vrfRoutesAdded: make(map[int][]Route),
		listRoutes:     make([]Route, 0),
		listVRFRoutes:  make(map[int][]Route),
		shouldError:    shouldError,
	}
}

// These methods are required by the CiliumClient interface but not tested in this file
func (m *MockCiliumClientForRouting) ApplyNetworkPolicy(ctx context.Context, policy *CiliumPolicy) error {
	return nil
}

func (m *MockCiliumClientForRouting) ListRoutes(ctx context.Context) ([]Route, error) {
	return m.listRoutes, nil
}

func (m *MockCiliumClientForRouting) ListVRFRoutes(ctx context.Context, vrfID int) ([]Route, error) {
	return m.listVRFRoutes[vrfID], nil
}

func (m *MockCiliumClientForRouting) CreateNAT(ctx context.Context, config *CiliumNATConfig) error {
	return nil
}

func (m *MockCiliumClientForRouting) RemoveNAT(ctx context.Context, config *CiliumNATConfig) error {
	return nil
}

func (m *MockCiliumClientForRouting) CreateNAT64(ctx context.Context, config *NAT64Config) error {
	return nil
}

func (m *MockCiliumClientForRouting) RemoveNAT64(ctx context.Context, config *NAT64Config) error {
	return nil
}

func (m *MockCiliumClientForRouting) CreatePortForward(ctx context.Context, config *PortForwardConfig) error {
	return nil
}

func (m *MockCiliumClientForRouting) RemovePortForward(ctx context.Context, config *PortForwardConfig) error {
	return nil
}

func (m *MockCiliumClientForRouting) ConfigureVLANRouting(ctx context.Context, config *CiliumVLANRoutingConfig) error {
	return nil
}

func (m *MockCiliumClientForRouting) ConfigureDPIIntegration(ctx context.Context, config *CiliumDPIIntegrationConfig) error {
	return nil
}

func (m *MockCiliumClientForRouting) DeleteNetworkPolicy(ctx context.Context, policyName string) error {
	return nil
}

// addRouteToCilium is called by the RouteSynchronizer to add a route
func (m *MockCiliumClientForRouting) AddRoute(route Route) error {
	if m.shouldError {
		return errRouteTestFailed
	}
	m.routesAdded = append(m.routesAdded, route)
	return nil
}

// removeRouteFromCilium is called by the RouteSynchronizer to remove a route
func (m *MockCiliumClientForRouting) DeleteRoute(route Route) error {
	if m.shouldError {
		return errRouteTestFailed
	}
	m.routesRemoved = append(m.routesRemoved, route)
	return nil
}

// addVRFRouteToCilium is called by the RouteSynchronizer to add a VRF route
func (m *MockCiliumClientForRouting) AddVRFRoute(route Route, vrfID int) error {
	if m.shouldError {
		return errRouteTestFailed
	}
	if _, exists := m.vrfRoutesAdded[vrfID]; !exists {
		m.vrfRoutesAdded[vrfID] = make([]Route, 0)
	}
	m.vrfRoutesAdded[vrfID] = append(m.vrfRoutesAdded[vrfID], route)
	return nil
}

func (m *MockCiliumClientForRouting) DeleteVRFRoute(route Route, vrfID int) error {
	if m.shouldError {
		return errRouteTestFailed
	}
	return nil
}

// TestRouteSynchronizer_SyncRoute tests the SyncRoute method
func TestRouteSynchronizer_SyncRoute(t *testing.T) {
	// Create a mock client
	mockClient := NewMockCiliumClientForRouting(false)

	// Create a route synchronizer with the mock client
	synchronizer := NewRouteSynchronizer(mockClient, 30*time.Second)

	// Test syncing a route
	ctx := context.Background()
	routeSync := &RouteSync{
		Destination: "192.168.1.0/24",
		Gateway:     net.ParseIP("10.0.0.1"),
		Interface:   "eth0",
		Metric:      100,
		TableID:     254,
		Action:      RouteSyncActionUpsert,
	}

	err := synchronizer.SyncRoute(ctx, routeSync)
	if err != nil {
		t.Errorf("SyncRoute returned error: %v", err)
	}

	// Verify a route was added
	if len(mockClient.routesAdded) != 1 {
		t.Errorf("Expected 1 route to be added, got %d", len(mockClient.routesAdded))
	} else {
		route := mockClient.routesAdded[0]

		if route.Gateway.String() != "10.0.0.1" {
			t.Errorf("Unexpected gateway: got %s, want %s", route.Gateway.String(), "10.0.0.1")
		}

		if route.OutputIface != "eth0" {
			t.Errorf("Unexpected output interface: got %s, want %s", route.OutputIface, "eth0")
		}

		if route.Priority != 100 {
			t.Errorf("Unexpected priority/metric: got %d, want %d", route.Priority, 100)
		}

		if route.Table != 254 {
			t.Errorf("Unexpected table ID: got %d, want %d", route.Table, 254)
		}

		if route.Type != "static" {
			t.Errorf("Unexpected route type: got %s, want %s", route.Type, "static")
		}
	}

	// Test syncing a route with VRF
	mockClient = NewMockCiliumClientForRouting(false)
	synchronizer = NewRouteSynchronizer(mockClient, 30*time.Second)

	routeSync = &RouteSync{
		Destination: "192.168.2.0/24",
		Gateway:     net.ParseIP("10.0.0.2"),
		Interface:   "eth1",
		Metric:      200,
		TableID:     254,
		VRF:         "vrf1",
		Action:      RouteSyncActionUpsert,
	}

	err = synchronizer.SyncRoute(ctx, routeSync)
	if err != nil {
		t.Errorf("SyncRoute with VRF returned error: %v", err)
	}

	// Verify the route was added with its VRF metadata preserved
	if len(mockClient.routesAdded) != 1 {
		t.Fatalf("Expected 1 route to be added, got %d", len(mockClient.routesAdded))
	}
	if mockClient.routesAdded[0].VRF != "vrf1" {
		t.Fatalf("Expected route VRF to be vrf1, got %q", mockClient.routesAdded[0].VRF)
	}

	// Test error case
	mockClient = NewMockCiliumClientForRouting(true)
	synchronizer = NewRouteSynchronizer(mockClient, 30*time.Second)

	routeSync = &RouteSync{
		Destination: "192.168.1.0/24",
		Gateway:     net.ParseIP("10.0.0.1"),
		Interface:   "eth0",
		Metric:      100,
		TableID:     254,
		Action:      RouteSyncActionUpsert,
	}

	err = synchronizer.SyncRoute(ctx, routeSync)
	if err == nil {
		t.Error("SyncRoute should return an error when the client fails")
	}

	// Test invalid CIDR
	mockClient = NewMockCiliumClientForRouting(false)
	synchronizer = NewRouteSynchronizer(mockClient, 30*time.Second)

	routeSync = &RouteSync{
		Destination: "invalid CIDR",
		Gateway:     net.ParseIP("10.0.0.1"),
		Interface:   "eth0",
		Metric:      100,
		TableID:     254,
		Action:      RouteSyncActionUpsert,
	}

	err = synchronizer.SyncRoute(ctx, routeSync)
	if err == nil {
		t.Error("SyncRoute should return an error with invalid CIDR")
	}
}

// TestRouteSynchronizer_Start_ExplicitlyFailsWithoutKernelDiscovery tests the unsupported background sync path.
func TestRouteSynchronizer_Start_ExplicitlyFailsWithoutKernelDiscovery(t *testing.T) {
	// Create a mock client
	mockClient := NewMockCiliumClientForRouting(false)

	// Create a route synchronizer with a short poll period
	synchronizer := NewRouteSynchronizer(mockClient, 50*time.Millisecond)

	// Start the synchronizer
	err := synchronizer.Start()
	if err == nil {
		t.Fatal("Start should fail when kernel route discovery is unsupported")
	}
	if !strings.Contains(err.Error(), "kernel route discovery is not supported") {
		t.Fatalf("expected unsupported kernel discovery error, got %v", err)
	}
}

// TestRouteSynchronizer_SyncRoutesForVRF tests the SyncRoutesForVRF method
func TestRouteSynchronizer_SyncRoutesForVRF(t *testing.T) {
	// Create a mock client
	mockClient := NewMockCiliumClientForRouting(false)
	_, destination, err := net.ParseCIDR("192.168.10.0/24")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}
	mockClient.listVRFRoutes[10] = []Route{
		{
			Destination: destination,
			Gateway:     net.ParseIP("10.0.0.1"),
			OutputIface: "eth0",
		},
	}

	// Create a route synchronizer with the mock client
	synchronizer := NewRouteSynchronizer(mockClient, 30*time.Second)

	// Test syncing routes for a VRF
	ctx := context.Background()
	vrfID := 10

	err = synchronizer.SyncRoutesForVRF(ctx, vrfID)
	if err != nil {
		t.Errorf("SyncRoutesForVRF returned error: %v", err)
	}

	if len(mockClient.vrfRoutesAdded[vrfID]) != 1 {
		t.Fatalf("expected 1 route to be added for VRF %d, got %d", vrfID, len(mockClient.vrfRoutesAdded[vrfID]))
	}
}

func TestRouteSynchronizer_SyncRoute_DeleteRequiresRouteDetails(t *testing.T) {
	mockClient := NewMockCiliumClientForRouting(false)
	synchronizer := NewRouteSynchronizer(mockClient, 30*time.Second)

	err := synchronizer.SyncRoute(context.Background(), &RouteSync{
		Namespace: "default",
		Name:      "missing-route-details",
		Action:    RouteSyncActionDelete,
	})
	if err == nil {
		t.Fatal("expected delete without route details to fail")
	}
	if !strings.Contains(err.Error(), "route deletion requires destination or full route details") {
		t.Fatalf("expected actionable delete error, got %v", err)
	}
}
