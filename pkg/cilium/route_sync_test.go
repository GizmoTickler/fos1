package cilium

import (
	"context"
	"net"
	"testing"
	"time"
)

// MockCiliumClientForRouting is a mock implementation for testing the RouteSynchronizer
type MockCiliumClientForRouting struct {
	// Track calls to methods
	routesAdded    []Route
	routesRemoved  []Route
	vrfRoutesAdded map[int][]Route
	
	// Configure responses
	shouldError bool
}

// NewMockCiliumClientForRouting creates a new mock client for routing tests
func NewMockCiliumClientForRouting(shouldError bool) *MockCiliumClientForRouting {
	return &MockCiliumClientForRouting{
		routesAdded:    make([]Route, 0),
		routesRemoved:  make([]Route, 0),
		vrfRoutesAdded: make(map[int][]Route),
		shouldError:    shouldError,
	}
}

// These methods are required by the CiliumClient interface but not tested in this file
func (m *MockCiliumClientForRouting) ApplyNetworkPolicy(ctx context.Context, policy *NetworkPolicy) error {
	return nil
}

func (m *MockCiliumClientForRouting) CreateNAT(ctx context.Context, config *NATConfig) error {
	return nil
}

func (m *MockCiliumClientForRouting) ConfigureVLANRouting(ctx context.Context, config *VLANRoutingConfig) error {
	return nil
}

func (m *MockCiliumClientForRouting) ConfigureDPIIntegration(ctx context.Context, config *DPIIntegrationConfig) error {
	return nil
}

// addRouteToCilium is called by the RouteSynchronizer to add a route
func (m *MockCiliumClientForRouting) addRouteToCilium(route Route) error {
	if m.shouldError {
		return ErrOperationFailed
	}
	m.routesAdded = append(m.routesAdded, route)
	return nil
}

// removeRouteFromCilium is called by the RouteSynchronizer to remove a route
func (m *MockCiliumClientForRouting) removeRouteFromCilium(route Route) error {
	if m.shouldError {
		return ErrOperationFailed
	}
	m.routesRemoved = append(m.routesRemoved, route)
	return nil
}

// addVRFRouteToCilium is called by the RouteSynchronizer to add a VRF route
func (m *MockCiliumClientForRouting) addVRFRouteToCilium(route Route, vrfID int) error {
	if m.shouldError {
		return ErrOperationFailed
	}
	if _, exists := m.vrfRoutesAdded[vrfID]; !exists {
		m.vrfRoutesAdded[vrfID] = make([]Route, 0)
	}
	m.vrfRoutesAdded[vrfID] = append(m.vrfRoutesAdded[vrfID], route)
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
	}
	
	err = synchronizer.SyncRoute(ctx, routeSync)
	if err != nil {
		t.Errorf("SyncRoute with VRF returned error: %v", err)
	}
	
	// Verify a VRF route was added
	if len(mockClient.vrfRoutesAdded) != 1 {
		t.Errorf("Expected routes to be added to 1 VRF, got %d", len(mockClient.vrfRoutesAdded))
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
	}
	
	err = synchronizer.SyncRoute(ctx, routeSync)
	if err == nil {
		t.Error("SyncRoute should return an error with invalid CIDR")
	}
}

// TestRouteSynchronizer_Start_Stop tests the Start and Stop methods
func TestRouteSynchronizer_Start_Stop(t *testing.T) {
	// Create a mock client
	mockClient := NewMockCiliumClientForRouting(false)
	
	// Create a route synchronizer with a short poll period
	synchronizer := NewRouteSynchronizer(mockClient, 50*time.Millisecond)
	
	// Start the synchronizer
	err := synchronizer.Start()
	if err != nil {
		t.Errorf("Start returned error: %v", err)
	}
	
	// Wait for at least one synchronization cycle
	time.Sleep(100 * time.Millisecond)
	
	// Stop the synchronizer
	synchronizer.Stop()
	
	// Verify synchronization was attempted
	// Note: Since we're using a mock implementation that returns empty routes,
	// we won't see any actual routes added or removed, but we can verify the
	// synchronizer ran without errors.
}

// TestRouteSynchronizer_SyncRoutesForVRF tests the SyncRoutesForVRF method
func TestRouteSynchronizer_SyncRoutesForVRF(t *testing.T) {
	// Create a mock client
	mockClient := NewMockCiliumClientForRouting(false)
	
	// Create a route synchronizer with the mock client
	synchronizer := NewRouteSynchronizer(mockClient, 30*time.Second)
	
	// Test syncing routes for a VRF
	ctx := context.Background()
	vrfID := 10
	
	err := synchronizer.SyncRoutesForVRF(ctx, vrfID)
	if err != nil {
		t.Errorf("SyncRoutesForVRF returned error: %v", err)
	}
	
	// Test error case
	mockClient = NewMockCiliumClientForRouting(true)
	synchronizer = NewRouteSynchronizer(mockClient, 30*time.Second)
	
	err = synchronizer.SyncRoutesForVRF(ctx, vrfID)
	if err == nil {
		t.Error("SyncRoutesForVRF should return an error when the client fails")
	}
}

// Define RouteSync to add the struct required for testing
type RouteSync struct {
	Destination string
	Gateway     net.IP
	Interface   string
	Metric      int
	TableID     int
	VRF         string
}
