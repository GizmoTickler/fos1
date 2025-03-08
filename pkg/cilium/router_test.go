package cilium

import (
	"context"
	"net"
	"testing"
	"time"
)

// MockCiliumClient is a mock implementation of CiliumClient for testing
type MockCiliumClient struct {
	routes      map[string]Route
	vrfs        map[int]map[string]Route
	policyRules []PolicyRule
}

// NewMockCiliumClient creates a new mock Cilium client
func NewMockCiliumClient() *MockCiliumClient {
	return &MockCiliumClient{
		routes:      make(map[string]Route),
		vrfs:        make(map[int]map[string]Route),
		policyRules: []PolicyRule{},
	}
}

// AddRoute adds a route to the mock client
func (c *MockCiliumClient) AddRoute(route Route) error {
	key := routeKey(route)
	c.routes[key] = route
	return nil
}

// DeleteRoute deletes a route from the mock client
func (c *MockCiliumClient) DeleteRoute(route Route) error {
	key := routeKey(route)
	delete(c.routes, key)
	return nil
}

// AddVRFRoute adds a route to a VRF in the mock client
func (c *MockCiliumClient) AddVRFRoute(route Route, vrfID int) error {
	if _, exists := c.vrfs[vrfID]; !exists {
		c.vrfs[vrfID] = make(map[string]Route)
	}
	key := routeKey(route)
	c.vrfs[vrfID][key] = route
	return nil
}

// DeleteVRFRoute deletes a route from a VRF in the mock client
func (c *MockCiliumClient) DeleteVRFRoute(route Route, vrfID int) error {
	if routes, exists := c.vrfs[vrfID]; exists {
		key := routeKey(route)
		delete(routes, key)
	}
	return nil
}

// AddPolicyRule adds a policy rule to the mock client
func (c *MockCiliumClient) AddPolicyRule(rule PolicyRule) error {
	c.policyRules = append(c.policyRules, rule)
	return nil
}

// DeletePolicyRule deletes a policy rule from the mock client
func (c *MockCiliumClient) DeletePolicyRule(priority int) error {
	newRules := make([]PolicyRule, 0, len(c.policyRules))
	for _, rule := range c.policyRules {
		if rule.Priority != priority {
			newRules = append(newRules, rule)
		}
	}
	c.policyRules = newRules
	return nil
}

// routeKey generates a unique key for a route
func routeKey(route Route) string {
	if route.Destination == nil {
		return "nil-destination"
	}
	return route.Destination.String()
}

func TestRouter(t *testing.T) {
	// Create a mock Cilium client
	client := NewMockCiliumClient()

	// Create a route synchronizer with the mock client
	routeSynchronizer := NewRouteSynchronizer(client, 10*time.Second)

	// Create a router with the mock client
	options := DefaultRouterOptions()
	router := NewRouter(client, routeSynchronizer, options)

	// Start the router
	if err := router.Start(); err != nil {
		t.Fatalf("Failed to start router: %v", err)
	}
	defer router.Stop()

	// Test adding a VRF
	vrfID, err := router.AddVRF("test-vrf", []int{100}, []string{"eth1"})
	if err != nil {
		t.Fatalf("Failed to add VRF: %v", err)
	}
	if vrfID <= 0 {
		t.Errorf("Expected VRF ID > 0, got %d", vrfID)
	}

	// Test adding a policy rule
	_, cidr, _ := net.ParseCIDR("192.168.1.0/24")
	rule := PolicyRule{
		Priority:     100,
		Table:        100,
		SourceIP:     cidr,
		InputInterface: "eth1",
	}
	if err := router.AddPolicyRule(rule); err != nil {
		t.Fatalf("Failed to add policy rule: %v", err)
	}

	// Test adding a route
	_, destNet, _ := net.ParseCIDR("10.0.0.0/24")
	route := Route{
		Destination: destNet,
		Gateway:     net.ParseIP("192.168.1.1"),
		OutputIface: "eth0",
		Priority:    100,
		Table:       254,
		Type:        "static",
	}
	if err := router.AddRoute(route); err != nil {
		t.Fatalf("Failed to add route: %v", err)
	}

	// Verify that the route was added to the mock client
	if len(client.routes) != 1 {
		t.Errorf("Expected 1 route, got %d", len(client.routes))
	}

	// Test adding a route to the VRF
	_, vrfDestNet, _ := net.ParseCIDR("10.1.0.0/24")
	vrfRoute := Route{
		Destination: vrfDestNet,
		Gateway:     net.ParseIP("192.168.1.2"),
		OutputIface: "eth1",
		Priority:    100,
		Table:       100,
		Type:        "static",
	}
	if err := router.AddRouteToVRF(vrfRoute, vrfID); err != nil {
		t.Fatalf("Failed to add route to VRF: %v", err)
	}

	// Test deleting the policy rule
	if err := router.DeletePolicyRule(100); err != nil {
		t.Fatalf("Failed to delete policy rule: %v", err)
	}

	// Test deleting the route
	if err := router.DeleteRoute(route); err != nil {
		t.Fatalf("Failed to delete route: %v", err)
	}

	// Test deleting the VRF
	if err := router.DeleteVRF(vrfID); err != nil {
		t.Fatalf("Failed to delete VRF: %v", err)
	}
}

func TestRouterWithSynchronizer(t *testing.T) {
	// Create a mock Cilium client
	client := NewMockCiliumClient()

	// Create a route synchronizer with the mock client
	routeSynchronizer := NewRouteSynchronizer(client, 10*time.Second)

	// Create a router with the mock client
	options := DefaultRouterOptions()
	router := NewRouter(client, routeSynchronizer, options)

	// Start the router
	if err := router.Start(); err != nil {
		t.Fatalf("Failed to start router: %v", err)
	}
	defer router.Stop()

	// Test synchronizing a route
	_, destNet, _ := net.ParseCIDR("10.0.0.0/24")
	route := Route{
		Destination: destNet,
		Gateway:     net.ParseIP("192.168.1.1"),
		OutputIface: "eth0",
		Priority:    100,
		Table:       254,
		Type:        "static",
	}

	// Create a RouteSync request
	routeSync := &RouteSync{
		Namespace: "default",
		Name:      "test-route",
		Route:     route,
		Action:    RouteSyncActionUpsert,
	}

	// Synchronize the route
	ctx := context.Background()
	if err := routeSynchronizer.SyncRoute(ctx, routeSync); err != nil {
		t.Fatalf("Failed to sync route: %v", err)
	}

	// Verify that the route was added to the mock client
	if len(client.routes) != 1 {
		t.Errorf("Expected 1 route, got %d", len(client.routes))
	}

	// Change the action to delete
	routeSync.Action = RouteSyncActionDelete

	// Synchronize the route again to delete it
	if err := routeSynchronizer.SyncRoute(ctx, routeSync); err != nil {
		t.Fatalf("Failed to sync route deletion: %v", err)
	}

	// Verify that the route was deleted from the mock client
	if len(client.routes) != 0 {
		t.Errorf("Expected 0 routes after deletion, got %d", len(client.routes))
	}
}
