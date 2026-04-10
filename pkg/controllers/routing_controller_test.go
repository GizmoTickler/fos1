package controllers

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/network/routing"
)

// testCiliumClient is a mock CiliumClient that tracks all operations for
// verification. It records routes, VRF routes, and policies applied.
type testCiliumClient struct {
	mu            sync.Mutex
	routes        map[string]cilium.Route
	vrfRoutes     map[int]map[string]cilium.Route
	policies      map[string]*cilium.CiliumPolicy
	vrfRouteCalls []vrfRouteCall
	shouldError   bool
}

type vrfRouteCall struct {
	Route cilium.Route
	VRFID int
}

func newTestCiliumClient() *testCiliumClient {
	return &testCiliumClient{
		routes:    make(map[string]cilium.Route),
		vrfRoutes: make(map[int]map[string]cilium.Route),
		policies:  make(map[string]*cilium.CiliumPolicy),
	}
}

func (c *testCiliumClient) ApplyNetworkPolicy(_ context.Context, policy *cilium.CiliumPolicy) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shouldError {
		return fmt.Errorf("mock error: apply network policy")
	}
	c.policies[policy.Name] = policy
	return nil
}

func (c *testCiliumClient) ListRoutes(_ context.Context) ([]cilium.Route, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	routes := make([]cilium.Route, 0, len(c.routes))
	for _, r := range c.routes {
		routes = append(routes, r)
	}
	return routes, nil
}

func (c *testCiliumClient) ListVRFRoutes(_ context.Context, vrfID int) ([]cilium.Route, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shouldError {
		return nil, fmt.Errorf("mock error: list VRF routes")
	}
	routeMap, exists := c.vrfRoutes[vrfID]
	if !exists {
		return []cilium.Route{}, nil
	}
	routes := make([]cilium.Route, 0, len(routeMap))
	for _, r := range routeMap {
		routes = append(routes, r)
	}
	return routes, nil
}

func (c *testCiliumClient) AddRoute(route cilium.Route) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shouldError {
		return fmt.Errorf("mock error: add route")
	}
	key := "nil"
	if route.Destination != nil {
		key = route.Destination.String()
	}
	c.routes[key] = route
	return nil
}

func (c *testCiliumClient) DeleteRoute(route cilium.Route) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shouldError {
		return fmt.Errorf("mock error: delete route")
	}
	key := "nil"
	if route.Destination != nil {
		key = route.Destination.String()
	}
	delete(c.routes, key)
	return nil
}

func (c *testCiliumClient) AddVRFRoute(route cilium.Route, vrfID int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shouldError {
		return fmt.Errorf("mock error: add VRF route")
	}
	if _, exists := c.vrfRoutes[vrfID]; !exists {
		c.vrfRoutes[vrfID] = make(map[string]cilium.Route)
	}
	key := "nil"
	if route.Destination != nil {
		key = route.Destination.String()
	}
	c.vrfRoutes[vrfID][key] = route
	c.vrfRouteCalls = append(c.vrfRouteCalls, vrfRouteCall{Route: route, VRFID: vrfID})
	return nil
}

func (c *testCiliumClient) DeleteVRFRoute(route cilium.Route, vrfID int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shouldError {
		return fmt.Errorf("mock error: delete VRF route")
	}
	if routeMap, exists := c.vrfRoutes[vrfID]; exists {
		key := "nil"
		if route.Destination != nil {
			key = route.Destination.String()
		}
		delete(routeMap, key)
	}
	return nil
}

func (c *testCiliumClient) CreateNAT(_ context.Context, _ *cilium.CiliumNATConfig) error {
	return nil
}
func (c *testCiliumClient) RemoveNAT(_ context.Context, _ *cilium.CiliumNATConfig) error {
	return nil
}
func (c *testCiliumClient) CreateNAT64(_ context.Context, _ *cilium.NAT64Config) error {
	return nil
}
func (c *testCiliumClient) RemoveNAT64(_ context.Context, _ *cilium.NAT64Config) error {
	return nil
}
func (c *testCiliumClient) CreatePortForward(_ context.Context, _ *cilium.PortForwardConfig) error {
	return nil
}
func (c *testCiliumClient) RemovePortForward(_ context.Context, _ *cilium.PortForwardConfig) error {
	return nil
}
func (c *testCiliumClient) ConfigureVLANRouting(_ context.Context, _ *cilium.CiliumVLANRoutingConfig) error {
	return nil
}
func (c *testCiliumClient) ConfigureDPIIntegration(_ context.Context, _ *cilium.CiliumDPIIntegrationConfig) error {
	return nil
}

// --- routingTableToID tests ---

func TestRoutingTableToID_WellKnown(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"", 254},
		{"main", 254},
		{"Main", 254},
		{"MAIN", 254},
		{"  main  ", 254},
		{"local", 255},
		{"default", 253},
	}
	for _, tt := range tests {
		got := routingTableToID(tt.input)
		if got != tt.expected {
			t.Errorf("routingTableToID(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestRoutingTableToID_Numeric(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"100", 100},
		{"1", 1},
		{"252", 252},
		{"0", 0},
		{"999", 999},
	}
	for _, tt := range tests {
		got := routingTableToID(tt.input)
		if got != tt.expected {
			t.Errorf("routingTableToID(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestRoutingTableToID_Named_Deterministic(t *testing.T) {
	// Named tables should always return the same value
	name := "my-custom-table"
	id1 := routingTableToID(name)
	id2 := routingTableToID(name)
	if id1 != id2 {
		t.Errorf("routingTableToID(%q) not deterministic: %d != %d", name, id1, id2)
	}
	if id1 < 1 || id1 > 252 {
		t.Errorf("routingTableToID(%q) = %d, expected 1-252", name, id1)
	}
}

// --- VRFTableID tests ---

func TestVRFTableID_ExplicitTableID(t *testing.T) {
	vrf := routing.VRF{Name: "test", TableID: 42}
	got := VRFTableID(vrf)
	if got != 42 {
		t.Errorf("VRFTableID with explicit TableID=42 returned %d", got)
	}
}

func TestVRFTableID_NumericName(t *testing.T) {
	vrf := routing.VRF{Name: "100", TableID: 0}
	got := VRFTableID(vrf)
	if got != 100 {
		t.Errorf("VRFTableID with numeric name '100' returned %d", got)
	}
}

func TestVRFTableID_StringName_Deterministic(t *testing.T) {
	vrf := routing.VRF{Name: "production", TableID: 0}
	id1 := VRFTableID(vrf)
	id2 := VRFTableID(vrf)
	if id1 != id2 {
		t.Errorf("VRFTableID not deterministic for %q: %d != %d", vrf.Name, id1, id2)
	}
	if id1 < 1 || id1 > 252 {
		t.Errorf("VRFTableID for %q = %d, expected 1-252", vrf.Name, id1)
	}
}

func TestVRFTableID_DifferentNames_MayDiffer(t *testing.T) {
	// While hash collisions are possible, distinct names should generally
	// produce distinct IDs. Test a small set to validate distribution.
	names := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	ids := make(map[int]string)
	for _, name := range names {
		vrf := routing.VRF{Name: name}
		id := VRFTableID(vrf)
		if id < 1 || id > 252 {
			t.Errorf("VRFTableID(%q) = %d, out of range", name, id)
		}
		ids[id] = name
	}
	// We expect at least 3 distinct IDs from 5 names (very conservative)
	if len(ids) < 3 {
		t.Errorf("VRFTableID hash distribution too poor: only %d unique IDs from %d names", len(ids), len(names))
	}
}

func TestVRFTableID_InvalidExplicitID_FallsBack(t *testing.T) {
	// TableID of 0 should fall back to name-based resolution
	vrf := routing.VRF{Name: "test-vrf", TableID: 0}
	got := VRFTableID(vrf)
	if got < 1 || got > 252 {
		t.Errorf("VRFTableID with TableID=0 returned %d, expected 1-252", got)
	}

	// TableID outside 1-252 should also fall back
	vrf2 := routing.VRF{Name: "test-vrf", TableID: 300}
	got2 := VRFTableID(vrf2)
	if got2 < 1 || got2 > 252 {
		t.Errorf("VRFTableID with TableID=300 returned %d, expected 1-252", got2)
	}
}

// --- SyncVRFPolicies tests ---

func TestSyncVRFPolicies_EmptyVRF(t *testing.T) {
	client := newTestCiliumClient()
	sync := &realCiliumSynchronizer{client: client}

	vrf := routing.VRF{
		Name:       "empty-vrf",
		TableID:    10,
		Interfaces: []string{},
		LeakRoutes: []routing.RouteLeak{},
	}

	err := sync.SyncVRFPolicies(vrf)
	if err != nil {
		t.Fatalf("SyncVRFPolicies for empty VRF should succeed, got: %v", err)
	}

	// No routes should be added
	if len(client.vrfRouteCalls) != 0 {
		t.Errorf("Expected 0 VRF route calls for empty VRF, got %d", len(client.vrfRouteCalls))
	}

	// No policies should be applied (no interfaces)
	if len(client.policies) != 0 {
		t.Errorf("Expected 0 policies for VRF with no interfaces, got %d", len(client.policies))
	}
}

func TestSyncVRFPolicies_WithRoutes(t *testing.T) {
	client := newTestCiliumClient()
	sync := &realCiliumSynchronizer{client: client}

	vrf := routing.VRF{
		Name:       "test-vrf",
		TableID:    50,
		Interfaces: []string{"eth0", "eth1"},
		LeakRoutes: []routing.RouteLeak{
			{
				FromVRF:      "other-vrf",
				ToVRF:        "test-vrf",
				Destinations: []string{"10.0.0.0/24", "10.1.0.0/24"},
			},
		},
	}

	err := sync.SyncVRFPolicies(vrf)
	if err != nil {
		t.Fatalf("SyncVRFPolicies failed: %v", err)
	}

	// Verify routes were added
	if len(client.vrfRouteCalls) != 2 {
		t.Errorf("Expected 2 VRF route calls, got %d", len(client.vrfRouteCalls))
	}

	// Verify VRF routes are in the correct table
	vrfRouteMap := client.vrfRoutes[50]
	if len(vrfRouteMap) != 2 {
		t.Errorf("Expected 2 routes in VRF table 50, got %d", len(vrfRouteMap))
	}

	// Verify policies were applied for interfaces
	if len(client.policies) != 2 {
		t.Errorf("Expected 2 policies (one per interface), got %d", len(client.policies))
	}

	// Check that policies have correct labels
	for _, pol := range client.policies {
		if pol.Labels["vrf"] != "test-vrf" {
			t.Errorf("Policy %s has wrong VRF label: %s", pol.Name, pol.Labels["vrf"])
		}
		if pol.Labels["vrf-table"] != "50" {
			t.Errorf("Policy %s has wrong table label: %s", pol.Name, pol.Labels["vrf-table"])
		}
	}
}

func TestSyncVRFPolicies_Idempotent(t *testing.T) {
	client := newTestCiliumClient()
	sync := &realCiliumSynchronizer{client: client}

	vrf := routing.VRF{
		Name:       "idempotent-vrf",
		TableID:    20,
		Interfaces: []string{"eth0"},
		LeakRoutes: []routing.RouteLeak{
			{
				Destinations: []string{"10.0.0.0/24"},
			},
		},
	}

	// First sync
	if err := sync.SyncVRFPolicies(vrf); err != nil {
		t.Fatalf("First SyncVRFPolicies failed: %v", err)
	}

	routeCountAfterFirst := len(client.vrfRouteCalls)
	policyCountAfterFirst := len(client.policies)

	// Second sync (should be idempotent - routes already exist, policies re-applied via kubectl apply)
	if err := sync.SyncVRFPolicies(vrf); err != nil {
		t.Fatalf("Second SyncVRFPolicies failed: %v", err)
	}

	// Routes should NOT be added again (idempotent check)
	if len(client.vrfRouteCalls) != routeCountAfterFirst {
		t.Errorf("Expected no new VRF route calls on second sync, but got %d total (was %d)",
			len(client.vrfRouteCalls), routeCountAfterFirst)
	}

	// Policies are re-applied (idempotent via kubectl apply), count stays the same
	if len(client.policies) != policyCountAfterFirst {
		t.Errorf("Expected same number of policies after second sync: got %d, was %d",
			len(client.policies), policyCountAfterFirst)
	}
}

func TestSyncVRFPolicies_RemovesStaleRoutes(t *testing.T) {
	client := newTestCiliumClient()
	sync := &realCiliumSynchronizer{client: client}

	// Pre-populate a stale route in the VRF
	_, staleNet, _ := net.ParseCIDR("192.168.99.0/24")
	client.vrfRoutes[30] = map[string]cilium.Route{
		staleNet.String(): {
			Destination: staleNet,
			Table:       30,
			VRF:         "vrf-30",
		},
	}

	vrf := routing.VRF{
		Name:       "cleanup-vrf",
		TableID:    30,
		Interfaces: []string{},
		LeakRoutes: []routing.RouteLeak{
			{
				Destinations: []string{"10.0.0.0/24"},
			},
		},
	}

	err := sync.SyncVRFPolicies(vrf)
	if err != nil {
		t.Fatalf("SyncVRFPolicies failed: %v", err)
	}

	// The stale route should have been removed
	if _, exists := client.vrfRoutes[30]["192.168.99.0/24"]; exists {
		t.Error("Stale route 192.168.99.0/24 was not removed")
	}

	// The desired route should exist
	if _, exists := client.vrfRoutes[30]["10.0.0.0/24"]; !exists {
		t.Error("Desired route 10.0.0.0/24 was not added")
	}
}

func TestSyncVRFPolicies_NoRoutes(t *testing.T) {
	client := newTestCiliumClient()
	sync := &realCiliumSynchronizer{client: client}

	vrf := routing.VRF{
		Name:       "no-routes-vrf",
		TableID:    40,
		Interfaces: []string{"eth0", "eth1", "eth2"},
		LeakRoutes: []routing.RouteLeak{},
	}

	err := sync.SyncVRFPolicies(vrf)
	if err != nil {
		t.Fatalf("SyncVRFPolicies with no routes failed: %v", err)
	}

	// No routes should be added
	if len(client.vrfRouteCalls) != 0 {
		t.Errorf("Expected 0 route calls, got %d", len(client.vrfRouteCalls))
	}

	// But policies should still be applied for interfaces
	if len(client.policies) != 3 {
		t.Errorf("Expected 3 policies (one per interface), got %d", len(client.policies))
	}
}

func TestSyncVRFPolicies_InvalidTableID(t *testing.T) {
	client := newTestCiliumClient()
	sync := &realCiliumSynchronizer{client: client}

	// TableID 0 is invalid for custom tables
	vrf := routing.VRF{
		Name:    "bad-table",
		TableID: 0, // Will be resolved via name hash, which should be valid
	}

	// This should still work because vrfNameToTableID maps to 1-252
	err := sync.SyncVRFPolicies(vrf)
	if err != nil {
		t.Fatalf("SyncVRFPolicies should succeed with name-derived table ID: %v", err)
	}
}

func TestSyncVRFPolicies_CiliumClientError(t *testing.T) {
	client := newTestCiliumClient()
	client.shouldError = true
	sync := &realCiliumSynchronizer{client: client}

	vrf := routing.VRF{
		Name:       "error-vrf",
		TableID:    10,
		Interfaces: []string{"eth0"},
		LeakRoutes: []routing.RouteLeak{
			{Destinations: []string{"10.0.0.0/24"}},
		},
	}

	err := sync.SyncVRFPolicies(vrf)
	if err == nil {
		t.Fatal("SyncVRFPolicies should return error when Cilium client fails")
	}
}

func TestSyncVRFPolicies_InvalidDestination(t *testing.T) {
	client := newTestCiliumClient()
	sync := &realCiliumSynchronizer{client: client}

	vrf := routing.VRF{
		Name:    "bad-dest-vrf",
		TableID: 10,
		LeakRoutes: []routing.RouteLeak{
			{Destinations: []string{"not-a-cidr", "10.0.0.0/24"}},
		},
	}

	// Should succeed, skipping the invalid destination with a warning
	err := sync.SyncVRFPolicies(vrf)
	if err != nil {
		t.Fatalf("SyncVRFPolicies should skip invalid destinations: %v", err)
	}

	// Only the valid destination should be added
	if len(client.vrfRouteCalls) != 1 {
		t.Errorf("Expected 1 VRF route call (valid dest only), got %d", len(client.vrfRouteCalls))
	}
}

// --- Route conversion tests ---

func TestRoutingToCiliumRoute(t *testing.T) {
	route := routing.Route{
		Destination: "10.0.0.0/24",
		NextHops: []routing.NextHop{
			{Address: "192.168.1.1", Interface: "eth0"},
		},
		Metric:   100,
		Table:    "42",
		Protocol: "static",
		VRF:      "test-vrf",
	}

	cRoute, err := routingToCiliumRoute(route)
	if err != nil {
		t.Fatalf("routingToCiliumRoute failed: %v", err)
	}

	if cRoute.Destination.String() != "10.0.0.0/24" {
		t.Errorf("Expected destination 10.0.0.0/24, got %s", cRoute.Destination.String())
	}
	if cRoute.Gateway.String() != "192.168.1.1" {
		t.Errorf("Expected gateway 192.168.1.1, got %s", cRoute.Gateway.String())
	}
	if cRoute.OutputIface != "eth0" {
		t.Errorf("Expected interface eth0, got %s", cRoute.OutputIface)
	}
	if cRoute.Priority != 100 {
		t.Errorf("Expected priority 100, got %d", cRoute.Priority)
	}
	if cRoute.Table != 42 {
		t.Errorf("Expected table 42, got %d", cRoute.Table)
	}
	if cRoute.VRF != "test-vrf" {
		t.Errorf("Expected VRF test-vrf, got %s", cRoute.VRF)
	}
}

func TestCiliumToRoutingRoute(t *testing.T) {
	_, dest, _ := net.ParseCIDR("10.0.0.0/24")
	gw := net.ParseIP("192.168.1.1")

	cRoute := cilium.Route{
		Destination: dest,
		Gateway:     gw,
		OutputIface: "eth0",
		Priority:    100,
		Table:       42,
		Type:        "static",
		VRF:         "vrf-1",
	}

	route := ciliumToRoutingRoute(cRoute)
	if route.Destination != "10.0.0.0/24" {
		t.Errorf("Expected destination 10.0.0.0/24, got %s", route.Destination)
	}
	if route.Table != "42" {
		t.Errorf("Expected table '42', got %s", route.Table)
	}
	if route.VRF != "vrf-1" {
		t.Errorf("Expected VRF vrf-1, got %s", route.VRF)
	}
}

// --- vrfNameToTableID tests ---

func TestVrfNameToTableID_Range(t *testing.T) {
	names := []string{
		"", "a", "production", "staging", "vrf-management",
		"very-long-name-that-exceeds-normal-length-limits-for-testing",
	}
	for _, name := range names {
		id := vrfNameToTableID(name)
		if id < 1 || id > 252 {
			t.Errorf("vrfNameToTableID(%q) = %d, out of range 1-252", name, id)
		}
	}
}

func TestVrfNameToTableID_Deterministic(t *testing.T) {
	name := "my-vrf"
	id1 := vrfNameToTableID(name)
	id2 := vrfNameToTableID(name)
	if id1 != id2 {
		t.Errorf("vrfNameToTableID(%q) not deterministic: %d != %d", name, id1, id2)
	}
}

// --- SyncRoute and RemoveRoute integration ---

func TestRealCiliumSynchronizer_SyncRoute(t *testing.T) {
	client := newTestCiliumClient()
	sync := &realCiliumSynchronizer{client: client}

	route := routing.Route{
		Destination: "10.0.0.0/24",
		NextHops:    []routing.NextHop{{Address: "192.168.1.1", Interface: "eth0"}},
		Metric:      100,
		Table:       "main",
		VRF:         "",
	}

	if err := sync.SyncRoute(route); err != nil {
		t.Fatalf("SyncRoute failed: %v", err)
	}

	if len(client.routes) != 1 {
		t.Errorf("Expected 1 route, got %d", len(client.routes))
	}
}

func TestRealCiliumSynchronizer_RemoveRoute(t *testing.T) {
	client := newTestCiliumClient()
	sync := &realCiliumSynchronizer{client: client}

	// Add a route first
	route := routing.Route{
		Destination: "10.0.0.0/24",
		NextHops:    []routing.NextHop{{Address: "192.168.1.1"}},
		Table:       "main",
	}
	if err := sync.SyncRoute(route); err != nil {
		t.Fatalf("SyncRoute failed: %v", err)
	}

	// Now remove it
	params := routing.RouteParams{Table: "main", VRF: ""}
	if err := sync.RemoveRoute("10.0.0.0/24", params); err != nil {
		t.Fatalf("RemoveRoute failed: %v", err)
	}

	if len(client.routes) != 0 {
		t.Errorf("Expected 0 routes after removal, got %d", len(client.routes))
	}
}

// --- Policy ordering test ---

func TestSyncVRFPolicies_InterfaceOrdering(t *testing.T) {
	client := newTestCiliumClient()
	sync := &realCiliumSynchronizer{client: client}

	// Provide interfaces in unsorted order
	vrf := routing.VRF{
		Name:       "ordered-vrf",
		TableID:    15,
		Interfaces: []string{"eth2", "eth0", "eth1"},
		LeakRoutes: []routing.RouteLeak{},
	}

	if err := sync.SyncVRFPolicies(vrf); err != nil {
		t.Fatalf("SyncVRFPolicies failed: %v", err)
	}

	// Verify policies are created for sorted interface names
	expectedNames := []string{
		"vrf-ordered-vrf-iface-eth0",
		"vrf-ordered-vrf-iface-eth1",
		"vrf-ordered-vrf-iface-eth2",
	}

	for _, name := range expectedNames {
		if _, exists := client.policies[name]; !exists {
			t.Errorf("Expected policy %s to exist", name)
		}
	}
}
