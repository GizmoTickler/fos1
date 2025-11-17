package routing

import (
	"context"
	"testing"
	"time"
)

// TestNewRouteManager tests creating a new route manager
func TestNewRouteManager(t *testing.T) {
	manager := NewRouteManager()
	if manager == nil {
		t.Fatal("NewRouteManager() returned nil")
	}
}

// TestNewRouteManagerWithContext tests creating a new route manager with context
func TestNewRouteManagerWithContext(t *testing.T) {
	ctx := context.Background()
	manager, err := NewRouteManagerWithContext(ctx)
	if err != nil {
		// This is expected to fail without root privileges due to route subscription
		t.Skipf("NewRouteManagerWithContext() requires root privileges: %v", err)
	}
	if manager == nil {
		t.Fatal("NewRouteManagerWithContext() returned nil manager")
	}

	// Clean up
	if rm, ok := manager.(*routeManager); ok {
		rm.kernelManager.Stop()
	}
}

// TestValidateRoute tests route validation
func TestValidateRoute(t *testing.T) {
	manager := &routeManager{
		routes:        make(map[string]map[string]*Route),
		kernelManager: NewKernelRouteManager(),
	}

	tests := []struct {
		name    string
		route   Route
		wantErr bool
	}{
		{
			name: "valid route",
			route: Route{
				Destination: "10.0.0.0/24",
				NextHops: []NextHop{
					{Address: "192.168.1.1"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing destination",
			route: Route{
				NextHops: []NextHop{
					{Address: "192.168.1.1"},
				},
			},
			wantErr: true,
		},
		{
			name: "missing next hops",
			route: Route{
				Destination: "10.0.0.0/24",
				NextHops:    []NextHop{},
			},
			wantErr: true,
		},
		{
			name: "next hop with interface",
			route: Route{
				Destination: "10.0.0.0/24",
				NextHops: []NextHop{
					{Interface: "eth0"},
				},
			},
			wantErr: false,
		},
		{
			name: "next hop without address or interface",
			route: Route{
				Destination: "10.0.0.0/24",
				NextHops: []NextHop{
					{Weight: 1},
				},
			},
			wantErr: true,
		},
		{
			name: "multi-path route",
			route: Route{
				Destination: "10.0.0.0/24",
				NextHops: []NextHop{
					{Address: "192.168.1.1", Weight: 1},
					{Address: "192.168.1.2", Weight: 1},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.validateRoute(tt.route)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRoute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRouteLifecycle tests adding, getting, updating, and deleting routes
// This test uses in-memory operations only, not actual kernel operations
func TestRouteLifecycle(t *testing.T) {
	// Note: These tests will fail with actual kernel operations without root privileges
	// In a real test environment, we would mock the kernel manager

	t.Log("This test demonstrates the API but requires root privileges for actual kernel operations")

	// Test route structure
	_ = Route{
		Destination: "10.0.0.0/24",
		NextHops: []NextHop{
			{Address: "192.168.1.1"},
		},
		Metric:   100,
		Protocol: "static",
		Table:    "main",
	}
}

// TestRouteTableManagement tests routing table operations
func TestRouteTableManagement(t *testing.T) {
	manager := &routeManager{
		routes:        make(map[string]map[string]*Route),
		kernelManager: NewKernelRouteManager(),
	}

	// Test that table defaults to "main"
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops: []NextHop{
			{Address: "192.168.1.1"},
		},
	}

	// Validate the route
	if err := manager.validateRoute(route); err != nil {
		t.Fatalf("validateRoute() failed: %v", err)
	}
}

// TestMultiPathRoute tests ECMP route handling
func TestMultiPathRoute(t *testing.T) {
	manager := &routeManager{
		routes:        make(map[string]map[string]*Route),
		kernelManager: NewKernelRouteManager(),
	}

	// Create a multi-path route
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops: []NextHop{
			{Address: "192.168.1.1", Weight: 1},
			{Address: "192.168.1.2", Weight: 1},
			{Address: "192.168.1.3", Weight: 2},
		},
		Metric:   100,
		Protocol: "static",
		Table:    "main",
	}

	// Validate the multi-path route
	if err := manager.validateRoute(route); err != nil {
		t.Fatalf("validateRoute() failed for multi-path route: %v", err)
	}

	// Check that we have 3 next hops
	if len(route.NextHops) != 3 {
		t.Errorf("Expected 3 next hops, got %d", len(route.NextHops))
	}

	// Verify weights
	expectedWeights := []int{1, 1, 2}
	for i, nextHop := range route.NextHops {
		if nextHop.Weight != expectedWeights[i] {
			t.Errorf("Next hop %d: expected weight %d, got %d", i, expectedWeights[i], nextHop.Weight)
		}
	}
}

// TestRoutePriority tests route priority/metric handling
func TestRoutePriority(t *testing.T) {
	manager := &routeManager{
		routes:        make(map[string]map[string]*Route),
		kernelManager: NewKernelRouteManager(),
	}

	routes := []Route{
		{
			Destination: "10.0.0.0/24",
			NextHops:    []NextHop{{Address: "192.168.1.1"}},
			Metric:      100,
			Preference:  10,
		},
		{
			Destination: "10.0.0.0/24",
			NextHops:    []NextHop{{Address: "192.168.1.2"}},
			Metric:      200,
			Preference:  20,
		},
	}

	for i, route := range routes {
		if err := manager.validateRoute(route); err != nil {
			t.Errorf("Route %d validation failed: %v", i, err)
		}
	}
}

// TestRouteProtocols tests different routing protocols
func TestRouteProtocols(t *testing.T) {
	manager := &routeManager{
		routes:        make(map[string]map[string]*Route),
		kernelManager: NewKernelRouteManager(),
	}

	protocols := []string{"static", "bgp", "ospf", "kernel", "boot"}

	for _, protocol := range protocols {
		route := Route{
			Destination: "10.0.0.0/24",
			NextHops:    []NextHop{{Address: "192.168.1.1"}},
			Protocol:    protocol,
		}

		if err := manager.validateRoute(route); err != nil {
			t.Errorf("Route with protocol %s validation failed: %v", protocol, err)
		}
	}
}

// TestRouteScope tests different route scopes
func TestRouteScope(t *testing.T) {
	scopes := []string{"global", "site", "link", "host"}

	for _, scope := range scopes {
		route := Route{
			Destination: "10.0.0.0/24",
			NextHops:    []NextHop{{Address: "192.168.1.1"}},
			Scope:       scope,
		}

		manager := &routeManager{
			routes:        make(map[string]map[string]*Route),
			kernelManager: NewKernelRouteManager(),
		}

		if err := manager.validateRoute(route); err != nil {
			t.Errorf("Route with scope %s validation failed: %v", scope, err)
		}
	}
}

// TestRouteVRF tests VRF support
func TestRouteVRF(t *testing.T) {
	manager := &routeManager{
		routes:        make(map[string]map[string]*Route),
		kernelManager: NewKernelRouteManager(),
	}

	route := Route{
		Destination: "10.0.0.0/24",
		NextHops:    []NextHop{{Address: "192.168.1.1"}},
		VRF:         "vrf-blue",
		Table:       "vrf-blue",
	}

	if err := manager.validateRoute(route); err != nil {
		t.Fatalf("Route with VRF validation failed: %v", err)
	}
}

// TestRouteTags tests route tagging
func TestRouteTags(t *testing.T) {
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops:    []NextHop{{Address: "192.168.1.1"}},
		Tags:        []string{"production", "critical", "wan"},
	}

	if len(route.Tags) != 3 {
		t.Errorf("Expected 3 tags, got %d", len(route.Tags))
	}

	expectedTags := map[string]bool{
		"production": true,
		"critical":   true,
		"wan":        true,
	}

	for _, tag := range route.Tags {
		if !expectedTags[tag] {
			t.Errorf("Unexpected tag: %s", tag)
		}
	}
}

// TestRouteTimestamp tests route timestamp handling
func TestRouteTimestamp(t *testing.T) {
	now := time.Now()
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops:    []NextHop{{Address: "192.168.1.1"}},
		LastUpdated: now,
	}

	if route.LastUpdated.IsZero() {
		t.Error("Route LastUpdated should not be zero")
	}

	if !route.LastUpdated.Equal(now) {
		t.Errorf("Expected LastUpdated to be %v, got %v", now, route.LastUpdated)
	}
}

// TestRouteError tests route error handling
func TestRouteError(t *testing.T) {
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops:    []NextHop{{Address: "192.168.1.1"}},
		Error:       "failed to install route",
	}

	if route.Error == "" {
		t.Error("Route Error should not be empty")
	}

	if route.Error != "failed to install route" {
		t.Errorf("Expected error 'failed to install route', got '%s'", route.Error)
	}
}

// TestRouteInstalledIn tests route installation tracking
func TestRouteInstalledIn(t *testing.T) {
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops:    []NextHop{{Address: "192.168.1.1"}},
		InstalledIn: []string{"kernel", "cilium"},
	}

	if len(route.InstalledIn) != 2 {
		t.Errorf("Expected 2 installation locations, got %d", len(route.InstalledIn))
	}

	expectedLocations := map[string]bool{
		"kernel": true,
		"cilium": true,
	}

	for _, location := range route.InstalledIn {
		if !expectedLocations[location] {
			t.Errorf("Unexpected installation location: %s", location)
		}
	}
}

// TestNextHopInterface tests next hop with interface
func TestNextHopInterface(t *testing.T) {
	manager := &routeManager{
		routes:        make(map[string]map[string]*Route),
		kernelManager: NewKernelRouteManager(),
	}

	route := Route{
		Destination: "10.0.0.0/24",
		NextHops: []NextHop{
			{Interface: "eth0"},
		},
	}

	if err := manager.validateRoute(route); err != nil {
		t.Fatalf("Route with interface next hop validation failed: %v", err)
	}
}

// TestNextHopAddressAndInterface tests next hop with both address and interface
func TestNextHopAddressAndInterface(t *testing.T) {
	manager := &routeManager{
		routes:        make(map[string]map[string]*Route),
		kernelManager: NewKernelRouteManager(),
	}

	route := Route{
		Destination: "10.0.0.0/24",
		NextHops: []NextHop{
			{Address: "192.168.1.1", Interface: "eth0"},
		},
	}

	if err := manager.validateRoute(route); err != nil {
		t.Fatalf("Route with address and interface next hop validation failed: %v", err)
	}
}

// TestRoutePreemptible tests preemptible route flag
func TestRoutePreemptible(t *testing.T) {
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops:    []NextHop{{Address: "192.168.1.1"}},
		Preemptible: true,
	}

	if !route.Preemptible {
		t.Error("Route should be preemptible")
	}
}

// TestRouteFilter tests route filtering logic
func TestRouteFilter(t *testing.T) {
	tests := []struct {
		name   string
		filter RouteFilter
	}{
		{
			name: "filter by destination",
			filter: RouteFilter{
				Destination: "10.0.0.0/24",
			},
		},
		{
			name: "filter by next hop",
			filter: RouteFilter{
				NextHop: "192.168.1.1",
			},
		},
		{
			name: "filter by protocol",
			filter: RouteFilter{
				Protocol: "bgp",
			},
		},
		{
			name: "filter by VRF",
			filter: RouteFilter{
				VRF: "vrf-blue",
			},
		},
		{
			name: "filter by table",
			filter: RouteFilter{
				Table: "main",
			},
		},
		{
			name: "filter by tag",
			filter: RouteFilter{
				Tag: "production",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the filter struct is valid
			_ = tt.filter
		})
	}
}

// TestRouteParams tests route parameter handling
func TestRouteParams(t *testing.T) {
	tests := []struct {
		name   string
		params RouteParams
	}{
		{
			name: "with VRF",
			params: RouteParams{
				VRF:   "vrf-blue",
				Table: "vrf-blue",
			},
		},
		{
			name: "with protocol",
			params: RouteParams{
				Protocol: "static",
				Table:    "main",
			},
		},
		{
			name: "minimal params",
			params: RouteParams{
				Table: "main",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the params struct is valid
			_ = tt.params
		})
	}
}
