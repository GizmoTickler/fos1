// +build integration

package routing

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// TestIntegrationRouteAddDelete tests adding and deleting routes in the kernel
// This test requires root privileges
func TestIntegrationRouteAddDelete(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	ctx := context.Background()
	kernelManager := NewKernelRouteManager()

	// Start the kernel manager
	if err := kernelManager.Start(ctx); err != nil {
		t.Fatalf("Failed to start kernel manager: %v", err)
	}
	defer kernelManager.Stop()

	// Create a dummy interface for testing
	dummyName := fmt.Sprintf("test-route-%d", time.Now().Unix())
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: dummyName,
		},
	}

	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("Failed to create dummy interface: %v", err)
	}
	defer netlink.LinkDel(dummy)

	// Set the interface up
	if err := netlink.LinkSetUp(dummy); err != nil {
		t.Fatalf("Failed to set interface up: %v", err)
	}

	// Add an IP address to the interface
	addr, _ := netlink.ParseAddr("192.168.100.1/24")
	if err := netlink.AddrAdd(dummy, addr); err != nil {
		t.Fatalf("Failed to add address: %v", err)
	}

	// Create a route
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops: []NextHop{
			{
				Address:   "192.168.100.254",
				Interface: dummyName,
			},
		},
		Metric:   100,
		Protocol: "static",
		Table:    "main",
	}

	// Add the route
	if err := kernelManager.AddRoute(route); err != nil {
		t.Fatalf("Failed to add route: %v", err)
	}

	// Verify the route was added
	getRoute, err := kernelManager.GetRoute(route.Destination, RouteParams{Table: "main"})
	if err != nil {
		t.Fatalf("Failed to get route: %v", err)
	}

	if getRoute.Destination != route.Destination {
		t.Errorf("Expected destination %s, got %s", route.Destination, getRoute.Destination)
	}

	// Delete the route
	if err := kernelManager.DeleteRoute(route.Destination, RouteParams{Table: "main"}); err != nil {
		t.Fatalf("Failed to delete route: %v", err)
	}

	// Verify the route was deleted (this should fail)
	_, err = kernelManager.GetRoute(route.Destination, RouteParams{Table: "main"})
	if err == nil {
		t.Error("Route should have been deleted")
	}
}

// TestIntegrationECMPRoute tests multi-path (ECMP) routing
// This test requires root privileges
func TestIntegrationECMPRoute(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	ctx := context.Background()
	kernelManager := NewKernelRouteManager()

	// Start the kernel manager
	if err := kernelManager.Start(ctx); err != nil {
		t.Fatalf("Failed to start kernel manager: %v", err)
	}
	defer kernelManager.Stop()

	// Create dummy interfaces for testing
	dummy1Name := fmt.Sprintf("test-route1-%d", time.Now().Unix())
	dummy1 := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: dummy1Name,
		},
	}

	if err := netlink.LinkAdd(dummy1); err != nil {
		t.Fatalf("Failed to create dummy interface 1: %v", err)
	}
	defer netlink.LinkDel(dummy1)

	if err := netlink.LinkSetUp(dummy1); err != nil {
		t.Fatalf("Failed to set interface 1 up: %v", err)
	}

	addr1, _ := netlink.ParseAddr("192.168.100.1/24")
	if err := netlink.AddrAdd(dummy1, addr1); err != nil {
		t.Fatalf("Failed to add address to interface 1: %v", err)
	}

	dummy2Name := fmt.Sprintf("test-route2-%d", time.Now().Unix())
	dummy2 := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: dummy2Name,
		},
	}

	if err := netlink.LinkAdd(dummy2); err != nil {
		t.Fatalf("Failed to create dummy interface 2: %v", err)
	}
	defer netlink.LinkDel(dummy2)

	if err := netlink.LinkSetUp(dummy2); err != nil {
		t.Fatalf("Failed to set interface 2 up: %v", err)
	}

	addr2, _ := netlink.ParseAddr("192.168.101.1/24")
	if err := netlink.AddrAdd(dummy2, addr2); err != nil {
		t.Fatalf("Failed to add address to interface 2: %v", err)
	}

	// Create an ECMP route with two next hops
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops: []NextHop{
			{
				Address:   "192.168.100.254",
				Interface: dummy1Name,
				Weight:    1,
			},
			{
				Address:   "192.168.101.254",
				Interface: dummy2Name,
				Weight:    1,
			},
		},
		Metric:   100,
		Protocol: "static",
		Table:    "main",
	}

	// Add the ECMP route
	if err := kernelManager.AddRoute(route); err != nil {
		t.Fatalf("Failed to add ECMP route: %v", err)
	}

	// Clean up
	if err := kernelManager.DeleteRoute(route.Destination, RouteParams{Table: "main"}); err != nil {
		t.Fatalf("Failed to delete ECMP route: %v", err)
	}
}

// TestIntegrationListRoutes tests listing routes from the kernel
// This test requires root privileges
func TestIntegrationListRoutes(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	ctx := context.Background()
	kernelManager := NewKernelRouteManager()

	// Start the kernel manager
	if err := kernelManager.Start(ctx); err != nil {
		t.Fatalf("Failed to start kernel manager: %v", err)
	}
	defer kernelManager.Stop()

	// List all routes in the main table
	routes, err := kernelManager.ListRoutes(RouteFilter{Table: "main"})
	if err != nil {
		t.Fatalf("Failed to list routes: %v", err)
	}

	t.Logf("Found %d routes in main table", len(routes))

	// There should be at least some routes (e.g., local routes)
	if len(routes) == 0 {
		t.Error("Expected at least some routes in the main table")
	}
}

// TestIntegrationGetRoutingTable tests getting the entire routing table
// This test requires root privileges
func TestIntegrationGetRoutingTable(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	ctx := context.Background()
	kernelManager := NewKernelRouteManager()

	// Start the kernel manager
	if err := kernelManager.Start(ctx); err != nil {
		t.Fatalf("Failed to start kernel manager: %v", err)
	}
	defer kernelManager.Stop()

	// Get all routes in the main table
	routes, err := kernelManager.GetRoutingTable("main", "")
	if err != nil {
		t.Fatalf("Failed to get routing table: %v", err)
	}

	t.Logf("Found %d routes in main routing table", len(routes))

	// There should be at least some routes
	if len(routes) == 0 {
		t.Error("Expected at least some routes in the main routing table")
	}

	// Verify each route has required fields
	for i, route := range routes {
		if route.Destination == "" {
			t.Errorf("Route %d has empty destination", i)
		}
		if route.Table == "" {
			t.Errorf("Route %d has empty table", i)
		}
	}
}

// TestIntegrationRouteUpdate tests updating a route
// This test requires root privileges
func TestIntegrationRouteUpdate(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	ctx := context.Background()
	kernelManager := NewKernelRouteManager()

	// Start the kernel manager
	if err := kernelManager.Start(ctx); err != nil {
		t.Fatalf("Failed to start kernel manager: %v", err)
	}
	defer kernelManager.Stop()

	// Create a dummy interface for testing
	dummyName := fmt.Sprintf("test-route-%d", time.Now().Unix())
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: dummyName,
		},
	}

	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("Failed to create dummy interface: %v", err)
	}
	defer netlink.LinkDel(dummy)

	if err := netlink.LinkSetUp(dummy); err != nil {
		t.Fatalf("Failed to set interface up: %v", err)
	}

	addr, _ := netlink.ParseAddr("192.168.100.1/24")
	if err := netlink.AddrAdd(dummy, addr); err != nil {
		t.Fatalf("Failed to add address: %v", err)
	}

	// Create initial route
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops: []NextHop{
			{
				Address:   "192.168.100.254",
				Interface: dummyName,
			},
		},
		Metric:   100,
		Protocol: "static",
		Table:    "main",
	}

	// Add the route
	if err := kernelManager.AddRoute(route); err != nil {
		t.Fatalf("Failed to add initial route: %v", err)
	}

	// Update the route with a different metric
	updatedRoute := route
	updatedRoute.Metric = 200

	// Delete and re-add (simulating an update)
	if err := kernelManager.DeleteRoute(route.Destination, RouteParams{Table: "main"}); err != nil {
		t.Fatalf("Failed to delete route for update: %v", err)
	}

	if err := kernelManager.AddRoute(updatedRoute); err != nil {
		t.Fatalf("Failed to add updated route: %v", err)
	}

	// Clean up
	if err := kernelManager.DeleteRoute(updatedRoute.Destination, RouteParams{Table: "main"}); err != nil {
		t.Fatalf("Failed to delete route: %v", err)
	}
}

// TestIntegrationRouteManagerWithContext tests the full route manager with context
// This test requires root privileges
func TestIntegrationRouteManagerWithContext(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	ctx := context.Background()
	manager, err := NewRouteManagerWithContext(ctx)
	if err != nil {
		t.Fatalf("Failed to create route manager: %v", err)
	}

	// Stop the kernel manager when done
	defer func() {
		if rm, ok := manager.(*routeManager); ok {
			rm.kernelManager.Stop()
		}
	}()

	// Create a dummy interface for testing
	dummyName := fmt.Sprintf("test-mgr-%d", time.Now().Unix())
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: dummyName,
		},
	}

	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("Failed to create dummy interface: %v", err)
	}
	defer netlink.LinkDel(dummy)

	if err := netlink.LinkSetUp(dummy); err != nil {
		t.Fatalf("Failed to set interface up: %v", err)
	}

	addr, _ := netlink.ParseAddr("192.168.100.1/24")
	if err := netlink.AddrAdd(dummy, addr); err != nil {
		t.Fatalf("Failed to add address: %v", err)
	}

	// Test AddRoute
	route := Route{
		Destination: "10.0.0.0/24",
		NextHops: []NextHop{
			{
				Address:   "192.168.100.254",
				Interface: dummyName,
			},
		},
		Metric:   100,
		Protocol: "static",
		Table:    "main",
	}

	if err := manager.AddRoute(route); err != nil {
		t.Fatalf("Failed to add route via manager: %v", err)
	}

	// Test GetRoute
	getRoute, err := manager.GetRoute(route.Destination, RouteParams{Table: "main"})
	if err != nil {
		t.Fatalf("Failed to get route via manager: %v", err)
	}

	if getRoute.Destination != route.Destination {
		t.Errorf("Expected destination %s, got %s", route.Destination, getRoute.Destination)
	}

	// Test ListRoutes
	routes, err := manager.ListRoutes(RouteFilter{Table: "main"})
	if err != nil {
		t.Fatalf("Failed to list routes via manager: %v", err)
	}

	if len(routes) == 0 {
		t.Error("Expected at least one route")
	}

	// Test DeleteRoute
	if err := manager.DeleteRoute(route.Destination, RouteParams{Table: "main"}); err != nil {
		t.Fatalf("Failed to delete route via manager: %v", err)
	}
}
