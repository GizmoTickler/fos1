package routing

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// routeManager implements the RouteManager interface
type routeManager struct {
	mutex         sync.RWMutex
	routes        map[string]map[string]*Route // table -> destination -> route (cache)
	kernelManager *KernelRouteManager
	ctx           context.Context
}

// NewRouteManager creates a new instance of the route manager
func NewRouteManager() RouteManager {
	return &routeManager{
		routes:        make(map[string]map[string]*Route),
		kernelManager: NewKernelRouteManager(),
		ctx:           context.Background(),
	}
}

// NewRouteManagerWithContext creates a new instance of the route manager with a context
func NewRouteManagerWithContext(ctx context.Context) (RouteManager, error) {
	kernelManager := NewKernelRouteManager()

	// Start the kernel manager to monitor route changes
	if err := kernelManager.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start kernel route manager: %w", err)
	}

	return &routeManager{
		routes:        make(map[string]map[string]*Route),
		kernelManager: kernelManager,
		ctx:           ctx,
	}, nil
}

// AddRoute adds a new route
func (m *routeManager) AddRoute(route Route) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Validate the route
	if err := m.validateRoute(route); err != nil {
		return fmt.Errorf("invalid route: %w", err)
	}

	// Create table if it doesn't exist
	tableName := route.Table
	if tableName == "" {
		tableName = "main"
	}

	if _, exists := m.routes[tableName]; !exists {
		m.routes[tableName] = make(map[string]*Route)
	}

	// Add the route to the kernel routing table
	if err := m.kernelManager.AddRoute(route); err != nil {
		return fmt.Errorf("failed to add route to kernel: %w", err)
	}

	// Clone the route to avoid external modification
	newRoute := route
	newRoute.InstalledIn = []string{"kernel"}
	newRoute.LastUpdated = time.Now()

	// Store the route in cache
	m.routes[tableName][route.Destination] = &newRoute

	return nil
}

// validateRoute validates a route before adding it
func (m *routeManager) validateRoute(route Route) error {
	if route.Destination == "" {
		return fmt.Errorf("destination is required")
	}

	if len(route.NextHops) == 0 {
		return fmt.Errorf("at least one next hop is required")
	}

	for i, nextHop := range route.NextHops {
		if nextHop.Address == "" && nextHop.Interface == "" {
			return fmt.Errorf("next hop %d must have either an address or interface", i)
		}
	}

	return nil
}

// DeleteRoute removes a route
func (m *routeManager) DeleteRoute(destination string, routeParams RouteParams) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Determine table
	tableName := routeParams.Table
	if tableName == "" {
		tableName = "main"
	}

	// Remove the route from the kernel routing table
	if err := m.kernelManager.DeleteRoute(destination, routeParams); err != nil {
		return fmt.Errorf("failed to delete route from kernel: %w", err)
	}

	// Remove the route from cache if it exists
	if table, exists := m.routes[tableName]; exists {
		delete(table, destination)
	}

	return nil
}

// GetRoute retrieves a route
func (m *routeManager) GetRoute(destination string, routeParams RouteParams) (*Route, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Get route from kernel
	route, err := m.kernelManager.GetRoute(destination, routeParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get route from kernel: %w", err)
	}

	return route, nil
}

// ListRoutes lists all routes, optionally filtered
func (m *routeManager) ListRoutes(filter RouteFilter) ([]*Route, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Get routes from kernel
	routes, err := m.kernelManager.ListRoutes(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes from kernel: %w", err)
	}

	return routes, nil
}


// UpdateRoute updates an existing route
func (m *routeManager) UpdateRoute(destination string, routeParams RouteParams, newRoute Route) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Validate the new route
	if err := m.validateRoute(newRoute); err != nil {
		return fmt.Errorf("invalid route: %w", err)
	}

	// Determine table
	tableName := routeParams.Table
	if tableName == "" {
		tableName = "main"
	}

	// Delete the old route from the kernel
	if err := m.kernelManager.DeleteRoute(destination, routeParams); err != nil {
		return fmt.Errorf("failed to delete old route from kernel: %w", err)
	}

	// Add the new route to the kernel
	if err := m.kernelManager.AddRoute(newRoute); err != nil {
		return fmt.Errorf("failed to add new route to kernel: %w", err)
	}

	// Update the route in cache
	updatedRoute := newRoute
	updatedRoute.InstalledIn = []string{"kernel"}
	updatedRoute.LastUpdated = time.Now()

	if _, exists := m.routes[tableName]; !exists {
		m.routes[tableName] = make(map[string]*Route)
	}
	m.routes[tableName][destination] = &updatedRoute

	return nil
}

// GetRoutingTable retrieves the entire routing table
func (m *routeManager) GetRoutingTable(tableName string, vrf string) ([]*Route, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Default to main table if not specified
	if tableName == "" {
		tableName = "main"
	}

	// Get routes from kernel
	routes, err := m.kernelManager.GetRoutingTable(tableName, vrf)
	if err != nil {
		return nil, fmt.Errorf("failed to get routing table from kernel: %w", err)
	}

	return routes, nil
}