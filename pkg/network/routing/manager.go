package routing

import (
	"fmt"
	"sync"
	"time"
)

// routeManager implements the RouteManager interface
type routeManager struct {
	mutex   sync.RWMutex
	routes  map[string]map[string]*Route // table -> destination -> route
	
	// Would normally have actual routing configuration dependencies here
	// netlink library, FRRouting client, etc.
}

// NewRouteManager creates a new instance of the route manager
func NewRouteManager() RouteManager {
	return &routeManager{
		routes: make(map[string]map[string]*Route),
	}
}

// AddRoute adds a new route
func (m *routeManager) AddRoute(route Route) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Create table if it doesn't exist
	tableName := route.Table
	if tableName == "" {
		tableName = "main"
	}
	
	if _, exists := m.routes[tableName]; !exists {
		m.routes[tableName] = make(map[string]*Route)
	}
	
	// Check if route already exists
	if _, exists := m.routes[tableName][route.Destination]; exists {
		return fmt.Errorf("route to %s already exists in table %s", route.Destination, tableName)
	}
	
	// This is a placeholder implementation
	// In a real implementation, we would:
	// 1. Validate the route
	// 2. Add the route to the kernel routing table
	// 3. If in a VRF, add to the VRF's routing table
	// 4. Synchronize with Cilium
	
	// Clone the route to avoid external modification
	newRoute := route
	newRoute.InstalledIn = []string{"kernel"} // Would actually check
	newRoute.LastUpdated = time.Now()
	
	// Store the route
	m.routes[tableName][route.Destination] = &newRoute
	
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
	
	// Check if table exists
	if _, exists := m.routes[tableName]; !exists {
		return fmt.Errorf("routing table %s does not exist", tableName)
	}
	
	// Check if route exists
	if _, exists := m.routes[tableName][destination]; !exists {
		return fmt.Errorf("route to %s does not exist in table %s", destination, tableName)
	}
	
	// This is a placeholder implementation
	// In a real implementation, we would:
	// 1. Remove the route from the kernel routing table
	// 2. If in a VRF, remove from the VRF's routing table
	// 3. Synchronize with Cilium
	
	// Remove the route
	delete(m.routes[tableName], destination)
	
	return nil
}

// GetRoute retrieves a route
func (m *routeManager) GetRoute(destination string, routeParams RouteParams) (*Route, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Determine table
	tableName := routeParams.Table
	if tableName == "" {
		tableName = "main"
	}
	
	// Check if table exists
	if _, exists := m.routes[tableName]; !exists {
		return nil, fmt.Errorf("routing table %s does not exist", tableName)
	}
	
	// Check if route exists
	route, exists := m.routes[tableName][destination]
	if !exists {
		return nil, fmt.Errorf("route to %s does not exist in table %s", destination, tableName)
	}
	
	// Clone the route to avoid external modification
	result := *route
	
	return &result, nil
}

// ListRoutes lists all routes, optionally filtered
func (m *routeManager) ListRoutes(filter RouteFilter) ([]*Route, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	var routes []*Route
	
	// Determine if we're filtering by table
	tableFilter := filter.Table
	if tableFilter == "" {
		// No table filter, search all tables
		for _, table := range m.routes {
			for _, route := range table {
				if m.routeMatchesFilter(route, filter) {
					// Clone the route to avoid external modification
					result := *route
					routes = append(routes, &result)
				}
			}
		}
	} else {
		// Table filter specified
		if table, exists := m.routes[tableFilter]; exists {
			for _, route := range table {
				if m.routeMatchesFilter(route, filter) {
					// Clone the route to avoid external modification
					result := *route
					routes = append(routes, &result)
				}
			}
		}
	}
	
	return routes, nil
}

// routeMatchesFilter checks if a route matches the given filter
func (m *routeManager) routeMatchesFilter(route *Route, filter RouteFilter) bool {
	// If any filter criteria doesn't match, return false
	
	// Destination filter
	if filter.Destination != "" && route.Destination != filter.Destination {
		return false
	}
	
	// NextHop filter
	if filter.NextHop != "" {
		match := false
		for _, nextHop := range route.NextHops {
			if nextHop.Address == filter.NextHop {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	
	// Protocol filter
	if filter.Protocol != "" && route.Protocol != filter.Protocol {
		return false
	}
	
	// VRF filter
	if filter.VRF != "" && route.VRF != filter.VRF {
		return false
	}
	
	// Tag filter
	if filter.Tag != "" {
		match := false
		for _, tag := range route.Tags {
			if tag == filter.Tag {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	
	// All filters passed
	return true
}

// UpdateRoute updates an existing route
func (m *routeManager) UpdateRoute(destination string, routeParams RouteParams, newRoute Route) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Determine table
	tableName := routeParams.Table
	if tableName == "" {
		tableName = "main"
	}
	
	// Check if table exists
	if _, exists := m.routes[tableName]; !exists {
		return fmt.Errorf("routing table %s does not exist", tableName)
	}
	
	// Check if route exists
	_, exists := m.routes[tableName][destination]
	if !exists {
		return fmt.Errorf("route to %s does not exist in table %s", destination, tableName)
	}
	
	// This is a placeholder implementation
	// In a real implementation, we would:
	// 1. Validate the route
	// 2. Update the route in the kernel routing table
	// 3. If in a VRF, update in the VRF's routing table
	// 4. Synchronize with Cilium
	
	// Update the route
	updatedRoute := newRoute
	updatedRoute.InstalledIn = []string{"kernel"} // Would actually check
	updatedRoute.LastUpdated = time.Now()
	
	// Store the updated route
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
	
	// Check if table exists
	table, exists := m.routes[tableName]
	if !exists {
		return nil, fmt.Errorf("routing table %s does not exist", tableName)
	}
	
	var routes []*Route
	
	// If VRF is specified, filter by VRF
	if vrf != "" {
		for _, route := range table {
			if route.VRF == vrf {
				// Clone the route to avoid external modification
				result := *route
				routes = append(routes, &result)
			}
		}
	} else {
		// No VRF filter, return all routes in the table
		for _, route := range table {
			// Clone the route to avoid external modification
			result := *route
			routes = append(routes, &result)
		}
	}
	
	return routes, nil
}