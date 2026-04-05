//go:build !linux

package routing

import (
	"context"
	"time"
)

type routeManager struct {
	routes map[string]map[string]*Route
}

// NewRouteManager creates a new instance of the route manager.
func NewRouteManager() RouteManager {
	return &routeManager{
		routes: make(map[string]map[string]*Route),
	}
}

// NewRouteManagerWithContext creates a new instance of the route manager with a context.
func NewRouteManagerWithContext(ctx context.Context) (RouteManager, error) {
	return NewRouteManager(), nil
}

func (m *routeManager) AddRoute(route Route) error {
	tableName := route.Table
	if tableName == "" {
		tableName = "main"
	}
	if _, exists := m.routes[tableName]; !exists {
		m.routes[tableName] = make(map[string]*Route)
	}
	newRoute := route
	newRoute.InstalledIn = []string{"stub"}
	newRoute.LastUpdated = time.Now()
	m.routes[tableName][route.Destination] = &newRoute
	return nil
}

func (m *routeManager) DeleteRoute(destination string, params RouteParams) error {
	tableName := params.Table
	if tableName == "" {
		tableName = "main"
	}
	if table, exists := m.routes[tableName]; exists {
		delete(table, destination)
	}
	return nil
}

func (m *routeManager) GetRoute(destination string, params RouteParams) (*Route, error) {
	tableName := params.Table
	if tableName == "" {
		tableName = "main"
	}
	if table, exists := m.routes[tableName]; exists {
		if route, exists := table[destination]; exists {
			cloned := *route
			return &cloned, nil
		}
	}
	return nil, nil
}

func (m *routeManager) ListRoutes(filter RouteFilter) ([]*Route, error) {
	routes := make([]*Route, 0)
	for _, table := range m.routes {
		for _, route := range table {
			cloned := *route
			routes = append(routes, &cloned)
		}
	}
	return routes, nil
}

func (m *routeManager) UpdateRoute(destination string, params RouteParams, newRoute Route) error {
	if err := m.DeleteRoute(destination, params); err != nil {
		return err
	}
	return m.AddRoute(newRoute)
}

func (m *routeManager) GetRoutingTable(tableName string, vrf string) ([]*Route, error) {
	if tableName == "" {
		tableName = "main"
	}
	routes := make([]*Route, 0)
	if table, exists := m.routes[tableName]; exists {
		for _, route := range table {
			if vrf == "" || route.VRF == vrf {
				cloned := *route
				routes = append(routes, &cloned)
			}
		}
	}
	return routes, nil
}
