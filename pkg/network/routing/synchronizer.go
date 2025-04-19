package routing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// RouteSynchronizer synchronizes routes between FRR, the kernel, and Cilium
type RouteSynchronizer struct {
	mutex            sync.RWMutex
	routeManager     RouteManager
	ciliumSynchronizer CiliumSynchronizer
	syncInterval     time.Duration
	stopCh           chan struct{}
}

// NewRouteSynchronizer creates a new route synchronizer
func NewRouteSynchronizer(
	routeManager RouteManager,
	ciliumSynchronizer CiliumSynchronizer,
	syncInterval time.Duration,
) *RouteSynchronizer {
	return &RouteSynchronizer{
		routeManager:      routeManager,
		ciliumSynchronizer: ciliumSynchronizer,
		syncInterval:      syncInterval,
		stopCh:            make(chan struct{}),
	}
}

// Start starts the route synchronizer
func (s *RouteSynchronizer) Start() {
	klog.Info("Starting route synchronizer")
	
	// Start a goroutine to periodically synchronize routes
	go s.syncRoutesLoop()
}

// Stop stops the route synchronizer
func (s *RouteSynchronizer) Stop() {
	klog.Info("Stopping route synchronizer")
	close(s.stopCh)
}

// syncRoutesLoop periodically synchronizes routes
func (s *RouteSynchronizer) syncRoutesLoop() {
	ticker := time.NewTicker(s.syncInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if err := s.SyncAllRoutes(); err != nil {
				klog.Errorf("Failed to synchronize routes: %v", err)
			}
		case <-s.stopCh:
			return
		}
	}
}

// SyncAllRoutes synchronizes all routes
func (s *RouteSynchronizer) SyncAllRoutes() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	klog.V(4).Info("Synchronizing all routes")
	
	// Get all routing tables
	tables, err := s.getRoutingTables()
	if err != nil {
		return fmt.Errorf("failed to get routing tables: %w", err)
	}
	
	// Synchronize each table
	for tableName, vrf := range tables {
		if err := s.syncRoutingTable(tableName, vrf); err != nil {
			klog.Errorf("Failed to synchronize routing table %s: %v", tableName, err)
		}
	}
	
	return nil
}

// SyncRoute synchronizes a single route
func (s *RouteSynchronizer) SyncRoute(route Route) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	klog.V(4).Infof("Synchronizing route to %s", route.Destination)
	
	// Add the route to the kernel
	if err := s.routeManager.AddRoute(route); err != nil {
		return fmt.Errorf("failed to add route to kernel: %w", err)
	}
	
	// Synchronize with Cilium
	if err := s.ciliumSynchronizer.SyncRoute(route); err != nil {
		return fmt.Errorf("failed to synchronize route with Cilium: %w", err)
	}
	
	return nil
}

// RemoveRoute removes a route
func (s *RouteSynchronizer) RemoveRoute(destination string, routeParams RouteParams) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	klog.V(4).Infof("Removing route to %s", destination)
	
	// Remove the route from the kernel
	if err := s.routeManager.DeleteRoute(destination, routeParams); err != nil {
		return fmt.Errorf("failed to remove route from kernel: %w", err)
	}
	
	// Remove from Cilium
	if err := s.ciliumSynchronizer.RemoveRoute(destination, routeParams); err != nil {
		return fmt.Errorf("failed to remove route from Cilium: %w", err)
	}
	
	return nil
}

// syncRoutingTable synchronizes a routing table
func (s *RouteSynchronizer) syncRoutingTable(tableName string, vrf string) error {
	klog.V(4).Infof("Synchronizing routing table %s for VRF %s", tableName, vrf)
	
	// Get routes from the kernel
	kernelRoutes, err := s.routeManager.GetRoutingTable(tableName, vrf)
	if err != nil {
		return fmt.Errorf("failed to get kernel routes: %w", err)
	}
	
	// Get routes from Cilium
	ciliumRoutes, err := s.ciliumSynchronizer.GetCiliumRoutes()
	if err != nil {
		return fmt.Errorf("failed to get Cilium routes: %w", err)
	}
	
	// Create maps for easier lookup
	kernelRouteMap := make(map[string]*Route)
	for _, route := range kernelRoutes {
		kernelRouteMap[route.Destination] = route
	}
	
	ciliumRouteMap := make(map[string]*Route)
	for _, route := range ciliumRoutes {
		ciliumRouteMap[route.Destination] = route
	}
	
	// Synchronize kernel routes to Cilium
	for _, route := range kernelRoutes {
		ciliumRoute, exists := ciliumRouteMap[route.Destination]
		if !exists || !routesEqual(route, ciliumRoute) {
			// Route doesn't exist in Cilium or is different, synchronize it
			if err := s.ciliumSynchronizer.SyncRoute(*route); err != nil {
				klog.Errorf("Failed to synchronize route to %s with Cilium: %v", route.Destination, err)
			}
		}
	}
	
	// Remove routes from Cilium that don't exist in the kernel
	for _, route := range ciliumRoutes {
		if route.Table != tableName || route.VRF != vrf {
			continue
		}
		
		_, exists := kernelRouteMap[route.Destination]
		if !exists {
			// Route exists in Cilium but not in the kernel, remove it
			routeParams := RouteParams{
				Table: tableName,
				VRF:   vrf,
			}
			if err := s.ciliumSynchronizer.RemoveRoute(route.Destination, routeParams); err != nil {
				klog.Errorf("Failed to remove route to %s from Cilium: %v", route.Destination, err)
			}
		}
	}
	
	return nil
}

// getRoutingTables gets all routing tables and their VRFs
func (s *RouteSynchronizer) getRoutingTables() (map[string]string, error) {
	// In a real implementation, this would get all routing tables from the system
	// For now, just return a map with the main table
	return map[string]string{
		"main": "main",
	}, nil
}

// routesEqual checks if two routes are equal
func routesEqual(a, b *Route) bool {
	if a.Destination != b.Destination {
		return false
	}
	
	if a.NextHop != b.NextHop {
		return false
	}
	
	if a.Metric != b.Metric {
		return false
	}
	
	if a.Protocol != b.Protocol {
		return false
	}
	
	if a.Preference != b.Preference {
		return false
	}
	
	if a.Table != b.Table {
		return false
	}
	
	if a.VRF != b.VRF {
		return false
	}
	
	return true
}
