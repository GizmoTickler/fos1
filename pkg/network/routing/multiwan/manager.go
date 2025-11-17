package multiwan

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/network/routing"
)

// manager implements the Manager interface
type manager struct {
	mutex         sync.RWMutex
	configs       map[string]Configuration // key: name
	statuses      map[string]*Status
	routeManager  routing.RouteManager
	loadBalancer  *loadBalancer
	failover      *failover
	monitor       *monitor
}

// NewManager creates a new multi-WAN manager
func NewManager(routeManager routing.RouteManager) Manager {
	m := &manager{
		configs:      make(map[string]Configuration),
		statuses:     make(map[string]*Status),
		routeManager: routeManager,
	}

	// Create load balancer
	m.loadBalancer = newLoadBalancer(m)

	// Create failover
	m.failover = newFailover(m)

	// Create monitor
	m.monitor = newMonitor(m)

	return m
}

// ApplyConfiguration applies a multi-WAN configuration
func (m *manager) ApplyConfiguration(config Configuration) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	klog.Infof("Applying multi-WAN configuration %s", config.Name)

	// Store the configuration
	m.configs[config.Name] = config

	// Initialize or update status
	status, exists := m.statuses[config.Name]
	if !exists {
		status = &Status{
			ActiveWANs:      make([]WANStatus, 0, len(config.WANInterfaces)),
			CurrentPrimary:  "",
			LastStateChange: time.Now().Format(time.RFC3339),
		}
		m.statuses[config.Name] = status
	}

	// Initialize WAN statuses
	for _, wan := range config.WANInterfaces {
		found := false
		for i, wanStatus := range status.ActiveWANs {
			if wanStatus.Name == wan.Name {
				found = true
				// Update existing WAN status
				status.ActiveWANs[i].Name = wan.Name
				break
			}
		}

		if !found {
			// Add new WAN status
			status.ActiveWANs = append(status.ActiveWANs, WANStatus{
				Name:       wan.Name,
				State:      "unknown",
				RTT:        0,
				PacketLoss: 0,
			})
		}
	}

	// Apply the configuration
	if err := m.applyRoutes(config); err != nil {
		return fmt.Errorf("failed to apply routes: %w", err)
	}

	// Start monitoring
	m.monitor.startMonitoring(config)

	// Start load balancing if enabled
	if config.LoadBalancing.Enabled {
		m.loadBalancer.startLoadBalancing(config)
	}

	// Start failover if enabled
	if config.Failover.Enabled {
		m.failover.startFailover(config)
	}

	return nil
}

// RemoveConfiguration removes a multi-WAN configuration
func (m *manager) RemoveConfiguration(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	klog.Infof("Removing multi-WAN configuration %s", name)

	// Check if the configuration exists
	config, exists := m.configs[name]
	if !exists {
		return fmt.Errorf("multi-WAN configuration %s does not exist", name)
	}

	// Stop monitoring
	m.monitor.stopMonitoring(name)

	// Stop load balancing
	m.loadBalancer.stopLoadBalancing(name)

	// Stop failover
	m.failover.stopFailover(name)

	// Remove routes
	if err := m.removeRoutes(config); err != nil {
		return fmt.Errorf("failed to remove routes: %w", err)
	}

	// Remove the configuration and status
	delete(m.configs, name)
	delete(m.statuses, name)

	return nil
}

// GetStatus gets the status of a multi-WAN configuration
func (m *manager) GetStatus(name string) (*Status, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	status, exists := m.statuses[name]
	if !exists {
		return nil, fmt.Errorf("multi-WAN configuration %s does not exist", name)
	}

	return status, nil
}

// ListConfigurations lists all multi-WAN configurations
func (m *manager) ListConfigurations() ([]Configuration, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	configs := make([]Configuration, 0, len(m.configs))
	for _, config := range m.configs {
		configs = append(configs, config)
	}

	return configs, nil
}

// applyRoutes applies routes for a multi-WAN configuration
func (m *manager) applyRoutes(config Configuration) error {
	// For each WAN interface, create a default route
	for _, wan := range config.WANInterfaces {
		// Create a default route
		route := routing.Route{
			Destination: "0.0.0.0/0",
			NextHops: []routing.NextHop{
				{
					Address: wan.Gateway,
				},
			},
			Metric:    config.DefaultRouteMetric + wan.Priority,
			Protocol:  "multiwan",
			VRF:       "main",
			Tags:      []string{"multiwan", fmt.Sprintf("wan-%s", wan.Name)},
			Temporary: true,
		}

		// Add the route
		if err := m.routeManager.AddRoute(route); err != nil {
			return fmt.Errorf("failed to add route for WAN %s: %w", wan.Name, err)
		}
	}

	return nil
}

// removeRoutes removes routes for a multi-WAN configuration
func (m *manager) removeRoutes(config Configuration) error {
	// For each WAN interface, remove the default route
	for _, wan := range config.WANInterfaces {
		// Create route parameters
		routeParams := routing.RouteParams{
			VRF:  "main",
			Tags: []string{"multiwan", fmt.Sprintf("wan-%s", wan.Name)},
		}

		// Delete the route
		if err := m.routeManager.DeleteRoute("0.0.0.0/0", routeParams); err != nil {
			return fmt.Errorf("failed to delete route for WAN %s: %w", wan.Name, err)
		}
	}

	return nil
}

// updateWANStatus updates the status of a WAN interface
func (m *manager) updateWANStatus(configName, wanName, state string, rtt int, packetLoss float64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if the configuration exists
	status, exists := m.statuses[configName]
	if !exists {
		klog.Warningf("Cannot update WAN status: multi-WAN configuration %s does not exist", configName)
		return
	}

	// Find the WAN status
	for i, wanStatus := range status.ActiveWANs {
		if wanStatus.Name == wanName {
			// Update the WAN status
			status.ActiveWANs[i].State = state
			status.ActiveWANs[i].RTT = rtt
			status.ActiveWANs[i].PacketLoss = packetLoss
			break
		}
	}
}

// setCurrentPrimary sets the current primary WAN interface
func (m *manager) setCurrentPrimary(configName, wanName string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if the configuration exists
	status, exists := m.statuses[configName]
	if !exists {
		klog.Warningf("Cannot set current primary: multi-WAN configuration %s does not exist", configName)
		return
	}

	// Update the current primary
	if status.CurrentPrimary != wanName {
		status.CurrentPrimary = wanName
		status.LastStateChange = time.Now().Format(time.RFC3339)
	}
}
