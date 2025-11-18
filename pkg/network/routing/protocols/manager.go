package protocols

import (
	"context"
	"fmt"
	"sync"

	"github.com/GizmoTickler/fos1/pkg/network/routing"
	"github.com/GizmoTickler/fos1/pkg/network/routing/frr"
)

// ProtocolHandler defines the interface for protocol handlers
type ProtocolHandler interface {
	// Start starts the protocol with the given configuration
	Start(config routing.ProtocolConfig) error
	
	// Stop stops the protocol
	Stop() error
	
	// Restart restarts the protocol
	Restart() error
	
	// GetStatus gets the status of the protocol
	GetStatus() *routing.ProtocolStatus
	
	// UpdateConfig updates the protocol configuration
	UpdateConfig(config routing.ProtocolConfig) error
}

// Manager implements the ProtocolManager interface
type Manager struct {
	mutex    sync.RWMutex
	handlers map[string]ProtocolHandler
	frrClient *frr.Client
}

// NewManager creates a new protocol manager
func NewManager(frrClient *frr.Client) routing.ProtocolManager {
	return &Manager{
		handlers: make(map[string]ProtocolHandler),
		frrClient: frrClient,
	}
}

// StartProtocol starts a routing protocol
func (m *Manager) StartProtocol(protocolName string, config routing.ProtocolConfig) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the protocol is already running
	if handler, exists := m.handlers[protocolName]; exists {
		// Update the configuration
		return handler.UpdateConfig(config)
	}
	
	// Create a new handler for the protocol
	var handler ProtocolHandler
	switch protocolName {
	case "bgp":
		handler = NewBGPHandler(m.frrClient)
	case "ospf":
		handler = NewOSPFHandler(m.frrClient)
	case "bfd":
		handler = NewBFDHandler(m.frrClient)
	default:
		return fmt.Errorf("unsupported protocol: %s", protocolName)
	}
	
	// Start the protocol
	if err := handler.Start(config); err != nil {
		return err
	}
	
	// Store the handler
	m.handlers[protocolName] = handler
	
	return nil
}

// StopProtocol stops a routing protocol
func (m *Manager) StopProtocol(protocolName string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the protocol is running
	handler, exists := m.handlers[protocolName]
	if !exists {
		return fmt.Errorf("protocol not running: %s", protocolName)
	}
	
	// Stop the protocol
	if err := handler.Stop(); err != nil {
		return err
	}
	
	// Remove the handler
	delete(m.handlers, protocolName)
	
	return nil
}

// RestartProtocol restarts a routing protocol
func (m *Manager) RestartProtocol(protocolName string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Check if the protocol is running
	handler, exists := m.handlers[protocolName]
	if !exists {
		return fmt.Errorf("protocol not running: %s", protocolName)
	}
	
	// Restart the protocol
	return handler.Restart()
}

// GetProtocolStatus retrieves the status of a protocol
func (m *Manager) GetProtocolStatus(protocolName string) (*routing.ProtocolStatus, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Check if the protocol is running
	handler, exists := m.handlers[protocolName]
	if !exists {
		return nil, fmt.Errorf("protocol not running: %s", protocolName)
	}
	
	// Get the status
	return handler.GetStatus(), nil
}

// ListProtocols lists all running protocols
func (m *Manager) ListProtocols() ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Get the list of protocols
	protocols := make([]string, 0, len(m.handlers))
	for protocol := range m.handlers {
		protocols = append(protocols, protocol)
	}
	
	return protocols, nil
}

// UpdateProtocolConfig updates the configuration of a protocol
func (m *Manager) UpdateProtocolConfig(protocolName string, config routing.ProtocolConfig) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if the protocol is running
	handler, exists := m.handlers[protocolName]
	if !exists {
		return fmt.Errorf("protocol not running: %s", protocolName)
	}

	// Update the configuration
	return handler.UpdateConfig(config)
}

// GetProtocolRoutes retrieves routes learned via a specific protocol
func (m *Manager) GetProtocolRoutes(protocolName string) ([]*routing.Route, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if the protocol is running
	if _, exists := m.handlers[protocolName]; !exists {
		return nil, fmt.Errorf("protocol not running: %s", protocolName)
	}

	// Query FRR for routes from this protocol
	ctx := context.Background()
	output, err := m.frrClient.GetRoutesByProtocol(ctx, protocolName)
	if err != nil {
		return nil, fmt.Errorf("failed to get routes for protocol %s: %w", protocolName, err)
	}

	// Parse the routing table output
	frrRoutes, err := m.frrClient.ParseRoutingTable(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse routing table: %w", err)
	}

	// Convert FRR routes to routing.Route format
	routes := make([]*routing.Route, 0, len(frrRoutes))
	for _, frrRoute := range frrRoutes {
		// Only include routes from the requested protocol
		if frrRoute.Protocol != protocolName {
			continue
		}

		// Create next hop
		nextHop := routing.NextHop{
			Address:   frrRoute.NextHop,
			Interface: frrRoute.Interface,
			Weight:    1, // FRR doesn't provide weight in show output
		}

		route := &routing.Route{
			Destination: frrRoute.Prefix,
			NextHops:    []routing.NextHop{nextHop},
			Metric:      frrRoute.Metric,
			Preference:  frrRoute.Distance,
			Protocol:    frrRoute.Protocol,
			Scope:       "global",
			VRF:         "main",
			Table:       "main",
		}

		routes = append(routes, route)
	}

	return routes, nil
}
