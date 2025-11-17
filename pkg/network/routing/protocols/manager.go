package protocols

import (
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
	// This would typically query the routing table for routes with the specified protocol
	// For now, return an error indicating this is not yet implemented
	return nil, fmt.Errorf("GetProtocolRoutes not yet implemented for protocol: %s", protocolName)
}
