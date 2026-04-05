//go:build !linux

package nic

import (
	"context"
	"fmt"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// Manager provides a non-linux stub implementation.
type Manager struct{}

// NewManager creates a new NIC Manager.
func NewManager() (*Manager, error) {
	return &Manager{}, nil
}

// Initialize initializes the NIC Manager.
func (m *Manager) Initialize(ctx context.Context) error {
	return nil
}

// Shutdown shuts down the NIC Manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	return nil
}

// GetNICInfo gets information about a network interface.
func (m *Manager) GetNICInfo(name string) (*types.NICInfo, error) {
	return nil, fmt.Errorf("NIC management is only supported on linux")
}

// ListNICs lists all network interfaces.
func (m *Manager) ListNICs() ([]string, error) {
	return []string{}, nil
}

// SetLinkState sets the state of a network interface.
func (m *Manager) SetLinkState(name string, up bool) error {
	return fmt.Errorf("NIC management is only supported on linux")
}

// SetMTU sets the MTU of a network interface.
func (m *Manager) SetMTU(name string, mtu int) error {
	return fmt.Errorf("NIC management is only supported on linux")
}

// GetStatistics gets statistics for a network interface.
func (m *Manager) GetStatistics(name string) (*types.NICStatistics, error) {
	return nil, fmt.Errorf("NIC management is only supported on linux")
}
