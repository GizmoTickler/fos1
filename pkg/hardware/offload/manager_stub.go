//go:build !linux

package offload

import (
	"context"
	"fmt"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// Manager provides a non-linux stub implementation.
type Manager struct{}

// NewManager creates a new Offload Manager.
func NewManager() (*Manager, error) {
	return &Manager{}, nil
}

// Initialize initializes the Offload Manager.
func (m *Manager) Initialize(ctx context.Context) error {
	return nil
}

// Shutdown shuts down the Offload Manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	return nil
}

// GetOffloadCapabilities gets the offload capabilities of an interface.
func (m *Manager) GetOffloadCapabilities(ifName string) (*types.OffloadCapabilities, error) {
	return nil, fmt.Errorf("hardware offload management is only supported on linux")
}

// SetOffloadFeature enables or disables an offload feature for an interface.
func (m *Manager) SetOffloadFeature(name string, feature string, enabled bool) error {
	return fmt.Errorf("hardware offload management is only supported on linux")
}

// GetOffloadStatistics gets statistics for offloaded operations on an interface.
func (m *Manager) GetOffloadStatistics(name string) (*types.OffloadStatistics, error) {
	return nil, fmt.Errorf("hardware offload management is only supported on linux")
}
