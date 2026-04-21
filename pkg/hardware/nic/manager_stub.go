//go:build !linux

package nic

import (
	"context"
	"fmt"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// Manager provides a non-linux stub implementation.
//
// All public methods return ErrNICUnsupportedPlatform wrapped with enough
// context for logs so the caller can tell at a glance the platform is the
// limiting factor rather than a driver / netlink failure.
type Manager struct{}

// NewManager creates a new NIC Manager stub. It does not return an error so
// that cross-platform tests can construct the manager without special-casing
// each OS; every method that actually needs ethtool / netlink returns an
// explicit unsupported error.
func NewManager() (*Manager, error) {
	return &Manager{}, nil
}

// Initialize is a no-op stub.
func (m *Manager) Initialize(ctx context.Context) error {
	return nil
}

// Shutdown is a no-op stub.
func (m *Manager) Shutdown(ctx context.Context) error {
	return nil
}

// GetNICInfo returns ErrNICUnsupportedPlatform.
func (m *Manager) GetNICInfo(name string) (*types.NICInfo, error) {
	return nil, fmt.Errorf("get NIC info for %s: %w", name, ErrNICUnsupportedPlatform)
}

// ListNICs returns ErrNICUnsupportedPlatform. Previous behaviour returned an
// empty slice with nil error which silently hid the fact that no real backend
// is available on this platform.
func (m *Manager) ListNICs() ([]string, error) {
	return nil, fmt.Errorf("list NICs: %w", ErrNICUnsupportedPlatform)
}

// SetLinkState returns ErrNICUnsupportedPlatform.
func (m *Manager) SetLinkState(name string, up bool) error {
	return fmt.Errorf("set link state for %s: %w", name, ErrNICUnsupportedPlatform)
}

// SetMTU returns ErrNICUnsupportedPlatform.
func (m *Manager) SetMTU(name string, mtu int) error {
	return fmt.Errorf("set MTU for %s: %w", name, ErrNICUnsupportedPlatform)
}

// GetStatistics returns ErrNICUnsupportedPlatform.
func (m *Manager) GetStatistics(name string) (*types.NICStatistics, error) {
	return nil, fmt.Errorf("get statistics for %s: %w", name, ErrNICUnsupportedPlatform)
}
