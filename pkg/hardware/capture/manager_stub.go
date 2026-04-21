//go:build !linux

// Package capture provides functionality for packet capture management.
package capture

import (
	"context"
	"fmt"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// Manager provides a non-linux stub implementation of the capture manager.
// All methods that would shell out to tcpdump return ErrCaptureUnsupported
// wrapped with the operation name so callers can log a platform-limited
// downgrade rather than silently producing empty pcaps.
type Manager struct{}

// NewManager constructs the stub manager. It intentionally does not return an
// error so cross-platform tests can exercise downstream plumbing without
// hard-coding per-OS branches; every capture method still surfaces
// ErrCaptureUnsupported.
func NewManager() (*Manager, error) {
	return &Manager{}, nil
}

// Initialize is a no-op on non-Linux platforms.
func (m *Manager) Initialize(ctx context.Context) error {
	return nil
}

// Shutdown is a no-op on non-Linux platforms.
func (m *Manager) Shutdown(ctx context.Context) error {
	return nil
}

// StartCapture always returns ErrCaptureUnsupported.
func (m *Manager) StartCapture(config types.CaptureConfig) (string, error) {
	return "", fmt.Errorf("start capture interface=%s: %w", config.Interface, ErrCaptureUnsupported)
}

// StopCapture always returns ErrCaptureUnsupported.
func (m *Manager) StopCapture(captureID string) error {
	return fmt.Errorf("stop capture %s: %w", captureID, ErrCaptureUnsupported)
}

// GetCaptureStatus always returns ErrCaptureUnsupported.
func (m *Manager) GetCaptureStatus(captureID string) (*types.CaptureStatus, error) {
	return nil, fmt.Errorf("get status for capture %s: %w", captureID, ErrCaptureUnsupported)
}

// ListCaptures returns ErrCaptureUnsupported — callers should not mistake an
// empty slice for "no captures running" when capture is fundamentally
// unsupported on this platform.
func (m *Manager) ListCaptures() ([]string, error) {
	return nil, fmt.Errorf("list captures: %w", ErrCaptureUnsupported)
}

// GetCapturePath always returns ErrCaptureUnsupported.
func (m *Manager) GetCapturePath(captureID string) (string, error) {
	return "", fmt.Errorf("get capture path for %s: %w", captureID, ErrCaptureUnsupported)
}
