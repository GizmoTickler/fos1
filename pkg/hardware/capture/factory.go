// Package capture provides functionality for packet capture management.
package capture

import (
	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// NewCaptureManager creates a new Capture Manager.
func NewCaptureManager() (types.CaptureManager, error) {
	return NewManager()
}
