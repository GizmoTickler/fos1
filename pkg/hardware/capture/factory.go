// Package capture provides functionality for packet capture management.
package capture

import (
	"github.com/varuntirumala1/fos1/pkg/hardware/types"
)

// NewCaptureManager creates a new Capture Manager.
func NewCaptureManager() (types.CaptureManager, error) {
	return NewManager()
}
