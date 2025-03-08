// Package capture provides functionality for packet capture management.
package capture

import (
	"github.com/varuntirumala1/fos1/pkg/hardware"
)

// NewCaptureManager creates a new Capture Manager.
func NewCaptureManager() (hardware.CaptureManager, error) {
	return NewManager()
}
