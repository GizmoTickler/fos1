// Package wan provides functionality for managing WAN interfaces.
package wan

import (
	"github.com/varuntirumala1/fos1/pkg/hardware"
)

// NewWANManager creates a new WAN Manager.
func NewWANManager() (hardware.WANManager, error) {
	return NewManager()
}
