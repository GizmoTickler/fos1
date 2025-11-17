// Package wan provides functionality for managing WAN interfaces.
package wan

import (
	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// NewWANManager creates a new WAN Manager.
func NewWANManager() (types.WANManager, error) {
	return NewManager()
}
