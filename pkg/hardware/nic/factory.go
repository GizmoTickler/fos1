// Package nic provides functionality for managing network interfaces.
package nic

import (
	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// NewNICManager creates a new NIC Manager.
func NewNICManager() (types.NICManager, error) {
	return NewManager()
}
