// Package nic provides functionality for managing network interfaces.
package nic

import (
	"github.com/varuntirumala1/fos1/pkg/hardware"
)

// NewNICManager creates a new NIC Manager.
func NewNICManager() (hardware.NICManager, error) {
	return NewManager()
}
