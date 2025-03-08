// Package offload provides functionality for managing hardware offloading features.
package offload

import (
	"github.com/varuntirumala1/fos1/pkg/hardware"
)

// NewOffloadManager creates a new Offload Manager.
func NewOffloadManager() (hardware.OffloadManager, error) {
	return NewManager()
}
