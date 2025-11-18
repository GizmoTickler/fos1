// Package offload provides functionality for managing hardware offloading features.
package offload

import (
	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// NewOffloadManager creates a new Offload Manager.
func NewOffloadManager() (types.OffloadManager, error) {
	return NewManager()
}
