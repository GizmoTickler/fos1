// Package ebpf provides functionality for managing eBPF programs and maps.
package ebpf

import (
	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// NewEBPFManager creates a new eBPF Manager.
func NewEBPFManager() (types.EBPFManager, error) {
	return NewManager()
}
