// Package ebpf provides functionality for managing eBPF programs and maps.
package ebpf

import (
	"github.com/varuntirumala1/fos1/pkg/hardware"
)

// NewEBPFManager creates a new eBPF Manager.
func NewEBPFManager() (hardware.EBPFManager, error) {
	return NewManager()
}
