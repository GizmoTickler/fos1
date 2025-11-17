// Package hardware provides hardware integration for the router/firewall system.
package hardware

import (
	"github.com/GizmoTickler/fos1/pkg/hardware/capture"
	"github.com/GizmoTickler/fos1/pkg/hardware/ebpf"
	"github.com/GizmoTickler/fos1/pkg/hardware/nic"
	"github.com/GizmoTickler/fos1/pkg/hardware/offload"
	"github.com/GizmoTickler/fos1/pkg/hardware/types"
	"github.com/GizmoTickler/fos1/pkg/hardware/wan"
)

// NewNICManager creates a new NIC Manager.
func NewNICManager() (types.NICManager, error) {
	return nic.NewNICManager()
}

// NewEBPFManager creates a new eBPF Manager.
func NewEBPFManager() (types.EBPFManager, error) {
	return ebpf.NewEBPFManager()
}

// NewOffloadManager creates a new Offload Manager.
func NewOffloadManager() (types.OffloadManager, error) {
	return offload.NewOffloadManager()
}

// NewCaptureManager creates a new Capture Manager.
func NewCaptureManager() (types.CaptureManager, error) {
	return capture.NewCaptureManager()
}

// NewWANManager creates a new WAN Manager.
func NewWANManager() (types.WANManager, error) {
	return wan.NewWANManager()
}
