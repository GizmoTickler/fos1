// Package hardware provides hardware integration for the router/firewall system.
package hardware

import (
	"github.com/varuntirumala1/fos1/pkg/hardware/capture"
	"github.com/varuntirumala1/fos1/pkg/hardware/ebpf"
	"github.com/varuntirumala1/fos1/pkg/hardware/nic"
	"github.com/varuntirumala1/fos1/pkg/hardware/offload"
	"github.com/varuntirumala1/fos1/pkg/hardware/wan"
)

// NewNICManager creates a new NIC Manager.
func NewNICManager() (NICManager, error) {
	return nic.NewNICManager()
}

// NewEBPFManager creates a new eBPF Manager.
func NewEBPFManager() (EBPFManager, error) {
	return ebpf.NewEBPFManager()
}

// NewOffloadManager creates a new Offload Manager.
func NewOffloadManager() (OffloadManager, error) {
	return offload.NewOffloadManager()
}

// NewCaptureManager creates a new Capture Manager.
func NewCaptureManager() (CaptureManager, error) {
	return capture.NewCaptureManager()
}

// NewWANManager creates a new WAN Manager.
func NewWANManager() (WANManager, error) {
	return wan.NewWANManager()
}
