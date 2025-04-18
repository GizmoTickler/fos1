package types

import (
	"context"
)

// NICManager defines the interface for network interface card management
type NICManager interface {
	// Initialize initializes the NIC manager
	Initialize(ctx context.Context) error

	// Shutdown shuts down the NIC manager
	Shutdown(ctx context.Context) error

	// GetNICInfo gets information about a network interface
	GetNICInfo(name string) (*NICInfo, error)

	// ListNICs lists all network interfaces
	ListNICs() ([]string, error)

	// SetLinkState sets the state of a network interface
	SetLinkState(name string, up bool) error

	// SetMTU sets the MTU of a network interface
	SetMTU(name string, mtu int) error

	// GetStatistics gets statistics for a network interface
	GetStatistics(name string) (*NICStatistics, error)
}

// NICInfo defines information about a network interface
type NICInfo struct {
	// Name is the name of the interface
	Name string

	// Type is the type of interface (e.g., ethernet, wireless)
	Type string

	// Driver is the driver name
	Driver string

	// MACAddress is the MAC address of the interface
	MACAddress string

	// MTU is the Maximum Transmission Unit
	MTU int

	// State is the current state of the interface
	State string

	// Speed is the link speed in Mbps
	Speed int

	// Duplex is the duplex mode (full, half)
	Duplex string

	// Features is a map of supported features
	Features map[string]bool

	// Statistics is the interface statistics
	Statistics NICStatistics
}

// NICStatistics defines statistics for a network interface
type NICStatistics struct {
	// RxPackets is the number of received packets
	RxPackets uint64

	// TxPackets is the number of transmitted packets
	TxPackets uint64

	// RxBytes is the number of received bytes
	RxBytes uint64

	// TxBytes is the number of transmitted bytes
	TxBytes uint64

	// RxErrors is the number of receive errors
	RxErrors uint64

	// TxErrors is the number of transmit errors
	TxErrors uint64

	// RxDropped is the number of received packets dropped
	RxDropped uint64

	// TxDropped is the number of transmitted packets dropped
	TxDropped uint64

	// Multicast is the number of multicast packets received
	Multicast uint64

	// Collisions is the number of collisions
	Collisions uint64
}
