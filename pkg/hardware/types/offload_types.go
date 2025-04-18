package types

import (
	"context"
)

// OffloadManager defines the interface for hardware offload management
type OffloadManager interface {
	// Initialize initializes the offload manager
	Initialize(ctx context.Context) error

	// Shutdown shuts down the offload manager
	Shutdown(ctx context.Context) error

	// GetOffloadCapabilities gets the offload capabilities for a network interface
	GetOffloadCapabilities(name string) (*OffloadCapabilities, error)

	// SetOffloadFeature enables or disables an offload feature
	SetOffloadFeature(name string, feature string, enabled bool) error

	// GetOffloadStatistics gets statistics for offloaded operations
	GetOffloadStatistics(name string) (*OffloadStatistics, error)
}

// OffloadCapabilities defines the offload capabilities for a network interface
type OffloadCapabilities struct {
	// Interface is the name of the interface
	Interface string

	// TxChecksumIPv4 indicates whether IPv4 transmit checksum offload is supported
	TxChecksumIPv4 bool

	// TxChecksumIPv6 indicates whether IPv6 transmit checksum offload is supported
	TxChecksumIPv6 bool

	// TxChecksumTCP indicates whether TCP transmit checksum offload is supported
	TxChecksumTCP bool

	// TxChecksumUDP indicates whether UDP transmit checksum offload is supported
	TxChecksumUDP bool

	// RxChecksumIPv4 indicates whether IPv4 receive checksum offload is supported
	RxChecksumIPv4 bool

	// RxChecksumIPv6 indicates whether IPv6 receive checksum offload is supported
	RxChecksumIPv6 bool

	// RxChecksumTCP indicates whether TCP receive checksum offload is supported
	RxChecksumTCP bool

	// RxChecksumUDP indicates whether UDP receive checksum offload is supported
	RxChecksumUDP bool

	// TxTCPSegmentation indicates whether TCP segmentation offload is supported
	TxTCPSegmentation bool

	// TxUDPFragmentation indicates whether UDP fragmentation offload is supported
	TxUDPFragmentation bool

	// RxGRO indicates whether generic receive offload is supported
	RxGRO bool

	// RxLRO indicates whether large receive offload is supported
	RxLRO bool

	// VLANAcceleration indicates whether VLAN acceleration is supported
	VLANAcceleration bool

	// NTuple indicates whether nTuple filtering is supported
	NTuple bool

	// RSSHash indicates whether RSS hashing is supported
	RSSHash bool
}

// OffloadStatistics defines statistics for offloaded operations
type OffloadStatistics struct {
	// Interface is the name of the interface
	Interface string

	// TxChecksumIPv4 is the number of IPv4 transmit checksums offloaded
	TxChecksumIPv4 uint64

	// TxChecksumIPv6 is the number of IPv6 transmit checksums offloaded
	TxChecksumIPv6 uint64

	// TxChecksumTCP is the number of TCP transmit checksums offloaded
	TxChecksumTCP uint64

	// TxChecksumUDP is the number of UDP transmit checksums offloaded
	TxChecksumUDP uint64

	// RxChecksumIPv4 is the number of IPv4 receive checksums offloaded
	RxChecksumIPv4 uint64

	// RxChecksumIPv6 is the number of IPv6 receive checksums offloaded
	RxChecksumIPv6 uint64

	// RxChecksumTCP is the number of TCP receive checksums offloaded
	RxChecksumTCP uint64

	// RxChecksumUDP is the number of UDP receive checksums offloaded
	RxChecksumUDP uint64

	// TxTCPSegmentation is the number of TCP segments offloaded
	TxTCPSegmentation uint64

	// TxUDPFragmentation is the number of UDP fragments offloaded
	TxUDPFragmentation uint64

	// RxGRO is the number of packets processed by GRO
	RxGRO uint64

	// RxLRO is the number of packets processed by LRO
	RxLRO uint64
}
