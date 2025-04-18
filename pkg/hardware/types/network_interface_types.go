package types

// InterfaceType defines the type of network interface
type InterfaceType string

const (
	// InterfaceTypePhysical represents a physical network interface
	InterfaceTypePhysical InterfaceType = "physical"

	// InterfaceTypeVirtual represents a virtual network interface
	InterfaceTypeVirtual InterfaceType = "virtual"

	// InterfaceTypeBridge represents a bridge network interface
	InterfaceTypeBridge InterfaceType = "bridge"

	// InterfaceTypeVLAN represents a VLAN network interface
	InterfaceTypeVLAN InterfaceType = "vlan"

	// InterfaceTypeBond represents a bonded network interface
	InterfaceTypeBond InterfaceType = "bond"
)

// NetworkInterface represents a network interface
type NetworkInterface struct {
	// Name is the name of the interface
	Name string

	// Type is the type of interface
	Type InterfaceType

	// MAC is the MAC address of the interface
	MAC string

	// MTU is the Maximum Transmission Unit
	MTU int

	// Enabled indicates whether the interface is enabled
	Enabled bool

	// State is the current state of the interface
	State string

	// Addresses is a list of IP addresses assigned to the interface
	Addresses []string

	// Statistics is the interface statistics
	Statistics InterfaceStatistics

	// OffloadFeatures is the hardware offloading features
	OffloadFeatures OffloadFeatures
}

// InterfaceStatistics represents statistics for a network interface
type InterfaceStatistics struct {
	// RxBytes is the number of received bytes
	RxBytes uint64

	// RxPackets is the number of received packets
	RxPackets uint64

	// RxErrors is the number of receive errors
	RxErrors uint64

	// RxDropped is the number of received packets dropped
	RxDropped uint64

	// TxBytes is the number of transmitted bytes
	TxBytes uint64

	// TxPackets is the number of transmitted packets
	TxPackets uint64

	// TxErrors is the number of transmit errors
	TxErrors uint64

	// TxDropped is the number of transmitted packets dropped
	TxDropped uint64

	// Collisions is the number of collisions
	Collisions uint64
}

// OffloadFeatures represents hardware offloading features
type OffloadFeatures struct {
	// TxChecksum indicates whether transmit checksum offload is enabled
	TxChecksum bool

	// RxChecksum indicates whether receive checksum offload is enabled
	RxChecksum bool

	// TSO indicates whether TCP segmentation offload is enabled
	TSO bool

	// GSO indicates whether generic segmentation offload is enabled
	GSO bool

	// GRO indicates whether generic receive offload is enabled
	GRO bool

	// LRO indicates whether large receive offload is enabled
	LRO bool

	// RPS indicates whether receive packet steering is enabled
	RPS bool

	// XPS indicates whether transmit packet steering is enabled
	XPS bool

	// NTUPLE indicates whether nTuple filtering is enabled
	NTUPLE bool

	// RFS indicates whether receive flow steering is enabled
	RFS bool
}

// InterfaceConfig represents the configuration for a network interface
type InterfaceConfig struct {
	// MTU is the Maximum Transmission Unit
	MTU int

	// Enabled indicates whether the interface is enabled
	Enabled bool

	// Addresses is a list of IP addresses to assign to the interface
	Addresses []string

	// EnableOffload indicates whether hardware offloading is enabled
	EnableOffload bool

	// OffloadFeatures is the hardware offloading features to configure
	OffloadFeatures OffloadFeatures
}
