package types

import (
	"context"
)

// WANManager defines the interface for WAN interface management
type WANManager interface {
	// Initialize initializes the WAN manager
	Initialize(ctx context.Context) error

	// Shutdown shuts down the WAN manager
	Shutdown(ctx context.Context) error

	// AddWANInterface adds a WAN interface
	AddWANInterface(config WANInterfaceConfig) error

	// RemoveWANInterface removes a WAN interface
	RemoveWANInterface(name string) error

	// GetWANInterface gets information about a WAN interface
	GetWANInterface(name string) (*WANInterfaceInfo, error)

	// ListWANInterfaces lists all WAN interfaces
	ListWANInterfaces() ([]string, error)

	// SetWANInterfaceState sets the state of a WAN interface
	SetWANInterfaceState(name string, up bool) error

	// GetWANStatistics gets statistics for a WAN interface
	GetWANStatistics(name string) (*WANStatistics, error)

	// TestWANConnectivity tests connectivity for a WAN interface
	TestWANConnectivity(name string) (*WANConnectivityResult, error)
}

// WANInterfaceConfig defines the configuration for a WAN interface
type WANInterfaceConfig struct {
	// Name is the name of the interface
	Name string

	// Type is the type of WAN interface (e.g., ethernet, pppoe, lte)
	Type string

	// PhysicalInterface is the name of the physical interface
	PhysicalInterface string

	// MTU is the Maximum Transmission Unit
	MTU int

	// Weight is the weight for load balancing
	Weight int

	// Priority is the priority for failover
	Priority int

	// Gateway is the gateway IP address
	Gateway string

	// DNS is a list of DNS servers
	DNS []string

	// Metric is the routing metric
	Metric int

	// Failover indicates whether this interface should be used for failover
	Failover bool

	// MonitorEnabled indicates whether monitoring is enabled
	MonitorEnabled bool

	// MonitorInterval is the monitoring interval in seconds
	MonitorInterval int

	// MonitorTargets is a list of targets to monitor
	MonitorTargets []string

	// PPPoE is the PPPoE configuration (if applicable)
	PPPoE *PPPoEConfig

	// LTE is the LTE configuration (if applicable)
	LTE *LTEConfig
}

// PPPoEConfig defines the configuration for PPPoE
type PPPoEConfig struct {
	// Username is the PPPoE username
	Username string

	// Password is the PPPoE password
	Password string

	// ServiceName is the PPPoE service name
	ServiceName string

	// ACName is the PPPoE AC name
	ACName string
}

// LTEConfig defines the configuration for LTE
type LTEConfig struct {
	// APN is the Access Point Name
	APN string

	// PIN is the SIM PIN
	PIN string

	// Username is the authentication username
	Username string

	// Password is the authentication password
	Password string
}

// WANInterfaceInfo defines information about a WAN interface
type WANInterfaceInfo struct {
	// Name is the name of the interface
	Name string

	// Type is the type of WAN interface
	Type string

	// PhysicalInterface is the name of the physical interface
	PhysicalInterface string

	// State is the current state of the interface
	State string

	// MTU is the Maximum Transmission Unit
	MTU int

	// Weight is the weight for load balancing
	Weight int

	// Priority is the priority for failover
	Priority int

	// Gateway is the gateway IP address
	Gateway string

	// DNS is a list of DNS servers
	DNS []string

	// Metric is the routing metric
	Metric int

	// IPAddress is the IP address
	IPAddress string

	// Netmask is the netmask
	Netmask string

	// IPv6Address is the IPv6 address
	IPv6Address string

	// IPv6Prefix is the IPv6 prefix length
	IPv6Prefix int

	// Statistics is the interface statistics
	Statistics WANStatistics
}

// WANStatistics defines statistics for a WAN interface
type WANStatistics struct {
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

	// Uptime is the uptime in seconds
	Uptime uint64

	// ConnectionCount is the number of connections
	ConnectionCount uint64

	// LastConnectedTime is the timestamp of the last connection
	LastConnectedTime int64

	// LastDisconnectedTime is the timestamp of the last disconnection
	LastDisconnectedTime int64
}

// WANConnectivityResult defines the result of a connectivity test
type WANConnectivityResult struct {
	// Success indicates whether the test was successful
	Success bool

	// Latency is the latency in milliseconds
	Latency int

	// PacketLoss is the packet loss percentage
	PacketLoss float64

	// DNSLatency is the DNS latency in milliseconds
	DNSLatency int

	// Bandwidth is the estimated bandwidth in Mbps
	Bandwidth float64

	// Error is the error message if the test failed
	Error string
}
