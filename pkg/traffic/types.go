package traffic

import (
	"time"
)

// Configuration represents a traffic management configuration
type Configuration struct {
	// Interface is the interface to apply the configuration to
	Interface string
	
	// UploadBandwidth is the upload bandwidth limit
	UploadBandwidth string
	
	// DownloadBandwidth is the download bandwidth limit
	DownloadBandwidth string
	
	// DefaultClass is the default traffic class for unclassified traffic
	DefaultClass string
	
	// Classes is a list of traffic classes
	Classes []Class
}

// Class represents a traffic class
type Class struct {
	// Name is the name of the class
	Name string
	
	// Priority is the priority of the class (1-7, with 1 being highest)
	Priority int
	
	// MinBandwidth is the minimum guaranteed bandwidth
	MinBandwidth string
	
	// MaxBandwidth is the maximum bandwidth limit
	MaxBandwidth string
	
	// Burst is the burst size
	Burst string
	
	// DSCP is the DSCP value for this class
	DSCP int
	
	// Applications is a list of applications to match
	Applications []string
	
	// ApplicationCategories is a list of application categories to match
	ApplicationCategories []string
	
	// SourceAddresses is a list of source addresses to match
	SourceAddresses []string
	
	// DestinationAddresses is a list of destination addresses to match
	DestinationAddresses []string
	
	// SourcePort is the source port or port range to match
	SourcePort string
	
	// DestinationPort is the destination port or port range to match
	DestinationPort string
	
	// Protocol is the protocol to match
	Protocol string
}

// ClassStatistics represents statistics for a traffic class
type ClassStatistics struct {
	// Packets is the number of packets processed
	Packets int64
	
	// Bytes is the number of bytes processed
	Bytes int64
	
	// Drops is the number of packets dropped
	Drops int64
	
	// Rate is the current rate in bits per second
	Rate int64
	
	// Utilization is the current utilization as a percentage
	Utilization float64
}

// InterfaceStatistics represents statistics for an interface
type InterfaceStatistics struct {
	// RxPackets is the number of received packets
	RxPackets int64
	
	// RxBytes is the number of received bytes
	RxBytes int64
	
	// RxDrops is the number of received packets dropped
	RxDrops int64
	
	// RxErrors is the number of received packets with errors
	RxErrors int64
	
	// TxPackets is the number of transmitted packets
	TxPackets int64
	
	// TxBytes is the number of transmitted bytes
	TxBytes int64
	
	// TxDrops is the number of transmitted packets dropped
	TxDrops int64
	
	// TxErrors is the number of transmitted packets with errors
	TxErrors int64
	
	// RxRate is the current receive rate in bits per second
	RxRate int64
	
	// TxRate is the current transmit rate in bits per second
	TxRate int64
	
	// RxUtilization is the current receive utilization as a percentage
	RxUtilization float64
	
	// TxUtilization is the current transmit utilization as a percentage
	TxUtilization float64
}

// Status represents the status of a traffic management configuration
type Status struct {
	// Interface is the interface the configuration is applied to
	Interface string
	
	// UploadBandwidth is the actual upload bandwidth limit
	UploadBandwidth string
	
	// DownloadBandwidth is the actual download bandwidth limit
	DownloadBandwidth string
	
	// ClassStatistics is a map of class name to class statistics
	ClassStatistics map[string]*ClassStatistics
	
	// InterfaceStatistics is the interface statistics
	InterfaceStatistics *InterfaceStatistics
	
	// LastUpdated is the timestamp of the last update
	LastUpdated time.Time
}

// Manager defines the interface for managing traffic
type Manager interface {
	// ApplyConfiguration applies a traffic management configuration
	ApplyConfiguration(config *Configuration) error
	
	// DeleteConfiguration deletes a traffic management configuration
	DeleteConfiguration(interfaceName string) error
	
	// GetStatus gets the status of a traffic management configuration
	GetStatus(interfaceName string) (*Status, error)
	
	// ListConfigurations lists all traffic management configurations
	ListConfigurations() ([]*Configuration, error)
	
	// GetClassStatistics gets statistics for a traffic class
	GetClassStatistics(interfaceName, className string) (*ClassStatistics, error)
	
	// GetInterfaceStatistics gets statistics for an interface
	GetInterfaceStatistics(interfaceName string) (*InterfaceStatistics, error)
}

// Classifier defines the interface for classifying traffic
type Classifier interface {
	// ClassifyPacket classifies a packet
	ClassifyPacket(packet PacketInfo) (string, error)
	
	// AddClassificationRule adds a classification rule
	AddClassificationRule(rule ClassificationRule) error
	
	// RemoveClassificationRule removes a classification rule
	RemoveClassificationRule(ruleName string) error
	
	// ListClassificationRules lists all classification rules
	ListClassificationRules() ([]ClassificationRule, error)
}

// PacketInfo represents information about a packet for classification
type PacketInfo struct {
	// SourceIP is the source IP address
	SourceIP string
	
	// DestinationIP is the destination IP address
	DestinationIP string
	
	// Protocol is the protocol (tcp, udp, icmp)
	Protocol string
	
	// SourcePort is the source port
	SourcePort int
	
	// DestinationPort is the destination port
	DestinationPort int
	
	// Interface is the incoming interface
	Interface string
	
	// Application is the application (if DPI is enabled)
	Application string
	
	// ApplicationCategory is the application category
	ApplicationCategory string
	
	// DSCP is the DSCP value
	DSCP int
	
	// Length is the packet length
	Length int
}

// ClassificationRule represents a rule for classifying traffic
type ClassificationRule struct {
	// Name is the name of the rule
	Name string
	
	// Priority is the priority of the rule (lower number = higher priority)
	Priority int
	
	// ClassName is the name of the class to assign to matching packets
	ClassName string
	
	// SourceAddresses is a list of source addresses to match
	SourceAddresses []string
	
	// DestinationAddresses is a list of destination addresses to match
	DestinationAddresses []string
	
	// Protocol is the protocol to match
	Protocol string
	
	// SourcePorts is a list of source ports or port ranges to match
	SourcePorts []string
	
	// DestinationPorts is a list of destination ports or port ranges to match
	DestinationPorts []string
	
	// Applications is a list of applications to match
	Applications []string
	
	// ApplicationCategories is a list of application categories to match
	ApplicationCategories []string
	
	// DSCP is the DSCP value to match
	DSCP int
}

// BandwidthAllocator defines the interface for allocating bandwidth
type BandwidthAllocator interface {
	// AllocateBandwidth allocates bandwidth to a class
	AllocateBandwidth(interfaceName, className string, minBandwidth, maxBandwidth string) error
	
	// ReleaseBandwidth releases bandwidth from a class
	ReleaseBandwidth(interfaceName, className string) error
	
	// GetBandwidthAllocation gets the bandwidth allocation for a class
	GetBandwidthAllocation(interfaceName, className string) (string, string, error)
	
	// GetTotalBandwidth gets the total bandwidth for an interface
	GetTotalBandwidth(interfaceName string) (string, error)
	
	// GetAvailableBandwidth gets the available bandwidth for an interface
	GetAvailableBandwidth(interfaceName string) (string, error)
}
