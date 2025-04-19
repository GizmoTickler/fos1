package multiwan

import (
	"time"
)

// Configuration represents a multi-WAN configuration
type Configuration struct {
	// Name is the name of the configuration
	Name string
	
	// Namespace is the namespace of the configuration
	Namespace string
	
	// Description is an optional description
	Description string
	
	// WANInterfaces is a list of WAN interfaces
	WANInterfaces []WANInterface
	
	// LoadBalancing is the load balancing configuration
	LoadBalancing LoadBalancing
	
	// Failover is the failover configuration
	Failover Failover
	
	// DefaultRouteMetric is the metric for the default route
	DefaultRouteMetric int
}

// WANInterface represents a WAN interface
type WANInterface struct {
	// Name is the name of the WAN interface
	Name string
	
	// Interface is the physical interface name
	Interface string
	
	// Weight is the weight for load balancing
	Weight int
	
	// Priority is the priority for failover
	Priority int
	
	// Description is an optional description
	Description string
	
	// Gateway is the gateway IP address
	Gateway string
	
	// Monitoring is the monitoring configuration
	Monitoring WANMonitoring
}

// WANMonitoring represents monitoring configuration for a WAN interface
type WANMonitoring struct {
	// Targets is a list of targets to monitor
	Targets []string
	
	// Method is the monitoring method (ping, http, dns)
	Method string
	
	// Interval is the monitoring interval in seconds
	Interval int
	
	// Timeout is the monitoring timeout in seconds
	Timeout int
	
	// FailThreshold is the number of failures before marking as down
	FailThreshold int
	
	// SuccessThreshold is the number of successes before marking as up
	SuccessThreshold int
}

// LoadBalancing represents load balancing configuration
type LoadBalancing struct {
	// Enabled indicates whether load balancing is enabled
	Enabled bool
	
	// Method is the load balancing method (weighted, round-robin, random)
	Method string
	
	// Sticky indicates whether to use sticky connections
	Sticky bool
	
	// StickyTimeout is the timeout for sticky connections in seconds
	StickyTimeout int
}

// Failover represents failover configuration
type Failover struct {
	// Enabled indicates whether failover is enabled
	Enabled bool
	
	// Preempt indicates whether to preempt back to higher priority
	Preempt bool
	
	// PreemptDelay is the delay before preempting in seconds
	PreemptDelay int
}

// WANStatus represents the status of a WAN interface
type WANStatus struct {
	// Name is the name of the WAN interface
	Name string
	
	// State is the state of the WAN interface (up, down)
	State string
	
	// RTT is the round-trip time in milliseconds
	RTT int
	
	// PacketLoss is the packet loss percentage
	PacketLoss float64
}

// Status represents the status of a multi-WAN configuration
type Status struct {
	// ActiveWANs is a list of active WAN interfaces
	ActiveWANs []WANStatus
	
	// CurrentPrimary is the current primary WAN interface
	CurrentPrimary string
	
	// LastStateChange is the last time the state changed
	LastStateChange string
}

// Manager defines the interface for managing multi-WAN configurations
type Manager interface {
	// ApplyConfiguration applies a multi-WAN configuration
	ApplyConfiguration(config Configuration) error
	
	// RemoveConfiguration removes a multi-WAN configuration
	RemoveConfiguration(name string) error
	
	// GetStatus gets the status of a multi-WAN configuration
	GetStatus(name string) (*Status, error)
	
	// ListConfigurations lists all multi-WAN configurations
	ListConfigurations() ([]Configuration, error)
}
