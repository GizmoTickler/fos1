package vlan

import (
	"net"
)

// This file contains type definitions for the VLAN implementation

// VLANManager defines the interface for managing VLAN interfaces
type VLANManager interface {
	// CreateVLAN creates a new VLAN interface
	CreateVLAN(parent string, vlanID int, name string, config VLANConfig) (*VLANInterface, error)
	
	// DeleteVLAN removes a VLAN interface
	DeleteVLAN(name string) error
	
	// GetVLAN retrieves information about a VLAN interface
	GetVLAN(name string) (*VLANInterface, error)
	
	// ListVLANs returns all configured VLAN interfaces
	ListVLANs() ([]*VLANInterface, error)
	
	// UpdateVLAN modifies a VLAN interface configuration
	UpdateVLAN(name string, config VLANConfig) (*VLANInterface, error)
	
	// ConfigureTrunk configures a trunk interface with multiple VLANs
	ConfigureTrunk(parent string, config TrunkConfig) error
	
	// GetTrunkConfig retrieves trunk configuration for an interface
	GetTrunkConfig(parent string) (*TrunkConfig, error)
	
	// AddVLANToTrunk adds a VLAN to a trunk interface
	AddVLANToTrunk(parent string, vlanID int) error
	
	// RemoveVLANFromTrunk removes a VLAN from a trunk interface
	RemoveVLANFromTrunk(parent string, vlanID int) error
	
	// Subscribe registers a callback for VLAN events
	Subscribe(handler VLANEventHandler) (subscriptionID string)
	
	// Unsubscribe removes a callback registered with Subscribe
	Unsubscribe(subscriptionID string)
}

// VLANConfig represents the configuration for a VLAN interface
type VLANConfig struct {
	MTU         int             // MTU for the VLAN interface
	Addresses   []IPConfig      // IP addresses and prefixes
	QoSPriority int             // 802.1p priority (0-7)
	DSCP        int             // DSCP value for QoS marking
	State       string          // "up" or "down"
	Description string          // Description of the VLAN
	Egress      QoSConfig       // Egress QoS configuration
	Ingress     QoSConfig       // Ingress QoS configuration
	Bridge      BridgeConfig    // Bridge configuration if this VLAN is bridged
	DHCPRelay   bool            // Whether to enable DHCP relay on this VLAN
	NDPProxy    bool            // Whether to enable NDP proxy (IPv6) on this VLAN
	RoutingPolicy *RoutingPolicy // Optional routing policy specific to this VLAN
}

// IPConfig represents an IP address configuration
type IPConfig struct {
	Address     net.IP      // IP address
	Prefix      int         // Prefix length
	Gateway     net.IP      // Default gateway (optional)
	IsVirtual   bool        // Whether this is a virtual IP (for HA)
	DNSServers  []net.IP    // DNS servers for this subnet
	NTPServers  []net.IP    // NTP servers for this subnet
}

// QoSConfig represents Quality of Service configuration
type QoSConfig struct {
	Enabled     bool        // Whether QoS is enabled
	DefaultClass int        // Default traffic class
	MaxRate     string      // Maximum rate (e.g., "1Gbit")
	Classes     []QoSClass  // QoS classes
}

// QoSClass represents a QoS traffic class
type QoSClass struct {
	ID          int         // Class ID
	Priority    int         // Priority (0-7)
	Rate        string      // Rate limit (e.g., "100Mbit")
	Ceiling     string      // Maximum rate (e.g., "1Gbit")
	Burst       string      // Burst size (e.g., "15kb")
}

// BridgeConfig represents bridge configuration
type BridgeConfig struct {
	Enabled     bool        // Whether bridge is enabled
	STP         bool        // Whether Spanning Tree Protocol is enabled
	ForwardDelay int        // STP forward delay in seconds
	HelloTime   int         // STP hello time in seconds
	MaxAge      int         // STP max age in seconds
	Priority    int         // STP priority
	Members     []string    // Member interfaces
}

// RoutingPolicy represents routing policy specific to a VLAN
type RoutingPolicy struct {
	AllowInternet   bool        // Whether traffic can reach the Internet
	AllowInterVLAN  bool        // Whether traffic can reach other VLANs
	Zones           []string    // Security zones this VLAN belongs to
	DefaultAction   string      // Default action for traffic (allow/deny)
}

// TrunkConfig represents the configuration for a trunk interface
type TrunkConfig struct {
	NativeVLAN   int           // Native (untagged) VLAN ID
	AllowedVLANs []int         // Allowed VLAN IDs on this trunk
	QinQ         bool          // Whether Q-in-Q is enabled
	QinQEthertype uint16       // Ethertype for Q-in-Q (default: 0x8100)
	MTU          int           // MTU for the trunk interface
	State        string        // "up" or "down"
}

// VLANInterface represents a configured VLAN interface
type VLANInterface struct {
	Name             string       // Interface name (e.g., "vlan100")
	Parent           string       // Parent interface name
	VLANID           int          // VLAN ID (1-4094)
	OperationalState string       // "up", "down", "pending"
	Config           VLANConfig   // Current configuration
	ActualMTU        int          // Actual MTU of the interface
	Statistics       VLANStats    // Interface statistics
	ErrorMessage     string       // Error message if applicable
	IsNative         bool         // Whether this is a native VLAN on a trunk
	IsQinQ           bool         // Whether this is a Q-in-Q VLAN
	OuterVLANID      int          // Outer VLAN ID for Q-in-Q (if applicable)
}

// VLANStats represents statistics for a VLAN interface
type VLANStats struct {
	RxPackets    uint64      // Received packets
	TxPackets    uint64      // Transmitted packets
	RxBytes      uint64      // Received bytes
	TxBytes      uint64      // Transmitted bytes
	RxErrors     uint64      // Receive errors
	TxErrors     uint64      // Transmit errors
	RxDropped    uint64      // Received packets dropped
	TxDropped    uint64      // Transmitted packets dropped
	LastUpdated  int64       // Unix timestamp of last update
}

// VLANState represents the possible operational states of a VLAN interface
type VLANState string

const (
	// VLANStateUp indicates the VLAN interface is up and operational
	VLANStateUp VLANState = "up"
	
	// VLANStateDown indicates the VLAN interface is administratively down
	VLANStateDown VLANState = "down"
	
	// VLANStatePending indicates the VLAN interface is waiting for the parent interface
	VLANStatePending VLANState = "pending"
	
	// VLANStateError indicates the VLAN interface is in an error state
	VLANStateError VLANState = "error"
)

// VLANControllerConfig defines the configuration for the VLAN controller
type VLANControllerConfig struct {
	// ResyncInterval is the interval at which the controller will resync with the API server
	ResyncInterval int
	
	// MaxConcurrentReconciles is the maximum number of concurrent reconciles
	MaxConcurrentReconciles int
	
	// DefaultQoSPriority is the default 802.1p priority if not specified
	DefaultQoSPriority int
	
	// DefaultDSCP is the default DSCP value if not specified
	DefaultDSCP int
	
	// DefaultMTU is the default MTU if not specified
	DefaultMTU int
	
	// VLANNetlinkTimeout is the timeout for netlink operations
	VLANNetlinkTimeout int
	
	// EnableSysctlConfiguration enables automatic sysctl configuration
	EnableSysctlConfiguration bool
}

// VLANEvent represents an event related to a VLAN interface
type VLANEvent struct {
	// Type is the type of event
	Type VLANEventType
	
	// Interface is the affected VLAN interface
	Interface *VLANInterface
	
	// Message is an optional message describing the event
	Message string
	
	// Timestamp is the time the event occurred
	Timestamp int64
}

// VLANEventType represents the type of VLAN event
type VLANEventType string

const (
	// VLANEventCreated indicates a VLAN interface was created
	VLANEventCreated VLANEventType = "created"
	
	// VLANEventDeleted indicates a VLAN interface was deleted
	VLANEventDeleted VLANEventType = "deleted"
	
	// VLANEventUpdated indicates a VLAN interface was updated
	VLANEventUpdated VLANEventType = "updated"
	
	// VLANEventStateChanged indicates the state of a VLAN interface changed
	VLANEventStateChanged VLANEventType = "state_changed"
	
	// VLANEventError indicates an error occurred with a VLAN interface
	VLANEventError VLANEventType = "error"
	
	// VLANEventTrunkModified indicates a trunk configuration was modified
	VLANEventTrunkModified VLANEventType = "trunk_modified"
	
	// VLANEventQoSModified indicates QoS configuration was modified
	VLANEventQoSModified VLANEventType = "qos_modified"
	
	// VLANEventBridgeModified indicates bridge configuration was modified
	VLANEventBridgeModified VLANEventType = "bridge_modified"
)

// VLANEventHandler is a callback for handling VLAN events
type VLANEventHandler func(event VLANEvent)