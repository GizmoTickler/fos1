package vlan

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
}

// VLANConfig represents the configuration for a VLAN interface
type VLANConfig struct {
	MTU        int      // MTU for the VLAN interface
	Addresses  []string // IP addresses and prefixes (e.g., "192.168.1.1/24")
	QoSPriority int     // 802.1p priority (0-7)
	DSCP       int      // DSCP value for QoS marking
	State      string   // "up" or "down"
}

// VLANInterface represents a configured VLAN interface
type VLANInterface struct {
	Name            string    // Interface name (e.g., "vlan100")
	Parent          string    // Parent interface name
	VLANID          int       // VLAN ID (1-4094)
	OperationalState string   // "up", "down", "pending"
	Config          VLANConfig // Current configuration
	ActualMTU       int       // Actual MTU of the interface
	ErrorMessage    string    // Error message if applicable
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
}

// VLANEvent represents an event related to a VLAN interface
type VLANEvent struct {
	// Type is the type of event
	Type VLANEventType
	
	// Interface is the affected VLAN interface
	Interface *VLANInterface
	
	// Message is an optional message describing the event
	Message string
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
)

// VLANEventHandler is a callback for handling VLAN events
type VLANEventHandler func(event VLANEvent)