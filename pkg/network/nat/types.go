package nat

import (
	"time"
)

// PolicyType represents the type of NAT policy
type PolicyType string

const (
	// TypeSNAT represents Source NAT
	TypeSNAT PolicyType = "snat"
	
	// TypeDNAT represents Destination NAT
	TypeDNAT PolicyType = "dnat"
	
	// TypeMasquerade represents Masquerade NAT
	TypeMasquerade PolicyType = "masquerade"
	
	// TypeFull represents Full NAT (both SNAT and DNAT)
	TypeFull PolicyType = "full"
	
	// TypeNAT66 represents NAT66 (IPv6 to IPv6)
	TypeNAT66 PolicyType = "nat66"
	
	// TypeNAT64 represents NAT64 (IPv6 to IPv4)
	TypeNAT64 PolicyType = "nat64"
)

// PortMapping represents a port mapping for DNAT
type PortMapping struct {
	// Protocol is the protocol (tcp, udp)
	Protocol string
	
	// ExternalPort is the external port
	ExternalPort int
	
	// InternalIP is the internal IP address
	InternalIP string
	
	// InternalPort is the internal port
	InternalPort int
	
	// Description is an optional description
	Description string
}

// IPv6Translation represents an IPv6 translation for NAT66
type IPv6Translation struct {
	// SourcePrefix is the source IPv6 prefix
	SourcePrefix string
	
	// DestinationIP is the destination IPv6 address
	DestinationIP string
	
	// TranslatedSourcePrefix is the translated source IPv6 prefix
	TranslatedSourcePrefix string
	
	// TranslatedDestinationIP is the translated destination IPv6 address
	TranslatedDestinationIP string
}

// Config represents a NAT configuration
type Config struct {
	// Name is the name of the NAT policy
	Name string
	
	// Namespace is the namespace of the NAT policy
	Namespace string
	
	// Type is the type of NAT policy
	Type PolicyType
	
	// Interface is the interface to apply the NAT policy to
	Interface string
	
	// ExternalIP is the external IP address for SNAT/DNAT
	ExternalIP string
	
	// SourceAddresses are the source addresses for SNAT/Masquerade
	SourceAddresses []string
	
	// PortMappings are the port mappings for DNAT
	PortMappings []PortMapping
	
	// IPv6Translations are the IPv6 translations for NAT66
	IPv6Translations []IPv6Translation
	
	// EnableTracking enables connection tracking
	EnableTracking bool
	
	// IPv6 indicates whether to use IPv6
	IPv6 bool
}

// Condition represents a condition in the NAT policy status
type Condition struct {
	// Type is the type of condition
	Type string
	
	// Status is the status of the condition
	Status string
	
	// LastTransitionTime is the last time the condition transitioned
	LastTransitionTime time.Time
	
	// Reason is the reason for the condition
	Reason string
	
	// Message is a human-readable message
	Message string
}

// Metrics represents metrics for a NAT policy
type Metrics struct {
	// Packets is the number of packets processed
	Packets int64
	
	// Bytes is the number of bytes processed
	Bytes int64
	
	// Translations is the number of translations
	Translations int64
}

// Status represents the status of a NAT policy
type Status struct {
	// ActiveConnections is the number of active connections
	ActiveConnections int64
	
	// Metrics are the metrics for the NAT policy
	Metrics Metrics
	
	// Conditions are the conditions for the NAT policy
	Conditions []Condition
}

// Manager defines the interface for managing NAT policies
type Manager interface {
	// ApplyNATPolicy applies a NAT policy
	ApplyNATPolicy(config Config) error
	
	// RemoveNATPolicy removes a NAT policy
	RemoveNATPolicy(name, namespace string) error
	
	// GetNATPolicyStatus gets the status of a NAT policy
	GetNATPolicyStatus(name, namespace string) (*Status, error)
	
	// ListNATPolicies lists all NAT policies
	ListNATPolicies() ([]Config, error)
}
