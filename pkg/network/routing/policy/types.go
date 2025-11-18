package policy

import (
	"time"
)

// RoutingPolicy represents a policy-based routing policy
type RoutingPolicy struct {
	// Name is the name of the policy
	Name string
	
	// Namespace is the namespace of the policy
	Namespace string
	
	// Description is an optional description
	Description string
	
	// Priority is the priority of the policy (lower number = higher priority)
	Priority int
	
	// Match is the match criteria for the policy
	Match PolicyMatch
	
	// Action is the action to take when the policy matches
	Action PolicyAction
	
	// VRF is the VRF this policy applies to
	VRF string
}

// PolicyMatch represents the match criteria for a routing policy
type PolicyMatch struct {
	// Source is the source match criteria
	Source SourceMatch
	
	// Destination is the destination match criteria
	Destination DestinationMatch
	
	// Protocol is the protocol to match (tcp, udp, icmp, all)
	Protocol string
	
	// Ports is a list of port ranges to match
	Ports []PortRange
	
	// Applications is a list of applications to match (requires DPI)
	Applications []string
	
	// TrafficType is a list of traffic types to match
	TrafficType []string
	
	// Time is the time match criteria
	Time TimeMatch
}

// SourceMatch represents the source match criteria
type SourceMatch struct {
	// Networks is a list of source networks to match
	Networks []string
	
	// Interfaces is a list of source interfaces to match
	Interfaces []string
}

// DestinationMatch represents the destination match criteria
type DestinationMatch struct {
	// Networks is a list of destination networks to match
	Networks []string
}

// PortRange represents a range of ports
type PortRange struct {
	// Start is the first port in the range
	Start int
	
	// End is the last port in the range
	End int
}

// TimeMatch represents the time match criteria
type TimeMatch struct {
	// DaysOfWeek is a list of days of the week to match
	DaysOfWeek []string
	
	// TimeOfDay is a list of time ranges to match
	TimeOfDay []TimeOfDay
}

// TimeOfDay represents a time range
type TimeOfDay struct {
	// Start is the start time (HH:MM)
	Start string
	
	// End is the end time (HH:MM)
	End string
}

// PolicyAction represents the action to take when a policy matches
type PolicyAction struct {
	// Type is the type of action (route, table, nat)
	Type string
	
	// NextHop is the next hop for route actions
	NextHop string
	
	// Table is the routing table for table actions
	Table string
	
	// Mark is the packet mark to set
	Mark int
	
	// DSCP is the DSCP value to set
	DSCP int
}

// PolicyStatus represents the status of a routing policy
type PolicyStatus struct {
	// Active indicates whether the policy is active
	Active bool
	
	// MatchCount is the number of times the policy has matched
	MatchCount int64
	
	// LastMatched is the last time the policy matched
	LastMatched time.Time
}

// Manager defines the interface for managing routing policies
type Manager interface {
	// ApplyPolicy applies a routing policy
	ApplyPolicy(policy RoutingPolicy) error
	
	// RemovePolicy removes a routing policy
	RemovePolicy(name, namespace string) error
	
	// GetPolicyStatus gets the status of a routing policy
	GetPolicyStatus(name, namespace string) (*PolicyStatus, error)
	
	// ListPolicies lists all routing policies
	ListPolicies() ([]RoutingPolicy, error)
	
	// EvaluatePacket evaluates a packet against all policies
	EvaluatePacket(packet PacketInfo) (*PolicyAction, error)
}

// PacketInfo represents information about a packet for policy evaluation
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
	
	// TrafficType is the traffic type
	TrafficType string
	
	// VRF is the VRF the packet is in
	VRF string
}

// IPRule represents a Linux IP rule for policy-based routing
type IPRule struct {
	// Priority is the priority of the rule (lower number = higher priority)
	Priority int

	// Table is the routing table to use
	Table int

	// Src is the source network to match (CIDR notation)
	Src string

	// Dst is the destination network to match (CIDR notation)
	Dst string

	// IifName is the input interface name to match
	IifName string

	// OifName is the output interface name to match
	OifName string

	// Mark is the fwmark to match
	Mark int

	// Mask is the fwmark mask
	Mask int

	// Tos is the TOS/DSCP value to match
	Tos int

	// Family is the address family (ipv4, ipv6, all)
	Family string

	// Action is the action to take (table, blacklist, prohibit, unreachable)
	Action string
}

// Address family constants
const (
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
	FamilyAll  = "all"
)

// Action constants
const (
	ActionToTable     = "table"
	ActionBlacklist   = "blacklist"
	ActionProhibit    = "prohibit"
	ActionUnreachable = "unreachable"
)

// Reserved routing table IDs
const (
	// Standard Linux routing tables
	TableUnspec  = 0   // RT_TABLE_UNSPEC
	TableDefault = 253 // RT_TABLE_DEFAULT
	TableMain    = 254 // RT_TABLE_MAIN
	TableLocal   = 255 // RT_TABLE_LOCAL

	// Custom routing tables start at 1
	TableCustomStart = 1
	TableCustomEnd   = 252
)
