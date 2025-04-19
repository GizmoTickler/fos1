package cilium

import (
	"net"
)

// NetworkPolicy represents a Cilium network policy.
type NetworkPolicy struct {
	// Name of the policy
	Name string

	// Description provides documentation about the policy
	Description string

	// SourceLabels defines the labels that must match the source of the traffic
	SourceLabels map[string]string

	// DestinationLabels defines the labels that must match the destination of the traffic
	DestinationLabels map[string]string

	// Rules contains L3/L4/L7 rules for this policy
	Rules []Rule

	// Namespace where the policy should be applied, empty for cluster-wide policies
	Namespace string
}

// Rule represents a Cilium network policy rule.
type Rule struct {
	// Protocol specifies the protocol (TCP, UDP, ICMP, etc.)
	Protocol string

	// Ports is a list of ports to match (applicable to TCP/UDP)
	Ports []int

	// PortRanges is a list of port ranges to match
	PortRanges []PortRange

	// ICMPType is the ICMP type to match (for ICMP protocol)
	ICMPType *int

	// ICMPCode is the ICMP code to match (for ICMP protocol)
	ICMPCode *int

	// Action to take (allow, deny, log)
	Action string

	// L7Rules contains application layer rules (DNS, HTTP, etc.)
	L7Rules L7Rules
}

// PortRange represents a range of ports.
type PortRange struct {
	// First port in the range
	First int

	// Last port in the range
	Last int
}

// L7Rules contains application layer rules.
type L7Rules struct {
	// HTTP rules for HTTP traffic
	HTTP []HTTPRule

	// DNS rules for DNS traffic
	DNS []DNSRule

	// Kafka rules for Kafka traffic
	Kafka []KafkaRule
}

// HTTPRule represents an HTTP-specific rule.
type HTTPRule struct {
	// Method is the HTTP method (GET, POST, etc.)
	Method string

	// Path is the URL path to match
	Path string

	// Host is the host to match
	Host string

	// Headers are the HTTP headers to match
	Headers map[string]string
}

// DNSRule represents a DNS-specific rule.
type DNSRule struct {
	// Pattern is the DNS pattern to match
	Pattern string
}

// KafkaRule represents a Kafka-specific rule.
type KafkaRule struct {
	// Topic is the Kafka topic to match
	Topic string

	// ApiKey is the Kafka API key to match
	ApiKey int
}

// NATConfig represents configuration for NAT.
type NATConfig struct {
	// SourceNetwork is the source network to NAT
	SourceNetwork string

	// DestinationIface is the outgoing interface
	DestinationIface string

	// IPv6 indicates whether to use NAT66 for IPv6
	IPv6 bool

	// ExcludedCIDRs are CIDRs to exclude from NAT
	ExcludedCIDRs []string
}

// NAT64Config represents configuration for NAT64 (IPv6 to IPv4).
type NAT64Config struct {
	// SourceNetwork is the source IPv6 network
	SourceNetwork string

	// DestinationIface is the outgoing interface
	DestinationIface string

	// Prefix64 is the NAT64 prefix (default: 64:ff9b::/96)
	Prefix64 string

	// ExcludedCIDRs are CIDRs to exclude from NAT64
	ExcludedCIDRs []string
}

// PortForwardConfig represents configuration for port forwarding.
type PortForwardConfig struct {
	// ExternalIP is the external IP address
	ExternalIP string

	// ExternalPort is the external port
	ExternalPort int

	// Protocol is the protocol (tcp, udp)
	Protocol string

	// InternalIP is the internal IP address
	InternalIP string

	// InternalPort is the internal port
	InternalPort int

	// Description is an optional description
	Description string
}

// VLANRoutingConfig represents configuration for VLAN routing in Cilium.
type VLANRoutingConfig struct {
	// VLANs is a map of VLAN IDs to VLAN configurations
	VLANs map[int]VLANConfig
}

// VLANConfig represents configuration for a single VLAN.
type VLANConfig struct {
	// Name of the VLAN
	Name string

	// ParentInterface is the parent interface for this VLAN
	ParentInterface string

	// Subnets are the subnets assigned to this VLAN
	Subnets []string

	// MTU is the MTU for this VLAN
	MTU int

	// Labels are Cilium labels to apply to this VLAN
	Labels map[string]string
}

// DPIIntegrationConfig represents configuration for DPI integration.
type DPIIntegrationConfig struct {
	// Enabled indicates whether DPI integration is enabled
	Enabled bool

	// ApplicationsToMonitor is a list of application protocols to monitor
	ApplicationsToMonitor []string

	// EnforcementMode specifies whether to block detected applications or just log
	EnforcementMode string

	// TargetInterfaces specifies which interfaces to apply DPI to
	TargetInterfaces []string
}

// RouteSync represents a route to be synchronized with Cilium.
type RouteSync struct {
	// Destination is the destination CIDR
	Destination string

	// Gateway is the next-hop gateway
	Gateway net.IP

	// Interface is the outgoing interface
	Interface string

	// VRF is the VRF this route belongs to (optional)
	VRF string

	// Metric is the route metric/priority
	Metric int

	// TableID is the routing table ID
	TableID int

	// Labels are Cilium labels for this route
	Labels map[string]string
}

// IPLookupPolicy represents policy for looking up the endpoints to connect to.
type IPLookupPolicy struct {
	// SourcePrefixes is a list of source CIDRs
	SourcePrefixes []string

	// DestinationPrefixes is a list of destination CIDRs
	DestinationPrefixes []string

	// LookupPriority is the priority of this lookup policy
	LookupPriority int

	// Table is the routing table to use
	Table int
}

// Error codes returned by Cilium operations
const (
	// ErrPolicyExists indicates a policy with the same name already exists
	ErrPolicyExists = "PolicyExists"

	// ErrPolicyNotFound indicates a policy was not found
	ErrPolicyNotFound = "PolicyNotFound"

	// ErrInvalidPolicy indicates a policy is invalid
	ErrInvalidPolicy = "InvalidPolicy"

	// ErrOperationFailed indicates a Cilium operation failed
	ErrOperationFailed = "OperationFailed"
)

// Client defines the interface for interacting with Cilium
type Client interface {
	// ApplyNetworkPolicy applies a Cilium network policy
	ApplyNetworkPolicy(ctx context.Context, policy *NetworkPolicy) error

	// CreateNAT creates NAT rules using Cilium's capabilities
	CreateNAT(ctx context.Context, config *NATConfig) error

	// RemoveNAT removes NAT rules
	RemoveNAT(ctx context.Context, config *NATConfig) error

	// CreateNAT64 creates NAT64 rules (IPv6 to IPv4)
	CreateNAT64(ctx context.Context, config *NAT64Config) error

	// RemoveNAT64 removes NAT64 rules
	RemoveNAT64(ctx context.Context, config *NAT64Config) error

	// CreatePortForward creates port forwarding rules
	CreatePortForward(ctx context.Context, config *PortForwardConfig) error

	// RemovePortForward removes port forwarding rules
	RemovePortForward(ctx context.Context, config *PortForwardConfig) error

	// ConfigureVLANRouting configures routing between VLANs
	ConfigureVLANRouting(ctx context.Context, config *VLANRoutingConfig) error

	// ConfigureDPIIntegration configures DPI integration
	ConfigureDPIIntegration(ctx context.Context, config *DPIIntegrationConfig) error
}
