package nat

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Condition type constants for NAT policy status
const (
	// ConditionApplied indicates the policy has been successfully applied via Cilium
	ConditionApplied = "Applied"

	// ConditionDegraded indicates the policy was partially applied (some rules failed)
	ConditionDegraded = "Degraded"

	// ConditionInvalid indicates the policy spec failed validation
	ConditionInvalid = "Invalid"

	// ConditionRemoved indicates the policy has been removed (used during deletion)
	ConditionRemoved = "Removed"
)

// Condition status values
const (
	ConditionStatusTrue  = "True"
	ConditionStatusFalse = "False"
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

	// ObservedGeneration is the generation of the resource that was last reconciled
	ObservedGeneration int64

	// LastAppliedHash is the hash of the last applied config spec for idempotency
	LastAppliedHash string

	// LastAppliedTime is when the config was last applied to Cilium
	LastAppliedTime time.Time
}

// SpecHash computes a deterministic hash of the config spec for change detection
func (c Config) SpecHash() string {
	h := sha256.New()
	fmt.Fprintf(h, "type=%s,iface=%s,extIP=%s,tracking=%t,ipv6=%t",
		c.Type, c.Interface, c.ExternalIP, c.EnableTracking, c.IPv6)

	sortedSrc := make([]string, len(c.SourceAddresses))
	copy(sortedSrc, c.SourceAddresses)
	sort.Strings(sortedSrc)
	fmt.Fprintf(h, ",src=%s", strings.Join(sortedSrc, ";"))

	for _, pm := range c.PortMappings {
		fmt.Fprintf(h, ",pm=%s:%d->%s:%d", pm.Protocol, pm.ExternalPort, pm.InternalIP, pm.InternalPort)
	}
	for _, t := range c.IPv6Translations {
		fmt.Fprintf(h, ",v6=%s->%s/%s->%s", t.SourcePrefix, t.TranslatedSourcePrefix, t.DestinationIP, t.TranslatedDestinationIP)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ValidateConfig validates a NAT config and returns an error describing any problems
func ValidateConfig(config Config) error {
	if config.Name == "" {
		return fmt.Errorf("name is required")
	}
	if config.Interface == "" {
		return fmt.Errorf("interface is required")
	}

	switch config.Type {
	case TypeSNAT:
		if config.ExternalIP == "" {
			return fmt.Errorf("externalIP is required for SNAT")
		}
		if len(config.SourceAddresses) == 0 {
			return fmt.Errorf("sourceAddresses is required for SNAT")
		}
	case TypeDNAT:
		if config.ExternalIP == "" {
			return fmt.Errorf("externalIP is required for DNAT")
		}
		if len(config.PortMappings) == 0 {
			return fmt.Errorf("portMappings is required for DNAT")
		}
		for i, pm := range config.PortMappings {
			if pm.Protocol == "" {
				return fmt.Errorf("portMapping[%d]: protocol is required", i)
			}
			if pm.ExternalPort <= 0 || pm.ExternalPort > 65535 {
				return fmt.Errorf("portMapping[%d]: externalPort must be 1-65535", i)
			}
			if pm.InternalIP == "" {
				return fmt.Errorf("portMapping[%d]: internalIP is required", i)
			}
			if pm.InternalPort <= 0 || pm.InternalPort > 65535 {
				return fmt.Errorf("portMapping[%d]: internalPort must be 1-65535", i)
			}
		}
	case TypeMasquerade:
		if len(config.SourceAddresses) == 0 {
			return fmt.Errorf("sourceAddresses is required for masquerade")
		}
	case TypeFull:
		if config.ExternalIP == "" {
			return fmt.Errorf("externalIP is required for full NAT")
		}
		if len(config.SourceAddresses) == 0 {
			return fmt.Errorf("sourceAddresses is required for full NAT")
		}
	case TypeNAT66:
		if len(config.SourceAddresses) == 0 {
			return fmt.Errorf("sourceAddresses is required for NAT66")
		}
	case TypeNAT64:
		if len(config.SourceAddresses) == 0 {
			return fmt.Errorf("sourceAddresses is required for NAT64")
		}
	default:
		return fmt.Errorf("unsupported NAT type: %s", config.Type)
	}

	return nil
}

// ApplyResult holds the result of applying a NAT policy, including partial failure info
type ApplyResult struct {
	// Applied indicates whether the policy was applied (vs skipped for idempotency)
	Applied bool

	// Degraded indicates partial application failure
	Degraded bool

	// Error is the error message if degraded
	Error string
}

// Manager defines the interface for managing NAT policies
type Manager interface {
	// ApplyNATPolicy applies a NAT policy and returns the result
	ApplyNATPolicy(config Config) (*ApplyResult, error)

	// RemoveNATPolicy removes a NAT policy
	RemoveNATPolicy(name, namespace string) error

	// GetNATPolicyStatus gets the status of a NAT policy
	GetNATPolicyStatus(name, namespace string) (*Status, error)

	// ListNATPolicies lists all NAT policies
	ListNATPolicies() ([]Config, error)
}
