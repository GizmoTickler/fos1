package ipam

import (
	"net"
	"time"
)

// AddressFamily represents the IP address family (IPv4 or IPv6)
type AddressFamily int

const (
	// FamilyIPv4 represents IPv4 addresses
	FamilyIPv4 AddressFamily = 4
	// FamilyIPv6 represents IPv6 addresses
	FamilyIPv6 AddressFamily = 6
	// FamilyAll represents both IPv4 and IPv6
	FamilyAll AddressFamily = 0
)

// AddressState represents the state of an IP address
type AddressState string

const (
	// StateUnknown indicates the address state is unknown
	StateUnknown AddressState = "unknown"
	// StateTentative indicates the address is undergoing duplicate address detection
	StateTentative AddressState = "tentative"
	// StateValid indicates the address is valid and in use
	StateValid AddressState = "valid"
	// StateDuplicate indicates the address is a duplicate
	StateDuplicate AddressState = "duplicate"
	// StateDeprecated indicates the address is deprecated
	StateDeprecated AddressState = "deprecated"
	// StateFailed indicates the address failed to be configured
	StateFailed AddressState = "failed"
)

// AddressScope represents the scope of an IP address
type AddressScope int

const (
	// ScopeGlobal indicates a globally routable address
	ScopeGlobal AddressScope = 0
	// ScopeSite indicates a site-local address
	ScopeSite AddressScope = 200
	// ScopeLink indicates a link-local address
	ScopeLink AddressScope = 253
	// ScopeHost indicates a host-local address
	ScopeHost AddressScope = 254
)

// IPAddress represents a managed IP address
type IPAddress struct {
	// Interface is the interface name this address is assigned to
	Interface string
	// Address is the IP address with prefix (e.g., "192.168.1.1/24")
	Address string
	// IP is the parsed IP address
	IP net.IP
	// Network is the parsed network
	Network *net.IPNet
	// Family is the address family (IPv4 or IPv6)
	Family AddressFamily
	// Scope is the address scope
	Scope AddressScope
	// State is the current state of the address
	State AddressState
	// Label is an optional label for the address
	Label string
	// Broadcast is the broadcast address (IPv4 only)
	Broadcast net.IP
	// PreferredLifetime is the preferred lifetime for the address
	PreferredLifetime time.Duration
	// ValidLifetime is the valid lifetime for the address
	ValidLifetime time.Duration
	// CreatedAt is when this address was created
	CreatedAt time.Time
	// UpdatedAt is when this address was last updated
	UpdatedAt time.Time
	// Flags contains additional flags
	Flags AddressFlags
}

// AddressFlags contains additional flags for an IP address
type AddressFlags struct {
	// Permanent indicates the address is permanent
	Permanent bool
	// Secondary indicates the address is a secondary address
	Secondary bool
	// Temporary indicates the address is temporary (IPv6 privacy extensions)
	Temporary bool
	// Deprecated indicates the address is deprecated
	Deprecated bool
	// Tentative indicates the address is tentative (undergoing DAD)
	Tentative bool
	// DadFailed indicates duplicate address detection failed
	DadFailed bool
	// HomeAddress indicates this is a home address (Mobile IPv6)
	HomeAddress bool
	// Optimistic indicates optimistic DAD is being used
	Optimistic bool
	// NoPrefixRoute indicates no automatic prefix route should be created
	NoPrefixRoute bool
	// ManagementTemp indicates this is a temporary management address
	ManagementTemp bool
}

// Subnet represents a managed subnet
type Subnet struct {
	// CIDR is the subnet in CIDR notation (e.g., "192.168.1.0/24")
	CIDR string
	// Network is the parsed network
	Network *net.IPNet
	// Family is the address family
	Family AddressFamily
	// Gateway is the default gateway for this subnet
	Gateway net.IP
	// StartIP is the start of the allocatable IP range
	StartIP net.IP
	// EndIP is the end of the allocatable IP range
	EndIP net.IP
	// Allocations tracks allocated addresses
	Allocations map[string]*IPAddress
	// Reserved tracks reserved addresses that should not be allocated
	Reserved map[string]bool
	// Description is an optional description
	Description string
}

// AllocationRequest represents a request to allocate an IP address
type AllocationRequest struct {
	// Interface is the interface to assign the address to
	Interface string
	// Subnet is the subnet to allocate from (optional, can be auto-detected)
	Subnet string
	// Family is the desired address family
	Family AddressFamily
	// PreferredIP is a preferred IP address (optional)
	PreferredIP net.IP
	// Label is an optional label for the address
	Label string
	// Scope is the desired scope
	Scope AddressScope
	// Permanent indicates if the address should be permanent
	Permanent bool
}

// AddressUpdate represents an address update event from the kernel
type AddressUpdate struct {
	// Interface is the interface name
	Interface string
	// Address is the IP address
	Address *IPAddress
	// Type is the update type (add, delete, change)
	Type AddressUpdateType
	// Timestamp is when the update occurred
	Timestamp time.Time
}

// AddressUpdateType represents the type of address update
type AddressUpdateType int

const (
	// AddressAdded indicates an address was added
	AddressAdded AddressUpdateType = 0
	// AddressDeleted indicates an address was deleted
	AddressDeleted AddressUpdateType = 1
	// AddressUpdated indicates an address was updated
	AddressUpdated AddressUpdateType = 2
)

// String returns the string representation of AddressUpdateType
func (t AddressUpdateType) String() string {
	switch t {
	case AddressAdded:
		return "added"
	case AddressDeleted:
		return "deleted"
	case AddressUpdated:
		return "updated"
	default:
		return "unknown"
	}
}

// String returns the string representation of AddressFamily
func (f AddressFamily) String() string {
	switch f {
	case FamilyIPv4:
		return "IPv4"
	case FamilyIPv6:
		return "IPv6"
	case FamilyAll:
		return "All"
	default:
		return "Unknown"
	}
}

// String returns the string representation of AddressScope
func (s AddressScope) String() string {
	switch s {
	case ScopeGlobal:
		return "global"
	case ScopeSite:
		return "site"
	case ScopeLink:
		return "link"
	case ScopeHost:
		return "host"
	default:
		return "unknown"
	}
}

// IsIPv4 returns true if the address is IPv4
func (a *IPAddress) IsIPv4() bool {
	return a.Family == FamilyIPv4
}

// IsIPv6 returns true if the address is IPv6
func (a *IPAddress) IsIPv6() bool {
	return a.Family == FamilyIPv6
}

// IsTentative returns true if the address is tentative (undergoing DAD)
func (a *IPAddress) IsTentative() bool {
	return a.State == StateTentative || a.Flags.Tentative
}

// IsDuplicate returns true if the address is a duplicate
func (a *IPAddress) IsDuplicate() bool {
	return a.State == StateDuplicate || a.Flags.DadFailed
}

// IsValid returns true if the address is valid
func (a *IPAddress) IsValid() bool {
	return a.State == StateValid
}

// PrefixLength returns the prefix length of the address
func (a *IPAddress) PrefixLength() int {
	if a.Network == nil {
		return 0
	}
	ones, _ := a.Network.Mask.Size()
	return ones
}

// Contains checks if an IP is within this subnet
func (s *Subnet) Contains(ip net.IP) bool {
	if s.Network == nil {
		return false
	}
	return s.Network.Contains(ip)
}

// IsIPv4 returns true if the subnet is IPv4
func (s *Subnet) IsIPv4() bool {
	return s.Family == FamilyIPv4
}

// IsIPv6 returns true if the subnet is IPv6
func (s *Subnet) IsIPv6() bool {
	return s.Family == FamilyIPv6
}

// Size returns the number of addresses in the subnet
func (s *Subnet) Size() uint64 {
	if s.Network == nil {
		return 0
	}
	ones, bits := s.Network.Mask.Size()
	if bits-ones >= 63 {
		// Too large to represent as uint64
		return 0
	}
	return 1 << uint(bits-ones)
}

// Available returns the number of available addresses in the subnet
func (s *Subnet) Available() uint64 {
	total := s.Size()
	if total == 0 {
		return 0
	}
	allocated := uint64(len(s.Allocations))
	reserved := uint64(len(s.Reserved))
	if allocated+reserved >= total {
		return 0
	}
	return total - allocated - reserved
}
