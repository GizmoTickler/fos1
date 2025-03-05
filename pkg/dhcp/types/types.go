package types

import "time"

// DHCPv4SubnetConfig represents a configuration for a DHCPv4 subnet
type DHCPv4SubnetConfig struct {
	Subnet        string            // Subnet in CIDR notation (e.g., "192.168.1.0/24")
	Pools         []Pool            // Pools of addresses to allocate
	Options       []DHCPOption      // DHCP options to provide
	Reservations  []DHCPv4Reservation // Static reservations
	ValidLifetime int               // Lease time in seconds
	RenewTimer    int               // Renew timer in seconds
	RebindTimer   int               // Rebind timer in seconds
}

// DHCPv6SubnetConfig represents a configuration for a DHCPv6 subnet
type DHCPv6SubnetConfig struct {
	Subnet             string            // Subnet in CIDR notation (e.g., "2001:db8::/64")
	Pools              []Pool            // Pools of addresses to allocate
	PrefixDelegation   *PrefixDelegation // Prefix delegation configuration
	Options            []DHCPOption      // DHCP options to provide
	Reservations       []DHCPv6Reservation // Static reservations
	ValidLifetime      int               // Lease time in seconds
	PreferredLifetime  int               // Preferred lifetime in seconds
	RenewTimer         int               // Renew timer in seconds
	RebindTimer        int               // Rebind timer in seconds
}

// Pool represents a range of IP addresses
type Pool struct {
	Start string // Start of the range
	End   string // End of the range
}

// PrefixDelegation represents prefix delegation configuration for DHCPv6
type PrefixDelegation struct {
	Prefix       string // Prefix to delegate
	PrefixLength int    // Length of the prefix
	DelegatedLen int    // Length of delegated prefixes
}

// DHCPOption represents a DHCP option
type DHCPOption struct {
	Name  string // Name of the option
	Code  int    // DHCP option code
	Data  string // Option value
}

// DHCPv4Reservation represents a static reservation for DHCPv4
type DHCPv4Reservation struct {
	HWAddress  string      // MAC address
	ClientID   string      // Client identifier
	IPAddress  string      // Reserved IP address
	Hostname   string      // Client hostname
	Options    []DHCPOption // Client-specific options
}

// DHCPv6Reservation represents a static reservation for DHCPv6
type DHCPv6Reservation struct {
	DUID       string      // DUID
	HWAddress  string      // MAC address
	IPAddress  string      // Reserved IP address
	Prefix     string      // Reserved prefix
	Hostname   string      // Client hostname
	Options    []DHCPOption // Client-specific options
}

// Lease represents a DHCP lease
type Lease struct {
	IP        string    // Leased IP address
	Hostname  string    // Client hostname
	MAC       string    // Client MAC address
	ClientID  string    // Client identifier
	DUID      string    // DHCPv6 DUID
	VLANRef   string    // Reference to the VLAN
	Domain    string    // Domain for the hostname
	TTL       uint32    // TTL for DNS records
	ExpiresAt time.Time // When the lease expires
}