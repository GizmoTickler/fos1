package types

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

