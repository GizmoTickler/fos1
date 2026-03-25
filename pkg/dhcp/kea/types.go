// Package kea provides a client for the Kea DHCP control socket API.
package kea

// KeaCommand represents a command sent to the Kea control socket.
type KeaCommand struct {
	// Command is the Kea command name (e.g., "lease4-get", "config-get").
	Command string `json:"command"`

	// Service targets specific Kea services (e.g., ["dhcp4"], ["dhcp6"]).
	Service []string `json:"service,omitempty"`

	// Arguments contains command-specific parameters.
	Arguments any `json:"arguments,omitempty"`
}

// KeaResponse represents a single response element from the Kea control socket.
// Kea always returns responses as a JSON array, even for single responses.
type KeaResponse struct {
	// Result is the status code: 0=success, 1=error, 2=unsupported, 3=empty.
	Result int `json:"result"`

	// Text is a human-readable status message.
	Text string `json:"text"`

	// Arguments contains the response data, structure varies by command.
	Arguments any `json:"arguments,omitempty"`
}

// Lease4 represents a DHCPv4 lease returned by the Kea lease4-get commands.
type Lease4 struct {
	// Address is the leased IPv4 address.
	Address string `json:"ip-address"`

	// HWAddress is the client hardware (MAC) address.
	HWAddress string `json:"hw-address"`

	// SubnetID is the Kea subnet identifier.
	SubnetID int `json:"subnet-id"`

	// ValidLifetime is the lease valid lifetime in seconds.
	ValidLifetime int `json:"valid-lft"`

	// Expire is the lease expiration as a Unix timestamp.
	Expire int64 `json:"expire"`

	// Hostname is the client-provided hostname.
	Hostname string `json:"hostname,omitempty"`

	// State is the lease state (0=default, 1=declined, 2=expired-reclaimed).
	State int `json:"state"`

	// ClientID is the DHCP client identifier.
	ClientID string `json:"client-id,omitempty"`
}

// Lease6 represents a DHCPv6 lease returned by the Kea lease6-get commands.
type Lease6 struct {
	// Address is the leased IPv6 address or prefix.
	Address string `json:"ip-address"`

	// DUID is the client DHCP Unique Identifier.
	DUID string `json:"duid"`

	// SubnetID is the Kea subnet identifier.
	SubnetID int `json:"subnet-id"`

	// ValidLifetime is the lease valid lifetime in seconds.
	ValidLifetime int `json:"valid-lft"`

	// Expire is the lease expiration as a Unix timestamp.
	Expire int64 `json:"expire"`

	// Hostname is the client-provided hostname.
	Hostname string `json:"hostname,omitempty"`

	// State is the lease state (0=default, 1=declined, 2=expired-reclaimed).
	State int `json:"state"`

	// Type is the lease type: "IA_NA" for addresses, "IA_PD" for prefixes.
	Type string `json:"type"`

	// PrefixLen is the delegated prefix length (only for IA_PD leases).
	PrefixLen int `json:"prefix-len,omitempty"`

	// IAID is the Identity Association Identifier.
	IAID int `json:"iaid"`
}
