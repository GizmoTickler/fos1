package types

// KeaConfig represents the configuration for a Kea DHCP server
type KeaConfig struct {
	// Dhcp4 contains the DHCPv4 configuration
	Dhcp4 *Kea4Config `json:"Dhcp4,omitempty"`

	// Dhcp6 contains the DHCPv6 configuration
	Dhcp6 *Kea6Config `json:"Dhcp6,omitempty"`
}

// Kea4Config contains the DHCPv4 configuration for Kea
type Kea4Config struct {
	// Interfaces is a list of interfaces to listen on
	Interfaces []string `json:"interfaces"`

	// ControlSocket contains the control socket configuration
	ControlSocket KeaControlSocket `json:"control-socket"`

	// LeaseDatabase contains the lease database configuration
	LeaseDatabase KeaDatabase `json:"lease-database"`

	// ValidLifetime is the default lease time in seconds
	ValidLifetime int `json:"valid-lifetime"`

	// MaxValidLifetime is the maximum lease time in seconds
	MaxValidLifetime int `json:"max-valid-lifetime"`

	// Subnet4 contains a list of IPv4 subnets
	Subnet4 []KeaSubnet4 `json:"subnet4"`

	// Loggers contains the logging configuration
	Loggers []KeaLogger `json:"loggers"`

	// HookLibraries contains the hook libraries configuration
	HookLibraries []KeaHookLibrary `json:"hooks-libraries,omitempty"`
}

// Kea6Config contains the DHCPv6 configuration for Kea
type Kea6Config struct {
	// Interfaces is a list of interfaces to listen on
	Interfaces []string `json:"interfaces"`

	// ControlSocket contains the control socket configuration
	ControlSocket KeaControlSocket `json:"control-socket"`

	// LeaseDatabase contains the lease database configuration
	LeaseDatabase KeaDatabase `json:"lease-database"`

	// ValidLifetime is the default lease time in seconds
	ValidLifetime int `json:"valid-lifetime"`

	// MaxValidLifetime is the maximum lease time in seconds
	MaxValidLifetime int `json:"max-valid-lifetime"`

	// Subnet6 contains a list of IPv6 subnets
	Subnet6 []KeaSubnet6 `json:"subnet6"`

	// Loggers contains the logging configuration
	Loggers []KeaLogger `json:"loggers"`

	// HookLibraries contains the hook libraries configuration
	HookLibraries []KeaHookLibrary `json:"hooks-libraries,omitempty"`
}

// KeaControlSocket defines the control socket configuration for Kea
type KeaControlSocket struct {
	// SocketType is the socket type (usually "unix")
	SocketType string `json:"socket-type"`

	// SocketName is the socket file path
	SocketName string `json:"socket-name"`
}

// KeaDatabase defines the database configuration for Kea
type KeaDatabase struct {
	// Type is the database type (e.g., "memfile", "postgresql")
	Type string `json:"type"`

	// Name is the database name
	Name string `json:"name,omitempty"`

	// Host is the database host
	Host string `json:"host,omitempty"`

	// User is the database user
	User string `json:"user,omitempty"`

	// Password is the database password
	Password string `json:"password,omitempty"`
}

// KeaSubnet4 defines an IPv4 subnet for Kea
type KeaSubnet4 struct {
	// Subnet is the subnet CIDR
	Subnet string `json:"subnet"`

	// Pools contains a list of address pools
	Pools []KeaPool `json:"pools"`

	// ReservationMode defines how reservations are used
	ReservationMode string `json:"reservation-mode,omitempty"`

	// Reservations contains static reservations
	Reservations []KeaReservation4 `json:"reservations,omitempty"`

	// Option-data contains DHCP options
	OptionData []KeaOptionData `json:"option-data,omitempty"`
}

// KeaSubnet6 defines an IPv6 subnet for Kea
type KeaSubnet6 struct {
	// Subnet is the subnet CIDR
	Subnet string `json:"subnet"`

	// Pools contains a list of address pools
	Pools []KeaPool `json:"pools"`

	// ReservationMode defines how reservations are used
	ReservationMode string `json:"reservation-mode,omitempty"`

	// Reservations contains static reservations
	Reservations []KeaReservation6 `json:"reservations,omitempty"`

	// Option-data contains DHCP options
	OptionData []KeaOptionData `json:"option-data,omitempty"`
}

// KeaPool defines an address pool
type KeaPool struct {
	// Pool is the address range for the pool
	Pool string `json:"pool"`
}

// KeaReservation4 defines a DHCPv4 reservation
type KeaReservation4 struct {
	// Hostname is the client hostname
	Hostname string `json:"hostname"`

	// HwAddress is the client MAC address (optional)
	HwAddress string `json:"hw-address,omitempty"`

	// ClientID is the client identifier (optional)
	ClientID string `json:"client-id,omitempty"`

	// IPAddress is the reserved IP address
	IPAddress string `json:"ip-address"`
}

// KeaReservation6 defines a DHCPv6 reservation
type KeaReservation6 struct {
	// Hostname is the client hostname
	Hostname string `json:"hostname"`

	// DUID is the client DUID (optional)
	DUID string `json:"duid,omitempty"`

	// HwAddress is the client hardware address (optional)
	HwAddress string `json:"hw-address,omitempty"`

	// IPAddresses is a list of reserved IP addresses
	IPAddresses []string `json:"ip-addresses,omitempty"`
}

// KeaOptionData defines a DHCP option
type KeaOptionData struct {
	// Name is the option name (optional)
	Name string `json:"name,omitempty"`

	// Code is the option code
	Code int `json:"code"`

	// Data is the option value
	Data string `json:"data"`

	// AlwaysSend indicates whether to always send the option
	AlwaysSend bool `json:"always-send,omitempty"`
}

// KeaLogger defines a logger configuration
type KeaLogger struct {
	// Name is the logger name
	Name string `json:"name"`

	// OutputOptions contains output options
	OutputOptions []KeaOutputOption `json:"output_options"`

	// Severity is the logging severity
	Severity string `json:"severity"`

	// DebugLevel is the debug level
	DebugLevel int `json:"debuglevel,omitempty"`
}

// KeaOutputOption defines a logger output option
type KeaOutputOption struct {
	// Output is the output destination
	Output string `json:"output"`
}

// KeaHookLibrary defines a hook library
type KeaHookLibrary struct {
	// Library is the library path
	Library string `json:"library"`

	// Parameters contains library parameters
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}
