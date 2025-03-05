package kea

// DHCPv4Config is the top-level configuration for Kea DHCP4
type DHCPv4Config struct {
	Dhcp4 DHCPv4 `json:"Dhcp4"`
}

// DHCPv4 is the main configuration section for Kea DHCP4
type DHCPv4 struct {
	InterfacesConfig InterfacesConfig    `json:"interfaces-config"`
	ControlSocket    ControlSocket       `json:"control-socket"`
	LeaseDatabase    LeaseDatabase       `json:"lease-database"`
	ValidLifetime    int                 `json:"valid-lifetime"`
	RenewTimer       int                 `json:"renew-timer"`
	RebindTimer      int                 `json:"rebind-timer"`
	OptionData       []DHCPOption        `json:"option-data,omitempty"`
	Subnet4          []DHCPv4Subnet      `json:"subnet4"`
	Loggers          []Logger            `json:"loggers"`
	HooksLibraries   []HooksLibrary      `json:"hooks-libraries,omitempty"`
}

// DHCPv6Config is the top-level configuration for Kea DHCP6
type DHCPv6Config struct {
	Dhcp6 DHCPv6 `json:"Dhcp6"`
}

// DHCPv6 is the main configuration section for Kea DHCP6
type DHCPv6 struct {
	InterfacesConfig   InterfacesConfig    `json:"interfaces-config"`
	ControlSocket      ControlSocket       `json:"control-socket"`
	LeaseDatabase      LeaseDatabase       `json:"lease-database"`
	PreferredLifetime  int                 `json:"preferred-lifetime"`
	ValidLifetime      int                 `json:"valid-lifetime"`
	RenewTimer         int                 `json:"renew-timer"`
	RebindTimer        int                 `json:"rebind-timer"`
	OptionData         []DHCPOption        `json:"option-data,omitempty"`
	Subnet6            []DHCPv6Subnet      `json:"subnet6"`
	Loggers            []Logger            `json:"loggers"`
	HooksLibraries     []HooksLibrary      `json:"hooks-libraries,omitempty"`
}

// InterfacesConfig configures which network interfaces Kea will use
type InterfacesConfig struct {
	Interfaces []string `json:"interfaces"`
}

// ControlSocket configures the socket Kea uses for control commands
type ControlSocket struct {
	SocketType string `json:"socket-type"`
	SocketName string `json:"socket-name"`
}

// LeaseDatabase configures where Kea stores lease information
type LeaseDatabase struct {
	Type    string `json:"type"`
	Persist bool   `json:"persist"`
	Name    string `json:"name"`
}

// HooksLibrary configures a Kea hooks library
type HooksLibrary struct {
	Library    string                 `json:"library"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// Logger configures Kea logging
type Logger struct {
	Name           string         `json:"name"`
	OutputOptions  []OutputOption `json:"output_options"`
	Severity       string         `json:"severity"`
	DebuggerLevel  int            `json:"debugger-level,omitempty"`
}

// OutputOption configures a logger output destination
type OutputOption struct {
	Output  string `json:"output"`
	Pattern string `json:"pattern,omitempty"`
}

// DHCPOption represents a DHCP option
type DHCPOption struct {
	Name       string `json:"name"`
	Data       string `json:"data"`
	AlwaysSend bool   `json:"always-send,omitempty"`
	Code       int    `json:"code,omitempty"`
}

// DHCPPool represents a range of IP addresses
type DHCPPool struct {
	Pool string `json:"pool"`
}

// DHCPv4Subnet represents a DHCP subnet configuration
type DHCPv4Subnet struct {
	ID              int                `json:"id"`
	Subnet          string             `json:"subnet"`
	Pools           []DHCPPool         `json:"pools,omitempty"`
	OptionData      []DHCPOption       `json:"option-data,omitempty"`
	Reservations    []DHCPv4Reservation `json:"reservations,omitempty"`
	ValidLifetime   int                `json:"valid-lifetime,omitempty"`
	RenewTimer      int                `json:"renew-timer,omitempty"`
	RebindTimer     int                `json:"rebind-timer,omitempty"`
}

// DHCPv4Reservation represents a static reservation for DHCPv4
type DHCPv4Reservation struct {
	HWAddress       string        `json:"hw-address,omitempty"`
	IPAddress       string        `json:"ip-address"`
	ClientID        string        `json:"client-id,omitempty"`
	CircuitID       string        `json:"circuit-id,omitempty"`
	Hostname        string        `json:"hostname,omitempty"`
	OptionData      []DHCPOption  `json:"option-data,omitempty"`
}

// DHCPv6Subnet represents a DHCPv6 subnet configuration
type DHCPv6Subnet struct {
	ID                 int                `json:"id"`
	Subnet             string             `json:"subnet"`
	Pools              []DHCPPool         `json:"pools,omitempty"`
	PdPools            []PDPool           `json:"pd-pools,omitempty"`
	OptionData         []DHCPOption       `json:"option-data,omitempty"`
	Reservations       []DHCPv6Reservation `json:"reservations,omitempty"`
	ValidLifetime      int                `json:"valid-lifetime,omitempty"`
	PreferredLifetime  int                `json:"preferred-lifetime,omitempty"`
	RenewTimer         int                `json:"renew-timer,omitempty"`
	RebindTimer        int                `json:"rebind-timer,omitempty"`
}

// PDPool represents a prefix delegation pool
type PDPool struct {
	Prefix            string  `json:"prefix"`
	PrefixLen         int     `json:"prefix-len"`
	DelegatedLen      int     `json:"delegated-len"`
}

// DHCPv6Reservation represents a static reservation for DHCPv6
type DHCPv6Reservation struct {
	DUID              string        `json:"duid,omitempty"`
	HWAddress         string        `json:"hw-address,omitempty"`
	IPAddresses       []string      `json:"ip-addresses,omitempty"`
	Prefixes          []string      `json:"prefixes,omitempty"`
	Hostname          string        `json:"hostname,omitempty"`
	OptionData        []DHCPOption  `json:"option-data,omitempty"`
}

// NewDHCPv4Config creates a new default DHCPv4 configuration
func NewDHCPv4Config() *DHCPv4Config {
	return &DHCPv4Config{
		Dhcp4: DHCPv4{
			InterfacesConfig: InterfacesConfig{
				Interfaces: []string{"*"},
			},
			ControlSocket: ControlSocket{
				SocketType: "unix",
				SocketName: "/var/run/kea/kea4-ctrl-socket",
			},
			LeaseDatabase: LeaseDatabase{
				Type:    "memfile",
				Persist: true,
				Name:    "/var/lib/kea/dhcp4.leases",
			},
			ValidLifetime: 86400,    // 1 day
			RenewTimer:    43200,    // 12 hours
			RebindTimer:   75600,    // 21 hours
			Subnet4:       []DHCPv4Subnet{},
			Loggers: []Logger{
				{
					Name: "kea-dhcp4",
					OutputOptions: []OutputOption{
						{
							Output:  "stdout",
							Pattern: "%-5p %m\n",
						},
					},
					Severity: "INFO",
				},
			},
		},
	}
}

// NewDHCPv6Config creates a new default DHCPv6 configuration
func NewDHCPv6Config() *DHCPv6Config {
	return &DHCPv6Config{
		Dhcp6: DHCPv6{
			InterfacesConfig: InterfacesConfig{
				Interfaces: []string{"*"},
			},
			ControlSocket: ControlSocket{
				SocketType: "unix",
				SocketName: "/var/run/kea/kea6-ctrl-socket",
			},
			LeaseDatabase: LeaseDatabase{
				Type:    "memfile",
				Persist: true,
				Name:    "/var/lib/kea/dhcp6.leases",
			},
			PreferredLifetime: 3600,     // 1 hour
			ValidLifetime:     86400,    // 1 day
			RenewTimer:        43200,    // 12 hours
			RebindTimer:       75600,    // 21 hours
			Subnet6:           []DHCPv6Subnet{},
			Loggers: []Logger{
				{
					Name: "kea-dhcp6",
					OutputOptions: []OutputOption{
						{
							Output:  "stdout",
							Pattern: "%-5p %m\n",
						},
					},
					Severity: "INFO",
				},
			},
		},
	}
}