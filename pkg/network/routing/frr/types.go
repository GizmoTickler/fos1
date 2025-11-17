package frr

// BGPNeighbor represents a BGP neighbor configuration for FRR
type BGPNeighbor struct {
	Address              string
	RemoteASNumber       int
	Description          string
	KeepaliveInterval    int
	HoldTime             int
	ConnectRetryInterval int
	BFDEnabled           bool
	RouteMapIn           string
	RouteMapOut          string
}

// BGPAddressFamily represents a BGP address family configuration for FRR
type BGPAddressFamily struct {
	Type           string // ipv4-unicast, ipv6-unicast, etc.
	Enabled        bool
	Redistributions []Redistribution
	Networks       []string
}

// Redistribution represents route redistribution configuration for FRR
type Redistribution struct {
	Protocol    string
	RouteMapRef string
}

// OSPFArea represents an OSPF area configuration for FRR
type OSPFArea struct {
	AreaID    string
	Interfaces []OSPFInterface
	StubArea   bool
	NSSAArea   bool
}

// OSPFInterface represents an OSPF interface configuration for FRR
type OSPFInterface struct {
	Name       string
	Network    string
	Cost       int
	Priority   int
}

// BFDPeer represents a BFD peer configuration for FRR
type BFDPeer struct {
	Address    string
	Interface  string
	LocalAddr  string
	SourceAddr string
	Multihop   bool
}

// RouteMap represents a route map configuration for FRR
type RouteMap struct {
	Name      string
	Entries   []RouteMapEntry
}

// RouteMapEntry represents a route map entry for FRR
type RouteMapEntry struct {
	Sequence  int
	Action    string // permit, deny
	Match     RouteMapMatch
	Set       RouteMapSet
}

// RouteMapMatch represents match conditions for a route map entry
type RouteMapMatch struct {
	Prefix     string
	PrefixLen  string
	Protocol   string
	Community  string
	ASPath     string
	Metric     int
	Tag        string
}

// RouteMapSet represents set actions for a route map entry
type RouteMapSet struct {
	Metric         int
	LocalPreference int
	Community      string
	NextHop        string
	Weight         int
	ASPathPrepend  string
}

// DaemonType represents the type of FRR daemon
type DaemonType string

const (
	// DaemonTypeBGPD is the BGP daemon
	DaemonTypeBGPD DaemonType = "bgpd"
	// DaemonTypeOSPFD is the OSPF daemon
	DaemonTypeOSPFD DaemonType = "ospfd"
	// DaemonTypeOSPF6D is the OSPFv3 daemon
	DaemonTypeOSPF6D DaemonType = "ospf6d"
	// DaemonTypeRIPD is the RIP daemon
	DaemonTypeRIPD DaemonType = "ripd"
	// DaemonTypeRIPNGD is the RIPng daemon
	DaemonTypeRIPNGD DaemonType = "ripngd"
	// DaemonTypeISISD is the IS-IS daemon
	DaemonTypeISISD DaemonType = "isisd"
	// DaemonTypePIMD is the PIM daemon
	DaemonTypePIMD DaemonType = "pimd"
	// DaemonTypeLDPD is the LDP daemon
	DaemonTypeLDPD DaemonType = "ldpd"
	// DaemonTypeNHRPD is the NHRP daemon
	DaemonTypeNHRPD DaemonType = "nhrpd"
	// DaemonTypeBFDD is the BFD daemon
	DaemonTypeBFDD DaemonType = "bfdd"
	// DaemonTypeFABRICD is the OpenFabric daemon
	DaemonTypeFABRICD DaemonType = "fabricd"
	// DaemonTypeZEBRA is the zebra routing manager
	DaemonTypeZEBRA DaemonType = "zebra"
)

// DaemonStatus represents the status of an FRR daemon
type DaemonStatus string

const (
	// DaemonStatusRunning indicates the daemon is running
	DaemonStatusRunning DaemonStatus = "running"
	// DaemonStatusStopped indicates the daemon is stopped
	DaemonStatusStopped DaemonStatus = "stopped"
	// DaemonStatusFailed indicates the daemon has failed
	DaemonStatusFailed DaemonStatus = "failed"
	// DaemonStatusUnknown indicates the daemon status is unknown
	DaemonStatusUnknown DaemonStatus = "unknown"
)

// DaemonInfo contains information about an FRR daemon
type DaemonInfo struct {
	// Type is the daemon type
	Type DaemonType
	// Status is the current daemon status
	Status DaemonStatus
	// PID is the process ID (if running)
	PID int
	// Version is the daemon version
	Version string
	// Uptime is how long the daemon has been running
	Uptime string
	// VTYPort is the VTY port number
	VTYPort int
}

// BGPNeighborStatus represents the runtime status of a BGP neighbor
type BGPNeighborStatus struct {
	// IP is the neighbor IP address
	IP string
	// ASN is the neighbor AS number
	ASN uint32
	// State is the BGP session state
	State string
	// Uptime is how long the session has been established
	Uptime string
	// PrefixReceived is the number of prefixes received
	PrefixReceived int
	// PrefixSent is the number of prefixes sent
	PrefixSent int
}

// BGPSummary contains BGP summary information
type BGPSummary struct {
	// RouterID is the local router ID
	RouterID string
	// LocalAS is the local AS number
	LocalAS uint32
	// Neighbors is the list of BGP neighbors
	Neighbors []BGPNeighborStatus
	// TableVersion is the BGP table version
	TableVersion uint64
	// TotalPrefixes is the total number of prefixes
	TotalPrefixes int
}

// OSPFNeighborStatus represents the runtime status of an OSPF neighbor
type OSPFNeighborStatus struct {
	// RouterID is the neighbor router ID
	RouterID string
	// Priority is the neighbor priority
	Priority int
	// State is the OSPF neighbor state
	State string
	// DeadTime is the dead timer
	DeadTime string
	// Address is the neighbor address
	Address string
	// Interface is the interface name
	Interface string
}

// OSPFInterfaceStatus represents the runtime status of an OSPF interface
type OSPFInterfaceStatus struct {
	// Name is the interface name
	Name string
	// State is the interface state
	State string
	// Address is the interface address
	Address string
	// Cost is the interface cost
	Cost int
	// Priority is the interface priority
	Priority int
	// DR is the designated router
	DR string
	// BDR is the backup designated router
	BDR string
	// Neighbors is the number of neighbors
	Neighbors int
}

// OSPFSummary contains OSPF summary information
type OSPFSummary struct {
	// RouterID is the router ID
	RouterID string
	// Areas is the number of areas
	Areas int
	// Interfaces is the list of OSPF interfaces
	Interfaces []OSPFInterfaceStatus
	// Neighbors is the list of OSPF neighbors
	Neighbors []OSPFNeighborStatus
	// LSACount is the total number of LSAs
	LSACount int
}

// Route represents a routing table entry
type Route struct {
	// Prefix is the destination prefix
	Prefix string
	// NextHop is the next hop address
	NextHop string
	// Interface is the outgoing interface
	Interface string
	// Protocol is the routing protocol
	Protocol string
	// Metric is the route metric
	Metric int
	// Distance is the administrative distance
	Distance int
	// Selected indicates if this route is selected
	Selected bool
	// FIBInstalled indicates if the route is installed in the FIB
	FIBInstalled bool
}

// RoutingTable represents the routing table
type RoutingTable struct {
	// Routes is the list of routes
	Routes []Route
	// TotalRoutes is the total number of routes
	TotalRoutes int
	// SelectedRoutes is the number of selected routes
	SelectedRoutes int
	// FIBRoutes is the number of routes in the FIB
	FIBRoutes int
}

// ConfigSection represents a section of FRR configuration
type ConfigSection struct {
	// Name is the section name (e.g., "router bgp")
	Name string
	// Commands is the list of configuration commands
	Commands []string
	// Subsections is the list of subsections
	Subsections []ConfigSection
}

// Config represents the complete FRR configuration
type Config struct {
	// Hostname is the router hostname
	Hostname string
	// Password is the VTY password (encrypted)
	Password string
	// EnablePassword is the enable password (encrypted)
	EnablePassword string
	// LogFile is the log file path
	LogFile string
	// LogLevel is the logging level
	LogLevel string
	// Sections is the list of configuration sections
	Sections []ConfigSection
}

// CommandResult represents the result of a vtysh command
type CommandResult struct {
	// Command is the command that was executed
	Command string
	// Output is the command output
	Output string
	// Error is any error that occurred
	Error error
	// Duration is how long the command took
	Duration string
}

// ClientConfig contains configuration for the FRR client
type ClientConfig struct {
	// VTYSHPath is the path to the vtysh binary
	VTYSHPath string
	// SocketPath is the path to the FRR VTY socket
	SocketPath string
	// ConfigPath is the path to the FRR configuration directory
	ConfigPath string
	// CommandTimeout is the timeout for commands (in seconds)
	CommandTimeout int
	// MaxRetries is the maximum number of retries for commands
	MaxRetries int
	// RetryDelay is the delay between retries (in seconds)
	RetryDelay int
}

// DefaultClientConfig returns the default client configuration
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		VTYSHPath:      "/usr/bin/vtysh",
		SocketPath:     "/var/run/frr",
		ConfigPath:     "/etc/frr",
		CommandTimeout: 30,
		MaxRetries:     3,
		RetryDelay:     1,
	}
}
