package routing

import (
	"time"
)

// RouteManager defines the interface for managing routes
type RouteManager interface {
	// AddRoute adds a new route
	AddRoute(route Route) error
	
	// DeleteRoute removes a route
	DeleteRoute(destination string, routeParams RouteParams) error
	
	// GetRoute retrieves a route
	GetRoute(destination string, routeParams RouteParams) (*Route, error)
	
	// ListRoutes lists all routes, optionally filtered
	ListRoutes(filter RouteFilter) ([]*Route, error)
	
	// UpdateRoute updates an existing route
	UpdateRoute(destination string, routeParams RouteParams, newRoute Route) error
	
	// GetRoutingTable retrieves the entire routing table
	GetRoutingTable(tableName string, vrf string) ([]*Route, error)
}

// Route represents a network route
type Route struct {
	Destination     string
	NextHops        []NextHop
	Metric          int
	Preference      int
	Protocol        string
	Scope           string
	VRF             string
	Table           string
	Preemptible     bool
	Tags            []string
	InstalledIn     []string
	LastUpdated     time.Time
	Error           string
}

// NextHop represents a next hop for a route
type NextHop struct {
	Address         string
	Interface       string
	Weight          int
}

// RouteParams provides parameters for route operations
type RouteParams struct {
	VRF             string
	Table           string
	Protocol        string
}

// RouteFilter provides filtering options for listing routes
type RouteFilter struct {
	Destination     string
	NextHop         string
	Protocol        string
	VRF             string
	Table           string
	Tag             string
}

// ProtocolManager defines the interface for managing routing protocols
type ProtocolManager interface {
	// StartProtocol starts a routing protocol
	StartProtocol(protocolName string, config ProtocolConfig) error
	
	// StopProtocol stops a routing protocol
	StopProtocol(protocolName string) error
	
	// RestartProtocol restarts a routing protocol
	RestartProtocol(protocolName string) error
	
	// GetProtocolStatus retrieves the status of a protocol
	GetProtocolStatus(protocolName string) (*ProtocolStatus, error)
	
	// ListProtocols lists all running protocols
	ListProtocols() ([]string, error)
	
	// UpdateProtocolConfig updates the configuration of a protocol
	UpdateProtocolConfig(protocolName string, config ProtocolConfig) error
	
	// GetProtocolRoutes retrieves routes learned via a specific protocol
	GetProtocolRoutes(protocolName string) ([]*Route, error)
}

// ProtocolConfig is a generic interface for protocol configuration
type ProtocolConfig interface {
	// GetProtocolName returns the name of the protocol
	GetProtocolName() string
}

// ProtocolStatus represents the status of a routing protocol
type ProtocolStatus struct {
	Name             string
	State            string
	Uptime           time.Duration
	StartTime        time.Time
	PrefixesReceived int
	PrefixesSent     int
	Neighbors        []NeighborStatus
}

// NeighborStatus represents the status of a routing protocol neighbor
type NeighborStatus struct {
	Address         string
	State           string
	Uptime          time.Duration
	PrefixesReceived int
	PrefixesSent    int
}

// BGPConfederation represents BGP confederation configuration
type BGPConfederation struct {
	Identifier      int
	Members         []int
	Peers           []int
}

// BGPConfig represents BGP protocol configuration
type BGPConfig struct {
	ASNumber          int
	RouterID          string
	Neighbors         []BGPNeighbor
	PeerGroups        []BGPPeerGroup
	AddressFamilies   []BGPAddressFamily
	RouteMaps         []RouteMap
	PrefixLists       []PrefixList
	ASPathLists       []ASPathAccessList
	CommunityLists    []CommunityList
	VRF               string
	EBGPMultihop      int
	DeterministicMED  bool
	Multipath         bool
	ClusterID         string
	Confederation     BGPConfederation
	GracefulRestart   bool
	LogNeighborChanges bool
	BestpathASPathMultipathRelax bool
	BestpathCompareRouterid bool
}

// GetProtocolName implements ProtocolConfig
func (c BGPConfig) GetProtocolName() string {
	return "bgp"
}

// BGPNeighbor represents a BGP neighbor configuration
type BGPNeighbor struct {
	Address              string
	RemoteASNumber       int
	Description          string
	KeepaliveInterval    int
	HoldTime             int
	ConnectRetryInterval int
	Authentication       BGPAuthentication
	BFDEnabled           bool
	PeerGroup            string
	RouteMapIn           string
	RouteMapOut          string
	PrefixListIn         string
	PrefixListOut        string
	FilterListIn         string
	FilterListOut        string
	MaxPrefixes          int
	DefaultOriginate     bool
	NextHopSelf          bool
	RemovePrivateAS      bool
	SendCommunity        bool
	SendExtendedCommunity bool
	SendLargeCommunity   bool
	Weight               int
	AllowASIn            int
}

// BGPAuthentication represents BGP authentication configuration
type BGPAuthentication struct {
	Type             string // md5, sha
	SecretRef        SecretRef
}

// SecretRef represents a reference to a secret
type SecretRef struct {
	Name             string
	Key              string
}

// BGPAddressFamily represents a BGP address family configuration
type BGPAddressFamily struct {
	Type                string // ipv4-unicast, ipv6-unicast, etc.
	Enabled             bool
	Redistributions     []Redistribution
	Networks            []BGPNetwork
	Aggregates          []BGPAggregate
	MaximumPaths        int
	MaximumPathsIBGP    int
	DistanceExternal    int
	DistanceInternal    int
	DistanceLocal       int
}

// Redistribution represents route redistribution configuration
type Redistribution struct {
	Protocol         string
	RouteMapRef      string
}

// BGPNetwork represents a network to be advertised in BGP
type BGPNetwork struct {
	Prefix           string
	RouteMap         string
	Backdoor         bool
}

// BGPAggregate represents a BGP route aggregate
type BGPAggregate struct {
	Prefix           string
	SummaryOnly      bool
	AsSet            bool
	RouteMap         string
}

// BGPCommunity represents a BGP community
type BGPCommunity struct {
	Value            string
	Type             string // standard, extended, large
}

// BGPPeerGroup represents a BGP peer group
type BGPPeerGroup struct {
	Name                 string
	RemoteASNumber       int
	Description          string
	KeepaliveInterval    int
	HoldTime             int
	ConnectRetryInterval int
	BFDEnabled           bool
	RouteMapIn           string
	RouteMapOut          string
	PrefixListIn         string
	PrefixListOut        string
	FilterListIn         string
	FilterListOut        string
	MaxPrefixes          int
	DefaultOriginate     bool
	NextHopSelf          bool
	RemovePrivateAS      bool
	SendCommunity        bool
	SendExtendedCommunity bool
	SendLargeCommunity   bool
	Weight               int
	AllowASIn            int
}

// PrefixList represents an IP prefix list for route filtering
type PrefixList struct {
	Name             string
	Description      string
	Entries          []PrefixListEntry
	AddressFamily    string // ipv4, ipv6
}

// PrefixListEntry represents an entry in a prefix list
type PrefixListEntry struct {
	Sequence         int
	Action           string // permit, deny
	Prefix           string
	GE               int    // greater than or equal
	LE               int    // less than or equal
}

// ASPathAccessList represents an AS path access list
type ASPathAccessList struct {
	Name             string
	Entries          []ASPathEntry
}

// ASPathEntry represents an entry in an AS path access list
type ASPathEntry struct {
	Action           string // permit, deny
	Regex            string
}

// CommunityList represents a community list for route filtering
type CommunityList struct {
	Name             string
	Type             string // standard, expanded
	Entries          []CommunityListEntry
}

// CommunityListEntry represents an entry in a community list
type CommunityListEntry struct {
	Action           string // permit, deny
	Communities      []string
}

// OSPFConfig represents OSPF protocol configuration
type OSPFConfig struct {
	RouterID         string
	Areas            []OSPFArea
	Redistributions  []Redistribution
	VRF              string
	ReferenceBandwidth int
}

// GetProtocolName implements ProtocolConfig
func (c OSPFConfig) GetProtocolName() string {
	return "ospf"
}

// OSPFArea represents an OSPF area configuration
type OSPFArea struct {
	AreaID           string
	Interfaces       []OSPFInterface
	StubArea         bool
	NSSAArea         bool
}

// OSPFInterface represents an OSPF interface configuration
type OSPFInterface struct {
	Name             string
	NetworkType      string // broadcast, point-to-point, etc.
	Priority         int
	Cost             int
	Authentication   OSPFAuthentication
}

// OSPFAuthentication represents OSPF authentication configuration
type OSPFAuthentication struct {
	Type             string // simple, md5
	Key              string
	KeyID            int
}

// ISISConfig represents IS-IS protocol configuration
type ISISConfig struct {
	SystemID         string
	AreaID           string
	Interfaces       []ISISInterface
	Level            string // level-1, level-2, level-1-2
	Redistributions  []Redistribution
	VRF              string
}

// GetProtocolName implements ProtocolConfig
func (c ISISConfig) GetProtocolName() string {
	return "isis"
}

// ISISInterface represents an IS-IS interface configuration
type ISISInterface struct {
	Name             string
	Level            string // level-1, level-2, level-1-2
	Priority         int
	Metric           int
}

// BFDConfig represents BFD protocol configuration
type BFDConfig struct {
	Enabled          bool
	MinTxInterval    int
	MinRxInterval    int
	Multiplier       int
	Peers            []BFDPeer
}

// GetProtocolName implements ProtocolConfig
func (c BFDConfig) GetProtocolName() string {
	return "bfd"
}

// BFDPeer represents a BFD peer configuration
type BFDPeer struct {
	Address          string
	Interface        string
}

// PIMConfig represents PIM protocol configuration
type PIMConfig struct {
	Enabled          bool
	RPAddress        string
	Interfaces       []PIMInterface
	MulticastGroups  []string
}

// GetProtocolName implements ProtocolConfig
func (c PIMConfig) GetProtocolName() string {
	return "pim"
}

// PIMInterface represents a PIM interface configuration
type PIMInterface struct {
	Name             string
	Mode             string // sparse, dense
}

// PolicyManager defines the interface for managing routing policies
type PolicyManager interface {
	// AddPolicy adds a new routing policy
	AddPolicy(policy RoutingPolicy) error
	
	// DeletePolicy removes a routing policy
	DeletePolicy(name string) error
	
	// GetPolicy retrieves a routing policy
	GetPolicy(name string) (*RoutingPolicy, error)
	
	// ListPolicies lists all routing policies
	ListPolicies() ([]*RoutingPolicy, error)
	
	// UpdatePolicy updates an existing routing policy
	UpdatePolicy(name string, policy RoutingPolicy) error
	
	// GetPolicyStatus retrieves the status of a policy
	GetPolicyStatus(name string) (*PolicyStatus, error)
}

// RoutingPolicy represents a policy-based routing policy
type RoutingPolicy struct {
	Name        string
	Description string
	Priority    int
	Match       PolicyMatch
	Action      PolicyAction
	VRF         string
}

// PolicyStatus represents the status of a routing policy
type PolicyStatus struct {
	Active      bool
	MatchCount  int64
	LastMatched time.Time
}

// PolicyMatch represents the match criteria for a routing policy
type PolicyMatch struct {
	Source          PolicyMatchSource
	Destination     PolicyMatchDestination
	Protocol        string
	Ports           []PortRange
	Applications    []string
	TrafficType     []string
	Time            PolicyMatchTime
}

// PolicyMatchSource represents source match criteria
type PolicyMatchSource struct {
	Networks        []string
	Interfaces      []string
}

// PolicyMatchDestination represents destination match criteria
type PolicyMatchDestination struct {
	Networks        []string
}

// PortRange represents a range of ports
type PortRange struct {
	Start           int
	End             int
}

// PolicyMatchTime represents time-based match criteria
type PolicyMatchTime struct {
	DaysOfWeek      []string
	TimeOfDay       []TimeRange
}

// TimeRange represents a time range
type TimeRange struct {
	Start           string
	End             string
}

// PolicyAction represents the action for a routing policy
type PolicyAction struct {
	Type            string
	NextHop         string
	Table           string
	Mark            int
	DSCP            int
}

// VRFManager defines the interface for managing VRF instances
type VRFManager interface {
	// CreateVRF creates a new VRF instance
	CreateVRF(vrf VRF) error
	
	// DeleteVRF removes a VRF instance
	DeleteVRF(name string) error
	
	// GetVRF retrieves a VRF instance
	GetVRF(name string) (*VRF, error)
	
	// ListVRFs lists all VRF instances
	ListVRFs() ([]*VRF, error)
	
	// UpdateVRF updates an existing VRF instance
	UpdateVRF(name string, vrf VRF) error
	
	// LeakRoutes leaks routes between VRF instances
	LeakRoutes(fromVRF string, toVRF string, routes []string) error
	
	// AddInterfaceToVRF adds an interface to a VRF
	AddInterfaceToVRF(vrfName string, interfaceName string) error
	
	// RemoveInterfaceFromVRF removes an interface from a VRF
	RemoveInterfaceFromVRF(vrfName string, interfaceName string) error
}

// VRF represents a Virtual Routing and Forwarding instance
type VRF struct {
	Name            string
	Description     string
	TableID         int
	Interfaces      []string
	RouteTargets    RouteTargets
	LeakRoutes      []RouteLeak
	CiliumPolicy    bool
}

// RouteTargets represents BGP route targets for a VRF
type RouteTargets struct {
	Import          []string
	Export          []string
}

// RouteLeak represents route leaking configuration
type RouteLeak struct {
	FromVRF         string
	ToVRF           string
	Destinations    []string
}

// MultiWANManager defines the interface for managing Multi-WAN
type MultiWANManager interface {
	// AddWANInterface adds a new WAN interface
	AddWANInterface(wan WANInterface) error
	
	// RemoveWANInterface removes a WAN interface
	RemoveWANInterface(name string) error
	
	// GetWANInterface retrieves a WAN interface
	GetWANInterface(name string) (*WANInterface, error)
	
	// ListWANInterfaces lists all WAN interfaces
	ListWANInterfaces() ([]*WANInterface, error)
	
	// UpdateWANInterface updates an existing WAN interface
	UpdateWANInterface(name string, wan WANInterface) error
	
	// GetWANStatus retrieves the status of a WAN interface
	GetWANStatus(name string) (*WANStatus, error)
	
	// SetActivePrimary sets the active primary WAN
	SetActivePrimary(name string) error
	
	// ConfigureLoadBalancing configures load balancing
	ConfigureLoadBalancing(config LoadBalancingConfig) error
	
	// ConfigureFailover configures failover
	ConfigureFailover(config FailoverConfig) error
}

// WANInterface represents a WAN interface
type WANInterface struct {
	Name            string
	Interface       string
	Weight          int
	Priority        int
	Description     string
	Gateway         string
	Monitoring      WANMonitoring
}

// WANMonitoring represents monitoring configuration for a WAN interface
type WANMonitoring struct {
	Targets         []string
	Method          string // ping, http, dns
	Interval        int
	Timeout         int
	FailThreshold   int
	SuccessThreshold int
}

// WANStatus represents the status of a WAN interface
type WANStatus struct {
	Name            string
	State           string
	RTT             float64
	PacketLoss      float64
	LastStateChange time.Time
}

// LoadBalancingConfig represents load balancing configuration
type LoadBalancingConfig struct {
	Enabled         bool
	Method          string // weighted, round-robin, per-connection, per-packet
	Sticky          bool
	StickyTimeout   int
}

// FailoverConfig represents failover configuration
type FailoverConfig struct {
	Enabled         bool
	Preempt         bool
	PreemptDelay    int
}

// CiliumSynchronizer defines the interface for synchronizing with Cilium
type CiliumSynchronizer interface {
	// SyncRoute synchronizes a route with Cilium
	SyncRoute(route Route) error
	
	// RemoveRoute removes a route from Cilium
	RemoveRoute(destination string, routeParams RouteParams) error
	
	// SyncRoutingTable synchronizes an entire routing table with Cilium
	SyncRoutingTable(tableName string, vrf string) error
	
	// GetCiliumRoutes retrieves routes installed in Cilium
	GetCiliumRoutes() ([]*Route, error)
	
	// SyncVRFPolicies synchronizes VRF isolation policies with Cilium
	SyncVRFPolicies(vrf VRF) error
}

// RouteMapManager defines the interface for managing route maps
type RouteMapManager interface {
	// CreateRouteMap creates a new route map
	CreateRouteMap(routeMap RouteMap) error
	
	// DeleteRouteMap deletes a route map
	DeleteRouteMap(name string) error
	
	// GetRouteMap retrieves a route map
	GetRouteMap(name string) (*RouteMap, error)
	
	// ListRouteMaps lists all route maps
	ListRouteMaps() ([]*RouteMap, error)
	
	// UpdateRouteMap updates an existing route map
	UpdateRouteMap(name string, routeMap RouteMap) error
	
	// ApplyRouteMap applies a route map to a specific context
	ApplyRouteMap(name string, context RouteMapContext) error
}

// RouteMap represents a route map
type RouteMap struct {
	Name            string
	Description     string
	Entries         []RouteMapEntry
	Applied         bool
	LastApplied     time.Time
}

// RouteMapEntry represents an entry in a route map
type RouteMapEntry struct {
	Sequence        int
	Action          string
	Match           RouteMapMatch
	Set             RouteMapSet
}

// RouteMapMatch represents match criteria for a route map
type RouteMapMatch struct {
	Prefix          string
	PrefixLen       string
	Protocol        string
	Community       string
	AsPath          string
	Metric          int
	Tag             string
}

// RouteMapSet represents set actions for a route map
type RouteMapSet struct {
	Metric          int
	LocalPreference int
	Community       string
	NextHop         string
	Weight          int
	AsPathPrepend   string
}

// RouteMapContext represents the context for applying a route map
type RouteMapContext struct {
	Protocol        string
	Direction       string  // in, out
	Peer            string
	Interface       string
}

// RouteAggregationManager defines the interface for managing route aggregation
type RouteAggregationManager interface {
	// CreateAggregate creates a new route aggregate
	CreateAggregate(aggregate RouteAggregate) error
	
	// DeleteAggregate deletes a route aggregate
	DeleteAggregate(name string) error
	
	// GetAggregate retrieves a route aggregate
	GetAggregate(name string) (*RouteAggregate, error)
	
	// ListAggregates lists all route aggregates
	ListAggregates() ([]*RouteAggregate, error)
	
	// UpdateAggregate updates an existing route aggregate
	UpdateAggregate(name string, aggregate RouteAggregate) error
	
	// RefreshAggregate refreshes a route aggregate
	RefreshAggregate(name string) error
}

// RouteAggregate represents a route aggregate
type RouteAggregate struct {
	Name              string
	Description       string
	Aggregate         string
	Summary           bool
	Method            string // auto, manual
	IncludeNetworks   []string
	ExcludeNetworks   []string
	Attributes        RouteAggregateAttributes
	AdvertisementControl RouteAggregateAdvertisement
	VRF               string
	Active            bool
	Specifics         int
	Summarized        bool
}

// RouteAggregateAttributes represents attributes for a route aggregate
type RouteAggregateAttributes struct {
	Metric            int
	Tag               string
}

// RouteAggregateAdvertisement represents advertisement control for a route aggregate
type RouteAggregateAdvertisement struct {
	AdvertiseMap      string
	SuppressMap       string
}