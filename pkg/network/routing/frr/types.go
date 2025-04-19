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
