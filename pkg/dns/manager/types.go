package manager

import "time"

// DNSZone defines a DNS zone
type DNSZone struct {
	Name     string
	Domain   string
	TTL      int32
	SOA      *SOARecord
	Records  []*DNSRecord
	Metadata map[string]string
}

// PTRZone defines a reverse lookup zone
type PTRZone struct {
	Name    string
	Network string
	TTL     int32
	SOA     *SOARecord
	Records []*DNSRecord
}

// SOARecord defines a Start of Authority record
type SOARecord struct {
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

// DNSRecord defines a DNS record
type DNSRecord struct {
	Name    string
	Type    string
	Value   string
	TTL     int32
	Dynamic bool
}

// DNSClient defines a DNS client with filtering options
type DNSClient struct {
	Name        string
	Description string
	Identifiers []ClientIdentifier
	Filtering   FilteringOptions
	Metadata    map[string]string
}

// ClientIdentifier defines a client identifier
type ClientIdentifier struct {
	Type  string // "ip", "mac", "hostname", "cidr"
	Value string
}

// FilteringOptions defines filtering options for a client
type FilteringOptions struct {
	Enabled    bool
	Exceptions []string
	BlockLists []string
}

// DNSFilterList defines a DNS filter list
type DNSFilterList struct {
	Name        string
	Enabled     bool
	Categories  []string
	CustomLists []CustomFilterList
	AllowLists  []AllowList
}

// CustomFilterList defines a custom filter list
type CustomFilterList struct {
	Name    string
	URL     string
	Enabled bool
}

// AllowList defines an allow list
type AllowList struct {
	Name    string
	Domains []string
}

// MDNSReflection defines rules for mDNS reflection
type MDNSReflection struct {
	Name            string
	Enabled         bool
	ReflectionRules []ReflectionRule
}

// ReflectionRule defines a rule for mDNS reflection
type ReflectionRule struct {
	Name             string
	SourceVLANs      []int
	DestinationVLANs []int
	ServiceTypes     []string
}

// DynamicDNSConfig defines configuration for dynamic DNS
type DynamicDNSConfig struct {
	Name               string
	Enabled            bool
	BaseDomain         string
	TTL                int32
	CreateReverse      bool
	UseClientHostname  bool
	HostnamePattern    string
	CleanupGracePeriod int32
}

// DNSStatus represents the status of all DNS services
type DNSStatus struct {
	CoreDNS *CoreDNSStatus
	AdGuard *AdGuardStatus
	MDNS    *MDNSStatus
}

// CoreDNSStatus represents the status of CoreDNS
type CoreDNSStatus struct {
	Running     bool
	Zones       int
	RecordsServed int
	QueryRate   float64
	CacheHitRate float64
	ErrorRate   float64
	LastError   string
	LastErrorTime time.Time
}

// AdGuardStatus represents the status of AdGuard Home
type AdGuardStatus struct {
	Running        bool
	FilteringEnabled bool
	BlockedQueries int64
	TotalQueries   int64
	BlockRate      float64
	AvgProcessingTime float64
	LastError      string
	LastErrorTime  time.Time
}

// MDNSStatus represents the status of mDNS
type MDNSStatus struct {
	Running          bool
	ReflectionEnabled bool
	ReflectionRules  int
	ServicesReflected int64
	LastError        string
	LastErrorTime    time.Time
}

// MDNSServiceType defines a mDNS service type
type MDNSServiceType struct {
	Name        string
	Description string
	Types       []ServiceType
}

// ServiceType defines a service type
type ServiceType struct {
	Name         string
	Description  string
	DefaultPorts []int32
}