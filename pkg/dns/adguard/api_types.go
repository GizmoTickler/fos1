package adguard

import "time"

// ServerStatus represents the response from GET /control/status
type ServerStatus struct {
	DNSAddresses  []string `json:"dns_addresses"`
	DNSPort       int      `json:"dns_port"`
	HTTPPort      int      `json:"http_port"`
	ProtectionEnabled bool `json:"protection_enabled"`
	Running       bool     `json:"running"`
	Version       string   `json:"version"`
	Language      string   `json:"language"`
}

// ClientInfo represents a client entry in AdGuard Home
type ClientInfo struct {
	Name               string   `json:"name"`
	IDs                []string `json:"ids"`
	Tags               []string `json:"tags"`
	UseGlobalSettings  bool     `json:"use_global_settings"`
	FilteringEnabled   bool     `json:"filtering_enabled"`
	ParentalEnabled    bool     `json:"parental_enabled"`
	SafeSearchEnabled  bool     `json:"safesearch_enabled"`
	SafeBrowsingEnabled bool   `json:"safebrowsing_enabled"`
	BlockedServices    []string `json:"blocked_services"`
	Upstreams          []string `json:"upstreams"`
}

// clientsResponse represents the response from GET /control/clients
type clientsResponse struct {
	Clients    []ClientInfo    `json:"clients"`
	AutoClients []autoClient  `json:"auto_clients"`
}

// autoClient represents an automatically discovered client
type autoClient struct {
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Source string `json:"source"`
}

// Stats represents the response from GET /control/stats
type Stats struct {
	NumDNSQueries           int64    `json:"num_dns_queries"`
	NumBlockedFiltering     int64    `json:"num_blocked_filtering"`
	NumReplacedSafebrowsing int64    `json:"num_replaced_safebrowsing"`
	NumReplacedParental     int64    `json:"num_replaced_parental"`
	NumReplacedSafesearch   int64    `json:"num_replaced_safesearch"`
	AvgProcessingTime       float64  `json:"avg_processing_time"`
	TopQueriedDomains       []map[string]int64 `json:"top_queried_domains"`
	TopBlockedDomains       []map[string]int64 `json:"top_blocked_domains"`
	TopClients              []map[string]int64 `json:"top_clients"`
	DNSQueries              []int64  `json:"dns_queries"`
	BlockedFiltering        []int64  `json:"blocked_filtering"`
	TimeUnits               string   `json:"time_units"`
}

// FilterListEntry represents a filter list in the AdGuard Home API
type FilterListEntry struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Enabled     bool      `json:"enabled"`
	LastUpdated time.Time `json:"last_updated"`
	RulesCount  int       `json:"rules_count"`
}

// addURLRequest represents the request body for POST /control/filtering/add_url
type addURLRequest struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

// removeURLRequest represents the request body for POST /control/filtering/remove_url
type removeURLRequest struct {
	URL string `json:"url"`
}

// refreshRequest represents the request body for POST /control/filtering/refresh
type refreshRequest struct {
	Whitelist bool `json:"whitelist"`
}

// updateClientRequest represents the request body for POST /control/clients/update
type updateClientRequest struct {
	Name string     `json:"name"`
	Data ClientInfo `json:"data"`
}
