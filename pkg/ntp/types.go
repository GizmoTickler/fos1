package ntp

import "time"

// NTPService represents the configuration for an NTP service
type NTPService struct {
	Name    string
	Enabled bool
	Sources Sources
	Server  ServerConfig
	Security SecurityConfig
	VLANConfig []VLANConfig
	Monitoring MonitoringConfig
}

// Sources defines the time sources for the NTP service
type Sources struct {
	Pools    []PoolSource
	Servers  []ServerSource
	Hardware HardwareSources
}

// PoolSource defines an NTP pool source
type PoolSource struct {
	Name    string
	Servers int
	IBurst  bool
	Prefer  bool
}

// ServerSource defines an NTP server source
type ServerSource struct {
	Address string
	IBurst  bool
	Prefer  bool
	MinPoll int
	MaxPoll int
}

// HardwareSources defines hardware time sources
type HardwareSources struct {
	PPS PPSSource
	GPS GPSSource
}

// PPSSource defines a PPS (Pulse Per Second) time source
type PPSSource struct {
	Enabled bool
	Device  string
	Prefer  bool
}

// GPSSource defines a GPS time source
type GPSSource struct {
	Enabled  bool
	Device   string
	RefClock bool
	Prefer   bool
}

// ServerConfig defines the NTP server configuration
type ServerConfig struct {
	Stratum   int
	DriftFile string
	MakeStep  StepConfig
	Local     LocalClockConfig
}

// StepConfig defines when to step the system clock
type StepConfig struct {
	Threshold float64
	Limit     int
}

// LocalClockConfig defines the local clock fallback
type LocalClockConfig struct {
	Enabled bool
	Stratum int
}

// SecurityConfig defines security settings for NTP
type SecurityConfig struct {
	NTS            NTSConfig
	Authentication AuthenticationConfig
	RateLimit      RateLimitConfig
	Access         []AccessRule
}

// NTSConfig defines Network Time Security settings
type NTSConfig struct {
	Enabled bool
}

// AuthenticationConfig defines authentication settings
type AuthenticationConfig struct {
	Enabled bool
	Keys    []AuthKey
}

// AuthKey defines an authentication key
type AuthKey struct {
	ID    int
	Type  string
	Value string
}

// RateLimitConfig defines rate limiting settings
type RateLimitConfig struct {
	Enabled  bool
	Interval int
	Burst    int
}

// AccessRule defines an access control rule
type AccessRule struct {
	Network    string
	Permission string
}

// VLANConfig defines NTP configuration for a VLAN
type VLANConfig struct {
	VLANRef     string
	Enabled     bool
	Broadcast   bool
	ClientsOnly bool
}

// MonitoringConfig defines monitoring settings
type MonitoringConfig struct {
	Enabled        bool
	Offset         OffsetThresholds
	SourcesMinimum int
}

// OffsetThresholds defines thresholds for clock offset
type OffsetThresholds struct {
	WarningThreshold  int
	CriticalThreshold int
}

// Status represents the status of the NTP service
type Status struct {
	Running       bool
	Synchronized  bool
	Stratum       int
	Offset        float64 // milliseconds
	Jitter        float64 // milliseconds
	SourceCount   int
	Sources       []Source
	LastError     string
	LastErrorTime time.Time
}

// Source represents an NTP time source
type Source struct {
	Name      string
	Type      string // Server, Pool, PPS, GPS, etc.
	Stratum   int
	Offset    float64 // milliseconds
	Jitter    float64 // milliseconds
	Delay     float64 // milliseconds
	Dispersion float64 // milliseconds
	Reach     int     // Octal value
	Selected  bool    // Whether this source is selected
}

// Metrics represents NTP metrics
type Metrics struct {
	Offset           float64 // System time offset in milliseconds
	Jitter           float64 // System jitter in milliseconds
	Stratum          int     // Stratum level
	SyncStatus       bool    // Whether system is synchronized
	SourceCount      int     // Number of sources
	SourcesReachable int     // Number of reachable sources
	FrequencyDrift   float64 // System clock frequency drift in parts per million
}