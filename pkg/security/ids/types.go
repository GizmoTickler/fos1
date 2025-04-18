package ids

import (
	"context"
	"time"
)

// Manager defines the interface for IDS/IPS management
type Manager interface {
	// Initialize initializes the IDS/IPS manager
	Initialize(ctx context.Context) error

	// Shutdown shuts down the IDS/IPS manager
	Shutdown(ctx context.Context) error

	// GetStatus gets the status of the IDS/IPS
	GetStatus() (*Status, error)

	// UpdateRules updates the IDS/IPS rules
	UpdateRules(config *RulesConfig) error

	// GetAlerts gets the alerts from the IDS/IPS
	GetAlerts(filter *AlertFilter) ([]*Alert, error)

	// GetStatistics gets the statistics from the IDS/IPS
	GetStatistics() (*Statistics, error)

	// EnableIPS enables IPS mode (blocking)
	EnableIPS() error

	// DisableIPS disables IPS mode (detection only)
	DisableIPS() error

	// AddInterface adds an interface to monitor
	AddInterface(name string, config *InterfaceConfig) error

	// RemoveInterface removes an interface from monitoring
	RemoveInterface(name string) error

	// GetInterfaces gets the monitored interfaces
	GetInterfaces() ([]string, error)
}

// Status represents the status of the IDS/IPS
type Status struct {
	// Running indicates whether the IDS/IPS is running
	Running bool

	// Mode is the mode of the IDS/IPS (IDS or IPS)
	Mode string

	// Uptime is the uptime of the IDS/IPS
	Uptime time.Duration

	// LastRestart is the time of the last restart
	LastRestart time.Time

	// RulesLastUpdated is the time when the rules were last updated
	RulesLastUpdated time.Time

	// RulesCount is the number of loaded rules
	RulesCount int

	// Interfaces are the monitored interfaces
	Interfaces []string

	// Errors are any errors that occurred
	Errors []string
}

// RulesConfig defines the configuration for IDS/IPS rules
type RulesConfig struct {
	// Sources are the sources for the rules
	Sources []RuleSource

	// CustomRules are custom rules
	CustomRules []string

	// DisabledRules are the IDs of disabled rules
	DisabledRules []string

	// ModifiedRules are rules that have been modified
	ModifiedRules map[string]string
}

// RuleSource defines a source for IDS/IPS rules
type RuleSource struct {
	// Name is the name of the source
	Name string

	// URL is the URL of the source
	URL string

	// Enabled indicates whether the source is enabled
	Enabled bool

	// Categories are the categories to include
	Categories []string

	// ExcludedCategories are the categories to exclude
	ExcludedCategories []string
}

// AlertFilter defines a filter for alerts
type AlertFilter struct {
	// StartTime is the start time for the filter
	StartTime time.Time

	// EndTime is the end time for the filter
	EndTime time.Time

	// Severity is the minimum severity for the filter
	Severity string

	// Categories are the categories to include
	Categories []string

	// Signatures are the signatures to include
	Signatures []string

	// SourceIPs are the source IPs to include
	SourceIPs []string

	// DestinationIPs are the destination IPs to include
	DestinationIPs []string

	// Limit is the maximum number of alerts to return
	Limit int

	// Offset is the offset for pagination
	Offset int
}

// Alert represents an alert from the IDS/IPS
type Alert struct {
	// ID is the ID of the alert
	ID string

	// Timestamp is the time of the alert
	Timestamp time.Time

	// Signature is the signature that triggered the alert
	Signature string

	// SignatureID is the ID of the signature
	SignatureID int

	// Category is the category of the alert
	Category string

	// Severity is the severity of the alert
	Severity string

	// SourceIP is the source IP of the alert
	SourceIP string

	// SourcePort is the source port of the alert
	SourcePort int

	// DestinationIP is the destination IP of the alert
	DestinationIP string

	// DestinationPort is the destination port of the alert
	DestinationPort int

	// Protocol is the protocol of the alert
	Protocol string

	// Interface is the interface where the alert was detected
	Interface string

	// Payload is the payload of the alert
	Payload string

	// Action is the action taken for the alert
	Action string
}

// Statistics represents statistics from the IDS/IPS
type Statistics struct {
	// PacketsReceived is the number of packets received
	PacketsReceived uint64

	// PacketsDropped is the number of packets dropped
	PacketsDropped uint64

	// PacketsInvalidChecksums is the number of packets with invalid checksums
	PacketsInvalidChecksums uint64

	// BytesReceived is the number of bytes received
	BytesReceived uint64

	// AlertsGenerated is the number of alerts generated
	AlertsGenerated uint64

	// SessionsTotal is the total number of sessions
	SessionsTotal uint64

	// SessionsCurrent is the current number of sessions
	SessionsCurrent uint64

	// CPUUsage is the CPU usage percentage
	CPUUsage float64

	// MemoryUsage is the memory usage in bytes
	MemoryUsage uint64

	// UptimeSeconds is the uptime in seconds
	UptimeSeconds uint64

	// InterfaceStats is the statistics per interface
	InterfaceStats map[string]InterfaceStatistics
}

// InterfaceStatistics represents statistics for an interface
type InterfaceStatistics struct {
	// PacketsReceived is the number of packets received
	PacketsReceived uint64

	// PacketsDropped is the number of packets dropped
	PacketsDropped uint64

	// BytesReceived is the number of bytes received
	BytesReceived uint64

	// AlertsGenerated is the number of alerts generated
	AlertsGenerated uint64
}

// InterfaceConfig defines the configuration for an interface
type InterfaceConfig struct {
	// Mode is the mode for the interface (IDS or IPS)
	Mode string

	// Promiscuous indicates whether to use promiscuous mode
	Promiscuous bool

	// BPFFilter is the BPF filter for the interface
	BPFFilter string

	// Checksum indicates whether to validate checksums
	Checksum bool

	// ThreadCount is the number of threads to use
	ThreadCount int
}

// SuricataConfig defines the configuration for Suricata
type SuricataConfig struct {
	// ConfigPath is the path to the Suricata configuration file
	ConfigPath string

	// RulesPath is the path to the Suricata rules directory
	RulesPath string

	// LogPath is the path to the Suricata log directory
	LogPath string

	// PIDPath is the path to the Suricata PID file
	PIDPath string

	// SocketPath is the path to the Suricata socket
	SocketPath string

	// DefaultMode is the default mode (IDS or IPS)
	DefaultMode string

	// DefaultThreads is the default number of threads
	DefaultThreads int

	// MaxPendingPackets is the maximum number of pending packets
	MaxPendingPackets int

	// DetectionEngineProfile is the detection engine profile
	DetectionEngineProfile string

	// MemoryProfile is the memory profile
	MemoryProfile string

	// StatsInterval is the interval for statistics
	StatsInterval time.Duration
}

// ZeekConfig defines the configuration for Zeek
type ZeekConfig struct {
	// ConfigPath is the path to the Zeek configuration file
	ConfigPath string

	// ScriptsPath is the path to the Zeek scripts directory
	ScriptsPath string

	// LogPath is the path to the Zeek log directory
	LogPath string

	// PIDPath is the path to the Zeek PID file
	PIDPath string

	// DefaultThreads is the default number of threads
	DefaultThreads int

	// ClusterMode indicates whether to use cluster mode
	ClusterMode bool

	// NodeName is the name of the node in cluster mode
	NodeName string

	// LogRotationInterval is the interval for log rotation
	LogRotationInterval time.Duration
}

// EventCorrelationConfig defines the configuration for event correlation
type EventCorrelationConfig struct {
	// Enabled indicates whether event correlation is enabled
	Enabled bool

	// CorrelationRules are the correlation rules
	CorrelationRules []CorrelationRule

	// MaxEventsInMemory is the maximum number of events to keep in memory
	MaxEventsInMemory int

	// MaxEventAge is the maximum age of events to keep in memory
	MaxEventAge time.Duration

	// OutputFormat is the format for correlated events
	OutputFormat string
}

// CorrelationRule defines a rule for event correlation
type CorrelationRule struct {
	// Name is the name of the rule
	Name string

	// Description is the description of the rule
	Description string

	// Conditions are the conditions for the rule
	Conditions []CorrelationCondition

	// Threshold is the threshold for the rule
	Threshold int

	// TimeWindow is the time window for the rule
	TimeWindow time.Duration

	// Severity is the severity of the rule
	Severity string

	// Action is the action to take when the rule matches
	Action string
}

// CorrelationCondition defines a condition for event correlation
type CorrelationCondition struct {
	// Field is the field to match
	Field string

	// Operator is the operator for the match
	Operator string

	// Value is the value to match
	Value string
}
