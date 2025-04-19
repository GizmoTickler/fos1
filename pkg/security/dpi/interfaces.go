package dpi

import (
	"context"
	"time"
)

// ZeekConnectorInterface defines the interface for the Zeek connector
type ZeekConnectorInterface interface {
	// Start starts the Zeek connector
	Start() error

	// Stop stops the Zeek connector
	Stop() error

	// Configure configures the Zeek connector
	Configure(config interface{}) error

	// Status returns the status of the Zeek engine
	Status() (ZeekStatus, error)

	// GetEvents returns a channel of DPI events
	GetEvents(ctx context.Context) (<-chan DPIEvent, error)

	// GetProtocolStats gets statistics for a specific protocol
	GetProtocolStats(protocol string) (map[string]interface{}, error)

	// ExtractProtocols extracts application protocols identified by Zeek
	ExtractProtocols() (map[string]int, error)
}

// ZeekStatus represents the status of the Zeek engine
type ZeekStatus struct {
	Running      bool
	Uptime       time.Duration
	LogsProcessed int64
	LastError    string
	Version      string
}

// DPIEvent represents an event from the DPI system
type DPIEvent struct {
	// Common fields for all DPI events
	Timestamp   time.Time
	SourceIP    string
	DestIP      string
	SourcePort  int
	DestPort    int
	Protocol    string
	Application string
	Category    string

	// Event-specific fields
	EventType   string // "flow", "alert", "notice", etc.
	Severity    int    // 0-4, with 4 being most severe
	Description string
	Signature   string
	SessionID   string

	// Raw event data
	RawData     map[string]interface{}
}

// ApplicationDetectorInterface defines the interface for application detection
type ApplicationDetectorInterface interface {
	// GetApplicationInfo gets information about an application
	GetApplicationInfo(applicationName string) (*ApplicationInfo, error)

	// GetAllApplications returns all known applications
	GetAllApplications() []*ApplicationInfo

	// GetApplicationsByCategory returns applications in a category
	GetApplicationsByCategory(category string) []*ApplicationInfo
}
