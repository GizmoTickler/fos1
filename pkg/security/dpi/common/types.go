package common

import (
	"time"
)

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

// ZeekStatus represents the status of the Zeek engine
type ZeekStatus struct {
	Running      bool
	Uptime       time.Duration
	LogsProcessed int64
	LastError    string
	Version      string
}

// ApplicationInfo represents information about an application
type ApplicationInfo struct {
	// Name of the application
	Name string

	// Category of the application
	Category string

	// Description of the application
	Description string

	// Known ports used by the application
	Ports []int

	// Known protocols used by the application
	Protocols []string

	// Risk level (1-5)
	RiskLevel int

	// Whether the application is encrypted
	Encrypted bool

	// Whether the application uses peer-to-peer communication
	P2P bool

	// Whether the application is a tunneling protocol
	Tunneling bool

	// Whether the application is a VPN
	VPN bool

	// Whether the application is a proxy
	Proxy bool

	// Whether the application is a remote access tool
	RemoteAccess bool

	// Whether the application is a file sharing service
	FileSharing bool

	// Whether the application is a messaging service
	Messaging bool

	// Whether the application is a social network
	SocialNetwork bool

	// Whether the application is a gaming service
	Gaming bool

	// Whether the application is a streaming service
	Streaming bool

	// Whether the application is a business application
	Business bool

	// Whether the application is a cloud service
	Cloud bool

	// Whether the application is a database
	Database bool

	// Whether the application is a web service
	Web bool

	// Whether the application is an IoT service
	IoT bool

	// Whether the application is a mobile application
	Mobile bool

	// Whether the application is a desktop application
	Desktop bool

	// Whether the application is a server application
	Server bool

	// Whether the application is a client application
	Client bool
}
