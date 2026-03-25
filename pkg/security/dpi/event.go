// Package dpi provides deep packet inspection functionality
package dpi

import (
	"time"
)

// DPIEvent represents an event from a DPI engine
// Deprecated: Use common.DPIEvent instead
type DPIEvent struct {
	// Timestamp of the event
	Timestamp time.Time

	// Network information
	SourceIP    string
	DestIP      string
	SourcePort  int
	DestPort    int
	Protocol    string
	VLAN        int    // VLAN ID

	// Application information
	Application string
	Category    string

	// Event details
	EventType   string
	Severity    int
	Description string
	Signature   string
	SessionID   string

	// Additional data
	RawData     map[string]interface{}
}

// ZeekStatus represents the status of the Zeek engine
// Deprecated: Use common.ZeekStatus instead
type ZeekStatus struct {
	Running      bool
	Uptime       time.Duration
	LogsProcessed int64
	LastError    string
	Version      string
}

// ApplicationInfo represents information about an application
// Deprecated: Use common.ApplicationInfo instead
type ApplicationInfo struct {
	Name        string
	Category    string
	Description string
	DefaultPorts []int
	Protocols   []string
	RiskLevel   int
	References  []string
}
