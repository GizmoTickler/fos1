package kubernetes

import (
	"time"
)

// DPIEvent represents an event from a DPI engine
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
