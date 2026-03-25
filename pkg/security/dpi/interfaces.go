package dpi

import (
	"context"

	"github.com/GizmoTickler/fos1/pkg/security/dpi/common"
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
	Status() (common.ZeekStatus, error)

	// GetEvents returns a channel of DPI events
	GetEvents(ctx context.Context) (<-chan common.DPIEvent, error)

	// GetProtocolStats gets statistics for a specific protocol
	GetProtocolStats(protocol string) (map[string]interface{}, error)

	// ExtractProtocols extracts application protocols identified by Zeek
	ExtractProtocols() (map[string]int, error)

	// GetLogsPath returns the path to Zeek logs
	GetLogsPath() string

	// GetPolicyPath returns the path to Zeek policy files
	GetPolicyPath() string
}

// ZeekStatus and DPIEvent types are now in the common package

// ApplicationDetectorInterface defines the interface for application detection
type ApplicationDetectorInterface interface {
	// GetApplicationInfo gets information about an application
	GetApplicationInfo(applicationName string) (*common.ApplicationInfo, error)

	// GetAllApplications returns all known applications
	GetAllApplications() []*common.ApplicationInfo

	// GetApplicationsByCategory returns applications in a category
	GetApplicationsByCategory(category string) []*common.ApplicationInfo
}

// DPIEngineConnector defines the interface for DPI engine connectors
type DPIEngineConnector interface {
	// Start starts the DPI engine connector
	Start() error

	// Stop stops the DPI engine connector
	Stop() error

	// GetEvents returns a channel of DPI events
	GetEvents(ctx context.Context) (<-chan common.DPIEvent, error)
}
