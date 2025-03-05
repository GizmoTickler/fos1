package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NTPService defines the NTP service custom resource
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ntp
// +kubebuilder:printcolumn:name="Enabled",type="boolean",JSONPath=".spec.enabled"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.syncStatus"
// +kubebuilder:printcolumn:name="Sources",type="integer",JSONPath=".status.sourceCount"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type NTPService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NTPServiceSpec   `json:"spec"`
	Status NTPServiceStatus `json:"status,omitempty"`
}

// NTPServiceList represents a list of NTP services
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NTPServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NTPService `json:"items"`
}

// NTPServiceSpec defines the desired state of the NTP service
type NTPServiceSpec struct {
	// Enabled indicates whether the NTP service is enabled
	// +kubebuilder:validation:Required
	Enabled bool `json:"enabled"`

	// Sources defines time sources for the NTP service
	// +kubebuilder:validation:Required
	Sources Sources `json:"sources"`

	// Server defines server-side NTP configuration
	// +kubebuilder:validation:Required
	Server ServerConfig `json:"server"`

	// Security defines security settings for NTP
	// +optional
	Security SecurityConfig `json:"security,omitempty"`

	// VLANConfig defines NTP configuration for VLANs
	// +optional
	VLANConfig []VLANConfig `json:"vlanConfig,omitempty"`

	// Monitoring defines monitoring settings
	// +optional
	Monitoring MonitoringConfig `json:"monitoring,omitempty"`
}

// Sources defines the time sources for the NTP service
type Sources struct {
	// Pools defines NTP pool sources
	// +optional
	Pools []PoolSource `json:"pools,omitempty"`

	// Servers defines direct NTP server sources
	// +optional
	Servers []ServerSource `json:"servers,omitempty"`

	// Hardware defines hardware time sources
	// +optional
	Hardware HardwareSources `json:"hardware,omitempty"`
}

// PoolSource defines an NTP pool source
type PoolSource struct {
	// Name is the hostname or address of the NTP pool
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Servers is the number of servers to use from the pool
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=16
	// +optional
	// +kubebuilder:default=4
	Servers int `json:"servers,omitempty"`

	// IBurst enables fast initial synchronization
	// +optional
	// +kubebuilder:default=true
	IBurst bool `json:"iburst,omitempty"`

	// Prefer indicates this is a preferred source
	// +optional
	// +kubebuilder:default=false
	Prefer bool `json:"prefer,omitempty"`
}

// ServerSource defines a direct NTP server source
type ServerSource struct {
	// Address is the hostname or IP address of the NTP server
	// +kubebuilder:validation:Required
	Address string `json:"address"`

	// IBurst enables fast initial synchronization
	// +optional
	// +kubebuilder:default=true
	IBurst bool `json:"iburst,omitempty"`

	// Prefer indicates this is a preferred source
	// +optional
	// +kubebuilder:default=false
	Prefer bool `json:"prefer,omitempty"`

	// MinPoll is the minimum polling interval in seconds as a power of 2
	// +kubebuilder:validation:Minimum=3
	// +kubebuilder:validation:Maximum=17
	// +optional
	// +kubebuilder:default=6
	MinPoll int `json:"minpoll,omitempty"`

	// MaxPoll is the maximum polling interval in seconds as a power of 2
	// +kubebuilder:validation:Minimum=3
	// +kubebuilder:validation:Maximum=17
	// +optional
	// +kubebuilder:default=10
	MaxPoll int `json:"maxpoll,omitempty"`
}

// HardwareSources defines hardware time sources
type HardwareSources struct {
	// PPS defines a Pulse Per Second time source
	// +optional
	PPS PPSSource `json:"pps,omitempty"`

	// GPS defines a GPS time source
	// +optional
	GPS GPSSource `json:"gps,omitempty"`
}

// PPSSource defines a PPS (Pulse Per Second) time source
type PPSSource struct {
	// Enabled indicates whether the PPS source is enabled
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Device is the path to the PPS device
	// +optional
	// +kubebuilder:default="/dev/pps0"
	Device string `json:"device,omitempty"`

	// Prefer indicates this is a preferred source
	// +optional
	// +kubebuilder:default=true
	Prefer bool `json:"prefer,omitempty"`
}

// GPSSource defines a GPS time source
type GPSSource struct {
	// Enabled indicates whether the GPS source is enabled
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Device is the path to the GPS device
	// +optional
	// +kubebuilder:default="/dev/ttyS0"
	Device string `json:"device,omitempty"`

	// RefClock indicates this is a reference clock
	// +optional
	// +kubebuilder:default=true
	RefClock bool `json:"refclock,omitempty"`

	// Prefer indicates this is a preferred source
	// +optional
	// +kubebuilder:default=true
	Prefer bool `json:"prefer,omitempty"`
}

// ServerConfig defines the NTP server configuration
type ServerConfig struct {
	// Stratum is the stratum level for this server
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=15
	// +optional
	// +kubebuilder:default=2
	Stratum int `json:"stratum,omitempty"`

	// DriftFile is the path to the drift file
	// +optional
	// +kubebuilder:default="/var/lib/chrony/drift"
	DriftFile string `json:"driftfile,omitempty"`

	// MakeStep defines when to step the system clock
	// +optional
	MakeStep StepConfig `json:"makestep,omitempty"`

	// Local defines the local clock configuration
	// +optional
	Local LocalClockConfig `json:"local,omitempty"`
}

// StepConfig defines when to step the system clock
type StepConfig struct {
	// Threshold is the minimum offset in seconds to step the clock
	// +kubebuilder:validation:Minimum=0.001
	// +optional
	// +kubebuilder:default=1.0
	Threshold float64 `json:"threshold,omitempty"`

	// Limit is the maximum number of clock steps
	// +kubebuilder:validation:Minimum=0
	// +optional
	// +kubebuilder:default=3
	Limit int `json:"limit,omitempty"`
}

// LocalClockConfig defines the local clock fallback
type LocalClockConfig struct {
	// Enabled indicates whether the local clock is enabled
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Stratum is the stratum level for the local clock
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=15
	// +optional
	// +kubebuilder:default=10
	Stratum int `json:"stratum,omitempty"`
}

// SecurityConfig defines security settings for NTP
type SecurityConfig struct {
	// NTS defines Network Time Security settings
	// +optional
	NTS NTSConfig `json:"nts,omitempty"`

	// Authentication defines authentication settings
	// +optional
	Authentication AuthConfig `json:"authentication,omitempty"`

	// RateLimit defines rate limiting settings
	// +optional
	RateLimit RateLimitConfig `json:"ratelimit,omitempty"`

	// Access defines access control rules
	// +optional
	Access []AccessRule `json:"access,omitempty"`
}

// NTSConfig defines Network Time Security settings
type NTSConfig struct {
	// Enabled indicates whether NTS is enabled
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`
}

// AuthConfig defines authentication settings
type AuthConfig struct {
	// Enabled indicates whether authentication is enabled
	// +optional
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Keys defines authentication keys
	// +optional
	Keys []AuthKey `json:"keys,omitempty"`
}

// AuthKey defines an authentication key
type AuthKey struct {
	// ID is the key ID
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Required
	ID int `json:"id"`

	// Type is the key type
	// +kubebuilder:validation:Enum=MD5;SHA1;SHA256;SHA384;SHA512
	// +kubebuilder:validation:Required
	Type string `json:"type"`

	// Value is the key value
	// +kubebuilder:validation:Required
	Value string `json:"value"`
}

// RateLimitConfig defines rate limiting settings
type RateLimitConfig struct {
	// Enabled indicates whether rate limiting is enabled
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Interval is the rate limiting interval in seconds
	// +kubebuilder:validation:Minimum=1
	// +optional
	// +kubebuilder:default=3
	Interval int `json:"interval,omitempty"`

	// Burst is the maximum number of packets per interval
	// +kubebuilder:validation:Minimum=1
	// +optional
	// +kubebuilder:default=8
	Burst int `json:"burst,omitempty"`
}

// AccessRule defines an access control rule
type AccessRule struct {
	// Network is the IP network in CIDR notation
	// +kubebuilder:validation:Required
	Network string `json:"network"`

	// Permission is the access permission
	// +kubebuilder:validation:Enum=allow;deny
	// +kubebuilder:validation:Required
	Permission string `json:"permission"`
}

// VLANConfig defines NTP configuration for a VLAN
type VLANConfig struct {
	// VLANRef is the name of the VLAN
	// +kubebuilder:validation:Required
	VLANRef string `json:"vlanRef"`

	// Enabled indicates whether NTP is enabled on this VLAN
	// +kubebuilder:validation:Required
	Enabled bool `json:"enabled"`

	// Broadcast indicates whether NTP broadcast is enabled
	// +optional
	// +kubebuilder:default=false
	Broadcast bool `json:"broadcast,omitempty"`

	// ClientsOnly indicates whether this VLAN can only be a client
	// +optional
	// +kubebuilder:default=false
	ClientsOnly bool `json:"clientsOnly,omitempty"`
}

// MonitoringConfig defines monitoring settings
type MonitoringConfig struct {
	// Enabled indicates whether monitoring is enabled
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Offset defines threshold settings for clock offset
	// +optional
	Offset OffsetThresholds `json:"offset,omitempty"`

	// SourcesMinimum is the minimum number of valid sources
	// +kubebuilder:validation:Minimum=1
	// +optional
	// +kubebuilder:default=3
	SourcesMinimum int `json:"sourcesMinimum,omitempty"`
}

// OffsetThresholds defines thresholds for clock offset
type OffsetThresholds struct {
	// WarningThreshold is the threshold in milliseconds for warnings
	// +kubebuilder:validation:Minimum=1
	// +optional
	// +kubebuilder:default=100
	WarningThreshold int `json:"warningThreshold,omitempty"`

	// CriticalThreshold is the threshold in milliseconds for critical alerts
	// +kubebuilder:validation:Minimum=1
	// +optional
	// +kubebuilder:default=1000
	CriticalThreshold int `json:"criticalThreshold,omitempty"`
}

// NTPServiceStatus defines the observed state of the NTP service
type NTPServiceStatus struct {
	// SyncStatus indicates the synchronization status
	// +optional
	SyncStatus string `json:"syncStatus,omitempty"`

	// Stratum is the current stratum level
	// +optional
	Stratum int `json:"stratum,omitempty"`

	// Offset is the current offset in milliseconds
	// +optional
	Offset float64 `json:"offset,omitempty"`

	// Jitter is the current jitter in milliseconds
	// +optional
	Jitter float64 `json:"jitter,omitempty"`

	// SourceCount is the number of time sources
	// +optional
	SourceCount int `json:"sourceCount,omitempty"`

	// Sources is the list of time sources
	// +optional
	Sources []SourceStatus `json:"sources,omitempty"`
}

// SourceStatus defines the status of a time source
type SourceStatus struct {
	// Name is the name or address of the source
	// +optional
	Name string `json:"name,omitempty"`

	// Type is the type of the source (Server, Pool, PPS, GPS, etc.)
	// +optional
	Type string `json:"type,omitempty"`

	// Stratum is the stratum level of the source
	// +optional
	Stratum int `json:"stratum,omitempty"`

	// Offset is the offset in milliseconds
	// +optional
	Offset float64 `json:"offset,omitempty"`

	// Reachability is the reachability score
	// +optional
	Reachability int `json:"reachability,omitempty"`

	// Selected indicates whether this source is selected
	// +optional
	Selected bool `json:"selected,omitempty"`
}