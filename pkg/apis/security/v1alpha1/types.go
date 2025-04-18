package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SuricataInstance defines a Suricata IDS/IPS instance
type SuricataInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SuricataInstanceSpec   `json:"spec"`
	Status SuricataInstanceStatus `json:"status,omitempty"`
}

// SuricataInstanceSpec defines the desired state of a Suricata instance
type SuricataInstanceSpec struct {
	// Mode is the mode of operation (IDS or IPS)
	Mode string `json:"mode,omitempty"`

	// Interfaces are the network interfaces to monitor
	Interfaces []SuricataInterface `json:"interfaces"`

	// RuleSources are the sources for Suricata rules
	RuleSources []RuleSource `json:"ruleSources,omitempty"`

	// CustomRules are custom Suricata rules
	CustomRules []string `json:"customRules,omitempty"`

	// DisabledRules are the IDs of disabled rules
	DisabledRules []string `json:"disabledRules,omitempty"`

	// Resources are the resource requirements
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// DetectionEngineProfile is the detection engine profile
	DetectionEngineProfile string `json:"detectionEngineProfile,omitempty"`

	// MemoryProfile is the memory profile
	MemoryProfile string `json:"memoryProfile,omitempty"`

	// MaxPendingPackets is the maximum number of pending packets
	MaxPendingPackets int `json:"maxPendingPackets,omitempty"`

	// StatsInterval is the interval for statistics
	StatsInterval string `json:"statsInterval,omitempty"`

	// LogLevel is the log level
	LogLevel string `json:"logLevel,omitempty"`

	// HostNetwork indicates whether to use host network
	HostNetwork bool `json:"hostNetwork,omitempty"`

	// NodeSelector is the node selector for deployment
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// SuricataInterface defines a network interface for Suricata
type SuricataInterface struct {
	// Name is the name of the interface
	Name string `json:"name"`

	// Promiscuous indicates whether to use promiscuous mode
	Promiscuous bool `json:"promiscuous,omitempty"`

	// BPFFilter is the BPF filter for the interface
	BPFFilter string `json:"bpfFilter,omitempty"`

	// Checksum indicates whether to validate checksums
	Checksum bool `json:"checksum,omitempty"`

	// ThreadCount is the number of threads to use
	ThreadCount int `json:"threadCount,omitempty"`
}

// RuleSource defines a source for IDS/IPS rules
type RuleSource struct {
	// Name is the name of the source
	Name string `json:"name"`

	// URL is the URL of the source
	URL string `json:"url"`

	// Enabled indicates whether the source is enabled
	Enabled bool `json:"enabled,omitempty"`

	// Categories are the categories to include
	Categories []string `json:"categories,omitempty"`

	// ExcludedCategories are the categories to exclude
	ExcludedCategories []string `json:"excludedCategories,omitempty"`
}

// SuricataInstanceStatus defines the observed state of a Suricata instance
type SuricataInstanceStatus struct {
	// Phase is the current phase of the instance
	Phase string `json:"phase,omitempty"`

	// Conditions are the current conditions of the instance
	Conditions []SuricataInstanceCondition `json:"conditions,omitempty"`

	// RulesLastUpdated is the time when the rules were last updated
	RulesLastUpdated metav1.Time `json:"rulesLastUpdated,omitempty"`

	// RulesCount is the number of loaded rules
	RulesCount int `json:"rulesCount,omitempty"`

	// Uptime is the uptime of the instance
	Uptime string `json:"uptime,omitempty"`

	// LastRestart is the time of the last restart
	LastRestart metav1.Time `json:"lastRestart,omitempty"`

	// AlertsGenerated is the number of alerts generated
	AlertsGenerated int `json:"alertsGenerated,omitempty"`

	// InterfaceStats is the statistics per interface
	InterfaceStats map[string]InterfaceStatistics `json:"interfaceStats,omitempty"`
}

// SuricataInstanceCondition defines a condition of a Suricata instance
type SuricataInstanceCondition struct {
	// Type is the type of the condition
	Type string `json:"type"`

	// Status is the status of the condition
	Status string `json:"status"`

	// Reason is the reason for the condition
	Reason string `json:"reason,omitempty"`

	// Message is the message for the condition
	Message string `json:"message,omitempty"`

	// LastTransitionTime is the time of the last transition
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
}

// InterfaceStatistics defines statistics for an interface
type InterfaceStatistics struct {
	// PacketsReceived is the number of packets received
	PacketsReceived int `json:"packetsReceived,omitempty"`

	// PacketsDropped is the number of packets dropped
	PacketsDropped int `json:"packetsDropped,omitempty"`

	// BytesReceived is the number of bytes received
	BytesReceived int `json:"bytesReceived,omitempty"`

	// AlertsGenerated is the number of alerts generated
	AlertsGenerated int `json:"alertsGenerated,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SuricataInstanceList contains a list of SuricataInstance
type SuricataInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SuricataInstance `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ZeekInstance defines a Zeek network analysis instance
type ZeekInstance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ZeekInstanceSpec   `json:"spec"`
	Status ZeekInstanceStatus `json:"status,omitempty"`
}

// ZeekInstanceSpec defines the desired state of a Zeek instance
type ZeekInstanceSpec struct {
	// Interfaces are the network interfaces to monitor
	Interfaces []ZeekInterface `json:"interfaces"`

	// Scripts are the Zeek scripts to load
	Scripts []ZeekScript `json:"scripts,omitempty"`

	// ClusterMode indicates whether to use cluster mode
	ClusterMode bool `json:"clusterMode,omitempty"`

	// NodeName is the name of the node in cluster mode
	NodeName string `json:"nodeName,omitempty"`

	// LogRotationInterval is the interval for log rotation
	LogRotationInterval string `json:"logRotationInterval,omitempty"`

	// Resources are the resource requirements
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// LogLevel is the log level
	LogLevel string `json:"logLevel,omitempty"`

	// HostNetwork indicates whether to use host network
	HostNetwork bool `json:"hostNetwork,omitempty"`

	// NodeSelector is the node selector for deployment
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// ThreadCount is the number of threads to use
	ThreadCount int `json:"threadCount,omitempty"`
}

// ZeekInterface defines a network interface for Zeek
type ZeekInterface struct {
	// Name is the name of the interface
	Name string `json:"name"`

	// Promiscuous indicates whether to use promiscuous mode
	Promiscuous bool `json:"promiscuous,omitempty"`

	// BPFFilter is the BPF filter for the interface
	BPFFilter string `json:"bpfFilter,omitempty"`
}

// ZeekScript defines a Zeek script
type ZeekScript struct {
	// Name is the name of the script
	Name string `json:"name"`

	// Path is the path to the script
	Path string `json:"path,omitempty"`

	// Enabled indicates whether the script is enabled
	Enabled bool `json:"enabled,omitempty"`

	// Config is the configuration for the script
	Config map[string]string `json:"config,omitempty"`
}

// ZeekInstanceStatus defines the observed state of a Zeek instance
type ZeekInstanceStatus struct {
	// Phase is the current phase of the instance
	Phase string `json:"phase,omitempty"`

	// Conditions are the current conditions of the instance
	Conditions []ZeekInstanceCondition `json:"conditions,omitempty"`

	// Uptime is the uptime of the instance
	Uptime string `json:"uptime,omitempty"`

	// LastRestart is the time of the last restart
	LastRestart metav1.Time `json:"lastRestart,omitempty"`

	// EventsGenerated is the number of events generated
	EventsGenerated int `json:"eventsGenerated,omitempty"`

	// InterfaceStats is the statistics per interface
	InterfaceStats map[string]ZeekInterfaceStatistics `json:"interfaceStats,omitempty"`
}

// ZeekInstanceCondition defines a condition of a Zeek instance
type ZeekInstanceCondition struct {
	// Type is the type of the condition
	Type string `json:"type"`

	// Status is the status of the condition
	Status string `json:"status"`

	// Reason is the reason for the condition
	Reason string `json:"reason,omitempty"`

	// Message is the message for the condition
	Message string `json:"message,omitempty"`

	// LastTransitionTime is the time of the last transition
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
}

// ZeekInterfaceStatistics defines statistics for an interface
type ZeekInterfaceStatistics struct {
	// PacketsReceived is the number of packets received
	PacketsReceived int `json:"packetsReceived,omitempty"`

	// PacketsDropped is the number of packets dropped
	PacketsDropped int `json:"packetsDropped,omitempty"`

	// BytesReceived is the number of bytes received
	BytesReceived int `json:"bytesReceived,omitempty"`

	// EventsGenerated is the number of events generated
	EventsGenerated int `json:"eventsGenerated,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ZeekInstanceList contains a list of ZeekInstance
type ZeekInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ZeekInstance `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EventCorrelation defines an event correlation instance
type EventCorrelation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EventCorrelationSpec   `json:"spec"`
	Status EventCorrelationStatus `json:"status,omitempty"`
}

// EventCorrelationSpec defines the desired state of an event correlation instance
type EventCorrelationSpec struct {
	// Enabled indicates whether event correlation is enabled
	Enabled bool `json:"enabled,omitempty"`

	// Rules are the correlation rules
	Rules []CorrelationRule `json:"rules"`

	// MaxEventsInMemory is the maximum number of events to keep in memory
	MaxEventsInMemory int `json:"maxEventsInMemory,omitempty"`

	// MaxEventAge is the maximum age of events to keep in memory
	MaxEventAge string `json:"maxEventAge,omitempty"`

	// OutputFormat is the format for correlated events
	OutputFormat string `json:"outputFormat,omitempty"`

	// Resources are the resource requirements
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector is the node selector for deployment
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
}

// CorrelationRule defines a rule for event correlation
type CorrelationRule struct {
	// Name is the name of the rule
	Name string `json:"name"`

	// Description is the description of the rule
	Description string `json:"description,omitempty"`

	// Conditions are the conditions for the rule
	Conditions []CorrelationCondition `json:"conditions"`

	// Threshold is the threshold for the rule
	Threshold int `json:"threshold,omitempty"`

	// TimeWindow is the time window for the rule
	TimeWindow string `json:"timeWindow,omitempty"`

	// Severity is the severity of the rule
	Severity string `json:"severity,omitempty"`

	// Action is the action to take when the rule matches
	Action string `json:"action,omitempty"`
}

// CorrelationCondition defines a condition for event correlation
type CorrelationCondition struct {
	// Field is the field to match
	Field string `json:"field"`

	// Operator is the operator for the match
	Operator string `json:"operator"`

	// Value is the value to match
	Value string `json:"value"`
}

// EventCorrelationStatus defines the observed state of an event correlation instance
type EventCorrelationStatus struct {
	// Phase is the current phase of the instance
	Phase string `json:"phase,omitempty"`

	// Conditions are the current conditions of the instance
	Conditions []EventCorrelationCondition `json:"conditions,omitempty"`

	// Uptime is the uptime of the instance
	Uptime string `json:"uptime,omitempty"`

	// LastRestart is the time of the last restart
	LastRestart metav1.Time `json:"lastRestart,omitempty"`

	// EventsProcessed is the number of events processed
	EventsProcessed int `json:"eventsProcessed,omitempty"`

	// CorrelationsDetected is the number of correlations detected
	CorrelationsDetected int `json:"correlationsDetected,omitempty"`

	// RuleStats is the statistics per rule
	RuleStats map[string]RuleStatistics `json:"ruleStats,omitempty"`
}

// EventCorrelationCondition defines a condition of an event correlation instance
type EventCorrelationCondition struct {
	// Type is the type of the condition
	Type string `json:"type"`

	// Status is the status of the condition
	Status string `json:"status"`

	// Reason is the reason for the condition
	Reason string `json:"reason,omitempty"`

	// Message is the message for the condition
	Message string `json:"message,omitempty"`

	// LastTransitionTime is the time of the last transition
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
}

// RuleStatistics defines statistics for a rule
type RuleStatistics struct {
	// Matches is the number of matches for the rule
	Matches int `json:"matches,omitempty"`

	// LastMatch is the time of the last match
	LastMatch metav1.Time `json:"lastMatch,omitempty"`

	// ActionsTriggered is the number of actions triggered
	ActionsTriggered int `json:"actionsTriggered,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EventCorrelationList contains a list of EventCorrelation
type EventCorrelationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EventCorrelation `json:"items"`
}
