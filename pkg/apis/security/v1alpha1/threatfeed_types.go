package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ThreatFeed defines a threat-intelligence feed to ingest.
//
// A ThreatFeed is polled on an interval, parsed according to its Format,
// and its indicators are translated into Cilium network policies that deny
// traffic to the referenced domains. Indicators are aged out according to
// MaxAge; when an indicator has not been seen in a fetch newer than MaxAge,
// the corresponding Cilium policy is removed.
//
// v0 shipped the "urlhaus-csv" format; Sprint 31 Ticket 53 adds "misp-json"
// behind an API-key Secret referenced via AuthSecretRef.
type ThreatFeed struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ThreatFeedSpec   `json:"spec"`
	Status ThreatFeedStatus `json:"status,omitempty"`
}

// ThreatFeedSpec defines the desired state of a ThreatFeed.
type ThreatFeedSpec struct {
	// URL is the feed source endpoint.
	URL string `json:"url"`

	// Format describes the feed content type. Supported values:
	//   - "urlhaus-csv" — abuse.ch URLhaus CSV feed (no auth)
	//   - "misp-json"   — MISP JSON /events/restSearch (requires AuthSecretRef)
	Format string `json:"format"`

	// AuthSecretRef points at a Kubernetes Secret providing credentials for
	// authenticated feeds. The controller reads the Secret's `apiKey` data
	// key and injects it into the fetcher. Required when Format requires
	// authentication (currently: "misp-json"); ignored otherwise.
	//
	// The Secret must live in the same namespace as the referring
	// ThreatFeed unless the Namespace field is explicitly set, matching
	// the upstream SecretReference semantics.
	AuthSecretRef *corev1.SecretReference `json:"authSecretRef,omitempty"`

	// RefreshInterval is how often the feed is re-fetched.
	RefreshInterval metav1.Duration `json:"refreshInterval"`

	// MaxAge is how long an ingested indicator stays enforced. An indicator
	// whose last-seen time is older than MaxAge is expired and its Cilium
	// policy is removed.
	MaxAge metav1.Duration `json:"maxAge"`

	// Enabled controls whether the feed is actively polled. Disabled feeds
	// leave their active indicators in place until MaxAge elapses.
	Enabled bool `json:"enabled,omitempty"`
}

// ThreatFeedStatus captures the observed state of a ThreatFeed.
type ThreatFeedStatus struct {
	// LastFetchTime records when the feed was last successfully fetched.
	LastFetchTime metav1.Time `json:"lastFetchTime,omitempty"`

	// LastFetchError contains the last fetch error, empty on success.
	LastFetchError string `json:"lastFetchError,omitempty"`

	// EntryCount is the number of indicator rows parsed in the most recent
	// successful fetch.
	EntryCount int32 `json:"entryCount,omitempty"`

	// ActiveIndicators is the number of indicators currently enforced as
	// Cilium policies. It may be less than EntryCount when entries have
	// expired or when the feed contains duplicates/unresolvable URLs.
	ActiveIndicators int32 `json:"activeIndicators,omitempty"`

	// Conditions captures the detailed state transitions of the feed.
	Conditions []ThreatFeedCondition `json:"conditions,omitempty"`
}

// ThreatFeedCondition describes a condition of a ThreatFeed.
type ThreatFeedCondition struct {
	// Type is the condition type (e.g. "Ready", "FetchSucceeded").
	Type string `json:"type"`

	// Status is the truthiness of the condition (True, False, Unknown).
	Status string `json:"status"`

	// Reason is a short CamelCase reason for the condition.
	Reason string `json:"reason,omitempty"`

	// Message is a human-readable message.
	Message string `json:"message,omitempty"`

	// LastTransitionTime is when the condition last transitioned.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ThreatFeedList contains a list of ThreatFeed resources.
type ThreatFeedList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ThreatFeed `json:"items"`
}

// Standard condition types emitted by the ThreatFeed controller.
const (
	// ThreatFeedConditionReady indicates whether the feed is enforced with
	// at least one active indicator.
	ThreatFeedConditionReady = "Ready"

	// ThreatFeedConditionFetchSucceeded indicates whether the most recent
	// fetch completed without error.
	ThreatFeedConditionFetchSucceeded = "FetchSucceeded"
)

// Supported ThreatFeed formats.
const (
	// ThreatFeedFormatURLhausCSV identifies the abuse.ch URLhaus CSV feed.
	ThreatFeedFormatURLhausCSV = "urlhaus-csv"

	// ThreatFeedFormatMISPJSON identifies the MISP events/restSearch JSON
	// feed. Requires AuthSecretRef.
	ThreatFeedFormatMISPJSON = "misp-json"
)

// Well-known data keys that the controller expects inside an auth Secret.
const (
	// ThreatFeedAuthSecretAPIKey is the data key the controller reads from
	// an AuthSecretRef'd Secret when the feed format is MISP JSON. The
	// value is passed verbatim as the `Authorization` header.
	ThreatFeedAuthSecretAPIKey = "apiKey"
)
