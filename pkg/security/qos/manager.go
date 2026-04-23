// Package qos historically hosted a TC-based QoSManager that shelled out
// to `tc` and `ip` binaries to apply HTB classful shaping. That prototype
// has been retired — Sprint 30 / Ticket 45 moved QoS enforcement onto
// Cilium's Bandwidth Manager via the translator in bandwidth_manager.go.
//
// This file is kept (rather than deleted) purely to preserve the legacy
// type aliases that other packages and the older tc-flavoured example
// YAML still reference by name. The types are intentionally data-only;
// no behaviour is attached here. Any new code should use the Bandwidth
// Manager translator, not these types.
package qos

// QoSProfile is the legacy tc-shaped view of a profile. Kept as a passive
// data structure so existing YAML examples still reference something. New
// callers must use qos.QoSProfileSpec (see bandwidth_manager.go) instead.
type QoSProfile struct {
	Interface         string
	UploadBandwidth   string
	DownloadBandwidth string
	DefaultClass      string
	Classes           []TrafficClass
}

// TrafficClass is the legacy tc-class descriptor. Retained for schema
// compatibility with existing QoSProfile CRs that still list `classes` —
// the Bandwidth Manager path ignores these fields.
type TrafficClass struct {
	Name                  string
	Priority              int
	MinBandwidth          string
	MaxBandwidth          string
	Burst                 string
	DSCP                  int
	Applications          []string
	ApplicationCategories []string
	SourceAddresses       []string
	DestinationAddresses  []string
	SourcePort            string
	DestinationPort       string
	Protocol              string
}

// ClassStatistics is the legacy stats shape a former tc-based implementation
// populated. Retained so it can be referenced without reintroducing the tc
// binary dependency; every field is zero by default.
type ClassStatistics struct {
	ClassID string
	Packets int64
	Bytes   int64
	Drops   int64
}
