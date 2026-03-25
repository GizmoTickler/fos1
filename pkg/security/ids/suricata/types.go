// Package suricata provides a client for interacting with the Suricata IDS/IPS
// engine via its Unix domain socket control interface.
package suricata

// Command represents a Suricata control socket command.
type Command struct {
	Command   string         `json:"command"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// Response represents a Suricata control socket response.
type Response struct {
	Return  string `json:"return"`
	Message any    `json:"message"`
}

// SuricataStats holds the counters returned by the "dump-counters" command.
type SuricataStats struct {
	Uptime  int64        `json:"uptime"`
	Capture CaptureStats `json:"capture"`
	Decoder DecoderStats `json:"decoder"`
	Flow    FlowStats    `json:"flow"`
	Detect  DetectStats  `json:"detect"`
}

// CaptureStats contains packet capture counters.
type CaptureStats struct {
	KernelPackets int64 `json:"kernel_packets"`
	KernelDrops   int64 `json:"kernel_drops"`
	Errors        int64 `json:"errors"`
}

// DecoderStats contains protocol decoder counters.
type DecoderStats struct {
	Pkts     int64 `json:"pkts"`
	Bytes    int64 `json:"bytes"`
	Invalid  int64 `json:"invalid"`
	IPv4     int64 `json:"ipv4"`
	IPv6     int64 `json:"ipv6"`
	Ethernet int64 `json:"ethernet"`
	TCP      int64 `json:"tcp"`
	UDP      int64 `json:"udp"`
	ICMP     int64 `json:"icmp"`
}

// FlowStats contains flow tracking counters.
type FlowStats struct {
	Total    int64 `json:"total"`
	Active   int64 `json:"active"`
	TCP      int64 `json:"tcp"`
	UDP      int64 `json:"udp"`
	ICMP     int64 `json:"icmp"`
	TimedOut int64 `json:"timed_out"`
}

// DetectStats contains detection engine counters.
type DetectStats struct {
	Alerts       int64 `json:"alerts"`
	RulesLoaded  int64 `json:"rules_loaded"`
	RulesFailed  int64 `json:"rules_failed"`
	RulesSkipped int64 `json:"rules_skipped"`
}
