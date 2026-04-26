// Package v1alpha1 hosts the network.fos1.io/v1alpha1 typed API surface.
//
// Sprint 31 / Ticket 52 introduced this package alongside the existing
// pkg/apis/network/v1 directory because the TrafficShaper CRD is a new API
// and follows the project's recent CRD-versioning convention of
// `*.fos1.io/v1alpha1` (matching QoSProfile, ThreatFeed, FilterPolicy, etc.).
// Older NetworkInterface/DHCPService types remain under v1 untouched.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TrafficShaper drives per-interface egress (and optional ingress) priority
// marking via the Sprint 30 Ticket 39 TC loader (`pkg/hardware/ebpf.TCLoader`).
//
// Composition with QoSProfile (Sprint 30 Ticket 45) is intentionally
// orthogonal:
//
//   - QoSProfile rate-limits **per pod** via Cilium Bandwidth Manager
//     (annotations on the pod's veth).
//   - TrafficShaper marks **per interface** (uplink / VLAN / bond) via the
//     `clsact` qdisc + `tc_qos_shape` BPF program. It writes to the
//     `qos_iface_priority` BPF map; the in-kernel program stamps
//     `skb->priority` for downstream classful qdiscs to honour.
//
// The two CRDs do not interact at the data plane: the BPF rate-limiter sits
// on the pod veth, the TC shaper sits on the host's uplink. Operators who
// want per-pod caps AND uplink-side prioritisation should author both.
type TrafficShaper struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TrafficShaperSpec   `json:"spec"`
	Status TrafficShaperStatus `json:"status,omitempty"`
}

// TrafficShaperSpec is the desired state of a TrafficShaper.
//
// Validation contract:
//
//   - Interface MUST be non-empty and resolvable on the host running the
//     controller (the controller reports Invalid=True if the interface
//     cannot be resolved at apply time — the spec field itself is just a
//     string here for forward-compatibility with not-yet-attached
//     interfaces).
//   - Direction MUST be one of {egress, ingress, both}. Empty defaults to
//     egress for backward-compatibility with the v1 plan shape.
//   - Rules MAY be empty (no-op shaper, useful for declaratively saying
//     "leave this interface alone") but if present each Rule must have at
//     least one match field set.
type TrafficShaperSpec struct {
	// Interface is the host network interface this shaper attaches to
	// (e.g. "eth0", "vlan100", "bond0"). The controller resolves the
	// ifindex at reconcile time; an unresolvable interface yields
	// Invalid=True without crashing the controller.
	Interface string `json:"interface"`

	// Direction selects which TC hook is bootstrapped:
	//
	//   - "egress"  — only the egress program is attached.
	//   - "ingress" — only the ingress program is attached.
	//   - "both"    — both programs are attached on the same clsact qdisc.
	//
	// Empty defaults to "egress" to match the most common uplink-shaping
	// case and preserve forward-compatibility with v1 specs that omit
	// Direction.
	Direction TrafficShaperDirection `json:"direction,omitempty"`

	// Rules is the list of priority rules to install. Each rule resolves
	// to one Put() into `qos_iface_priority` plus, in the future, a TBF
	// rate cap (Rate is parsed but not yet enforced — see the design
	// notes; the v1 data path stamps skb->priority and relies on a
	// downstream classful qdisc to enforce the cap).
	//
	// The controller hashes the entire Rules slice into LastAppliedHash
	// for idempotent reconcile.
	Rules []TrafficShaperRule `json:"rules,omitempty"`
}

// TrafficShaperDirection is the TC hook direction for a shaper.
type TrafficShaperDirection string

// Direction values accepted on TrafficShaperSpec.Direction.
const (
	// TrafficShaperDirectionEgress attaches only the egress TC program.
	// This is the default and the most common case (uplink shaping).
	TrafficShaperDirectionEgress TrafficShaperDirection = "egress"

	// TrafficShaperDirectionIngress attaches only the ingress TC program.
	// Useful for marking inbound traffic on a VLAN before it crosses
	// into pod networking — supported but rare in v1.
	TrafficShaperDirectionIngress TrafficShaperDirection = "ingress"

	// TrafficShaperDirectionBoth attaches both ingress and egress
	// programs on the same clsact qdisc.
	TrafficShaperDirectionBoth TrafficShaperDirection = "both"
)

// TrafficShaperRule pairs a match clause with a TC priority class. At least
// one of MatchCIDR / MatchDSCP must be set; rules with no match field are
// rejected at translate time.
type TrafficShaperRule struct {
	// MatchCIDR matches packets whose destination IP falls inside the
	// given CIDR. Mutually compatible with MatchDSCP — when both are set
	// the rule fires only on packets matching both. Empty string means
	// "do not filter on CIDR".
	MatchCIDR string `json:"matchCIDR,omitempty"`

	// MatchDSCP matches packets carrying this DSCP value (0-63). The zero
	// value is ambiguous with "no DSCP match", so the field is treated as
	// unset when MatchDSCP == 0 — operators who actually need to match
	// DSCP=0 (best-effort default) should keep that rule implicit.
	MatchDSCP int32 `json:"matchDSCP,omitempty"`

	// Priority is the TC priority class assigned to matching packets.
	// Written into the `qos_iface_priority` BPF map keyed by the
	// shaper's resolved ifindex. Must be 1-7 to fit the standard 802.1p
	// PCP range; values outside that range are rejected.
	Priority uint32 `json:"priority"`

	// Rate is an optional rate cap expressed in TC's Rate format
	// ("100Mbit", "10Mbps", "1Gbit"). Parsed but not enforced by the v1
	// data path — kept on the spec so a future TBF/HTB layer can pick
	// it up without a CRD change. Empty string means "no rate cap".
	Rate string `json:"rate,omitempty"`
}

// TrafficShaperStatus captures the observed state of a TrafficShaper.
type TrafficShaperStatus struct {
	// ObservedGeneration is the metadata.generation reflected by this
	// status. Operators can compare ObservedGeneration vs.
	// metadata.generation to detect a pending reconcile.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastAppliedHash is a short content hash of the spec.Rules slice
	// at the time the last successful reconcile completed. Used by the
	// controller to short-circuit when the spec has not changed.
	LastAppliedHash string `json:"lastAppliedHash,omitempty"`

	// LastUpdated is the wall-clock time of the last status writeback.
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`

	// AppliedRuleCount is the number of rules that landed in the
	// `qos_iface_priority` BPF map on the most recent reconcile. May be
	// less than len(spec.Rules) if some rules failed validation.
	AppliedRuleCount int32 `json:"appliedRuleCount,omitempty"`

	// Conditions captures the detailed state transitions. The controller
	// always emits Applied / Degraded / Invalid / Removed so consumers
	// see explicit False rather than absent conditions.
	Conditions []TrafficShaperCondition `json:"conditions,omitempty"`
}

// TrafficShaperCondition describes one condition of a TrafficShaper.
//
// The shape mirrors the metav1.Condition convention but is duplicated here
// so the type is self-contained and matches the project's existing
// ThreatFeedCondition / SuricataInstance conditions which also embed their
// own condition struct rather than depend on the unstable metav1 condition
// (some older Kubernetes versions ship slightly different field tags).
type TrafficShaperCondition struct {
	// Type is the condition type — one of TrafficShaperCondition*
	// constants below.
	Type string `json:"type"`

	// Status is "True", "False", or "Unknown". The controller always
	// emits "True" or "False" — never "Unknown" — so consumers can
	// treat absent-or-Unknown as a controller bug.
	Status string `json:"status"`

	// Reason is a short CamelCase tag explaining why the condition is
	// in its current state. Empty when no specific reason applies.
	Reason string `json:"reason,omitempty"`

	// Message is a human-readable expansion of Reason.
	Message string `json:"message,omitempty"`

	// LastTransitionTime is when the condition last flipped status.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
}

// Standard condition types emitted by the TrafficShaper controller. Kept
// as constants so callers (status writers, tests) reference them by name.
const (
	// TrafficShaperConditionApplied is True when the controller has
	// pushed every rule into the BPF priority map and attached the
	// requested direction(s).
	TrafficShaperConditionApplied = "Applied"

	// TrafficShaperConditionDegraded is True when the apply partially
	// succeeded: at least one rule landed but at least one rule errored
	// (e.g. the interface vanished mid-apply). Applied may still be True.
	TrafficShaperConditionDegraded = "Degraded"

	// TrafficShaperConditionInvalid is True when the spec failed
	// validation (no interface, bad direction, no match fields on a
	// rule, priority out of range). The controller does not retry until
	// the spec changes.
	TrafficShaperConditionInvalid = "Invalid"

	// TrafficShaperConditionRemoved is True after a delete-handler has
	// cleared the priority map for the shaper's interface. Lives only
	// briefly because the CR is being deleted from the API server.
	TrafficShaperConditionRemoved = "Removed"
)

// Standard condition statuses.
const (
	// TrafficShaperConditionStatusTrue is the "True" string used in
	// Status fields. Kept as a constant so a typo can't sneak in.
	TrafficShaperConditionStatusTrue = "True"

	// TrafficShaperConditionStatusFalse is the "False" string used in
	// Status fields.
	TrafficShaperConditionStatusFalse = "False"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TrafficShaperList contains a list of TrafficShaper resources.
type TrafficShaperList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrafficShaper `json:"items"`
}
