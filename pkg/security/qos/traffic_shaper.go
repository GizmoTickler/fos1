// Package qos hosts both the QoSProfile / Bandwidth Manager translator
// (Sprint 30 Ticket 45, see bandwidth_manager.go) and the TrafficShaper /
// TC-loader translator (Sprint 31 Ticket 52, this file).
//
// The two translators are intentionally orthogonal:
//
//   - bandwidth_manager.go drives **per-pod** egress rate limits via Cilium
//     Bandwidth Manager pod annotations.
//   - traffic_shaper.go drives **per-interface** egress (and optional
//     ingress) priority marking via the Sprint 30 Ticket 39 TC loader
//     (`pkg/hardware/ebpf.TCLoader`). It writes into the
//     `qos_iface_priority` BPF map and (re)attaches the tc_qos_shape
//     program against a clsact qdisc.
//
// They do not share state and do not interact at the data plane. An
// operator wanting both per-pod caps and uplink-side prioritisation
// authors a QoSProfile AND a TrafficShaper.
package qos

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	networkv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/network/v1alpha1"
)

// TCBackend is the minimal surface the TrafficShaper translator needs from
// the Sprint 30 Ticket 39 TCLoader. Defining it as an interface lets unit
// tests inject a recording fake without depending on a Linux-only
// `*ebpf.Collection`. Both EnsureAttached invocations (one per direction)
// are idempotent — the loader's underlying `link.AttachTCX` will reuse an
// existing TCX attachment if one is present.
//
// The interface exposes only methods whose signatures match between the
// Linux and stub builds of `pkg/hardware/ebpf.TCLoader` so this package
// compiles cleanly on darwin / windows for development and CI.
type TCBackend interface {
	// SetPriority writes (ifaceName → priority) into the BPF priority
	// map. Idempotent — a second call with the same arguments is a no-op
	// at the kernel level (BPF_ANY overwrites the existing entry).
	SetPriority(ifaceName string, priority uint32) error

	// ClearPriority removes any priority entry for ifaceName. Returning
	// nil when no entry exists is part of the contract.
	ClearPriority(ifaceName string) error

	// EnsureAttached attaches the tc_qos_shape program to the given
	// interface in the requested direction(s). Implementations track the
	// resulting `link.Link` internally so a subsequent EnsureDetached
	// call can release them. Idempotent — re-invoking with the same
	// (interface, direction) pair must not produce duplicate attachments
	// nor an error.
	EnsureAttached(ifaceName string, direction networkv1alpha1.TrafficShaperDirection) error

	// EnsureDetached releases every link the backend has installed for
	// ifaceName, in any direction. Used during teardown. Returning nil
	// when no links were installed is part of the contract.
	EnsureDetached(ifaceName string) error
}

// TrafficShaperPlan is the deterministic, IO-free output of the
// TrafficShaper translator. It captures everything the controller needs to
// hand to a TCBackend: the resolved interface, the chosen priority, the
// attach direction, and a content hash for idempotent re-apply.
type TrafficShaperPlan struct {
	// Interface mirrors spec.interface verbatim. The translator does not
	// resolve ifindex — that's a controller-side concern at apply time.
	Interface string

	// Direction is the resolved attach direction (default "egress" when
	// the spec leaves it empty).
	Direction networkv1alpha1.TrafficShaperDirection

	// Priority is the value the translator chose to write into the BPF
	// priority map for Interface. v1 collapses the spec.rules slice into
	// a single per-ifindex priority by selecting the lowest Priority
	// value across all rules — matching 802.1p semantics where lower
	// PCP values are higher-priority. Operators wanting per-flow
	// classification beyond a single priority must wait for a future
	// expansion of the BPF program (see "Future work" in the design
	// doc).
	Priority uint32

	// AppliedRuleCount is len(spec.rules) at translate time. Captured on
	// the plan so the controller can persist it into status.appliedRuleCount
	// without re-counting.
	AppliedRuleCount int32

	// Hash is a short content hash over the spec fields the plan
	// depends on. Stable across translate calls with equal inputs;
	// different across any spec mutation that changes the apply path.
	Hash string
}

// Errors emitted by the translator. The controller maps each one to
// Invalid=True on the CRD status with the error's message as the reason.
var (
	// ErrTrafficShaperNoInterface is returned when spec.interface is
	// empty.
	ErrTrafficShaperNoInterface = fmt.Errorf("traffic shaper: spec.interface is required")

	// ErrTrafficShaperBadDirection is returned when spec.direction is
	// set to a value outside the {egress, ingress, both} set.
	ErrTrafficShaperBadDirection = fmt.Errorf("traffic shaper: spec.direction must be egress, ingress, or both")

	// ErrTrafficShaperNoRules is returned when the rule list is empty.
	// A shaper with no rules has nothing to install — the operator
	// likely wanted to delete the CR instead.
	ErrTrafficShaperNoRules = fmt.Errorf("traffic shaper: spec.rules must contain at least one rule")

	// ErrTrafficShaperEmptyRule is returned when a rule has no match
	// fields (no MatchCIDR, no MatchDSCP). Such a rule cannot identify
	// any traffic and is rejected.
	ErrTrafficShaperEmptyRule = fmt.Errorf("traffic shaper: each rule must set at least one of matchCIDR or matchDSCP")

	// ErrTrafficShaperBadPriority is returned when a rule's priority
	// is outside the 1-7 (802.1p PCP) range. Operators who want
	// best-effort (priority 0) should leave the rule out entirely.
	ErrTrafficShaperBadPriority = fmt.Errorf("traffic shaper: rule.priority must be in [1,7]")
)

// TranslateTrafficShaper converts a TrafficShaperSpec into a
// TrafficShaperPlan. Pure / deterministic — two calls with equal inputs
// return equal plans (including hash).
//
// Validation is performed up-front: the function returns one of the
// Err* sentinels above on the first violation found, and the controller
// maps that to Invalid=True. Successful return guarantees Plan is
// ready to hand to a TCBackend.
//
// Rule fan-out: the spec exposes a slice of rules (CIDR, DSCP) for
// forward-compatibility with a richer BPF data path, but the v1 program
// only stores a single priority per ifindex. The translator collapses
// the slice by picking the **lowest** Priority value across all rules
// — matching 802.1p semantics where 0/1 is highest priority, 7 is
// lowest. The collapse is documented on the plan struct.
func TranslateTrafficShaper(spec *networkv1alpha1.TrafficShaperSpec) (*TrafficShaperPlan, error) {
	if spec == nil {
		return nil, fmt.Errorf("traffic shaper: nil spec")
	}
	if strings.TrimSpace(spec.Interface) == "" {
		return nil, ErrTrafficShaperNoInterface
	}

	dir, err := normalizeDirection(spec.Direction)
	if err != nil {
		return nil, err
	}

	if len(spec.Rules) == 0 {
		return nil, ErrTrafficShaperNoRules
	}

	// Pick the lowest priority across all valid rules. Lower PCP =
	// higher priority in 802.1p. Each rule still has to validate
	// individually so an operator can't sneak in a malformed rule by
	// pairing it with a valid one.
	var lowest uint32 = 0
	picked := false
	for i, r := range spec.Rules {
		if err := validateRule(i, &r); err != nil {
			return nil, err
		}
		if !picked || r.Priority < lowest {
			lowest = r.Priority
			picked = true
		}
	}

	return &TrafficShaperPlan{
		Interface:        spec.Interface,
		Direction:        dir,
		Priority:         lowest,
		AppliedRuleCount: int32(len(spec.Rules)),
		Hash:             trafficShaperHash(spec.Interface, dir, spec.Rules),
	}, nil
}

// normalizeDirection canonicalises spec.Direction. Empty defaults to
// egress to match the v1 plan shape.
func normalizeDirection(d networkv1alpha1.TrafficShaperDirection) (networkv1alpha1.TrafficShaperDirection, error) {
	switch d {
	case "":
		return networkv1alpha1.TrafficShaperDirectionEgress, nil
	case networkv1alpha1.TrafficShaperDirectionEgress,
		networkv1alpha1.TrafficShaperDirectionIngress,
		networkv1alpha1.TrafficShaperDirectionBoth:
		return d, nil
	default:
		return "", fmt.Errorf("%w: got %q", ErrTrafficShaperBadDirection, d)
	}
}

// validateRule enforces the contract documented on the
// TrafficShaperRule type. The index is woven into the error message so
// operators can locate the offending rule in their YAML.
func validateRule(idx int, r *networkv1alpha1.TrafficShaperRule) error {
	hasMatch := strings.TrimSpace(r.MatchCIDR) != "" || r.MatchDSCP > 0
	if !hasMatch {
		return fmt.Errorf("%w (rule[%d])", ErrTrafficShaperEmptyRule, idx)
	}
	if r.Priority < 1 || r.Priority > 7 {
		return fmt.Errorf("%w (rule[%d] priority=%d)", ErrTrafficShaperBadPriority, idx, r.Priority)
	}
	return nil
}

// trafficShaperHash is a stable content hash used to short-circuit
// reconciles when the spec hasn't changed. The hash includes every spec
// field the translator consults so any change that affects the plan
// changes the hash.
func trafficShaperHash(iface string, dir networkv1alpha1.TrafficShaperDirection, rules []networkv1alpha1.TrafficShaperRule) string {
	// Sort rules by a stable key so two specs with the same rules in
	// different orders hash to the same value. Stability is
	// alphabetical-by-CIDR then numeric-by-DSCP then numeric-by-priority.
	sorted := make([]networkv1alpha1.TrafficShaperRule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].MatchCIDR != sorted[j].MatchCIDR {
			return sorted[i].MatchCIDR < sorted[j].MatchCIDR
		}
		if sorted[i].MatchDSCP != sorted[j].MatchDSCP {
			return sorted[i].MatchDSCP < sorted[j].MatchDSCP
		}
		return sorted[i].Priority < sorted[j].Priority
	})

	h := sha256.New()
	fmt.Fprintf(h, "iface=%s;dir=%s;", iface, dir)
	for _, r := range sorted {
		fmt.Fprintf(h, "cidr=%s;dscp=%d;prio=%d;rate=%s|", r.MatchCIDR, r.MatchDSCP, r.Priority, r.Rate)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ApplyTrafficShaper installs a TrafficShaperPlan via the supplied
// TCBackend. It is the single seam between the pure translator and the
// effectful TCLoader: the controller passes a real `*ebpf.TCLoader`
// wrapper in production and a recording fake in tests.
//
// Sequence:
//
//  1. SetPriority(iface, plan.Priority) — populates the BPF map first
//     so the program reads the desired priority on its very first
//     invocation after attach.
//  2. EnsureAttached(iface, plan.Direction) — installs (or reuses) the
//     TCX link.
//
// The reverse sequence is in RemoveTrafficShaper. A partial failure
// (SetPriority OK, attach fails) leaves the priority map populated;
// the controller surfaces the error and the next reconcile retries.
// We deliberately do not roll back the SetPriority on attach failure
// because the priority entry is harmless when no program is bound to
// it — an unattached map entry is invisible to packets.
func ApplyTrafficShaper(backend TCBackend, plan *TrafficShaperPlan) error {
	if backend == nil {
		return fmt.Errorf("traffic shaper: nil backend")
	}
	if plan == nil {
		return fmt.Errorf("traffic shaper: nil plan")
	}
	if err := backend.SetPriority(plan.Interface, plan.Priority); err != nil {
		return fmt.Errorf("set priority on %q: %w", plan.Interface, err)
	}
	if err := backend.EnsureAttached(plan.Interface, plan.Direction); err != nil {
		return fmt.Errorf("attach TC program on %q: %w", plan.Interface, err)
	}
	return nil
}

// RemoveTrafficShaper detaches the TC program and clears the priority
// map for the given interface. Called by the controller's delete
// handler. Detach happens before clear so packets in-flight don't see
// a stale priority while the program is still attached; the map
// clear that follows is the bookkeeping pass.
func RemoveTrafficShaper(backend TCBackend, ifaceName string) error {
	if backend == nil {
		return fmt.Errorf("traffic shaper: nil backend")
	}
	if strings.TrimSpace(ifaceName) == "" {
		return fmt.Errorf("traffic shaper: empty interface")
	}
	if err := backend.EnsureDetached(ifaceName); err != nil {
		return fmt.Errorf("detach TC program on %q: %w", ifaceName, err)
	}
	if err := backend.ClearPriority(ifaceName); err != nil {
		return fmt.Errorf("clear priority on %q: %w", ifaceName, err)
	}
	return nil
}
