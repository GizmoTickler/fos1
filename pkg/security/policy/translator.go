// Package policy translates FilterPolicy CRDs into CiliumNetworkPolicy
// objects. Per ADR-0001 (Cilium-First Control Plane), Cilium is the sole
// enforcement backend for routed/filtered traffic; this package does not
// emit nftables or iptables rules.
package policy

import (
	"fmt"
	"strings"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// CiliumPolicyTranslator converts FilterPolicy CRDs into one or more
// cilium.CiliumPolicy objects that the Cilium client can apply as
// CiliumNetworkPolicy resources. The translator is pure (no side effects);
// the apply path is owned by the PolicyController, which consumes the
// translator output and drives idempotent reconcile.
type CiliumPolicyTranslator struct {
	logger *PolicyLogger
}

// NewCiliumPolicyTranslator builds a translator. The cilium.CiliumClient
// argument is retained for API compatibility with older callers; the
// translator itself is stateless and does not perform I/O.
func NewCiliumPolicyTranslator(_ cilium.CiliumClient, logger *PolicyLogger) *CiliumPolicyTranslator {
	return &CiliumPolicyTranslator{
		logger: logger,
	}
}

// TranslatePolicy converts the FilterPolicy into a slice of
// *cilium.CiliumPolicy that the controller will apply. Disabled policies
// return an empty slice without error so callers can treat the disable
// path as a no-op apply.
//
// Output Cilium policy names are deterministic: `fos1-filter-<namespace>-<name>`.
// See ciliumPolicyName() in types.go for the exact sanitization rules.
func (t *CiliumPolicyTranslator) TranslatePolicy(policy *FilterPolicy, zones map[string]*FilterZone) ([]*cilium.CiliumPolicy, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy must not be nil")
	}
	if !policy.Spec.Enabled {
		return nil, nil
	}

	// Zones are not yet wired into the CiliumNetworkPolicy output; retained
	// as an argument for forward compatibility with zone-scoped policies.
	_ = zones

	rules := translateCiliumRules(policy)
	translated := &cilium.CiliumPolicy{
		Name:        ciliumPolicyName(policy),
		Description: policy.Spec.Description,
		Namespace:   policy.ObjectMeta.Namespace,
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "fos1-policy-controller",
			"fos1.io/policy-name":          policyObjectName(policy),
			"fos1.io/policy-namespace":     policy.ObjectMeta.Namespace,
		},
		Rules: rules,
	}

	return []*cilium.CiliumPolicy{translated}, nil
}

// translateCiliumRules maps the FilterPolicy spec into concrete Cilium rules.
// Each port selector becomes its own CiliumRule so operators see a 1:1
// correspondence between FilterPolicy port blocks and Cilium rule entries.
func translateCiliumRules(policy *FilterPolicy) []cilium.CiliumRule {
	spec := policy.Spec
	action, denied := translatePolicyAction(spec.Actions)
	srcCIDRs := extractCIDRs(spec.Selectors.Sources)
	dstCIDRs := extractCIDRs(spec.Selectors.Destinations)

	if len(spec.Selectors.Ports) == 0 {
		return []cilium.CiliumRule{{
			Action:   action,
			Denied:   denied,
			FromCIDR: srcCIDRs,
			ToCIDR:   dstCIDRs,
		}}
	}

	rules := make([]cilium.CiliumRule, 0, len(spec.Selectors.Ports))
	for _, selector := range spec.Selectors.Ports {
		portRule := cilium.PortRule{
			Ports: make([]cilium.Port, 0, len(selector.Ports)),
		}
		for _, port := range selector.Ports {
			portRule.Ports = append(portRule.Ports, cilium.Port{
				Port:     uint16(port),
				Protocol: translateCiliumProtocol(selector.Protocol),
			})
		}
		rules = append(rules, cilium.CiliumRule{
			Protocol: selector.Protocol,
			Action:   action,
			Denied:   denied,
			FromCIDR: srcCIDRs,
			ToCIDR:   dstCIDRs,
			ToPorts:  []cilium.PortRule{portRule},
		})
	}

	return rules
}

// translatePolicyAction reduces the set of FilterPolicy actions to a single
// verdict (allow / deny / reject). Multiple actions collapse to the last
// terminal verdict seen; non-terminal actions (e.g. "log") do not change
// the verdict. Default is deny.
func translatePolicyAction(actions []PolicyAction) (string, bool) {
	action := "deny"
	denied := true

	for _, policyAction := range actions {
		switch strings.ToLower(policyAction.Type) {
		case "allow", "accept":
			action = "allow"
			denied = false
		case "deny", "drop":
			action = "deny"
			denied = true
		case "reject":
			action = "reject"
			denied = true
		}
	}

	return action, denied
}

// translateCiliumProtocol returns the lowercase protocol string Cilium
// expects, or the empty string for unknown protocols (which Cilium treats
// as "any").
func translateCiliumProtocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	case "icmp":
		return "icmp"
	default:
		return ""
	}
}

// extractCIDRs pulls CIDR string values from selectors of type
// cidr/network/ip/subnet. Selectors with other types are ignored so
// non-network selectors (e.g. application tags) do not leak into the
// CIDR match set.
func extractCIDRs(selectors []Selector) []string {
	var cidrs []string
	for _, s := range selectors {
		switch strings.ToLower(s.Type) {
		case "cidr", "network", "ip", "subnet":
			for _, v := range s.Values {
				if str, ok := v.(string); ok && str != "" {
					cidrs = append(cidrs, str)
				}
			}
		}
	}
	return cidrs
}

// policyKey returns the informer-style "<namespace>/<name>" key used as the
// primary cache index.
func policyKey(p *FilterPolicy) string {
	name := p.Name
	if name == "" {
		name = p.ObjectMeta.Name
	}
	ns := p.ObjectMeta.Namespace
	if ns != "" {
		return fmt.Sprintf("%s/%s", ns, name)
	}
	return name
}
