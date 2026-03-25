package policy

import (
	"fmt"
	"strings"
	"sync"

	"github.com/GizmoTickler/fos1/pkg/security/firewall"
)

const (
	// defaultFilterTable is the nftables table name used for filter policies.
	defaultFilterTable = "fos1-filter"
)

// PolicyTranslator converts FilterPolicy CRDs into NFTFirewallRule structs
// and applies them through a FirewallManager.
type PolicyTranslator struct {
	firewallMgr firewall.FirewallManager

	// appliedRules tracks rule handles keyed by policy name for removal.
	appliedRules map[string][]appliedRule
	mu           sync.Mutex
}

// appliedRule records a rule that was applied to the firewall so it can be removed later.
type appliedRule struct {
	chain  firewall.ChainRef
	handle uint64
}

// NewPolicyTranslator creates a new PolicyTranslator backed by the given FirewallManager.
func NewPolicyTranslator(fwMgr firewall.FirewallManager) *PolicyTranslator {
	return &PolicyTranslator{
		firewallMgr:  fwMgr,
		appliedRules: make(map[string][]appliedRule),
	}
}

// TranslatePolicy converts a FilterPolicy into a list of NFTFirewallRules.
// It maps the policy's selectors and actions into firewall-level rule structures.
func (t *PolicyTranslator) TranslatePolicy(policy *FilterPolicy) ([]firewall.NFTFirewallRule, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy must not be nil")
	}

	spec := policy.Spec
	if !spec.Enabled {
		return nil, nil
	}

	// Determine the verdict from the policy actions.
	verdict, logEnabled, logPrefix := translateActions(spec.Actions)

	// Determine the chain based on scope.
	chain := scopeToChain(spec.Scope)

	// Collect source and destination CIDRs from selectors.
	srcCIDRs := extractCIDRs(spec.Selectors.Sources)
	dstCIDRs := extractCIDRs(spec.Selectors.Destinations)

	// If no sources or destinations are specified, use a single empty string
	// to represent "any".
	if len(srcCIDRs) == 0 {
		srcCIDRs = []string{""}
	}
	if len(dstCIDRs) == 0 {
		dstCIDRs = []string{""}
	}

	var rules []firewall.NFTFirewallRule

	// If there are port selectors, generate per-port rules.
	if len(spec.Selectors.Ports) > 0 {
		for _, ps := range spec.Selectors.Ports {
			proto := translateProtocol(ps.Protocol)
			for _, port := range ps.Ports {
				for _, src := range srcCIDRs {
					for _, dst := range dstCIDRs {
						rule := firewall.NFTFirewallRule{
							Chain:   chain,
							Verdict: verdict,
							Matches: []firewall.RuleMatch{
								{
									Protocol: proto,
									DestPort: uint16(port),
									SourceAddr: src,
									DestAddr:   dst,
								},
							},
							Log:       logEnabled,
							LogPrefix: logPrefix,
							Counter:   true,
							Comment:   policyComment(policy),
							Priority:  spec.Priority,
						}
						rules = append(rules, rule)
					}
				}
			}
		}
	} else {
		// No port selectors — generate rules for each src/dst combination.
		for _, src := range srcCIDRs {
			for _, dst := range dstCIDRs {
				rule := firewall.NFTFirewallRule{
					Chain:   chain,
					Verdict: verdict,
					Matches: []firewall.RuleMatch{
						{
							SourceAddr: src,
							DestAddr:   dst,
						},
					},
					Log:       logEnabled,
					LogPrefix: logPrefix,
					Counter:   true,
					Comment:   policyComment(policy),
					Priority:  spec.Priority,
				}
				rules = append(rules, rule)
			}
		}
	}

	return rules, nil
}

// ApplyPolicy translates a FilterPolicy and applies the resulting rules to the firewall.
func (t *PolicyTranslator) ApplyPolicy(policy *FilterPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy must not be nil")
	}

	policyName := policyKey(policy)

	// Remove any previously applied rules for this policy.
	if err := t.RemovePolicy(policyName); err != nil {
		return fmt.Errorf("removing old rules for policy %q: %w", policyName, err)
	}

	rules, err := t.TranslatePolicy(policy)
	if err != nil {
		return fmt.Errorf("translating policy %q: %w", policyName, err)
	}

	if len(rules) == 0 {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var applied []appliedRule
	for _, rule := range rules {
		handle, err := t.firewallMgr.AddRule(rule)
		if err != nil {
			// Best-effort rollback: remove rules we already added.
			for _, ar := range applied {
				_ = t.firewallMgr.DeleteRule(ar.chain, ar.handle)
			}
			return fmt.Errorf("adding rule for policy %q: %w", policyName, err)
		}
		applied = append(applied, appliedRule{chain: rule.Chain, handle: handle})
	}

	// Commit the batch to the kernel.
	if err := t.firewallMgr.Commit(); err != nil {
		return fmt.Errorf("committing rules for policy %q: %w", policyName, err)
	}

	t.appliedRules[policyName] = applied
	return nil
}

// RemovePolicy removes all firewall rules associated with the named policy.
func (t *PolicyTranslator) RemovePolicy(policyName string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	applied, ok := t.appliedRules[policyName]
	if !ok {
		return nil
	}

	var errs []string
	for _, ar := range applied {
		if err := t.firewallMgr.DeleteRule(ar.chain, ar.handle); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		// Even on partial failure, commit what we can and clear the tracking.
		_ = t.firewallMgr.Commit()
		delete(t.appliedRules, policyName)
		return fmt.Errorf("removing rules for policy %q: %s", policyName, strings.Join(errs, "; "))
	}

	if err := t.firewallMgr.Commit(); err != nil {
		delete(t.appliedRules, policyName)
		return fmt.Errorf("committing removal for policy %q: %w", policyName, err)
	}

	delete(t.appliedRules, policyName)
	return nil
}

// --- helper functions ---

// translateActions reads the policy actions and returns the primary verdict,
// whether logging is enabled, and the log prefix.
func translateActions(actions []PolicyAction) (firewall.Verdict, bool, string) {
	verdict := firewall.VerdictDrop // default to drop if no action specified
	logEnabled := false
	logPrefix := ""

	for _, a := range actions {
		switch strings.ToLower(a.Type) {
		case "allow", "accept":
			verdict = firewall.VerdictAccept
		case "deny", "drop":
			verdict = firewall.VerdictDrop
		case "reject":
			verdict = firewall.VerdictReject
		case "log":
			logEnabled = true
			if prefix, ok := a.Parameters["prefix"].(string); ok {
				logPrefix = prefix
			}
		}
	}
	return verdict, logEnabled, logPrefix
}

// scopeToChain maps a policy scope string to an nftables ChainRef.
func scopeToChain(scope string) firewall.ChainRef {
	chain := "forward" // default chain
	switch strings.ToLower(scope) {
	case "input", "ingress":
		chain = "input"
	case "output", "egress":
		chain = "output"
	case "forward", "transit":
		chain = "forward"
	}
	return firewall.ChainRef{
		Table: defaultFilterTable,
		Chain: chain,
	}
}

// extractCIDRs pulls CIDR values from a list of Selectors.
// It looks for selectors of type "cidr" or "network" and returns
// the string values found.
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

// translateProtocol maps a string protocol name to the firewall Protocol type.
func translateProtocol(proto string) firewall.Protocol {
	switch strings.ToLower(proto) {
	case "tcp":
		return firewall.ProtocolTCP
	case "udp":
		return firewall.ProtocolUDP
	case "icmp":
		return firewall.ProtocolICMP
	default:
		return firewall.ProtocolAny
	}
}

// policyComment generates a human-readable comment for firewall rules derived from a policy.
func policyComment(p *FilterPolicy) string {
	name := p.Name
	if name == "" {
		name = p.ObjectMeta.Name
	}
	ns := p.ObjectMeta.Namespace
	if ns != "" {
		return fmt.Sprintf("policy:%s/%s", ns, name)
	}
	return fmt.Sprintf("policy:%s", name)
}

// policyKey returns a unique string key for a policy.
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
