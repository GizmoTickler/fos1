package firewall

import (
	"fmt"
	"sort"
	"sync"

	"k8s.io/klog/v2"
)

// ManagedRule wraps an NFTFirewallRule with tracking metadata for the high-level manager.
type ManagedRule struct {
	// Rule is the underlying firewall rule.
	Rule NFTFirewallRule
	// Handle is the kernel-assigned handle after the rule has been committed.
	Handle uint64
	// Applied indicates whether the rule has been committed to the kernel.
	Applied bool
}

// Manager provides a high-level interface for firewall management.
// It wraps a FirewallManager implementation with rule tracking, priority ordering,
// and convenience methods for common firewall operations.
type Manager struct {
	mu      sync.RWMutex
	backend FirewallManager

	// rules tracks all managed rules by chain (key: "table/chain")
	rules map[string][]*ManagedRule
}

// NewManager creates a new high-level firewall manager wrapping the given backend.
func NewManager(backend FirewallManager) *Manager {
	return &Manager{
		backend: backend,
		rules:   make(map[string][]*ManagedRule),
	}
}

// ruleMapKey builds a map key from a ChainRef.
func ruleMapKey(ref ChainRef) string {
	return fmt.Sprintf("%s/%s", ref.Table, ref.Chain)
}

// Initialize initializes the underlying firewall backend.
func (m *Manager) Initialize() error {
	return m.backend.Initialize()
}

// Close closes the underlying firewall backend and clears all tracked rules.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rules = make(map[string][]*ManagedRule)
	return m.backend.Close()
}

// DefaultFirewallSetup creates the base table structure with default chains and policies.
// This calls Initialize on the backend which sets up:
//   - fos1-filter table (inet) with input (drop), forward (drop), output (accept) chains
//   - fos1-nat table (inet) with prerouting (accept), postrouting (accept) chains
//   - Established/related accept rules on input and forward
//   - Invalid state drop rules on input and forward
//   - Loopback accept on input
func (m *Manager) DefaultFirewallSetup() error {
	if err := m.backend.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize firewall backend: %w", err)
	}

	klog.Info("Default firewall setup complete")
	return nil
}

// AddRule adds a rule to the tracked rule set and appends it to the chain.
// Rules are ordered by priority within their chain (lower priority = earlier in chain).
// The rule is added to the backend immediately. Call Commit to apply atomically.
func (m *Manager) AddRule(rule NFTFirewallRule) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	handle, err := m.backend.AddRule(rule)
	if err != nil {
		return 0, fmt.Errorf("failed to add rule: %w", err)
	}

	managed := &ManagedRule{
		Rule:    rule,
		Handle:  handle,
		Applied: false,
	}

	key := ruleMapKey(rule.Chain)
	m.rules[key] = append(m.rules[key], managed)

	klog.V(4).Infof("Added managed rule to %s (priority %d)", key, rule.Priority)
	return handle, nil
}

// InsertRule inserts a rule at the beginning of a chain.
func (m *Manager) InsertRule(rule NFTFirewallRule) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	handle, err := m.backend.InsertRule(rule)
	if err != nil {
		return 0, fmt.Errorf("failed to insert rule: %w", err)
	}

	managed := &ManagedRule{
		Rule:    rule,
		Handle:  handle,
		Applied: false,
	}

	key := ruleMapKey(rule.Chain)
	// Prepend to the tracked list
	m.rules[key] = append([]*ManagedRule{managed}, m.rules[key]...)

	klog.V(4).Infof("Inserted managed rule at beginning of %s (priority %d)", key, rule.Priority)
	return handle, nil
}

// DeleteRule deletes a tracked rule by its chain reference and handle.
func (m *Manager) DeleteRule(ref ChainRef, handle uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.backend.DeleteRule(ref, handle); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	key := ruleMapKey(ref)
	rules := m.rules[key]
	for i, r := range rules {
		if r.Handle == handle {
			m.rules[key] = append(rules[:i], rules[i+1:]...)
			break
		}
	}

	klog.V(4).Infof("Deleted managed rule handle %d from %s", handle, key)
	return nil
}

// ApplyRulesByPriority flushes a chain and re-applies all tracked rules sorted by priority.
// This ensures rules are ordered correctly even if they were added out of order.
func (m *Manager) ApplyRulesByPriority(ref ChainRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := ruleMapKey(ref)
	rules := m.rules[key]
	if len(rules) == 0 {
		return nil
	}

	// Sort by priority (lower = earlier)
	sorted := make([]*ManagedRule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Rule.Priority < sorted[j].Rule.Priority
	})

	// Flush the chain
	if err := m.backend.FlushChain(ref); err != nil {
		return fmt.Errorf("failed to flush chain %s/%s: %w", ref.Table, ref.Chain, err)
	}

	// Re-add rules in priority order
	for _, managed := range sorted {
		handle, err := m.backend.AddRule(managed.Rule)
		if err != nil {
			return fmt.Errorf("failed to re-add rule to %s/%s: %w", ref.Table, ref.Chain, err)
		}
		managed.Handle = handle
		managed.Applied = true
	}

	// Update tracked rules to sorted order
	m.rules[key] = sorted

	klog.V(2).Infof("Applied %d rules by priority to %s", len(sorted), key)
	return nil
}

// Commit atomically applies all pending changes to the kernel.
func (m *Manager) Commit() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.backend.Commit(); err != nil {
		return fmt.Errorf("failed to commit firewall changes: %w", err)
	}

	// Mark all rules as applied
	for _, rules := range m.rules {
		for _, r := range rules {
			r.Applied = true
		}
	}

	klog.V(2).Info("Committed all firewall changes")
	return nil
}

// GetTrackedRules returns a copy of all tracked rules for a given chain, sorted by priority.
func (m *Manager) GetTrackedRules(ref ChainRef) []ManagedRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := ruleMapKey(ref)
	rules := m.rules[key]

	result := make([]ManagedRule, len(rules))
	for i, r := range rules {
		result[i] = *r
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Rule.Priority < result[j].Rule.Priority
	})

	return result
}

// GetTrackedRuleCount returns the total number of tracked rules across all chains.
func (m *Manager) GetTrackedRuleCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, rules := range m.rules {
		count += len(rules)
	}
	return count
}

// AllowPort adds a rule to accept traffic on the specified protocol and port
// in the fos1-filter input chain.
func (m *Manager) AllowPort(proto Protocol, port uint16, comment string) (uint64, error) {
	rule := NFTFirewallRule{
		Chain: ChainRef{
			Table: "fos1-filter",
			Chain: "input",
		},
		Matches: []RuleMatch{
			{
				Protocol: proto,
				DestPort: port,
				CTState:  []string{"new"},
			},
		},
		Verdict: VerdictAccept,
		Counter: true,
		Comment: comment,
	}
	return m.AddRule(rule)
}

// BlockIP adds a rule to drop all traffic from the specified source address
// in the fos1-filter input chain.
func (m *Manager) BlockIP(addr string, comment string) (uint64, error) {
	rule := NFTFirewallRule{
		Chain: ChainRef{
			Table: "fos1-filter",
			Chain: "input",
		},
		Matches: []RuleMatch{
			{
				SourceAddr: addr,
			},
		},
		Verdict:  VerdictDrop,
		Counter:  true,
		Log:      true,
		LogPrefix: "fos1-blocked: ",
		Comment:  comment,
		Priority: 10,
	}
	return m.AddRule(rule)
}

// AllowForward adds a rule to accept forwarded traffic between specified
// input and output interfaces in the fos1-filter forward chain.
func (m *Manager) AllowForward(inIface, outIface string, comment string) (uint64, error) {
	rule := NFTFirewallRule{
		Chain: ChainRef{
			Table: "fos1-filter",
			Chain: "forward",
		},
		Matches: []RuleMatch{
			{
				InInterface:  inIface,
				OutInterface: outIface,
				CTState:      []string{"new"},
			},
		},
		Verdict: VerdictAccept,
		Counter: true,
		Comment: comment,
	}
	return m.AddRule(rule)
}

// AllowICMP adds a rule to accept ICMP traffic in the fos1-filter input chain.
func (m *Manager) AllowICMP(comment string) (uint64, error) {
	rule := NFTFirewallRule{
		Chain: ChainRef{
			Table: "fos1-filter",
			Chain: "input",
		},
		Matches: []RuleMatch{
			{
				Protocol: ProtocolICMP,
			},
		},
		Verdict: VerdictAccept,
		Counter: true,
		Comment: comment,
		Priority: 50,
	}
	return m.AddRule(rule)
}

// EnsureChain creates a chain if it does not already exist, delegating to the backend.
func (m *Manager) EnsureChain(table string, chain string, chainType ChainType, hook ChainHook, priority int) error {
	return m.backend.EnsureChain(table, chain, chainType, hook, priority)
}

// FlushChain removes all rules from a chain, also clearing tracked rules.
func (m *Manager) FlushChain(ref ChainRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.backend.FlushChain(ref); err != nil {
		return err
	}

	key := ruleMapKey(ref)
	delete(m.rules, key)
	return nil
}

// GetRuleCounters delegates to the backend to retrieve rule counters.
func (m *Manager) GetRuleCounters(ref ChainRef, handle uint64) (*RuleCounters, error) {
	return m.backend.GetRuleCounters(ref, handle)
}
