package suricata

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"k8s.io/klog/v2"
)

const (
	// defaultRuleFile is the default filename for custom rules managed by the RuleManager.
	defaultRuleFile = "local.rules"
)

// RuleManager manages Suricata rules on disk and can trigger live rule reloads
// via the Suricata control socket.
type RuleManager struct {
	client   *Client // socket client for reload
	rulesDir string  // directory containing rule files
	mu       sync.Mutex
}

// NewRuleManager creates a new RuleManager that stores rules in rulesDir and
// uses the provided Client to trigger rule reloads.
func NewRuleManager(client *Client, rulesDir string) *RuleManager {
	return &RuleManager{
		client:   client,
		rulesDir: rulesDir,
	}
}

// localRulePath returns the path to the managed local rules file.
func (m *RuleManager) localRulePath() string {
	return filepath.Join(m.rulesDir, defaultRuleFile)
}

// AddRule appends a rule to the local rule file. If a rule with the same SID
// already exists, it is replaced.
func (m *RuleManager) AddRule(rule *Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if rule.SID == 0 {
		return fmt.Errorf("rule must have a non-zero SID")
	}

	rules, err := m.loadLocalRules()
	if err != nil {
		return err
	}

	// Replace existing rule with same SID, or append
	found := false
	for i, existing := range rules {
		if existing.SID == rule.SID {
			rules[i] = rule
			found = true
			break
		}
	}
	if !found {
		rules = append(rules, rule)
	}

	if err := WriteRuleFile(m.localRulePath(), rules); err != nil {
		return fmt.Errorf("write rules: %w", err)
	}

	klog.V(2).Infof("Added rule SID=%d to %s", rule.SID, m.localRulePath())
	return nil
}

// DisableRule comments out a rule by SID. The rule remains in the file but is
// prefixed with # so Suricata will not load it.
func (m *RuleManager) DisableRule(sid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rules, err := m.loadLocalRules()
	if err != nil {
		return err
	}

	found := false
	for _, rule := range rules {
		if rule.SID == sid {
			rule.Enabled = false
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("rule with SID %d not found", sid)
	}

	if err := WriteRuleFile(m.localRulePath(), rules); err != nil {
		return fmt.Errorf("write rules: %w", err)
	}

	klog.V(2).Infof("Disabled rule SID=%d", sid)
	return nil
}

// EnableRule un-comments a previously disabled rule by SID.
func (m *RuleManager) EnableRule(sid int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rules, err := m.loadLocalRules()
	if err != nil {
		return err
	}

	found := false
	for _, rule := range rules {
		if rule.SID == sid {
			rule.Enabled = true
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("rule with SID %d not found", sid)
	}

	if err := WriteRuleFile(m.localRulePath(), rules); err != nil {
		return fmt.Errorf("write rules: %w", err)
	}

	klog.V(2).Infof("Enabled rule SID=%d", sid)
	return nil
}

// ReloadRules writes all managed rules to disk and sends a reload-rules command
// to the running Suricata instance via the control socket.
func (m *RuleManager) ReloadRules(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client == nil {
		return fmt.Errorf("no client configured for rule reload")
	}

	if err := m.client.ReloadRules(ctx); err != nil {
		return fmt.Errorf("reload rules via socket: %w", err)
	}

	klog.V(2).Info("Suricata rules reloaded via socket")
	return nil
}

// ListRules returns all rules from all .rules files in the rules directory.
func (m *RuleManager) ListRules() ([]*Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.loadAllRules()
}

// GetRule finds and returns a rule by its SID across all rule files.
func (m *RuleManager) GetRule(sid int) (*Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rules, err := m.loadAllRules()
	if err != nil {
		return nil, err
	}

	for _, rule := range rules {
		if rule.SID == sid {
			return rule, nil
		}
	}

	return nil, fmt.Errorf("rule with SID %d not found", sid)
}

// loadLocalRules loads rules from the managed local rules file.
// If the file does not exist, an empty slice is returned.
func (m *RuleManager) loadLocalRules() ([]*Rule, error) {
	path := m.localRulePath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}

	rules, err := ParseRuleFile(path)
	if err != nil {
		return nil, fmt.Errorf("load local rules from %s: %w", path, err)
	}
	return rules, nil
}

// loadAllRules loads rules from every .rules file in the rules directory.
func (m *RuleManager) loadAllRules() ([]*Rule, error) {
	entries, err := os.ReadDir(m.rulesDir)
	if err != nil {
		return nil, fmt.Errorf("read rules directory %s: %w", m.rulesDir, err)
	}

	var allRules []*Rule
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".rules" {
			continue
		}

		path := filepath.Join(m.rulesDir, entry.Name())
		rules, err := ParseRuleFile(path)
		if err != nil {
			klog.Warningf("Failed to parse rule file %s: %v", path, err)
			continue
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}
