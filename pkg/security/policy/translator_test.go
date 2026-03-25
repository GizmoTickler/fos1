package policy

import (
	"fmt"
	"sync"
	"testing"

	"github.com/GizmoTickler/fos1/pkg/security/firewall"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// mockFirewallManager is a test double for firewall.FirewallManager.
type mockFirewallManager struct {
	mu            sync.Mutex
	rules         map[string][]firewall.NFTFirewallRule
	nextHandle    uint64
	commitCalled  int
	addRuleErr    error
	deleteRuleErr error
	commitErr     error
}

func newMockFirewallManager() *mockFirewallManager {
	return &mockFirewallManager{
		rules:      make(map[string][]firewall.NFTFirewallRule),
		nextHandle: 1,
	}
}

func (m *mockFirewallManager) Initialize() error                                  { return nil }
func (m *mockFirewallManager) Close() error                                       { return nil }
func (m *mockFirewallManager) EnsureTable(_ string, _ firewall.TableFamily) error { return nil }
func (m *mockFirewallManager) EnsureChain(_ string, _ string, _ firewall.ChainType, _ firewall.ChainHook, _ int) error {
	return nil
}
func (m *mockFirewallManager) DeleteChain(_ firewall.ChainRef) error { return nil }
func (m *mockFirewallManager) FlushChain(_ firewall.ChainRef) error  { return nil }

func (m *mockFirewallManager) AddRule(rule firewall.NFTFirewallRule) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addRuleErr != nil {
		return 0, m.addRuleErr
	}
	handle := m.nextHandle
	m.nextHandle++
	rule.Handle = handle
	key := rule.Chain.Table + "/" + rule.Chain.Chain
	m.rules[key] = append(m.rules[key], rule)
	return handle, nil
}

func (m *mockFirewallManager) InsertRule(rule firewall.NFTFirewallRule) (uint64, error) {
	return m.AddRule(rule)
}

func (m *mockFirewallManager) DeleteRule(ref firewall.ChainRef, handle uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteRuleErr != nil {
		return m.deleteRuleErr
	}
	key := ref.Table + "/" + ref.Chain
	rules := m.rules[key]
	for i, r := range rules {
		if r.Handle == handle {
			m.rules[key] = append(rules[:i], rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("rule handle %d not found in chain %s", handle, key)
}

func (m *mockFirewallManager) ListRules(ref firewall.ChainRef) ([]firewall.NFTFirewallRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := ref.Table + "/" + ref.Chain
	return m.rules[key], nil
}

func (m *mockFirewallManager) CreateSet(_ string, _ string, _ uint32, _ bool) error { return nil }
func (m *mockFirewallManager) AddSetElements(_ string, _ string, _ [][]byte) error  { return nil }
func (m *mockFirewallManager) DeleteSet(_ string, _ string) error                   { return nil }

func (m *mockFirewallManager) Commit() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commitCalled++
	return m.commitErr
}

func (m *mockFirewallManager) GetRuleCounters(_ firewall.ChainRef, _ uint64) (*firewall.RuleCounters, error) {
	return &firewall.RuleCounters{}, nil
}

func (m *mockFirewallManager) totalRules() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, rules := range m.rules {
		total += len(rules)
	}
	return total
}

// --- Tests ---

func TestTranslatePolicy_SimpleAllow(t *testing.T) {
	tr := NewPolicyTranslator(newMockFirewallManager())

	policy := &FilterPolicy{
		Name: "allow-all",
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 100,
			Scope:    "forward",
			Selectors: FilterSelectors{},
			Actions: []PolicyAction{
				{Type: "allow"},
			},
		},
	}

	rules, err := tr.TranslatePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Verdict != firewall.VerdictAccept {
		t.Errorf("expected verdict accept, got %s", rules[0].Verdict)
	}
	if rules[0].Chain.Chain != "forward" {
		t.Errorf("expected chain forward, got %s", rules[0].Chain.Chain)
	}
	if rules[0].Priority != 100 {
		t.Errorf("expected priority 100, got %d", rules[0].Priority)
	}
}

func TestTranslatePolicy_DenyWithSourceDest(t *testing.T) {
	tr := NewPolicyTranslator(newMockFirewallManager())

	policy := &FilterPolicy{
		Name: "deny-specific",
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 50,
			Scope:    "input",
			Selectors: FilterSelectors{
				Sources: []Selector{
					{Type: "cidr", Values: []interface{}{"10.0.0.0/8"}},
				},
				Destinations: []Selector{
					{Type: "cidr", Values: []interface{}{"192.168.1.0/24"}},
				},
			},
			Actions: []PolicyAction{
				{Type: "deny"},
			},
		},
	}

	rules, err := tr.TranslatePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Verdict != firewall.VerdictDrop {
		t.Errorf("expected verdict drop, got %s", r.Verdict)
	}
	if r.Chain.Chain != "input" {
		t.Errorf("expected chain input, got %s", r.Chain.Chain)
	}
	if len(r.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(r.Matches))
	}
	if r.Matches[0].SourceAddr != "10.0.0.0/8" {
		t.Errorf("expected source 10.0.0.0/8, got %s", r.Matches[0].SourceAddr)
	}
	if r.Matches[0].DestAddr != "192.168.1.0/24" {
		t.Errorf("expected dest 192.168.1.0/24, got %s", r.Matches[0].DestAddr)
	}
}

func TestTranslatePolicy_PortMatching(t *testing.T) {
	tr := NewPolicyTranslator(newMockFirewallManager())

	policy := &FilterPolicy{
		Name: "allow-http",
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 200,
			Scope:    "input",
			Selectors: FilterSelectors{
				Ports: []PortSelector{
					{Protocol: "tcp", Ports: []int32{80, 443}},
				},
			},
			Actions: []PolicyAction{
				{Type: "accept"},
			},
		},
	}

	rules, err := tr.TranslatePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (one per port), got %d", len(rules))
	}

	if rules[0].Matches[0].DestPort != 80 {
		t.Errorf("expected dest port 80, got %d", rules[0].Matches[0].DestPort)
	}
	if rules[0].Matches[0].Protocol != firewall.ProtocolTCP {
		t.Errorf("expected protocol tcp, got %s", rules[0].Matches[0].Protocol)
	}
	if rules[1].Matches[0].DestPort != 443 {
		t.Errorf("expected dest port 443, got %d", rules[1].Matches[0].DestPort)
	}
}

func TestTranslatePolicy_MultipleRules(t *testing.T) {
	tr := NewPolicyTranslator(newMockFirewallManager())

	policy := &FilterPolicy{
		Name: "multi-rule",
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 10,
			Scope:    "forward",
			Selectors: FilterSelectors{
				Sources: []Selector{
					{Type: "cidr", Values: []interface{}{"10.0.0.0/8", "172.16.0.0/12"}},
				},
				Destinations: []Selector{
					{Type: "cidr", Values: []interface{}{"192.168.1.0/24"}},
				},
			},
			Actions: []PolicyAction{
				{Type: "allow"},
			},
		},
	}

	rules, err := tr.TranslatePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 source CIDRs x 1 dest CIDR = 2 rules
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Matches[0].SourceAddr != "10.0.0.0/8" {
		t.Errorf("expected first source 10.0.0.0/8, got %s", rules[0].Matches[0].SourceAddr)
	}
	if rules[1].Matches[0].SourceAddr != "172.16.0.0/12" {
		t.Errorf("expected second source 172.16.0.0/12, got %s", rules[1].Matches[0].SourceAddr)
	}
}

func TestTranslatePolicy_RejectWithLog(t *testing.T) {
	tr := NewPolicyTranslator(newMockFirewallManager())

	policy := &FilterPolicy{
		Name: "reject-and-log",
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 300,
			Scope:    "output",
			Selectors: FilterSelectors{},
			Actions: []PolicyAction{
				{Type: "reject"},
				{Type: "log", Parameters: map[string]interface{}{"prefix": "REJECTED: "}},
			},
		},
	}

	rules, err := tr.TranslatePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Verdict != firewall.VerdictReject {
		t.Errorf("expected verdict reject, got %s", r.Verdict)
	}
	if r.Chain.Chain != "output" {
		t.Errorf("expected chain output, got %s", r.Chain.Chain)
	}
	if !r.Log {
		t.Error("expected log to be enabled")
	}
	if r.LogPrefix != "REJECTED: " {
		t.Errorf("expected log prefix 'REJECTED: ', got %q", r.LogPrefix)
	}
}

func TestTranslatePolicy_DisabledPolicy(t *testing.T) {
	tr := NewPolicyTranslator(newMockFirewallManager())

	policy := &FilterPolicy{
		Name: "disabled",
		Spec: FilterPolicySpec{
			Enabled: false,
			Selectors: FilterSelectors{},
			Actions: []PolicyAction{
				{Type: "allow"},
			},
		},
	}

	rules, err := tr.TranslatePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules for disabled policy, got %d", len(rules))
	}
}

func TestTranslatePolicy_NilPolicy(t *testing.T) {
	tr := NewPolicyTranslator(newMockFirewallManager())

	_, err := tr.TranslatePolicy(nil)
	if err == nil {
		t.Fatal("expected error for nil policy")
	}
}

func TestApplyPolicy(t *testing.T) {
	mock := newMockFirewallManager()
	tr := NewPolicyTranslator(mock)

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-apply", Namespace: "default"},
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 100,
			Scope:    "forward",
			Selectors: FilterSelectors{
				Ports: []PortSelector{
					{Protocol: "tcp", Ports: []int32{22}},
				},
			},
			Actions: []PolicyAction{
				{Type: "allow"},
			},
		},
	}

	if err := tr.ApplyPolicy(policy); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.totalRules() != 1 {
		t.Fatalf("expected 1 rule in mock, got %d", mock.totalRules())
	}
	if mock.commitCalled != 1 {
		t.Errorf("expected commit called once, got %d", mock.commitCalled)
	}
}

func TestRemovePolicy(t *testing.T) {
	mock := newMockFirewallManager()
	tr := NewPolicyTranslator(mock)

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-remove", Namespace: "default"},
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 100,
			Scope:    "forward",
			Selectors: FilterSelectors{},
			Actions: []PolicyAction{
				{Type: "deny"},
			},
		},
	}

	if err := tr.ApplyPolicy(policy); err != nil {
		t.Fatalf("apply error: %v", err)
	}
	if mock.totalRules() != 1 {
		t.Fatalf("expected 1 rule after apply, got %d", mock.totalRules())
	}

	if err := tr.RemovePolicy("default/test-remove"); err != nil {
		t.Fatalf("remove error: %v", err)
	}
	if mock.totalRules() != 0 {
		t.Fatalf("expected 0 rules after remove, got %d", mock.totalRules())
	}
}

func TestApplyPolicy_ReplacesExisting(t *testing.T) {
	mock := newMockFirewallManager()
	tr := NewPolicyTranslator(mock)

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "replace-test", Namespace: "ns"},
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 10,
			Scope:    "input",
			Selectors: FilterSelectors{},
			Actions: []PolicyAction{
				{Type: "allow"},
			},
		},
	}

	if err := tr.ApplyPolicy(policy); err != nil {
		t.Fatalf("first apply error: %v", err)
	}
	if mock.totalRules() != 1 {
		t.Fatalf("expected 1 rule, got %d", mock.totalRules())
	}

	// Apply again — should replace, not duplicate.
	if err := tr.ApplyPolicy(policy); err != nil {
		t.Fatalf("second apply error: %v", err)
	}
	if mock.totalRules() != 1 {
		t.Fatalf("expected 1 rule after re-apply, got %d", mock.totalRules())
	}
}

func TestPriorityOrdering(t *testing.T) {
	tr := NewPolicyTranslator(newMockFirewallManager())

	highPriority := &FilterPolicy{
		Name: "high",
		Spec: FilterPolicySpec{
			Enabled:   true,
			Priority:  10,
			Scope:     "forward",
			Selectors: FilterSelectors{},
			Actions:   []PolicyAction{{Type: "deny"}},
		},
	}
	lowPriority := &FilterPolicy{
		Name: "low",
		Spec: FilterPolicySpec{
			Enabled:   true,
			Priority:  1000,
			Scope:     "forward",
			Selectors: FilterSelectors{},
			Actions:   []PolicyAction{{Type: "allow"}},
		},
	}

	highRules, err := tr.TranslatePolicy(highPriority)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lowRules, err := tr.TranslatePolicy(lowPriority)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if highRules[0].Priority >= lowRules[0].Priority {
		t.Errorf("high priority rule (%d) should have lower priority value than low priority rule (%d)",
			highRules[0].Priority, lowRules[0].Priority)
	}
}
