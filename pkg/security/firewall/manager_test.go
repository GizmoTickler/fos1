package firewall

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFirewallManager is a test double that implements FirewallManager in memory.
type mockFirewallManager struct {
	mu            sync.Mutex
	initialized   bool
	closed        bool
	tables        map[string]TableFamily
	chains        map[string]ChainType
	rules         map[string][]mockRule
	sets          map[string]mockSet
	committed     int
	nextHandle    uint64
	flushErr      error
	addRuleErr    error
	insertRuleErr error
	deleteRuleErr error
}

type mockRule struct {
	rule   NFTFirewallRule
	handle uint64
}

type mockSet struct {
	keyType  uint32
	interval bool
	elements [][]byte
}

func newMockFirewallManager() *mockFirewallManager {
	return &mockFirewallManager{
		tables:     make(map[string]TableFamily),
		chains:     make(map[string]ChainType),
		rules:      make(map[string][]mockRule),
		sets:       make(map[string]mockSet),
		nextHandle: 1,
	}
}

func (m *mockFirewallManager) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.initialized = true
	// Set up default tables and chains
	m.tables["fos1-filter"] = FamilyINET
	m.tables["fos1-nat"] = FamilyINET
	m.chains["fos1-filter/input"] = ChainTypeFilter
	m.chains["fos1-filter/forward"] = ChainTypeFilter
	m.chains["fos1-filter/output"] = ChainTypeFilter
	m.chains["fos1-nat/prerouting"] = ChainTypeNAT
	m.chains["fos1-nat/postrouting"] = ChainTypeNAT
	return nil
}

func (m *mockFirewallManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockFirewallManager) EnsureTable(name string, family TableFamily) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tables[name] = family
	return nil
}

func (m *mockFirewallManager) EnsureChain(table string, chain string, chainType ChainType, hook ChainHook, priority int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s", table, chain)
	m.chains[key] = chainType
	return nil
}

func (m *mockFirewallManager) DeleteChain(ref ChainRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s", ref.Table, ref.Chain)
	delete(m.chains, key)
	delete(m.rules, key)
	return nil
}

func (m *mockFirewallManager) FlushChain(ref ChainRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.flushErr != nil {
		return m.flushErr
	}
	key := fmt.Sprintf("%s/%s", ref.Table, ref.Chain)
	m.rules[key] = nil
	return nil
}

func (m *mockFirewallManager) AddRule(rule NFTFirewallRule) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addRuleErr != nil {
		return 0, m.addRuleErr
	}
	handle := m.nextHandle
	m.nextHandle++
	key := fmt.Sprintf("%s/%s", rule.Chain.Table, rule.Chain.Chain)
	m.rules[key] = append(m.rules[key], mockRule{rule: rule, handle: handle})
	return handle, nil
}

func (m *mockFirewallManager) InsertRule(rule NFTFirewallRule) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.insertRuleErr != nil {
		return 0, m.insertRuleErr
	}
	handle := m.nextHandle
	m.nextHandle++
	key := fmt.Sprintf("%s/%s", rule.Chain.Table, rule.Chain.Chain)
	newRules := []mockRule{{rule: rule, handle: handle}}
	m.rules[key] = append(newRules, m.rules[key]...)
	return handle, nil
}

func (m *mockFirewallManager) DeleteRule(ref ChainRef, handle uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteRuleErr != nil {
		return m.deleteRuleErr
	}
	key := fmt.Sprintf("%s/%s", ref.Table, ref.Chain)
	rules := m.rules[key]
	for i, r := range rules {
		if r.handle == handle {
			m.rules[key] = append(rules[:i], rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("rule handle %d not found", handle)
}

func (m *mockFirewallManager) ListRules(ref ChainRef) ([]NFTFirewallRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s", ref.Table, ref.Chain)
	rules := m.rules[key]
	result := make([]NFTFirewallRule, len(rules))
	for i, r := range rules {
		result[i] = r.rule
		result[i].Handle = r.handle
	}
	return result, nil
}

func (m *mockFirewallManager) CreateSet(table string, name string, keyType uint32, interval bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s", table, name)
	m.sets[key] = mockSet{keyType: keyType, interval: interval}
	return nil
}

func (m *mockFirewallManager) AddSetElements(table string, setName string, elements [][]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s", table, setName)
	s, ok := m.sets[key]
	if !ok {
		return fmt.Errorf("set %s not found", setName)
	}
	s.elements = append(s.elements, elements...)
	m.sets[key] = s
	return nil
}

func (m *mockFirewallManager) DeleteSet(table string, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s", table, name)
	delete(m.sets, key)
	return nil
}

func (m *mockFirewallManager) Commit() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.committed++
	return nil
}

func (m *mockFirewallManager) GetRuleCounters(ref ChainRef, handle uint64) (*RuleCounters, error) {
	return &RuleCounters{Packets: 42, Bytes: 1024}, nil
}

func TestManagerInitializeAndClose(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)

	err := mgr.Initialize()
	require.NoError(t, err)
	assert.True(t, mock.initialized)

	err = mgr.Close()
	require.NoError(t, err)
	assert.True(t, mock.closed)
}

func TestManagerDefaultFirewallSetup(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)

	err := mgr.DefaultFirewallSetup()
	require.NoError(t, err)
	assert.True(t, mock.initialized)
	assert.Contains(t, mock.tables, "fos1-filter")
	assert.Contains(t, mock.tables, "fos1-nat")
	assert.Contains(t, mock.chains, "fos1-filter/input")
	assert.Contains(t, mock.chains, "fos1-filter/forward")
	assert.Contains(t, mock.chains, "fos1-filter/output")
}

func TestManagerAddRule(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}
	rule := NFTFirewallRule{
		Chain: ref,
		Matches: []RuleMatch{
			{Protocol: ProtocolTCP, DestPort: 22},
		},
		Verdict: VerdictAccept,
		Comment: "Allow SSH",
		Priority: 100,
	}

	handle, err := mgr.AddRule(rule)
	require.NoError(t, err)
	assert.NotZero(t, handle)

	tracked := mgr.GetTrackedRules(ref)
	require.Len(t, tracked, 1)
	assert.Equal(t, "Allow SSH", tracked[0].Rule.Comment)
	assert.Equal(t, handle, tracked[0].Handle)
}

func TestManagerInsertRule(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}

	_, err := mgr.AddRule(NFTFirewallRule{
		Chain:   ref,
		Verdict: VerdictAccept,
		Comment: "Second",
		Priority: 200,
	})
	require.NoError(t, err)

	_, err = mgr.InsertRule(NFTFirewallRule{
		Chain:   ref,
		Verdict: VerdictDrop,
		Comment: "First",
		Priority: 100,
	})
	require.NoError(t, err)

	tracked := mgr.GetTrackedRules(ref)
	require.Len(t, tracked, 2)
	// GetTrackedRules sorts by priority
	assert.Equal(t, "First", tracked[0].Rule.Comment)
	assert.Equal(t, "Second", tracked[1].Rule.Comment)
}

func TestManagerDeleteRule(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}
	handle, err := mgr.AddRule(NFTFirewallRule{
		Chain:   ref,
		Verdict: VerdictAccept,
		Comment: "to delete",
	})
	require.NoError(t, err)

	err = mgr.DeleteRule(ref, handle)
	require.NoError(t, err)

	tracked := mgr.GetTrackedRules(ref)
	assert.Len(t, tracked, 0)
	assert.Equal(t, 0, mgr.GetTrackedRuleCount())
}

func TestManagerPriorityOrdering(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	ref := ChainRef{Table: "fos1-filter", Chain: "forward"}

	// Add rules out of priority order
	_, err := mgr.AddRule(NFTFirewallRule{
		Chain:    ref,
		Verdict:  VerdictAccept,
		Comment:  "Low priority",
		Priority: 300,
	})
	require.NoError(t, err)

	_, err = mgr.AddRule(NFTFirewallRule{
		Chain:    ref,
		Verdict:  VerdictDrop,
		Comment:  "High priority",
		Priority: 100,
	})
	require.NoError(t, err)

	_, err = mgr.AddRule(NFTFirewallRule{
		Chain:    ref,
		Verdict:  VerdictAccept,
		Comment:  "Medium priority",
		Priority: 200,
	})
	require.NoError(t, err)

	// GetTrackedRules returns them sorted by priority
	tracked := mgr.GetTrackedRules(ref)
	require.Len(t, tracked, 3)
	assert.Equal(t, "High priority", tracked[0].Rule.Comment)
	assert.Equal(t, "Medium priority", tracked[1].Rule.Comment)
	assert.Equal(t, "Low priority", tracked[2].Rule.Comment)
}

func TestManagerApplyRulesByPriority(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}

	// Add rules out of order
	_, err := mgr.AddRule(NFTFirewallRule{
		Chain:    ref,
		Verdict:  VerdictDrop,
		Comment:  "Third",
		Priority: 300,
	})
	require.NoError(t, err)

	_, err = mgr.AddRule(NFTFirewallRule{
		Chain:    ref,
		Verdict:  VerdictAccept,
		Comment:  "First",
		Priority: 100,
	})
	require.NoError(t, err)

	_, err = mgr.AddRule(NFTFirewallRule{
		Chain:    ref,
		Verdict:  VerdictAccept,
		Comment:  "Second",
		Priority: 200,
	})
	require.NoError(t, err)

	// Apply by priority (flushes and re-adds in order)
	err = mgr.ApplyRulesByPriority(ref)
	require.NoError(t, err)

	// After apply, all should be marked as applied
	tracked := mgr.GetTrackedRules(ref)
	require.Len(t, tracked, 3)
	for _, r := range tracked {
		assert.True(t, r.Applied)
	}
	assert.Equal(t, "First", tracked[0].Rule.Comment)
	assert.Equal(t, "Second", tracked[1].Rule.Comment)
	assert.Equal(t, "Third", tracked[2].Rule.Comment)

	// Verify the mock backend has rules in priority order
	backendRules := mock.rules["fos1-filter/input"]
	require.Len(t, backendRules, 3)
	assert.Equal(t, "First", backendRules[0].rule.Comment)
	assert.Equal(t, "Second", backendRules[1].rule.Comment)
	assert.Equal(t, "Third", backendRules[2].rule.Comment)
}

func TestManagerCommit(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}
	_, err := mgr.AddRule(NFTFirewallRule{
		Chain:   ref,
		Verdict: VerdictAccept,
	})
	require.NoError(t, err)

	err = mgr.Commit()
	require.NoError(t, err)
	assert.Equal(t, 1, mock.committed)

	// After commit, rules should be marked as applied
	tracked := mgr.GetTrackedRules(ref)
	require.Len(t, tracked, 1)
	assert.True(t, tracked[0].Applied)
}

func TestManagerAllowPort(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	handle, err := mgr.AllowPort(ProtocolTCP, 443, "Allow HTTPS")
	require.NoError(t, err)
	assert.NotZero(t, handle)

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}
	tracked := mgr.GetTrackedRules(ref)
	require.Len(t, tracked, 1)
	assert.Equal(t, VerdictAccept, tracked[0].Rule.Verdict)
	assert.Equal(t, "Allow HTTPS", tracked[0].Rule.Comment)
	require.Len(t, tracked[0].Rule.Matches, 1)
	assert.Equal(t, ProtocolTCP, tracked[0].Rule.Matches[0].Protocol)
	assert.Equal(t, uint16(443), tracked[0].Rule.Matches[0].DestPort)
}

func TestManagerBlockIP(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	handle, err := mgr.BlockIP("10.0.0.50", "Block bad actor")
	require.NoError(t, err)
	assert.NotZero(t, handle)

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}
	tracked := mgr.GetTrackedRules(ref)
	require.Len(t, tracked, 1)
	assert.Equal(t, VerdictDrop, tracked[0].Rule.Verdict)
	assert.True(t, tracked[0].Rule.Log)
	assert.Equal(t, "10.0.0.50", tracked[0].Rule.Matches[0].SourceAddr)
}

func TestManagerAllowForward(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	handle, err := mgr.AllowForward("eth0", "eth1", "LAN to WAN")
	require.NoError(t, err)
	assert.NotZero(t, handle)

	ref := ChainRef{Table: "fos1-filter", Chain: "forward"}
	tracked := mgr.GetTrackedRules(ref)
	require.Len(t, tracked, 1)
	assert.Equal(t, "eth0", tracked[0].Rule.Matches[0].InInterface)
	assert.Equal(t, "eth1", tracked[0].Rule.Matches[0].OutInterface)
}

func TestManagerAllowICMP(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	handle, err := mgr.AllowICMP("Allow ping")
	require.NoError(t, err)
	assert.NotZero(t, handle)

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}
	tracked := mgr.GetTrackedRules(ref)
	require.Len(t, tracked, 1)
	assert.Equal(t, ProtocolICMP, tracked[0].Rule.Matches[0].Protocol)
}

func TestManagerFlushChain(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}
	_, err := mgr.AddRule(NFTFirewallRule{
		Chain:   ref,
		Verdict: VerdictAccept,
	})
	require.NoError(t, err)

	err = mgr.FlushChain(ref)
	require.NoError(t, err)

	tracked := mgr.GetTrackedRules(ref)
	assert.Len(t, tracked, 0)
	assert.Equal(t, 0, mgr.GetTrackedRuleCount())
}

func TestManagerGetTrackedRuleCount(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	assert.Equal(t, 0, mgr.GetTrackedRuleCount())

	inputRef := ChainRef{Table: "fos1-filter", Chain: "input"}
	forwardRef := ChainRef{Table: "fos1-filter", Chain: "forward"}

	_, _ = mgr.AddRule(NFTFirewallRule{Chain: inputRef, Verdict: VerdictAccept})
	_, _ = mgr.AddRule(NFTFirewallRule{Chain: inputRef, Verdict: VerdictDrop})
	_, _ = mgr.AddRule(NFTFirewallRule{Chain: forwardRef, Verdict: VerdictAccept})

	assert.Equal(t, 3, mgr.GetTrackedRuleCount())
}

func TestManagerGetRuleCounters(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}
	counters, err := mgr.GetRuleCounters(ref, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), counters.Packets)
	assert.Equal(t, uint64(1024), counters.Bytes)
}

func TestManagerAddRuleError(t *testing.T) {
	mock := newMockFirewallManager()
	mock.addRuleErr = fmt.Errorf("simulated error")
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}
	_, err := mgr.AddRule(NFTFirewallRule{Chain: ref, Verdict: VerdictAccept})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "simulated error")
}

func TestManagerDeleteRuleError(t *testing.T) {
	mock := newMockFirewallManager()
	mgr := NewManager(mock)
	require.NoError(t, mgr.Initialize())

	ref := ChainRef{Table: "fos1-filter", Chain: "input"}
	// Try to delete a non-existent rule
	mock.deleteRuleErr = fmt.Errorf("not found")
	err := mgr.DeleteRule(ref, 999)
	assert.Error(t, err)
}

func TestRuleMapKey(t *testing.T) {
	ref := ChainRef{Table: "mytable", Chain: "mychain"}
	assert.Equal(t, "mytable/mychain", ruleMapKey(ref))
}
