//go:build linux

package firewall

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

const (
	// defaultFilterTable is the name of the default filter table.
	defaultFilterTable = "fos1-filter"
	// defaultNATTable is the name of the default NAT table.
	defaultNATTable = "fos1-nat"
)

// KernelFirewallManager implements FirewallManager using the google/nftables library
// for direct netlink communication with the kernel nftables subsystem.
type KernelFirewallManager struct {
	conn *nftables.Conn

	mu     sync.RWMutex
	tables map[string]*nftables.Table
	chains map[string]*nftables.Chain
	sets   map[string]*nftables.Set
}

// NewKernelFirewallManager creates a new kernel-based firewall manager.
func NewKernelFirewallManager() *KernelFirewallManager {
	return &KernelFirewallManager{
		tables: make(map[string]*nftables.Table),
		chains: make(map[string]*nftables.Chain),
		sets:   make(map[string]*nftables.Set),
	}
}

// tableKey returns a unique key for a table given its name and family.
func tableKey(name string, family nftables.TableFamily) string {
	return fmt.Sprintf("%d:%s", family, name)
}

// chainKey returns a unique key for a chain given its table key and chain name.
func chainKey(tableRef string, chain string) string {
	return fmt.Sprintf("%s/%s", tableRef, chain)
}

// setKey returns a unique key for a set given its table key and set name.
func setKey(tableRef string, setName string) string {
	return fmt.Sprintf("%s/@%s", tableRef, setName)
}

// Initialize sets up the nftables connection and creates the default table structure.
// It creates the fos1-filter table (inet family) with input, forward, and output chains,
// and the fos1-nat table (inet family) with prerouting and postrouting chains.
// Default policies are drop for input/forward and accept for output.
// Established/related connection tracking accept rules are added by default.
func (m *KernelFirewallManager) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.conn = &nftables.Conn{}

	// Create filter table (inet for dual-stack)
	if err := m.ensureTableLocked(defaultFilterTable, nftables.TableFamilyINet); err != nil {
		return fmt.Errorf("failed to create filter table: %w", err)
	}

	// Create NAT table (inet for dual-stack)
	if err := m.ensureTableLocked(defaultNATTable, nftables.TableFamilyINet); err != nil {
		return fmt.Errorf("failed to create NAT table: %w", err)
	}

	// Create filter chains with appropriate policies
	policyDrop := nftables.ChainPolicyDrop
	policyAccept := nftables.ChainPolicyAccept

	filterTable := m.tables[tableKey(defaultFilterTable, nftables.TableFamilyINet)]

	// Input chain: default drop
	inputChain := m.conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyDrop,
	})
	m.chains[chainKey(tableKey(defaultFilterTable, nftables.TableFamilyINet), "input")] = inputChain

	// Forward chain: default drop
	forwardChain := m.conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyDrop,
	})
	m.chains[chainKey(tableKey(defaultFilterTable, nftables.TableFamilyINet), "forward")] = forwardChain

	// Output chain: default accept
	outputChain := m.conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    filterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyAccept,
	})
	m.chains[chainKey(tableKey(defaultFilterTable, nftables.TableFamilyINet), "output")] = outputChain

	// NAT chains
	natTable := m.tables[tableKey(defaultNATTable, nftables.TableFamilyINet)]

	preroutingChain := m.conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Policy:   &policyAccept,
	})
	m.chains[chainKey(tableKey(defaultNATTable, nftables.TableFamilyINet), "prerouting")] = preroutingChain

	postroutingChain := m.conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    natTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   &policyAccept,
	})
	m.chains[chainKey(tableKey(defaultNATTable, nftables.TableFamilyINet), "postrouting")] = postroutingChain

	// Add established/related accept rules for input and forward chains
	for _, chain := range []*nftables.Chain{inputChain, forwardChain} {
		m.conn.AddRule(&nftables.Rule{
			Table: filterTable,
			Chain: chain,
			Exprs: []expr.Any{
				// ct state established,related
				&expr.Ct{
					Key:      expr.CtKeySTATE,
					Register: 1,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
					Xor:            binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		})

		// Drop invalid connections
		m.conn.AddRule(&nftables.Rule{
			Table: filterTable,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Ct{
					Key:      expr.CtKeySTATE,
					Register: 1,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitINVALID),
					Xor:            binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Cmp{
					Op:       expr.CmpOpNeq,
					Register: 1,
					Data:     binaryutil.NativeEndian.PutUint32(0),
				},
				&expr.Verdict{
					Kind: expr.VerdictDrop,
				},
			},
		})
	}

	// Allow loopback traffic on input
	m.conn.AddRule(&nftables.Rule{
		Table: filterTable,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname("lo"),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// Commit all changes atomically
	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to commit initial firewall setup: %w", err)
	}

	klog.Info("Kernel firewall manager initialized with default tables and chains")
	return nil
}

// Close releases all resources held by the firewall manager.
func (m *KernelFirewallManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tables = make(map[string]*nftables.Table)
	m.chains = make(map[string]*nftables.Chain)
	m.sets = make(map[string]*nftables.Set)
	m.conn = nil

	klog.Info("Kernel firewall manager closed")
	return nil
}

// EnsureTable creates a table with the given name and family if it does not already exist.
func (m *KernelFirewallManager) EnsureTable(name string, family TableFamily) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return fmt.Errorf("firewall manager not initialized")
	}

	nfFamily := toNFTableFamily(family)
	return m.ensureTableLocked(name, nfFamily)
}

// ensureTableLocked creates a table; caller must hold m.mu.
func (m *KernelFirewallManager) ensureTableLocked(name string, family nftables.TableFamily) error {
	key := tableKey(name, family)
	if _, ok := m.tables[key]; ok {
		return nil
	}

	t := m.conn.AddTable(&nftables.Table{
		Family: family,
		Name:   name,
	})
	m.tables[key] = t

	klog.V(2).Infof("Ensured nftables table %s (family %d)", name, family)
	return nil
}

// EnsureChain creates a base chain if it does not already exist.
func (m *KernelFirewallManager) EnsureChain(table string, chain string, chainType ChainType, hook ChainHook, priority int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return fmt.Errorf("firewall manager not initialized")
	}

	// Look up the table across all families
	nfTable, err := m.findTableLocked(table)
	if err != nil {
		return err
	}

	tKey := tableKey(nfTable.Name, nfTable.Family)
	cKey := chainKey(tKey, chain)
	if _, ok := m.chains[cKey]; ok {
		return nil
	}

	nfChainType := toNFChainType(chainType)
	nfHook := toNFChainHook(hook)
	nfPriority := nftables.ChainPriority(priority)

	c := m.conn.AddChain(&nftables.Chain{
		Name:     chain,
		Table:    nfTable,
		Type:     nfChainType,
		Hooknum:  &nfHook,
		Priority: &nfPriority,
	})
	m.chains[cKey] = c

	klog.V(2).Infof("Ensured chain %s in table %s", chain, table)
	return nil
}

// DeleteChain deletes a chain and all its rules.
func (m *KernelFirewallManager) DeleteChain(ref ChainRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return fmt.Errorf("firewall manager not initialized")
	}

	nfTable, err := m.findTableLocked(ref.Table)
	if err != nil {
		return err
	}

	tKey := tableKey(nfTable.Name, nfTable.Family)
	cKey := chainKey(tKey, ref.Chain)
	chain, ok := m.chains[cKey]
	if !ok {
		return fmt.Errorf("chain %s/%s not found", ref.Table, ref.Chain)
	}

	m.conn.DelChain(chain)
	delete(m.chains, cKey)

	klog.V(2).Infof("Deleted chain %s from table %s", ref.Chain, ref.Table)
	return nil
}

// FlushChain removes all rules from a chain without deleting the chain itself.
func (m *KernelFirewallManager) FlushChain(ref ChainRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return fmt.Errorf("firewall manager not initialized")
	}

	nfTable, err := m.findTableLocked(ref.Table)
	if err != nil {
		return err
	}

	tKey := tableKey(nfTable.Name, nfTable.Family)
	cKey := chainKey(tKey, ref.Chain)
	chain, ok := m.chains[cKey]
	if !ok {
		return fmt.Errorf("chain %s/%s not found", ref.Table, ref.Chain)
	}

	m.conn.FlushChain(chain)

	klog.V(2).Infof("Flushed chain %s in table %s", ref.Chain, ref.Table)
	return nil
}

// AddRule appends a rule to the end of a chain and returns the kernel-assigned handle.
func (m *KernelFirewallManager) AddRule(rule NFTFirewallRule) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return 0, fmt.Errorf("firewall manager not initialized")
	}

	nfTable, nfChain, err := m.resolveChainLocked(rule.Chain)
	if err != nil {
		return 0, err
	}

	exprs, err := buildRuleExprs(rule)
	if err != nil {
		return 0, fmt.Errorf("failed to build rule expressions: %w", err)
	}

	r := m.conn.AddRule(&nftables.Rule{
		Table:    nfTable,
		Chain:    nfChain,
		Exprs:    exprs,
		UserData: []byte(rule.Comment),
	})

	klog.V(4).Infof("Added rule to chain %s/%s", rule.Chain.Table, rule.Chain.Chain)
	return r.Handle, nil
}

// InsertRule inserts a rule at the beginning of a chain and returns the kernel-assigned handle.
func (m *KernelFirewallManager) InsertRule(rule NFTFirewallRule) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return 0, fmt.Errorf("firewall manager not initialized")
	}

	nfTable, nfChain, err := m.resolveChainLocked(rule.Chain)
	if err != nil {
		return 0, err
	}

	exprs, err := buildRuleExprs(rule)
	if err != nil {
		return 0, fmt.Errorf("failed to build rule expressions: %w", err)
	}

	r := m.conn.InsertRule(&nftables.Rule{
		Table:    nfTable,
		Chain:    nfChain,
		Exprs:    exprs,
		UserData: []byte(rule.Comment),
	})

	klog.V(4).Infof("Inserted rule at beginning of chain %s/%s", rule.Chain.Table, rule.Chain.Chain)
	return r.Handle, nil
}

// DeleteRule deletes a rule identified by its chain reference and kernel handle.
func (m *KernelFirewallManager) DeleteRule(ref ChainRef, handle uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return fmt.Errorf("firewall manager not initialized")
	}

	nfTable, nfChain, err := m.resolveChainLocked(ref)
	if err != nil {
		return err
	}

	if err := m.conn.DelRule(&nftables.Rule{
		Table:  nfTable,
		Chain:  nfChain,
		Handle: handle,
	}); err != nil {
		return fmt.Errorf("failed to delete rule with handle %d: %w", handle, err)
	}

	klog.V(4).Infof("Deleted rule handle %d from chain %s/%s", handle, ref.Table, ref.Chain)
	return nil
}

// ListRules returns all rules in a given chain.
func (m *KernelFirewallManager) ListRules(ref ChainRef) ([]NFTFirewallRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.conn == nil {
		return nil, fmt.Errorf("firewall manager not initialized")
	}

	nfTable, nfChain, err := m.resolveChainLocked(ref)
	if err != nil {
		return nil, err
	}

	rules, err := m.conn.GetRules(nfTable, nfChain)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules for chain %s/%s: %w", ref.Table, ref.Chain, err)
	}

	result := make([]NFTFirewallRule, 0, len(rules))
	for _, r := range rules {
		fwRule := NFTFirewallRule{
			Chain:  ref,
			Handle: r.Handle,
		}
		if r.UserData != nil {
			fwRule.Comment = string(r.UserData)
		}
		result = append(result, fwRule)
	}

	return result, nil
}

// CreateSet creates a new nftables set for address or port matching.
// The keyType parameter should be one of the nftables set key type magic numbers
// (e.g., 7 for ipv4_addr, 8 for ipv6_addr, 13 for inet_service).
func (m *KernelFirewallManager) CreateSet(table string, name string, keyType uint32, interval bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return fmt.Errorf("firewall manager not initialized")
	}

	nfTable, err := m.findTableLocked(table)
	if err != nil {
		return err
	}

	setDatatype := nftables.TypeIPAddr
	switch keyType {
	case 7:
		setDatatype = nftables.TypeIPAddr
	case 8:
		setDatatype = nftables.TypeIP6Addr
	case 13:
		setDatatype = nftables.TypeInetService
	case 12:
		setDatatype = nftables.TypeInetProto
	default:
		return fmt.Errorf("unsupported set key type: %d", keyType)
	}

	s := &nftables.Set{
		Table:    nfTable,
		Name:     name,
		KeyType:  setDatatype,
		Interval: interval,
	}

	if err := m.conn.AddSet(s, nil); err != nil {
		return fmt.Errorf("failed to create set %s in table %s: %w", name, table, err)
	}

	tKey := tableKey(nfTable.Name, nfTable.Family)
	m.sets[setKey(tKey, name)] = s

	klog.V(2).Infof("Created set %s in table %s (keyType=%d, interval=%v)", name, table, keyType, interval)
	return nil
}

// AddSetElements adds elements to an existing nftables set.
// Each element in the elements slice is a byte representation of the value to add.
func (m *KernelFirewallManager) AddSetElements(table string, setName string, elements [][]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return fmt.Errorf("firewall manager not initialized")
	}

	nfTable, err := m.findTableLocked(table)
	if err != nil {
		return err
	}

	tKey := tableKey(nfTable.Name, nfTable.Family)
	s, ok := m.sets[setKey(tKey, setName)]
	if !ok {
		return fmt.Errorf("set %s not found in table %s", setName, table)
	}

	setElements := make([]nftables.SetElement, 0, len(elements))
	for _, elem := range elements {
		setElements = append(setElements, nftables.SetElement{Key: elem})
	}

	if err := m.conn.SetAddElements(s, setElements); err != nil {
		return fmt.Errorf("failed to add elements to set %s: %w", setName, err)
	}

	klog.V(4).Infof("Added %d elements to set %s in table %s", len(elements), setName, table)
	return nil
}

// DeleteSet removes an nftables set and all its elements.
func (m *KernelFirewallManager) DeleteSet(table string, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return fmt.Errorf("firewall manager not initialized")
	}

	nfTable, err := m.findTableLocked(table)
	if err != nil {
		return err
	}

	tKey := tableKey(nfTable.Name, nfTable.Family)
	sKey := setKey(tKey, name)
	s, ok := m.sets[sKey]
	if !ok {
		return fmt.Errorf("set %s not found in table %s", name, table)
	}

	m.conn.DelSet(s)
	delete(m.sets, sKey)

	klog.V(2).Infof("Deleted set %s from table %s", name, table)
	return nil
}

// Commit atomically applies all pending changes to the kernel.
func (m *KernelFirewallManager) Commit() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return fmt.Errorf("firewall manager not initialized")
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to commit nftables changes: %w", err)
	}

	klog.V(2).Info("Committed nftables changes")
	return nil
}

// GetRuleCounters returns packet and byte counters for a specific rule.
func (m *KernelFirewallManager) GetRuleCounters(ref ChainRef, handle uint64) (*RuleCounters, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.conn == nil {
		return nil, fmt.Errorf("firewall manager not initialized")
	}

	nfTable, nfChain, err := m.resolveChainLocked(ref)
	if err != nil {
		return nil, err
	}

	rules, err := m.conn.GetRules(nfTable, nfChain)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules for chain %s/%s: %w", ref.Table, ref.Chain, err)
	}

	for _, r := range rules {
		if r.Handle != handle {
			continue
		}
		for _, e := range r.Exprs {
			if counter, ok := e.(*expr.Counter); ok {
				return &RuleCounters{
					Packets: counter.Packets,
					Bytes:   counter.Bytes,
				}, nil
			}
		}
		return &RuleCounters{}, nil
	}

	return nil, fmt.Errorf("rule with handle %d not found in chain %s/%s", handle, ref.Table, ref.Chain)
}

// findTableLocked finds a table by name across all families; caller must hold m.mu.
func (m *KernelFirewallManager) findTableLocked(name string) (*nftables.Table, error) {
	// Check inet first, then ipv4, then ipv6
	for _, family := range []nftables.TableFamily{nftables.TableFamilyINet, nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		key := tableKey(name, family)
		if t, ok := m.tables[key]; ok {
			return t, nil
		}
	}
	return nil, fmt.Errorf("table %s not found", name)
}

// resolveChainLocked resolves a ChainRef to kernel table and chain objects; caller must hold m.mu.
func (m *KernelFirewallManager) resolveChainLocked(ref ChainRef) (*nftables.Table, *nftables.Chain, error) {
	nfTable, err := m.findTableLocked(ref.Table)
	if err != nil {
		return nil, nil, err
	}

	tKey := tableKey(nfTable.Name, nfTable.Family)
	cKey := chainKey(tKey, ref.Chain)
	chain, ok := m.chains[cKey]
	if !ok {
		return nil, nil, fmt.Errorf("chain %s/%s not found", ref.Table, ref.Chain)
	}

	return nfTable, chain, nil
}

// buildRuleExprs constructs nftables expressions from an NFTFirewallRule.
func buildRuleExprs(rule NFTFirewallRule) ([]expr.Any, error) {
	var exprs []expr.Any

	for _, match := range rule.Matches {
		matchExprs, err := buildMatchExprs(match)
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, matchExprs...)
	}

	// Add counter if enabled
	if rule.Counter {
		exprs = append(exprs, &expr.Counter{})
	}

	// Add log if enabled
	if rule.Log {
		prefix := rule.LogPrefix
		if prefix == "" {
			prefix = "fos1: "
		}
		exprs = append(exprs, &expr.Log{
			Key:  1 << 0, // NFTA_LOG_PREFIX
			Data: []byte(prefix),
		})
	}

	// Add verdict
	verdictExpr, err := buildVerdictExpr(rule.Verdict, rule.JumpTarget)
	if err != nil {
		return nil, err
	}
	// Log verdict is non-terminal; do not append a verdict expression for it
	// since the Log expression above handles it
	if rule.Verdict != VerdictLog {
		exprs = append(exprs, verdictExpr)
	}

	return exprs, nil
}

// buildMatchExprs constructs nftables expressions for a single RuleMatch.
func buildMatchExprs(match RuleMatch) ([]expr.Any, error) {
	var exprs []expr.Any

	// Protocol matching
	if match.Protocol != ProtocolAny && match.Protocol != "" {
		proto, err := protocolNumber(match.Protocol)
		if err != nil {
			return nil, err
		}
		exprs = append(exprs,
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{proto},
			},
		)
	}

	// Input interface matching
	if match.InInterface != "" {
		exprs = append(exprs,
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(match.InInterface),
			},
		)
	}

	// Output interface matching
	if match.OutInterface != "" {
		exprs = append(exprs,
			&expr.Meta{
				Key:      expr.MetaKeyOIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(match.OutInterface),
			},
		)
	}

	// Source address matching
	if match.SourceAddr != "" {
		addrExprs, err := buildAddrMatchExprs(match.SourceAddr, true)
		if err != nil {
			return nil, fmt.Errorf("invalid source address %s: %w", match.SourceAddr, err)
		}
		exprs = append(exprs, addrExprs...)
	}

	// Destination address matching
	if match.DestAddr != "" {
		addrExprs, err := buildAddrMatchExprs(match.DestAddr, false)
		if err != nil {
			return nil, fmt.Errorf("invalid destination address %s: %w", match.DestAddr, err)
		}
		exprs = append(exprs, addrExprs...)
	}

	// Source port matching
	if match.SourcePort != 0 {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0, // source port offset in TCP/UDP header
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(match.SourcePort),
			},
		)
	}

	// Destination port matching
	if match.DestPort != 0 {
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // destination port offset in TCP/UDP header
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(match.DestPort),
			},
		)
	}

	// Connection tracking state matching
	if len(match.CTState) > 0 {
		ctExprs, err := buildCTStateExprs(match.CTState)
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, ctExprs...)
	}

	// Set lookup matching
	if match.SetRef != "" {
		op := expr.CmpOpEq
		if match.Negate {
			op = expr.CmpOpNeq
		}
		_ = op // Lookup has its own Invert field
		exprs = append(exprs,
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        match.SetRef,
				Invert:         match.Negate,
			},
		)
	}

	return exprs, nil
}

// buildAddrMatchExprs builds payload + cmp expressions for IP address matching.
func buildAddrMatchExprs(addr string, isSrc bool) ([]expr.Any, error) {
	// Determine if this is a CIDR or single IP
	ip, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		// Try as a single IP
		ip = net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("invalid address: %s", addr)
		}
		// Treat single IP as /32 or /128
		if ip.To4() != nil {
			_, ipNet, _ = net.ParseCIDR(ip.String() + "/32")
		} else {
			_, ipNet, _ = net.ParseCIDR(ip.String() + "/128")
		}
	}

	isIPv4 := ipNet.IP.To4() != nil

	var offset uint32
	var addrLen uint32
	if isIPv4 {
		if isSrc {
			offset = 12 // IPv4 source address offset in IP header
		} else {
			offset = 16 // IPv4 destination address offset in IP header
		}
		addrLen = 4
	} else {
		if isSrc {
			offset = 8 // IPv6 source address offset in IPv6 header
		} else {
			offset = 24 // IPv6 destination address offset in IPv6 header
		}
		addrLen = 16
	}

	var exprs []expr.Any

	// Load the address from the packet
	exprs = append(exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,
		Len:          addrLen,
	})

	// For CIDR matching, we need to mask and compare
	ones, bits := ipNet.Mask.Size()
	if ones < bits {
		// Apply netmask via bitwise operation
		exprs = append(exprs, &expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            addrLen,
			Mask:           []byte(ipNet.Mask),
			Xor:            make([]byte, addrLen),
		})
	}

	// Compare with the network address
	var networkAddr []byte
	if isIPv4 {
		networkAddr = ipNet.IP.To4()
	} else {
		networkAddr = ipNet.IP.To16()
	}

	exprs = append(exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     networkAddr,
	})

	return exprs, nil
}

// buildCTStateExprs builds connection tracking state match expressions.
func buildCTStateExprs(states []string) ([]expr.Any, error) {
	var stateMask uint32
	for _, state := range states {
		switch strings.ToLower(state) {
		case "new":
			stateMask |= expr.CtStateBitNEW
		case "established":
			stateMask |= expr.CtStateBitESTABLISHED
		case "related":
			stateMask |= expr.CtStateBitRELATED
		case "invalid":
			stateMask |= expr.CtStateBitINVALID
		default:
			return nil, fmt.Errorf("unknown connection tracking state: %s", state)
		}
	}

	return []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(stateMask),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(0),
		},
	}, nil
}

// buildVerdictExpr constructs a verdict expression.
func buildVerdictExpr(verdict Verdict, jumpTarget string) (expr.Any, error) {
	switch verdict {
	case VerdictAccept:
		return &expr.Verdict{Kind: expr.VerdictAccept}, nil
	case VerdictDrop:
		return &expr.Verdict{Kind: expr.VerdictDrop}, nil
	case VerdictReject:
		return &expr.Reject{
			Type: unix.NFT_REJECT_ICMPX_UNREACH,
			Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH,
		}, nil
	case VerdictJump:
		if jumpTarget == "" {
			return nil, fmt.Errorf("jump verdict requires a target chain")
		}
		return &expr.Verdict{Kind: expr.VerdictJump, Chain: jumpTarget}, nil
	case VerdictReturn:
		return &expr.Verdict{Kind: expr.VerdictReturn}, nil
	case VerdictLog:
		// Log is non-terminal; return a no-op verdict (handled by Log expression)
		return &expr.Verdict{Kind: expr.VerdictAccept}, nil
	default:
		return nil, fmt.Errorf("unsupported verdict: %s", verdict)
	}
}

// protocolNumber converts a Protocol to its numeric representation.
func protocolNumber(proto Protocol) (byte, error) {
	switch proto {
	case ProtocolTCP:
		return unix.IPPROTO_TCP, nil
	case ProtocolUDP:
		return unix.IPPROTO_UDP, nil
	case ProtocolICMP:
		return unix.IPPROTO_ICMP, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

// ifname converts an interface name to a null-padded byte slice for nftables matching.
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

// toNFTableFamily converts a TableFamily to the nftables library's TableFamily type.
func toNFTableFamily(family TableFamily) nftables.TableFamily {
	switch family {
	case FamilyINET:
		return nftables.TableFamilyINet
	case FamilyIPv4:
		return nftables.TableFamilyIPv4
	case FamilyIPv6:
		return nftables.TableFamilyIPv6
	default:
		return nftables.TableFamilyINet
	}
}

// toNFChainType converts a ChainType to the nftables library's ChainType type.
func toNFChainType(ct ChainType) nftables.ChainType {
	switch ct {
	case ChainTypeFilter:
		return nftables.ChainTypeFilter
	case ChainTypeNAT:
		return nftables.ChainTypeNAT
	case ChainTypeRoute:
		return nftables.ChainTypeRoute
	default:
		return nftables.ChainTypeFilter
	}
}

// toNFChainHook converts a ChainHook to the nftables library's ChainHook type.
func toNFChainHook(hook ChainHook) nftables.ChainHook {
	switch hook {
	case HookInput:
		return *nftables.ChainHookInput
	case HookOutput:
		return *nftables.ChainHookOutput
	case HookForward:
		return *nftables.ChainHookForward
	case HookPrerouting:
		return *nftables.ChainHookPrerouting
	case HookPostrouting:
		return *nftables.ChainHookPostrouting
	default:
		return *nftables.ChainHookInput
	}
}

// Ensure unused imports are used.
var _ = binary.BigEndian
