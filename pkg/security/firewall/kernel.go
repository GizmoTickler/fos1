package firewall

import (
	"context"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// KernelFirewallManager manages nftables firewall rules via netlink
type KernelFirewallManager struct {
	conn *nftables.Conn

	// Track created tables and chains
	tables map[string]*nftables.Table
	chains map[string]*nftables.Chain
	sets   map[string]*nftables.Set
}

// NewKernelFirewallManager creates a new kernel-based firewall manager
func NewKernelFirewallManager() (*KernelFirewallManager, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create nftables connection: %w", err)
	}

	return &KernelFirewallManager{
		conn:   conn,
		tables: make(map[string]*nftables.Table),
		chains: make(map[string]*nftables.Chain),
		sets:   make(map[string]*nftables.Set),
	}, nil
}

// Close closes the nftables connection
func (m *KernelFirewallManager) Close() error {
	// No explicit close needed for nftables.Conn
	return nil
}

// InitializeFirewall sets up the basic nftables structure
func (m *KernelFirewallManager) InitializeFirewall(ctx context.Context) error {
	// Create filter table for IPv4
	ipv4Table := m.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})
	m.tables["ipv4-filter"] = ipv4Table

	// Create filter table for IPv6
	ipv6Table := m.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "filter",
	})
	m.tables["ipv6-filter"] = ipv6Table

	// Create NAT table for IPv4
	ipv4NatTable := m.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})
	m.tables["ipv4-nat"] = ipv4NatTable

	// Create NAT table for IPv6
	ipv6NatTable := m.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "nat",
	})
	m.tables["ipv6-nat"] = ipv6NatTable

	// Flush existing rules and apply tables
	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables: %w", err)
	}

	// Create standard chains for IPv4 filter
	if err := m.createStandardChains(ipv4Table, nftables.TableFamilyIPv4); err != nil {
		return fmt.Errorf("failed to create IPv4 standard chains: %w", err)
	}

	// Create standard chains for IPv6 filter
	if err := m.createStandardChains(ipv6Table, nftables.TableFamilyIPv6); err != nil {
		return fmt.Errorf("failed to create IPv6 standard chains: %w", err)
	}

	// Create NAT chains for IPv4
	if err := m.createNATChains(ipv4NatTable, nftables.TableFamilyIPv4); err != nil {
		return fmt.Errorf("failed to create IPv4 NAT chains: %w", err)
	}

	// Create NAT chains for IPv6
	if err := m.createNATChains(ipv6NatTable, nftables.TableFamilyIPv6); err != nil {
		return fmt.Errorf("failed to create IPv6 NAT chains: %w", err)
	}

	// Apply connection tracking rules
	if err := m.setupConnectionTracking(ipv4Table, nftables.TableFamilyIPv4); err != nil {
		return fmt.Errorf("failed to setup IPv4 connection tracking: %w", err)
	}

	if err := m.setupConnectionTracking(ipv6Table, nftables.TableFamilyIPv6); err != nil {
		return fmt.Errorf("failed to setup IPv6 connection tracking: %w", err)
	}

	// Apply all changes
	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply initial firewall configuration: %w", err)
	}

	return nil
}

// createStandardChains creates standard filter chains (input, forward, output)
func (m *KernelFirewallManager) createStandardChains(table *nftables.Table, family nftables.TableFamily) error {
	// Input chain
	policyDrop := nftables.ChainPolicyDrop
	policyAccept := nftables.ChainPolicyAccept
	hookInput := nftables.ChainHookInput
	hookForward := nftables.ChainHookForward
	hookOutput := nftables.ChainHookOutput
	priorityFilter := nftables.ChainPriorityFilter

	inputChain := m.conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  &hookInput,
		Priority: &priorityFilter,
		Policy:   &policyDrop,
	})
	m.chains[fmt.Sprintf("%s-%s-input", family, table.Name)] = inputChain

	// Forward chain
	forwardChain := m.conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  &hookForward,
		Priority: &priorityFilter,
		Policy:   &policyDrop,
	})
	m.chains[fmt.Sprintf("%s-%s-forward", family, table.Name)] = forwardChain

	// Output chain
	outputChain := m.conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  &hookOutput,
		Priority: &priorityFilter,
		Policy:   &policyAccept,
	})
	m.chains[fmt.Sprintf("%s-%s-output", family, table.Name)] = outputChain

	return nil
}

// createNATChains creates NAT chains (prerouting, postrouting)
func (m *KernelFirewallManager) createNATChains(table *nftables.Table, family nftables.TableFamily) error {
	// Prerouting chain for DNAT
	hookPrerouting := nftables.ChainHookPrerouting
	hookPostrouting := nftables.ChainHookPostrouting
	priorityNATDest := nftables.ChainPriorityNATDest
	priorityNATSource := nftables.ChainPriorityNATSource

	preroutingChain := m.conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  &hookPrerouting,
		Priority: &priorityNATDest,
	})
	m.chains[fmt.Sprintf("%s-%s-prerouting", family, table.Name)] = preroutingChain

	// Postrouting chain for SNAT/masquerade
	postroutingChain := m.conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  &hookPostrouting,
		Priority: &priorityNATSource,
	})
	m.chains[fmt.Sprintf("%s-%s-postrouting", family, table.Name)] = postroutingChain

	return nil
}

// setupConnectionTracking sets up connection tracking rules for stateful filtering
func (m *KernelFirewallManager) setupConnectionTracking(table *nftables.Table, family nftables.TableFamily) error {
	inputChain := m.chains[fmt.Sprintf("%s-%s-input", family, table.Name)]
	forwardChain := m.chains[fmt.Sprintf("%s-%s-forward", family, table.Name)]

	// Allow established and related connections on input
	m.conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match connection state: established, related
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x00, 0x00, 0x00, 0x06}, // ESTABLISHED | RELATED
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			// Counter
			&expr.Counter{},
			// Verdict: accept
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// Drop invalid connections on input
	m.conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match connection state: invalid
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x00, 0x00, 0x00, 0x01}, // INVALID
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			// Counter
			&expr.Counter{},
			// Verdict: drop
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	// Allow established and related connections on forward
	m.conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardChain,
		Exprs: []expr.Any{
			// Match connection state: established, related
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x00, 0x00, 0x00, 0x06}, // ESTABLISHED | RELATED
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			// Counter
			&expr.Counter{},
			// Verdict: accept
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// Drop invalid connections on forward
	m.conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardChain,
		Exprs: []expr.Any{
			// Match connection state: invalid
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 1,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x00, 0x00, 0x00, 0x01}, // INVALID
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			// Counter
			&expr.Counter{},
			// Verdict: drop
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	return nil
}

// CreateTable creates a new nftables table
func (m *KernelFirewallManager) CreateTable(name string, family nftables.TableFamily) (*nftables.Table, error) {
	table := m.conn.AddTable(&nftables.Table{
		Family: family,
		Name:   name,
	})

	if err := m.conn.Flush(); err != nil {
		return nil, fmt.Errorf("failed to create table %s: %w", name, err)
	}

	key := fmt.Sprintf("%s-%s", family, name)
	m.tables[key] = table

	return table, nil
}

// DeleteTable deletes an nftables table
func (m *KernelFirewallManager) DeleteTable(name string, family nftables.TableFamily) error {
	key := fmt.Sprintf("%s-%s", family, name)
	table, exists := m.tables[key]
	if !exists {
		return fmt.Errorf("table %s not found", name)
	}

	m.conn.DelTable(table)

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to delete table %s: %w", name, err)
	}

	delete(m.tables, key)

	return nil
}

// CreateChain creates a new nftables chain
func (m *KernelFirewallManager) CreateChain(table *nftables.Table, name string, chainType nftables.ChainType, hook *nftables.ChainHook, priority *nftables.ChainPriority, policy *nftables.ChainPolicy) (*nftables.Chain, error) {
	chain := &nftables.Chain{
		Name:  name,
		Table: table,
		Type:  chainType,
	}

	if hook != nil {
		chain.Hooknum = hook
	}

	if priority != nil {
		chain.Priority = priority
	}

	if policy != nil {
		chain.Policy = policy
	}

	m.conn.AddChain(chain)

	if err := m.conn.Flush(); err != nil {
		return nil, fmt.Errorf("failed to create chain %s: %w", name, err)
	}

	key := fmt.Sprintf("%s-%s-%s", table.Family, table.Name, name)
	m.chains[key] = chain

	return chain, nil
}

// DeleteChain deletes an nftables chain
func (m *KernelFirewallManager) DeleteChain(table *nftables.Table, name string) error {
	key := fmt.Sprintf("%s-%s-%s", table.Family, table.Name, name)
	chain, exists := m.chains[key]
	if !exists {
		return fmt.Errorf("chain %s not found", name)
	}

	m.conn.DelChain(chain)

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to delete chain %s: %w", name, err)
	}

	delete(m.chains, key)

	return nil
}

// CreateIPSet creates a new IP set for efficient IP matching
func (m *KernelFirewallManager) CreateIPSet(table *nftables.Table, name string, keyType nftables.SetDatatype, ips []string) (*nftables.Set, error) {
	set := &nftables.Set{
		Table:   table,
		Name:    name,
		KeyType: keyType,
	}

	m.conn.AddSet(set, nil)

	// Add elements to the set
	elements := make([]nftables.SetElement, 0, len(ips))
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}

		var key []byte
		if keyType == nftables.TypeIPAddr {
			key = ip.To4()
		} else if keyType == nftables.TypeIP6Addr {
			key = ip.To16()
		}

		elements = append(elements, nftables.SetElement{
			Key: key,
		})
	}

	if len(elements) > 0 {
		if err := m.conn.SetAddElements(set, elements); err != nil {
			return nil, fmt.Errorf("failed to add elements to set: %w", err)
		}
	}

	if err := m.conn.Flush(); err != nil {
		return nil, fmt.Errorf("failed to create IP set %s: %w", name, err)
	}

	key := fmt.Sprintf("%s-%s-%s", table.Family, table.Name, name)
	m.sets[key] = set

	return set, nil
}

// DeleteIPSet deletes an IP set
func (m *KernelFirewallManager) DeleteIPSet(table *nftables.Table, name string) error {
	key := fmt.Sprintf("%s-%s-%s", table.Family, table.Name, name)
	set, exists := m.sets[key]
	if !exists {
		return fmt.Errorf("set %s not found", name)
	}

	m.conn.DelSet(set)

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to delete IP set %s: %w", name, err)
	}

	delete(m.sets, key)

	return nil
}

// AddIPToSet adds an IP address to an existing set
func (m *KernelFirewallManager) AddIPToSet(table *nftables.Table, name string, ipStr string) error {
	key := fmt.Sprintf("%s-%s-%s", table.Family, table.Name, name)
	set, exists := m.sets[key]
	if !exists {
		return fmt.Errorf("set %s not found", name)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	var ipKey []byte
	if set.KeyType == nftables.TypeIPAddr {
		ipKey = ip.To4()
	} else if set.KeyType == nftables.TypeIP6Addr {
		ipKey = ip.To16()
	}

	err := m.conn.SetAddElements(set, []nftables.SetElement{
		{Key: ipKey},
	})
	if err != nil {
		return fmt.Errorf("failed to add IP to set: %w", err)
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply IP addition: %w", err)
	}

	return nil
}

// RemoveIPFromSet removes an IP address from a set
func (m *KernelFirewallManager) RemoveIPFromSet(table *nftables.Table, name string, ipStr string) error {
	key := fmt.Sprintf("%s-%s-%s", table.Family, table.Name, name)
	set, exists := m.sets[key]
	if !exists {
		return fmt.Errorf("set %s not found", name)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}

	var ipKey []byte
	if set.KeyType == nftables.TypeIPAddr {
		ipKey = ip.To4()
	} else if set.KeyType == nftables.TypeIP6Addr {
		ipKey = ip.To16()
	}

	err := m.conn.SetDeleteElements(set, []nftables.SetElement{
		{Key: ipKey},
	})
	if err != nil {
		return fmt.Errorf("failed to remove IP from set: %w", err)
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply IP removal: %w", err)
	}

	return nil
}

// AddRule adds a rule to a chain
func (m *KernelFirewallManager) AddRule(table *nftables.Table, chain *nftables.Chain, rule *nftables.Rule) error {
	rule.Table = table
	rule.Chain = chain

	m.conn.AddRule(rule)

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to add rule: %w", err)
	}

	return nil
}

// DeleteRule deletes a rule from a chain
func (m *KernelFirewallManager) DeleteRule(rule *nftables.Rule) error {
	if err := m.conn.DelRule(rule); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply rule deletion: %w", err)
	}

	return nil
}

// ListRules lists all rules in a chain
func (m *KernelFirewallManager) ListRules(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
	rules, err := m.conn.GetRules(table, chain)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	return rules, nil
}

// FlushChain removes all rules from a chain
func (m *KernelFirewallManager) FlushChain(table *nftables.Table, chain *nftables.Chain) error {
	m.conn.FlushChain(chain)

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush chain: %w", err)
	}

	return nil
}

// GetTable retrieves a table by name and family
func (m *KernelFirewallManager) GetTable(name string, family nftables.TableFamily) (*nftables.Table, error) {
	key := fmt.Sprintf("%s-%s", family, name)
	table, exists := m.tables[key]
	if !exists {
		return nil, fmt.Errorf("table %s not found", name)
	}

	return table, nil
}

// GetChain retrieves a chain by name
func (m *KernelFirewallManager) GetChain(table *nftables.Table, name string) (*nftables.Chain, error) {
	key := fmt.Sprintf("%s-%s-%s", table.Family, table.Name, name)
	chain, exists := m.chains[key]
	if !exists {
		return nil, fmt.Errorf("chain %s not found", name)
	}

	return chain, nil
}

// GetSet retrieves a set by name
func (m *KernelFirewallManager) GetSet(table *nftables.Table, name string) (*nftables.Set, error) {
	key := fmt.Sprintf("%s-%s-%s", table.Family, table.Name, name)
	set, exists := m.sets[key]
	if !exists {
		return nil, fmt.Errorf("set %s not found", name)
	}

	return set, nil
}

// Helper function to convert protocol string to number
func protocolToNumber(protocol string) uint8 {
	switch protocol {
	case "tcp":
		return unix.IPPROTO_TCP
	case "udp":
		return unix.IPPROTO_UDP
	case "icmp":
		return unix.IPPROTO_ICMP
	case "icmpv6":
		return unix.IPPROTO_ICMPV6
	default:
		return 0
	}
}
