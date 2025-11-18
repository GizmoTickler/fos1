package firewall

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/nftables"

	"github.com/GizmoTickler/fos1/pkg/security/firewall/rules"
	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

// Manager manages firewall policies and rules
type Manager struct {
	kernel *KernelFirewallManager

	// Track active policies
	policies map[string]*policy.FilterPolicy
	mu       sync.RWMutex

	// Track zones
	zones map[string]*policy.FilterZone
}

// NewManager creates a new firewall manager
func NewManager() (*Manager, error) {
	kernel, err := NewKernelFirewallManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create kernel firewall manager: %w", err)
	}

	return &Manager{
		kernel:   kernel,
		policies: make(map[string]*policy.FilterPolicy),
		zones:    make(map[string]*policy.FilterZone),
	}, nil
}

// Initialize initializes the firewall
func (m *Manager) Initialize(ctx context.Context) error {
	return m.kernel.InitializeFirewall(ctx)
}

// Close closes the firewall manager
func (m *Manager) Close() error {
	return m.kernel.Close()
}

// ApplyPolicy applies a filter policy to the firewall
func (m *Manager) ApplyPolicy(ctx context.Context, policy *policy.FilterPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Determine target chain based on policy scope
	var chainName string
	switch policy.Spec.Scope {
	case "input":
		chainName = "input"
	case "output":
		chainName = "output"
	case "forward":
		chainName = "forward"
	default:
		chainName = "forward" // default to forward
	}

	// Build rules for IPv4
	ipv4Table, err := m.kernel.GetTable("filter", nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("failed to get IPv4 table: %w", err)
	}

	ipv4Chain, err := m.kernel.GetChain(ipv4Table, chainName)
	if err != nil {
		return fmt.Errorf("failed to get IPv4 chain: %w", err)
	}

	builder := rules.NewRuleBuilder(policy)
	ipv4Rules, err := builder.BuildRules(ipv4Table, ipv4Chain)
	if err != nil {
		return fmt.Errorf("failed to build IPv4 rules: %w", err)
	}

	// Add IPv4 rules
	for _, rule := range ipv4Rules {
		if err := m.kernel.AddRule(ipv4Table, ipv4Chain, rule); err != nil {
			return fmt.Errorf("failed to add IPv4 rule: %w", err)
		}
	}

	// Build rules for IPv6
	ipv6Table, err := m.kernel.GetTable("filter", nftables.TableFamilyIPv6)
	if err != nil {
		return fmt.Errorf("failed to get IPv6 table: %w", err)
	}

	ipv6Chain, err := m.kernel.GetChain(ipv6Table, chainName)
	if err != nil {
		return fmt.Errorf("failed to get IPv6 chain: %w", err)
	}

	ipv6Rules, err := builder.BuildRules(ipv6Table, ipv6Chain)
	if err != nil {
		return fmt.Errorf("failed to build IPv6 rules: %w", err)
	}

	// Add IPv6 rules
	for _, rule := range ipv6Rules {
		if err := m.kernel.AddRule(ipv6Table, ipv6Chain, rule); err != nil {
			return fmt.Errorf("failed to add IPv6 rule: %w", err)
		}
	}

	// Store policy
	policyKey := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	m.policies[policyKey] = policy

	return nil
}

// RemovePolicy removes a filter policy from the firewall
func (m *Manager) RemovePolicy(ctx context.Context, name string, namespace string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	policyKey := fmt.Sprintf("%s/%s", namespace, name)

	// Remove from tracking
	delete(m.policies, policyKey)

	// Note: Actual rule removal requires tracking rule handles
	// This is a simplified implementation
	// In production, you'd need to track rule handles and delete specific rules

	return nil
}

// CreateZone creates a firewall zone
func (m *Manager) CreateZone(ctx context.Context, zone *policy.FilterZone) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	zoneName := zone.Name

	// Create zone-specific chains for IPv4
	ipv4Table, err := m.kernel.GetTable("filter", nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("failed to get IPv4 table: %w", err)
	}

	inputChainName := fmt.Sprintf("input_%s", zoneName)
	forwardChainName := fmt.Sprintf("forward_%s", zoneName)

	_, err = m.kernel.CreateChain(ipv4Table, inputChainName, nftables.ChainTypeFilter, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create IPv4 input chain for zone: %w", err)
	}

	_, err = m.kernel.CreateChain(ipv4Table, forwardChainName, nftables.ChainTypeFilter, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create IPv4 forward chain for zone: %w", err)
	}

	// Create zone-specific chains for IPv6
	ipv6Table, err := m.kernel.GetTable("filter", nftables.TableFamilyIPv6)
	if err != nil {
		return fmt.Errorf("failed to get IPv6 table: %w", err)
	}

	_, err = m.kernel.CreateChain(ipv6Table, inputChainName, nftables.ChainTypeFilter, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create IPv6 input chain for zone: %w", err)
	}

	_, err = m.kernel.CreateChain(ipv6Table, forwardChainName, nftables.ChainTypeFilter, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to create IPv6 forward chain for zone: %w", err)
	}

	// Store zone
	m.zones[zoneName] = zone

	return nil
}

// DeleteZone deletes a firewall zone
func (m *Manager) DeleteZone(ctx context.Context, zoneName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Delete zone-specific chains for IPv4
	ipv4Table, err := m.kernel.GetTable("filter", nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("failed to get IPv4 table: %w", err)
	}

	inputChainName := fmt.Sprintf("input_%s", zoneName)
	forwardChainName := fmt.Sprintf("forward_%s", zoneName)

	if err := m.kernel.DeleteChain(ipv4Table, inputChainName); err != nil {
		// Chain might not exist, continue
	}

	if err := m.kernel.DeleteChain(ipv4Table, forwardChainName); err != nil {
		// Chain might not exist, continue
	}

	// Delete zone-specific chains for IPv6
	ipv6Table, err := m.kernel.GetTable("filter", nftables.TableFamilyIPv6)
	if err != nil {
		return fmt.Errorf("failed to get IPv6 table: %w", err)
	}

	if err := m.kernel.DeleteChain(ipv6Table, inputChainName); err != nil {
		// Chain might not exist, continue
	}

	if err := m.kernel.DeleteChain(ipv6Table, forwardChainName); err != nil {
		// Chain might not exist, continue
	}

	// Remove from tracking
	delete(m.zones, zoneName)

	return nil
}

// CreateIPSet creates an IP set
func (m *Manager) CreateIPSet(ctx context.Context, name string, family nftables.TableFamily, ips []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var table *nftables.Table
	var err error

	if family == nftables.TableFamilyIPv4 {
		table, err = m.kernel.GetTable("filter", nftables.TableFamilyIPv4)
	} else {
		table, err = m.kernel.GetTable("filter", nftables.TableFamilyIPv6)
	}

	if err != nil {
		return fmt.Errorf("failed to get table: %w", err)
	}

	keyType := nftables.TypeIPAddr
	if family == nftables.TableFamilyIPv6 {
		keyType = nftables.TypeIP6Addr
	}

	_, err = m.kernel.CreateIPSet(table, name, keyType, ips)
	if err != nil {
		return fmt.Errorf("failed to create IP set: %w", err)
	}

	return nil
}

// DeleteIPSet deletes an IP set
func (m *Manager) DeleteIPSet(ctx context.Context, name string, family nftables.TableFamily) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var table *nftables.Table
	var err error

	if family == nftables.TableFamilyIPv4 {
		table, err = m.kernel.GetTable("filter", nftables.TableFamilyIPv4)
	} else {
		table, err = m.kernel.GetTable("filter", nftables.TableFamilyIPv6)
	}

	if err != nil {
		return fmt.Errorf("failed to get table: %w", err)
	}

	if err := m.kernel.DeleteIPSet(table, name); err != nil {
		return fmt.Errorf("failed to delete IP set: %w", err)
	}

	return nil
}

// AddIPToSet adds an IP to a set
func (m *Manager) AddIPToSet(ctx context.Context, setName string, family nftables.TableFamily, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var table *nftables.Table
	var err error

	if family == nftables.TableFamilyIPv4 {
		table, err = m.kernel.GetTable("filter", nftables.TableFamilyIPv4)
	} else {
		table, err = m.kernel.GetTable("filter", nftables.TableFamilyIPv6)
	}

	if err != nil {
		return fmt.Errorf("failed to get table: %w", err)
	}

	if err := m.kernel.AddIPToSet(table, setName, ip); err != nil {
		return fmt.Errorf("failed to add IP to set: %w", err)
	}

	return nil
}

// RemoveIPFromSet removes an IP from a set
func (m *Manager) RemoveIPFromSet(ctx context.Context, setName string, family nftables.TableFamily, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var table *nftables.Table
	var err error

	if family == nftables.TableFamilyIPv4 {
		table, err = m.kernel.GetTable("filter", nftables.TableFamilyIPv4)
	} else {
		table, err = m.kernel.GetTable("filter", nftables.TableFamilyIPv6)
	}

	if err != nil {
		return fmt.Errorf("failed to get table: %w", err)
	}

	if err := m.kernel.RemoveIPFromSet(table, setName, ip); err != nil {
		return fmt.Errorf("failed to remove IP from set: %w", err)
	}

	return nil
}

// GetPolicies returns all active policies
func (m *Manager) GetPolicies() map[string]*policy.FilterPolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policies := make(map[string]*policy.FilterPolicy, len(m.policies))
	for k, v := range m.policies {
		policies[k] = v
	}

	return policies
}

// GetZones returns all zones
func (m *Manager) GetZones() map[string]*policy.FilterZone {
	m.mu.RLock()
	defer m.mu.RUnlock()

	zones := make(map[string]*policy.FilterZone, len(m.zones))
	for k, v := range m.zones {
		zones[k] = v
	}

	return zones
}
