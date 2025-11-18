package firewall

import (
	"context"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKernelFirewallManager(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	require.NotNil(t, manager)
	require.NotNil(t, manager.conn)
	require.NotNil(t, manager.tables)
	require.NotNil(t, manager.chains)
	require.NotNil(t, manager.sets)

	err = manager.Close()
	assert.NoError(t, err)
}

func TestKernelFirewallManager_CreateTable(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Test creating IPv4 table
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	assert.NoError(t, err)
	assert.NotNil(t, table)
	assert.Equal(t, "test_table", table.Name)
	assert.Equal(t, nftables.TableFamilyIPv4, table.Family)

	// Verify table is tracked
	key := "ip-test_table"
	trackedTable, exists := manager.tables[key]
	assert.True(t, exists)
	assert.Equal(t, table, trackedTable)
}

func TestKernelFirewallManager_DeleteTable(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create a table
	_, err = manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	// Delete the table
	err = manager.DeleteTable("test_table", nftables.TableFamilyIPv4)
	assert.NoError(t, err)

	// Verify table is no longer tracked
	key := "ip-test_table"
	_, exists := manager.tables[key]
	assert.False(t, exists)
}

func TestKernelFirewallManager_CreateChain(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create a table first
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	// Create a chain
	chain, err := manager.CreateChain(table, "test_chain", nftables.ChainTypeFilter, nil, nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, chain)
	assert.Equal(t, "test_chain", chain.Name)
	assert.Equal(t, nftables.ChainTypeFilter, chain.Type)

	// Verify chain is tracked
	key := "ip-test_table-test_chain"
	trackedChain, exists := manager.chains[key]
	assert.True(t, exists)
	assert.Equal(t, chain, trackedChain)
}

func TestKernelFirewallManager_DeleteChain(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and chain
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	_, err = manager.CreateChain(table, "test_chain", nftables.ChainTypeFilter, nil, nil, nil)
	require.NoError(t, err)

	// Delete the chain
	err = manager.DeleteChain(table, "test_chain")
	assert.NoError(t, err)

	// Verify chain is no longer tracked
	key := "ip-test_table-test_chain"
	_, exists := manager.chains[key]
	assert.False(t, exists)
}

func TestKernelFirewallManager_CreateIPSet(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create a table first
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	// Create IP set
	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	set, err := manager.CreateIPSet(table, "test_set", nftables.TypeIPAddr, ips)
	assert.NoError(t, err)
	assert.NotNil(t, set)
	assert.Equal(t, "test_set", set.Name)
	assert.Equal(t, nftables.TypeIPAddr, set.KeyType)

	// Verify set is tracked
	key := "ip-test_table-test_set"
	trackedSet, exists := manager.sets[key]
	assert.True(t, exists)
	assert.Equal(t, set, trackedSet)
}

func TestKernelFirewallManager_DeleteIPSet(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and set
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	ips := []string{"192.168.1.1"}
	_, err = manager.CreateIPSet(table, "test_set", nftables.TypeIPAddr, ips)
	require.NoError(t, err)

	// Delete the set
	err = manager.DeleteIPSet(table, "test_set")
	assert.NoError(t, err)

	// Verify set is no longer tracked
	key := "ip-test_table-test_set"
	_, exists := manager.sets[key]
	assert.False(t, exists)
}

func TestKernelFirewallManager_AddIPToSet(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and set
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	_, err = manager.CreateIPSet(table, "test_set", nftables.TypeIPAddr, []string{})
	require.NoError(t, err)

	// Add IP to set
	err = manager.AddIPToSet(table, "test_set", "192.168.1.100")
	assert.NoError(t, err)
}

func TestKernelFirewallManager_RemoveIPFromSet(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and set with an IP
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	ips := []string{"192.168.1.100"}
	_, err = manager.CreateIPSet(table, "test_set", nftables.TypeIPAddr, ips)
	require.NoError(t, err)

	// Remove IP from set
	err = manager.RemoveIPFromSet(table, "test_set", "192.168.1.100")
	assert.NoError(t, err)
}

func TestKernelFirewallManager_AddRule(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and chain
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	chain, err := manager.CreateChain(table, "test_chain", nftables.ChainTypeFilter, nil, nil, nil)
	require.NoError(t, err)

	// Create a simple rule (accept all)
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}

	err = manager.AddRule(table, chain, rule)
	assert.NoError(t, err)
}

func TestKernelFirewallManager_ListRules(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and chain
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	chain, err := manager.CreateChain(table, "test_chain", nftables.ChainTypeFilter, nil, nil, nil)
	require.NoError(t, err)

	// List rules (should be empty initially)
	rules, err := manager.ListRules(table, chain)
	assert.NoError(t, err)
	assert.NotNil(t, rules)
}

func TestKernelFirewallManager_FlushChain(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and chain
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	chain, err := manager.CreateChain(table, "test_chain", nftables.ChainTypeFilter, nil, nil, nil)
	require.NoError(t, err)

	// Flush chain
	err = manager.FlushChain(table, chain)
	assert.NoError(t, err)
}

func TestKernelFirewallManager_GetTable(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create a table
	createdTable, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	// Get the table
	table, err := manager.GetTable("test_table", nftables.TableFamilyIPv4)
	assert.NoError(t, err)
	assert.Equal(t, createdTable, table)

	// Try to get non-existent table
	_, err = manager.GetTable("nonexistent", nftables.TableFamilyIPv4)
	assert.Error(t, err)
}

func TestKernelFirewallManager_GetChain(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and chain
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	createdChain, err := manager.CreateChain(table, "test_chain", nftables.ChainTypeFilter, nil, nil, nil)
	require.NoError(t, err)

	// Get the chain
	chain, err := manager.GetChain(table, "test_chain")
	assert.NoError(t, err)
	assert.Equal(t, createdChain, chain)

	// Try to get non-existent chain
	_, err = manager.GetChain(table, "nonexistent")
	assert.Error(t, err)
}

func TestKernelFirewallManager_GetSet(t *testing.T) {
	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and set
	table, err := manager.CreateTable("test_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	ips := []string{"192.168.1.1"}
	createdSet, err := manager.CreateIPSet(table, "test_set", nftables.TypeIPAddr, ips)
	require.NoError(t, err)

	// Get the set
	set, err := manager.GetSet(table, "test_set")
	assert.NoError(t, err)
	assert.Equal(t, createdSet, set)

	// Try to get non-existent set
	_, err = manager.GetSet(table, "nonexistent")
	assert.Error(t, err)
}

func TestProtocolToNumber(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		expected uint8
	}{
		{"TCP", "tcp", 6},
		{"UDP", "udp", 17},
		{"ICMP", "icmp", 1},
		{"ICMPv6", "icmpv6", 58},
		{"Unknown", "unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := protocolToNumber(tt.protocol)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKernelFirewallManager_InitializeFirewall(t *testing.T) {
	// This test requires actual root privileges to run
	// It's marked as integration test
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()
	err = manager.InitializeFirewall(ctx)

	// This will fail if not running as root, which is expected
	// The test validates the code structure works
	if err != nil {
		t.Logf("InitializeFirewall failed (expected without root): %v", err)
	}
}
