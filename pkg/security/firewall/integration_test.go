//go:build integration
// +build integration

package firewall

import (
	"context"
	"os"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

// TestIntegration_InitializeFirewall tests the full firewall initialization
// This test requires root privileges
func TestIntegration_InitializeFirewall(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()
	err = manager.InitializeFirewall(ctx)
	require.NoError(t, err)

	// Verify tables were created
	ipv4Table, err := manager.GetTable("filter", nftables.TableFamilyIPv4)
	assert.NoError(t, err)
	assert.NotNil(t, ipv4Table)

	ipv6Table, err := manager.GetTable("filter", nftables.TableFamilyIPv6)
	assert.NoError(t, err)
	assert.NotNil(t, ipv6Table)

	// Verify chains were created
	ipv4InputChain, err := manager.GetChain(ipv4Table, "input")
	assert.NoError(t, err)
	assert.NotNil(t, ipv4InputChain)

	ipv4ForwardChain, err := manager.GetChain(ipv4Table, "forward")
	assert.NoError(t, err)
	assert.NotNil(t, ipv4ForwardChain)

	ipv4OutputChain, err := manager.GetChain(ipv4Table, "output")
	assert.NoError(t, err)
	assert.NotNil(t, ipv4OutputChain)
}

// TestIntegration_CreateAndDeleteTable tests table lifecycle
func TestIntegration_CreateAndDeleteTable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table
	table, err := manager.CreateTable("test_integration", nftables.TableFamilyIPv4)
	require.NoError(t, err)
	assert.NotNil(t, table)

	// Verify table exists
	retrievedTable, err := manager.GetTable("test_integration", nftables.TableFamilyIPv4)
	assert.NoError(t, err)
	assert.Equal(t, table.Name, retrievedTable.Name)

	// Delete table
	err = manager.DeleteTable("test_integration", nftables.TableFamilyIPv4)
	assert.NoError(t, err)
}

// TestIntegration_CreateAndDeleteChain tests chain lifecycle
func TestIntegration_CreateAndDeleteChain(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table
	table, err := manager.CreateTable("test_chain_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	// Create chain
	chain, err := manager.CreateChain(table, "test_chain", nftables.ChainTypeFilter, nil, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, chain)

	// Verify chain exists
	retrievedChain, err := manager.GetChain(table, "test_chain")
	assert.NoError(t, err)
	assert.Equal(t, chain.Name, retrievedChain.Name)

	// Delete chain
	err = manager.DeleteChain(table, "test_chain")
	assert.NoError(t, err)

	// Clean up
	err = manager.DeleteTable("test_chain_table", nftables.TableFamilyIPv4)
	assert.NoError(t, err)
}

// TestIntegration_CreateIPSetAndAddRemoveIPs tests IP set operations
func TestIntegration_CreateIPSetAndAddRemoveIPs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table
	table, err := manager.CreateTable("test_ipset_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	// Create IP set with initial IPs
	ips := []string{"192.168.1.1", "192.168.1.2"}
	set, err := manager.CreateIPSet(table, "test_set", nftables.TypeIPAddr, ips)
	require.NoError(t, err)
	assert.NotNil(t, set)

	// Add IP to set
	err = manager.AddIPToSet(table, "test_set", "192.168.1.100")
	assert.NoError(t, err)

	// Remove IP from set
	err = manager.RemoveIPFromSet(table, "test_set", "192.168.1.1")
	assert.NoError(t, err)

	// Delete set
	err = manager.DeleteIPSet(table, "test_set")
	assert.NoError(t, err)

	// Clean up
	err = manager.DeleteTable("test_ipset_table", nftables.TableFamilyIPv4)
	assert.NoError(t, err)
}

// TestIntegration_AddAndListRules tests rule management
func TestIntegration_AddAndListRules(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and chain
	table, err := manager.CreateTable("test_rule_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	chain, err := manager.CreateChain(table, "test_rule_chain", nftables.ChainTypeFilter, nil, nil, nil)
	require.NoError(t, err)

	// Create and add a simple rule (accept all)
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}

	err = manager.AddRule(table, chain, rule)
	require.NoError(t, err)

	// List rules
	rules, err := manager.ListRules(table, chain)
	assert.NoError(t, err)
	assert.NotEmpty(t, rules)

	// Clean up
	err = manager.DeleteChain(table, "test_rule_chain")
	assert.NoError(t, err)

	err = manager.DeleteTable("test_rule_table", nftables.TableFamilyIPv4)
	assert.NoError(t, err)
}

// TestIntegration_FlushChain tests chain flushing
func TestIntegration_FlushChain(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	manager, err := NewKernelFirewallManager()
	require.NoError(t, err)
	defer manager.Close()

	// Create table and chain
	table, err := manager.CreateTable("test_flush_table", nftables.TableFamilyIPv4)
	require.NoError(t, err)

	chain, err := manager.CreateChain(table, "test_flush_chain", nftables.ChainTypeFilter, nil, nil, nil)
	require.NoError(t, err)

	// Add a rule
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
	err = manager.AddRule(table, chain, rule)
	require.NoError(t, err)

	// Flush chain
	err = manager.FlushChain(table, chain)
	assert.NoError(t, err)

	// Verify chain is empty
	rules, err := manager.ListRules(table, chain)
	assert.NoError(t, err)
	assert.Empty(t, rules)

	// Clean up
	err = manager.DeleteChain(table, "test_flush_chain")
	assert.NoError(t, err)

	err = manager.DeleteTable("test_flush_table", nftables.TableFamilyIPv4)
	assert.NoError(t, err)
}

// TestIntegration_ManagerApplyPolicy tests applying a FilterPolicy
func TestIntegration_ManagerApplyPolicy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	manager, err := NewManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Initialize firewall
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	// Create a test policy
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-allow-http",
			Namespace: "default",
		},
		Spec: policy.FilterPolicySpec{
			Scope:   "forward",
			Enabled: true,
			Selectors: policy.FilterSelectors{
				Ports: []policy.PortSelector{
					{
						Protocol: "tcp",
						Ports:    []int32{80, 443},
					},
				},
			},
			Actions: []policy.PolicyAction{
				{
					Type: "accept",
				},
			},
		},
	}

	// Apply the policy
	err = manager.ApplyPolicy(ctx, testPolicy)
	assert.NoError(t, err)

	// Verify policy is tracked
	policies := manager.GetPolicies()
	assert.Contains(t, policies, "default/test-allow-http")
}

// TestIntegration_ManagerCreateZone tests zone creation
func TestIntegration_ManagerCreateZone(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	manager, err := NewManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Initialize firewall
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	// Create a test zone
	testZone := &policy.FilterZone{
		ObjectMeta: metav1.ObjectMeta{
			Name: "trusted",
		},
		Spec: policy.FilterZoneSpec{
			TrustLevel:           "trusted",
			DefaultIngressAction: "accept",
			DefaultEgressAction:  "accept",
		},
	}
	testZone.Name = "trusted"

	// Create the zone
	err = manager.CreateZone(ctx, testZone)
	assert.NoError(t, err)

	// Verify zone is tracked
	zones := manager.GetZones()
	assert.Contains(t, zones, "trusted")

	// Clean up
	err = manager.DeleteZone(ctx, "trusted")
	assert.NoError(t, err)
}

// TestIntegration_ManagerIPSet tests IP set management through Manager
func TestIntegration_ManagerIPSet(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	manager, err := NewManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Initialize firewall
	err = manager.Initialize(ctx)
	require.NoError(t, err)

	// Create IP set
	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	err = manager.CreateIPSet(ctx, "blacklist", nftables.TableFamilyIPv4, ips)
	assert.NoError(t, err)

	// Add IP to set
	err = manager.AddIPToSet(ctx, "blacklist", nftables.TableFamilyIPv4, "192.168.1.100")
	assert.NoError(t, err)

	// Remove IP from set
	err = manager.RemoveIPFromSet(ctx, "blacklist", nftables.TableFamilyIPv4, "192.168.1.1")
	assert.NoError(t, err)

	// Delete set
	err = manager.DeleteIPSet(ctx, "blacklist", nftables.TableFamilyIPv4)
	assert.NoError(t, err)
}
