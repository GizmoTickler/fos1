// +build integration

package policy

import (
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestKernelRuleManager_AddDeleteRule tests adding and deleting IP rules
func TestKernelRuleManager_AddDeleteRule(t *testing.T) {
	// Check for root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}

	krm := NewKernelRuleManager()

	rule := IPRule{
		Priority: 1000,
		Table:    100,
		Src:      "10.0.0.0/24",
		Family:   FamilyIPv4,
		Action:   ActionToTable,
	}

	// Add rule
	err := krm.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// List rules to verify
	rules, err := krm.ListRules(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	found := false
	for _, r := range rules {
		if r.Priority == 1000 && r.Table == 100 && r.Src == "10.0.0.0/24" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Rule was not found in kernel")
	}

	// Delete rule
	err = krm.DeleteRule(rule)
	if err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}

	// Verify rule was deleted
	rules, err = krm.ListRules(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	found = false
	for _, r := range rules {
		if r.Priority == 1000 && r.Table == 100 && r.Src == "10.0.0.0/24" {
			found = true
			break
		}
	}

	if found {
		t.Error("Rule was not deleted from kernel")
	}
}

// TestKernelRuleManager_AddDeleteRuleIPv6 tests adding and deleting IPv6 IP rules
func TestKernelRuleManager_AddDeleteRuleIPv6(t *testing.T) {
	// Check for root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}

	krm := NewKernelRuleManager()

	rule := IPRule{
		Priority: 1001,
		Table:    101,
		Src:      "2001:db8::/32",
		Family:   FamilyIPv6,
		Action:   ActionToTable,
	}

	// Add rule
	err := krm.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// List rules to verify
	rules, err := krm.ListRules(netlink.FAMILY_V6)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	found := false
	for _, r := range rules {
		if r.Priority == 1001 && r.Table == 101 && r.Src == "2001:db8::/32" {
			found = true
			break
		}
	}

	if !found {
		t.Error("IPv6 rule was not found in kernel")
	}

	// Delete rule
	err = krm.DeleteRule(rule)
	if err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}

	// Verify rule was deleted
	rules, err = krm.ListRules(netlink.FAMILY_V6)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	found = false
	for _, r := range rules {
		if r.Priority == 1001 && r.Table == 101 && r.Src == "2001:db8::/32" {
			found = true
			break
		}
	}

	if found {
		t.Error("IPv6 rule was not deleted from kernel")
	}
}

// TestKernelRuleManager_RuleWithDestination tests rules with destination
func TestKernelRuleManager_RuleWithDestination(t *testing.T) {
	// Check for root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}

	krm := NewKernelRuleManager()

	rule := IPRule{
		Priority: 1002,
		Table:    102,
		Dst:      "192.168.1.0/24",
		Family:   FamilyIPv4,
		Action:   ActionToTable,
	}

	// Add rule
	err := krm.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Cleanup
	defer krm.DeleteRule(rule)

	// List rules to verify
	rules, err := krm.ListRules(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	found := false
	for _, r := range rules {
		if r.Priority == 1002 && r.Table == 102 && r.Dst == "192.168.1.0/24" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Rule with destination was not found in kernel")
	}
}

// TestKernelRuleManager_RuleWithInterface tests rules with interface
func TestKernelRuleManager_RuleWithInterface(t *testing.T) {
	// Check for root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}

	// Create a dummy interface for testing
	la := netlink.NewLinkAttrs()
	la.Name = "test-pbr0"
	dummy := &netlink.Dummy{LinkAttrs: la}

	err := netlink.LinkAdd(dummy)
	if err != nil {
		t.Fatalf("Failed to create dummy interface: %v", err)
	}
	defer netlink.LinkDel(dummy)

	krm := NewKernelRuleManager()

	rule := IPRule{
		Priority: 1003,
		Table:    103,
		IifName:  "test-pbr0",
		Family:   FamilyIPv4,
		Action:   ActionToTable,
	}

	// Add rule
	err = krm.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Cleanup
	defer krm.DeleteRule(rule)

	// List rules to verify
	rules, err := krm.ListRules(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	found := false
	for _, r := range rules {
		if r.Priority == 1003 && r.Table == 103 && r.IifName == "test-pbr0" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Rule with interface was not found in kernel")
	}
}

// TestKernelRuleManager_RuleWithMark tests rules with fwmark
func TestKernelRuleManager_RuleWithMark(t *testing.T) {
	// Check for root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}

	krm := NewKernelRuleManager()

	rule := IPRule{
		Priority: 1004,
		Table:    104,
		Mark:     0x100,
		Mask:     0xFFFFFFFF,
		Family:   FamilyIPv4,
		Action:   ActionToTable,
	}

	// Add rule
	err := krm.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Cleanup
	defer krm.DeleteRule(rule)

	// List rules to verify
	rules, err := krm.ListRules(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	found := false
	for _, r := range rules {
		if r.Priority == 1004 && r.Table == 104 && r.Mark == 0x100 {
			found = true
			break
		}
	}

	if !found {
		t.Error("Rule with fwmark was not found in kernel")
	}
}

// TestKernelRuleManager_AddRouteToTable tests adding routes to custom tables
func TestKernelRuleManager_AddRouteToTable(t *testing.T) {
	// Check for root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}

	// Create a dummy interface for testing
	la := netlink.NewLinkAttrs()
	la.Name = "test-pbr1"
	dummy := &netlink.Dummy{LinkAttrs: la}

	err := netlink.LinkAdd(dummy)
	if err != nil {
		t.Fatalf("Failed to create dummy interface: %v", err)
	}
	defer netlink.LinkDel(dummy)

	// Bring the interface up
	err = netlink.LinkSetUp(dummy)
	if err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}

	krm := NewKernelRuleManager()

	// Parse destination
	_, dst, err := net.ParseCIDR("10.10.0.0/24")
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}

	// Parse gateway
	gw := net.ParseIP("192.168.1.1")

	// Add route to table
	err = krm.AddRouteToTable(105, dst, gw, "test-pbr1", 100)
	if err != nil {
		t.Fatalf("AddRouteToTable failed: %v", err)
	}

	// Cleanup
	defer krm.DeleteRouteFromTable(105, dst)

	// List routes in table to verify
	routes, err := krm.GetRoutesInTable(105, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("GetRoutesInTable failed: %v", err)
	}

	found := false
	for _, route := range routes {
		if route.Table == 105 && route.Dst != nil && route.Dst.String() == "10.10.0.0/24" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Route was not found in custom table")
	}
}

// TestKernelRuleManager_DeleteRoutingTable tests deleting all routes from a table
func TestKernelRuleManager_DeleteRoutingTable(t *testing.T) {
	// Check for root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}

	// Create a dummy interface for testing
	la := netlink.NewLinkAttrs()
	la.Name = "test-pbr2"
	dummy := &netlink.Dummy{LinkAttrs: la}

	err := netlink.LinkAdd(dummy)
	if err != nil {
		t.Fatalf("Failed to create dummy interface: %v", err)
	}
	defer netlink.LinkDel(dummy)

	// Bring the interface up
	err = netlink.LinkSetUp(dummy)
	if err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}

	krm := NewKernelRuleManager()

	// Parse destination
	_, dst, err := net.ParseCIDR("10.11.0.0/24")
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}

	// Parse gateway
	gw := net.ParseIP("192.168.1.1")

	// Add route to table
	err = krm.AddRouteToTable(106, dst, gw, "test-pbr2", 100)
	if err != nil {
		t.Fatalf("AddRouteToTable failed: %v", err)
	}

	// Delete all routes from table
	err = krm.DeleteRoutingTable(106)
	if err != nil {
		t.Fatalf("DeleteRoutingTable failed: %v", err)
	}

	// Verify table is empty
	routes, err := krm.GetRoutesInTable(106, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("GetRoutesInTable failed: %v", err)
	}

	if len(routes) != 0 {
		t.Errorf("Expected 0 routes in table, got %d", len(routes))
	}
}

// TestKernelRuleManager_RuleWithTOS tests rules with TOS/DSCP
func TestKernelRuleManager_RuleWithTOS(t *testing.T) {
	// Check for root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}

	krm := NewKernelRuleManager()

	rule := IPRule{
		Priority: 1005,
		Table:    107,
		Tos:      0x10, // DSCP 4
		Family:   FamilyIPv4,
		Action:   ActionToTable,
	}

	// Add rule
	err := krm.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Cleanup
	defer krm.DeleteRule(rule)

	// List rules to verify
	rules, err := krm.ListRules(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	found := false
	for _, r := range rules {
		if r.Priority == 1005 && r.Table == 107 && r.Tos == 0x10 {
			found = true
			break
		}
	}

	if !found {
		t.Error("Rule with TOS was not found in kernel")
	}
}

// TestKernelRuleManager_ListRules tests listing all IP rules
func TestKernelRuleManager_ListRules(t *testing.T) {
	// Check for root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}

	krm := NewKernelRuleManager()

	// List IPv4 rules
	rules, err := krm.ListRules(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	// Should have at least the default rules (local, main, default)
	if len(rules) < 3 {
		t.Errorf("Expected at least 3 default rules, got %d", len(rules))
	}

	// Verify default rules exist
	hasLocal := false
	hasMain := false
	hasDefault := false

	for _, r := range rules {
		if r.Table == TableLocal {
			hasLocal = true
		}
		if r.Table == TableMain {
			hasMain = true
		}
		if r.Table == TableDefault {
			hasDefault = true
		}
	}

	if !hasLocal {
		t.Error("Default local table rule not found")
	}
	if !hasMain {
		t.Error("Default main table rule not found")
	}
	if !hasDefault {
		t.Error("Default default table rule not found")
	}
}

// TestKernelRuleManager_ComplexRule tests a rule with multiple criteria
func TestKernelRuleManager_ComplexRule(t *testing.T) {
	// Check for root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}

	// Create a dummy interface for testing
	la := netlink.NewLinkAttrs()
	la.Name = "test-pbr3"
	dummy := &netlink.Dummy{LinkAttrs: la}

	err := netlink.LinkAdd(dummy)
	if err != nil {
		t.Fatalf("Failed to create dummy interface: %v", err)
	}
	defer netlink.LinkDel(dummy)

	krm := NewKernelRuleManager()

	rule := IPRule{
		Priority: 1006,
		Table:    108,
		Src:      "10.0.0.0/24",
		Dst:      "192.168.1.0/24",
		IifName:  "test-pbr3",
		Mark:     0x200,
		Mask:     0xFFFFFFFF,
		Family:   FamilyIPv4,
		Action:   ActionToTable,
	}

	// Add rule
	err = krm.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Cleanup
	defer krm.DeleteRule(rule)

	// List rules to verify
	rules, err := krm.ListRules(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	found := false
	for _, r := range rules {
		if r.Priority == 1006 && r.Table == 108 &&
			r.Src == "10.0.0.0/24" && r.Dst == "192.168.1.0/24" &&
			r.IifName == "test-pbr3" && r.Mark == 0x200 {
			found = true
			break
		}
	}

	if !found {
		t.Error("Complex rule was not found in kernel")
	}
}
