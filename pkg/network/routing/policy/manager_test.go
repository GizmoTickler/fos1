package policy

import (
	"testing"

	"github.com/GizmoTickler/fos1/pkg/network/routing"
)

// mockRouteManager is a mock implementation of routing.RouteManager
type mockRouteManager struct {
	routes map[string]routing.Route
}

func newMockRouteManager() *mockRouteManager {
	return &mockRouteManager{
		routes: make(map[string]routing.Route),
	}
}

func (m *mockRouteManager) AddRoute(route routing.Route) error {
	key := route.Destination + "-" + route.Table
	m.routes[key] = route
	return nil
}

func (m *mockRouteManager) DeleteRoute(destination string, params routing.RouteParams) error {
	key := destination + "-" + params.Table
	delete(m.routes, key)
	return nil
}

func (m *mockRouteManager) GetRoute(destination string, params routing.RouteParams) (*routing.Route, error) {
	key := destination + "-" + params.Table
	if route, exists := m.routes[key]; exists {
		return &route, nil
	}
	return nil, nil
}

func (m *mockRouteManager) ListRoutes(filter routing.RouteFilter) ([]*routing.Route, error) {
	routes := make([]*routing.Route, 0, len(m.routes))
	for _, route := range m.routes {
		r := route
		routes = append(routes, &r)
	}
	return routes, nil
}

func (m *mockRouteManager) UpdateRoute(destination string, params routing.RouteParams, newRoute routing.Route) error {
	key := destination + "-" + params.Table
	m.routes[key] = newRoute
	return nil
}

func (m *mockRouteManager) GetRoutingTable(tableName string, vrf string) ([]*routing.Route, error) {
	routes := make([]*routing.Route, 0)
	for _, route := range m.routes {
		if route.Table == tableName && route.VRF == vrf {
			r := route
			routes = append(routes, &r)
		}
	}
	return routes, nil
}

// TestNewManager tests manager creation
func TestNewManager(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr)

	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
}

// TestApplyPolicySourceNetwork tests applying a policy with source network match
func TestApplyPolicySourceNetwork(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Networks: []string{"10.0.0.0/24"},
			},
		},
		Action: PolicyAction{
			Type:  "table",
			Table: "100",
		},
	}

	err := mgr.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("ApplyPolicy failed: %v", err)
	}

	// Verify policy was stored
	key := "default/test-policy"
	if _, exists := mgr.policies[key]; !exists {
		t.Error("Policy was not stored")
	}

	// Verify status was created
	if _, exists := mgr.statuses[key]; !exists {
		t.Error("Policy status was not created")
	}
}

// TestApplyPolicyDestinationNetwork tests applying a policy with destination network match
func TestApplyPolicyDestinationNetwork(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Destination: DestinationMatch{
				Networks: []string{"192.168.1.0/24"},
			},
		},
		Action: PolicyAction{
			Type:  "table",
			Table: "101",
		},
	}

	err := mgr.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("ApplyPolicy failed: %v", err)
	}

	// Verify policy was stored
	key := "default/test-policy"
	if _, exists := mgr.policies[key]; !exists {
		t.Error("Policy was not stored")
	}
}

// TestApplyPolicyInterface tests applying a policy with interface match
func TestApplyPolicyInterface(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Interfaces: []string{"eth0"},
			},
		},
		Action: PolicyAction{
			Type:  "table",
			Table: "102",
		},
	}

	err := mgr.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("ApplyPolicy failed: %v", err)
	}

	// Verify policy was stored
	key := "default/test-policy"
	if _, exists := mgr.policies[key]; !exists {
		t.Error("Policy was not stored")
	}
}

// TestApplyPolicyMark tests applying a policy with fwmark
func TestApplyPolicyMark(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Networks: []string{"10.0.0.0/24"},
			},
		},
		Action: PolicyAction{
			Type: "nat",
			Mark: 0x100,
		},
	}

	err := mgr.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("ApplyPolicy failed: %v", err)
	}

	// Verify policy was stored
	key := "default/test-policy"
	if _, exists := mgr.policies[key]; !exists {
		t.Error("Policy was not stored")
	}
}

// TestApplyPolicyRoute tests applying a policy with route action
func TestApplyPolicyRoute(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Networks: []string{"10.0.0.0/24"},
			},
		},
		Action: PolicyAction{
			Type:    "route",
			NextHop: "192.168.1.1",
		},
	}

	err := mgr.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("ApplyPolicy failed: %v", err)
	}

	// Verify policy was stored
	key := "default/test-policy"
	if _, exists := mgr.policies[key]; !exists {
		t.Error("Policy was not stored")
	}

	// Verify route was added (should have at least one route for IPv4)
	if len(routeMgr.routes) == 0 {
		t.Error("No routes were added")
	}
}

// TestRemovePolicy tests removing a policy
func TestRemovePolicy(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Networks: []string{"10.0.0.0/24"},
			},
		},
		Action: PolicyAction{
			Type:  "table",
			Table: "100",
		},
	}

	// Apply policy
	err := mgr.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("ApplyPolicy failed: %v", err)
	}

	// Remove policy
	err = mgr.RemovePolicy("test-policy", "default")
	if err != nil {
		t.Fatalf("RemovePolicy failed: %v", err)
	}

	// Verify policy was removed
	key := "default/test-policy"
	if _, exists := mgr.policies[key]; exists {
		t.Error("Policy was not removed")
	}

	// Verify status was removed
	if _, exists := mgr.statuses[key]; exists {
		t.Error("Policy status was not removed")
	}
}

// TestGetPolicyStatus tests getting policy status
func TestGetPolicyStatus(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Networks: []string{"10.0.0.0/24"},
			},
		},
		Action: PolicyAction{
			Type:  "table",
			Table: "100",
		},
	}

	// Apply policy
	err := mgr.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("ApplyPolicy failed: %v", err)
	}

	// Get status
	status, err := mgr.GetPolicyStatus("test-policy", "default")
	if err != nil {
		t.Fatalf("GetPolicyStatus failed: %v", err)
	}

	if !status.Active {
		t.Error("Policy status should be active")
	}

	if status.MatchCount != 0 {
		t.Errorf("Expected match count 0, got %d", status.MatchCount)
	}
}

// TestListPolicies tests listing all policies
func TestListPolicies(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	// Apply multiple policies
	policies := []RoutingPolicy{
		{
			Name:      "policy1",
			Namespace: "default",
			Priority:  100,
			Match: PolicyMatch{
				Source: SourceMatch{
					Networks: []string{"10.0.0.0/24"},
				},
			},
			Action: PolicyAction{
				Type:  "table",
				Table: "100",
			},
		},
		{
			Name:      "policy2",
			Namespace: "default",
			Priority:  200,
			Match: PolicyMatch{
				Source: SourceMatch{
					Networks: []string{"10.1.0.0/24"},
				},
			},
			Action: PolicyAction{
				Type:  "table",
				Table: "101",
			},
		},
	}

	for _, policy := range policies {
		err := mgr.ApplyPolicy(policy)
		if err != nil {
			t.Fatalf("ApplyPolicy failed: %v", err)
		}
	}

	// List policies
	listedPolicies, err := mgr.ListPolicies()
	if err != nil {
		t.Fatalf("ListPolicies failed: %v", err)
	}

	if len(listedPolicies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(listedPolicies))
	}

	// Verify policies are sorted by priority
	if len(listedPolicies) >= 2 {
		if listedPolicies[0].Priority > listedPolicies[1].Priority {
			t.Error("Policies are not sorted by priority")
		}
	}
}

// TestEvaluatePacket tests packet evaluation against policies
func TestEvaluatePacket(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Networks: []string{"10.0.0.0/24"},
			},
			Destination: DestinationMatch{
				Networks: []string{"192.168.1.0/24"},
			},
			Protocol: "tcp",
		},
		Action: PolicyAction{
			Type:  "table",
			Table: "100",
		},
	}

	// Apply policy
	err := mgr.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("ApplyPolicy failed: %v", err)
	}

	// Test matching packet
	packet := PacketInfo{
		SourceIP:      "10.0.0.5",
		DestinationIP: "192.168.1.10",
		Protocol:      "tcp",
		SourcePort:    12345,
		DestinationPort: 80,
	}

	action, err := mgr.EvaluatePacket(packet)
	if err != nil {
		t.Fatalf("EvaluatePacket failed: %v", err)
	}

	if action == nil {
		t.Fatal("Expected action, got nil")
	}

	if action.Type != "table" {
		t.Errorf("Expected action type 'table', got '%s'", action.Type)
	}

	if action.Table != "100" {
		t.Errorf("Expected table '100', got '%s'", action.Table)
	}

	// Verify match count was incremented
	status, err := mgr.GetPolicyStatus("test-policy", "default")
	if err != nil {
		t.Fatalf("GetPolicyStatus failed: %v", err)
	}

	if status.MatchCount != 1 {
		t.Errorf("Expected match count 1, got %d", status.MatchCount)
	}
}

// TestEvaluatePacketNoMatch tests packet evaluation with no matching policy
func TestEvaluatePacketNoMatch(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Networks: []string{"10.0.0.0/24"},
			},
		},
		Action: PolicyAction{
			Type:  "table",
			Table: "100",
		},
	}

	// Apply policy
	err := mgr.ApplyPolicy(policy)
	if err != nil {
		t.Fatalf("ApplyPolicy failed: %v", err)
	}

	// Test non-matching packet
	packet := PacketInfo{
		SourceIP:      "10.1.0.5",
		DestinationIP: "192.168.1.10",
		Protocol:      "tcp",
	}

	action, err := mgr.EvaluatePacket(packet)
	if err != nil {
		t.Fatalf("EvaluatePacket failed: %v", err)
	}

	if action != nil {
		t.Error("Expected no action for non-matching packet")
	}
}

// TestTableAllocator tests the table allocator
func TestTableAllocator(t *testing.T) {
	ta := newTableAllocator()

	// Allocate a table
	tableID1, err := ta.allocate("policy1")
	if err != nil {
		t.Fatalf("allocate failed: %v", err)
	}

	if tableID1 != TableCustomStart {
		t.Errorf("Expected table ID %d, got %d", TableCustomStart, tableID1)
	}

	// Allocate another table
	tableID2, err := ta.allocate("policy2")
	if err != nil {
		t.Fatalf("allocate failed: %v", err)
	}

	if tableID2 != TableCustomStart+1 {
		t.Errorf("Expected table ID %d, got %d", TableCustomStart+1, tableID2)
	}

	// Allocate same policy again (should return same table)
	tableID1Again, err := ta.allocate("policy1")
	if err != nil {
		t.Fatalf("allocate failed: %v", err)
	}

	if tableID1Again != tableID1 {
		t.Errorf("Expected table ID %d, got %d", tableID1, tableID1Again)
	}

	// Get table for policy
	tableID, exists := ta.get("policy1")
	if !exists {
		t.Error("Expected table to exist for policy1")
	}

	if tableID != tableID1 {
		t.Errorf("Expected table ID %d, got %d", tableID1, tableID)
	}

	// Release table
	ta.release(tableID1)

	// Verify table was released
	_, exists = ta.get("policy1")
	if exists {
		t.Error("Expected table to not exist after release")
	}
}

// TestPolicyToIPRule tests converting a policy to an IP rule
func TestPolicyToIPRule(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Networks:   []string{"10.0.0.0/24"},
				Interfaces: []string{"eth0"},
			},
			Destination: DestinationMatch{
				Networks: []string{"192.168.1.0/24"},
			},
		},
		Action: PolicyAction{
			Type:  "table",
			Table: "100",
			Mark:  0x100,
			DSCP:  10,
		},
	}

	rule := mgr.policyToIPRule(policy, 100)

	if rule.Priority != 100 {
		t.Errorf("Expected priority 100, got %d", rule.Priority)
	}

	if rule.Table != 100 {
		t.Errorf("Expected table 100, got %d", rule.Table)
	}

	if rule.Src != "10.0.0.0/24" {
		t.Errorf("Expected src 10.0.0.0/24, got %s", rule.Src)
	}

	if rule.Dst != "192.168.1.0/24" {
		t.Errorf("Expected dst 192.168.1.0/24, got %s", rule.Dst)
	}

	if rule.IifName != "eth0" {
		t.Errorf("Expected iif eth0, got %s", rule.IifName)
	}

	if rule.Mark != 0x100 {
		t.Errorf("Expected mark 0x100, got 0x%x", rule.Mark)
	}

	expectedTos := 10 << 2 // DSCP is upper 6 bits of TOS
	if rule.Tos != expectedTos {
		t.Errorf("Expected TOS %d, got %d", expectedTos, rule.Tos)
	}
}

// TestPolicyToIPRuleIPv6 tests converting an IPv6 policy to an IP rule
func TestPolicyToIPRuleIPv6(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Networks: []string{"2001:db8::/32"},
			},
			Destination: DestinationMatch{
				Networks: []string{"2001:db8:1::/48"},
			},
		},
		Action: PolicyAction{
			Type:  "table",
			Table: "100",
		},
	}

	rule := mgr.policyToIPRule(policy, 100)

	if rule.Family != FamilyIPv6 {
		t.Errorf("Expected family %s, got %s", FamilyIPv6, rule.Family)
	}

	if rule.Src != "2001:db8::/32" {
		t.Errorf("Expected src 2001:db8::/32, got %s", rule.Src)
	}

	if rule.Dst != "2001:db8:1::/48" {
		t.Errorf("Expected dst 2001:db8:1::/48, got %s", rule.Dst)
	}
}

// TestIsIPv6Network tests IPv6 network detection
func TestIsIPv6Network(t *testing.T) {
	tests := []struct {
		network string
		isIPv6  bool
	}{
		{"10.0.0.0/24", false},
		{"192.168.1.0/24", false},
		{"2001:db8::/32", true},
		{"::1/128", true},
		{"::/0", true},
		{"fe80::/10", true},
		{"", false},
	}

	for _, test := range tests {
		result := isIPv6Network(test.network)
		if result != test.isIPv6 {
			t.Errorf("isIPv6Network(%s) = %v, expected %v", test.network, result, test.isIPv6)
		}
	}
}

// TestUnsupportedActionType tests handling of unsupported action types
func TestUnsupportedActionType(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	policy := RoutingPolicy{
		Name:      "test-policy",
		Namespace: "default",
		Priority:  100,
		Match: PolicyMatch{
			Source: SourceMatch{
				Networks: []string{"10.0.0.0/24"},
			},
		},
		Action: PolicyAction{
			Type: "unsupported",
		},
	}

	err := mgr.ApplyPolicy(policy)
	if err == nil {
		t.Fatal("Expected error for unsupported action type")
	}
}

// TestRemoveNonexistentPolicy tests removing a policy that doesn't exist
func TestRemoveNonexistentPolicy(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	err := mgr.RemovePolicy("nonexistent", "default")
	if err == nil {
		t.Fatal("Expected error when removing nonexistent policy")
	}
}

// TestGetPolicyStatusNonexistent tests getting status of nonexistent policy
func TestGetPolicyStatusNonexistent(t *testing.T) {
	routeMgr := newMockRouteManager()
	mgr := NewManager(routeMgr).(*manager)

	_, err := mgr.GetPolicyStatus("nonexistent", "default")
	if err == nil {
		t.Fatal("Expected error when getting status of nonexistent policy")
	}
}
