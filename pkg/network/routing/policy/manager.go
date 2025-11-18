package policy

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/network/routing"
)

// manager implements the Manager interface
type manager struct {
	mutex         sync.RWMutex
	policies      map[string]RoutingPolicy // key: namespace/name
	statuses      map[string]*PolicyStatus
	routeManager  routing.RouteManager
	policyEngine  *engine
	kernelRuleMgr *KernelRuleManager
	tableAllocator *tableAllocator
}

// tableAllocator manages routing table ID allocation
type tableAllocator struct {
	mutex     sync.Mutex
	allocated map[int]string // table ID -> policy key
	nextTable int
}

// newTableAllocator creates a new table allocator
func newTableAllocator() *tableAllocator {
	return &tableAllocator{
		allocated: make(map[int]string),
		nextTable: TableCustomStart,
	}
}

// allocate allocates a new routing table ID for a policy
func (ta *tableAllocator) allocate(policyKey string) (int, error) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	// Check if table is already allocated for this policy
	for tableID, key := range ta.allocated {
		if key == policyKey {
			return tableID, nil
		}
	}

	// Find next available table
	for ta.nextTable <= TableCustomEnd {
		if _, exists := ta.allocated[ta.nextTable]; !exists {
			tableID := ta.nextTable
			ta.allocated[tableID] = policyKey
			ta.nextTable++
			return tableID, nil
		}
		ta.nextTable++
	}

	return 0, fmt.Errorf("no available routing table IDs")
}

// release releases a routing table ID
func (ta *tableAllocator) release(tableID int) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()
	delete(ta.allocated, tableID)
}

// get returns the table ID for a policy
func (ta *tableAllocator) get(policyKey string) (int, bool) {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()
	for tableID, key := range ta.allocated {
		if key == policyKey {
			return tableID, true
		}
	}
	return 0, false
}

// NewManager creates a new policy manager
func NewManager(routeManager routing.RouteManager) Manager {
	return &manager{
		policies:       make(map[string]RoutingPolicy),
		statuses:       make(map[string]*PolicyStatus),
		routeManager:   routeManager,
		policyEngine:   newEngine(),
		kernelRuleMgr:  NewKernelRuleManager(),
		tableAllocator: newTableAllocator(),
	}
}

// ApplyPolicy applies a routing policy
func (m *manager) ApplyPolicy(policy RoutingPolicy) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	klog.Infof("Applying routing policy %s", key)

	// Store the policy
	m.policies[key] = policy

	// Initialize or update status
	status, exists := m.statuses[key]
	if !exists {
		status = &PolicyStatus{
			Active:      true,
			MatchCount:  0,
			LastMatched: time.Time{},
		}
		m.statuses[key] = status
	} else {
		status.Active = true
	}

	// Apply the policy based on its action type
	switch policy.Action.Type {
	case "route":
		return m.applyRouteAction(policy)
	case "table":
		return m.applyTableAction(policy)
	case "nat":
		return m.applyNATAction(policy)
	default:
		return fmt.Errorf("unsupported action type: %s", policy.Action.Type)
	}
}

// RemovePolicy removes a routing policy
func (m *manager) RemovePolicy(name, namespace string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := fmt.Sprintf("%s/%s", namespace, name)
	klog.Infof("Removing routing policy %s", key)

	// Check if the policy exists
	policy, exists := m.policies[key]
	if !exists {
		return fmt.Errorf("routing policy %s does not exist", key)
	}

	// Remove the policy based on its action type
	var err error
	switch policy.Action.Type {
	case "route":
		err = m.removeRouteAction(policy)
	case "table":
		err = m.removeTableAction(policy)
	case "nat":
		err = m.removeNATAction(policy)
	default:
		err = fmt.Errorf("unsupported action type: %s", policy.Action.Type)
	}

	if err != nil {
		return err
	}

	// Remove the policy and status
	delete(m.policies, key)
	delete(m.statuses, key)

	return nil
}

// GetPolicyStatus gets the status of a routing policy
func (m *manager) GetPolicyStatus(name, namespace string) (*PolicyStatus, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	key := fmt.Sprintf("%s/%s", namespace, name)
	status, exists := m.statuses[key]
	if !exists {
		return nil, fmt.Errorf("routing policy %s does not exist", key)
	}

	return status, nil
}

// ListPolicies lists all routing policies
func (m *manager) ListPolicies() ([]RoutingPolicy, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	policies := make([]RoutingPolicy, 0, len(m.policies))
	for _, policy := range m.policies {
		policies = append(policies, policy)
	}

	// Sort policies by priority
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Priority < policies[j].Priority
	})

	return policies, nil
}

// EvaluatePacket evaluates a packet against all policies
func (m *manager) EvaluatePacket(packet PacketInfo) (*PolicyAction, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Get all policies
	policies := make([]RoutingPolicy, 0, len(m.policies))
	for _, policy := range m.policies {
		// Only include policies for the packet's VRF
		if policy.VRF == packet.VRF {
			policies = append(policies, policy)
		}
	}

	// Sort policies by priority
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Priority < policies[j].Priority
	})

	// Evaluate policies in order
	for _, policy := range policies {
		if m.policyEngine.matchesPolicy(packet, policy) {
			// Update match count and last matched time
			key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
			if status, exists := m.statuses[key]; exists {
				status.MatchCount++
				status.LastMatched = time.Now()
			}

			// Return the action
			action := policy.Action
			return &action, nil
		}
	}

	// No matching policy
	return nil, nil
}

// applyRouteAction applies a route action
func (m *manager) applyRouteAction(policy RoutingPolicy) error {
	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)

	// For route action, we create an IP rule that directs matching traffic
	// to a custom routing table with the specific next hop

	// Allocate a routing table for this policy
	tableID, err := m.tableAllocator.allocate(key)
	if err != nil {
		return fmt.Errorf("failed to allocate routing table: %w", err)
	}

	// Create the IP rule
	rule := m.policyToIPRule(policy, tableID)
	if err := m.kernelRuleMgr.AddRule(rule); err != nil {
		m.tableAllocator.release(tableID)
		return fmt.Errorf("failed to add IP rule: %w", err)
	}

	// Add a default route in the custom table pointing to the next hop
	if policy.Action.NextHop != "" {
		route := routing.Route{
			Destination: "0.0.0.0/0", // Default route for IPv4
			NextHops: []routing.NextHop{
				{
					Address: policy.Action.NextHop,
				},
			},
			Metric:   policy.Priority,
			Protocol: "policy",
			VRF:      policy.VRF,
			Table:    fmt.Sprintf("%d", tableID),
			Tags:     []string{"policy", fmt.Sprintf("policy-%s", policy.Name)},
		}

		if err := m.routeManager.AddRoute(route); err != nil {
			// Clean up the rule on error
			_ = m.kernelRuleMgr.DeleteRule(rule)
			m.tableAllocator.release(tableID)
			return fmt.Errorf("failed to add route: %w", err)
		}

		// Add IPv6 default route if applicable
		if m.shouldAddIPv6Route(policy) {
			route6 := routing.Route{
				Destination: "::/0", // Default route for IPv6
				NextHops: []routing.NextHop{
					{
						Address: policy.Action.NextHop,
					},
				},
				Metric:   policy.Priority,
				Protocol: "policy",
				VRF:      policy.VRF,
				Table:    fmt.Sprintf("%d", tableID),
				Tags:     []string{"policy", fmt.Sprintf("policy-%s", policy.Name)},
			}
			_ = m.routeManager.AddRoute(route6) // Ignore error if IPv6 not needed
		}
	}

	return nil
}

// shouldAddIPv6Route checks if an IPv6 route should be added
func (m *manager) shouldAddIPv6Route(policy RoutingPolicy) bool {
	// Check if any source or destination networks are IPv6
	for _, network := range policy.Match.Source.Networks {
		if isIPv6Network(network) {
			return true
		}
	}
	for _, network := range policy.Match.Destination.Networks {
		if isIPv6Network(network) {
			return true
		}
	}
	return false
}

// isIPv6Network checks if a network string is IPv6
func isIPv6Network(network string) bool {
	if network == "" {
		return false
	}
	// Check if it contains ':'
	return len(network) > 0 && (network[0] == ':' || containsColon(network))
}

// containsColon checks if a string contains ':'
func containsColon(s string) bool {
	for _, c := range s {
		if c == ':' {
			return true
		}
	}
	return false
}

// removeRouteAction removes a route action
func (m *manager) removeRouteAction(policy RoutingPolicy) error {
	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)

	// Get the table ID for this policy
	tableID, exists := m.tableAllocator.get(key)
	if !exists {
		klog.Warningf("No table allocated for policy %s", key)
		return nil
	}

	// Create the IP rule to delete
	rule := m.policyToIPRule(policy, tableID)

	// Delete the IP rule
	if err := m.kernelRuleMgr.DeleteRule(rule); err != nil {
		klog.Warningf("Failed to delete IP rule for policy %s: %v", key, err)
	}

	// Delete routes from the custom table
	routeParams := routing.RouteParams{
		VRF:   policy.VRF,
		Table: fmt.Sprintf("%d", tableID),
	}

	_ = m.routeManager.DeleteRoute("0.0.0.0/0", routeParams)
	_ = m.routeManager.DeleteRoute("::/0", routeParams)

	// Release the table
	m.tableAllocator.release(tableID)

	return nil
}

// applyTableAction applies a table action
func (m *manager) applyTableAction(policy RoutingPolicy) error {
	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	klog.Infof("Applying table action for policy %s: use table %s", key, policy.Action.Table)

	// Parse table ID from policy.Action.Table
	var tableID int
	if _, err := fmt.Sscanf(policy.Action.Table, "%d", &tableID); err != nil {
		return fmt.Errorf("invalid table ID %s: %w", policy.Action.Table, err)
	}

	// Validate table ID
	if tableID < TableCustomStart || tableID > TableCustomEnd {
		if tableID != TableMain && tableID != TableDefault {
			return fmt.Errorf("invalid table ID %d: must be between %d and %d", tableID, TableCustomStart, TableCustomEnd)
		}
	}

	// Create the IP rule
	rule := m.policyToIPRule(policy, tableID)
	if err := m.kernelRuleMgr.AddRule(rule); err != nil {
		return fmt.Errorf("failed to add IP rule: %w", err)
	}

	klog.Infof("Successfully applied table action for policy %s: use table %d", key, tableID)
	return nil
}

// removeTableAction removes a table action
func (m *manager) removeTableAction(policy RoutingPolicy) error {
	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	klog.Infof("Removing table action for policy %s: table %s", key, policy.Action.Table)

	// Parse table ID from policy.Action.Table
	var tableID int
	if _, err := fmt.Sscanf(policy.Action.Table, "%d", &tableID); err != nil {
		return fmt.Errorf("invalid table ID %s: %w", policy.Action.Table, err)
	}

	// Create the IP rule to delete
	rule := m.policyToIPRule(policy, tableID)

	// Delete the IP rule
	if err := m.kernelRuleMgr.DeleteRule(rule); err != nil {
		klog.Warningf("Failed to delete IP rule for policy %s: %v", key, err)
		return err
	}

	klog.Infof("Successfully removed table action for policy %s", key)
	return nil
}

// applyNATAction applies a NAT action
func (m *manager) applyNATAction(policy RoutingPolicy) error {
	// NAT actions are handled by the NAT manager (Phase 3)
	// Policy-based routing can be combined with NAT by using marks
	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	klog.Infof("NAT action for policy %s is managed by NAT manager", key)

	// If a mark is specified, we can create an IP rule for mark-based routing
	if policy.Action.Mark != 0 {
		return m.applyMarkBasedRouting(policy)
	}

	return nil
}

// removeNATAction removes a NAT action
func (m *manager) removeNATAction(policy RoutingPolicy) error {
	// NAT actions are handled by the NAT manager (Phase 3)
	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	klog.Infof("NAT action for policy %s is managed by NAT manager", key)

	// If a mark was specified, we need to remove the mark-based routing rule
	if policy.Action.Mark != 0 {
		return m.removeMarkBasedRouting(policy)
	}

	return nil
}

// applyMarkBasedRouting applies mark-based routing
func (m *manager) applyMarkBasedRouting(policy RoutingPolicy) error {
	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	klog.Infof("Applying mark-based routing for policy %s: mark %d", key, policy.Action.Mark)

	// Allocate a routing table for this policy
	tableID, err := m.tableAllocator.allocate(key)
	if err != nil {
		return fmt.Errorf("failed to allocate routing table: %w", err)
	}

	// Create an IP rule that matches the fwmark
	rule := IPRule{
		Priority: policy.Priority,
		Table:    tableID,
		Mark:     policy.Action.Mark,
		Mask:     0xFFFFFFFF, // Match the entire mark
		Family:   FamilyAll,
		Action:   ActionToTable,
	}

	if err := m.kernelRuleMgr.AddRule(rule); err != nil {
		m.tableAllocator.release(tableID)
		return fmt.Errorf("failed to add IP rule for mark-based routing: %w", err)
	}

	klog.Infof("Successfully applied mark-based routing for policy %s", key)
	return nil
}

// removeMarkBasedRouting removes mark-based routing
func (m *manager) removeMarkBasedRouting(policy RoutingPolicy) error {
	key := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	klog.Infof("Removing mark-based routing for policy %s: mark %d", key, policy.Action.Mark)

	// Get the table ID for this policy
	tableID, exists := m.tableAllocator.get(key)
	if !exists {
		klog.Warningf("No table allocated for policy %s", key)
		return nil
	}

	// Create the IP rule to delete
	rule := IPRule{
		Priority: policy.Priority,
		Table:    tableID,
		Mark:     policy.Action.Mark,
		Mask:     0xFFFFFFFF,
		Family:   FamilyAll,
		Action:   ActionToTable,
	}

	// Delete the IP rule
	if err := m.kernelRuleMgr.DeleteRule(rule); err != nil {
		klog.Warningf("Failed to delete IP rule for mark-based routing: %v", err)
	}

	// Release the table
	m.tableAllocator.release(tableID)

	klog.Infof("Successfully removed mark-based routing for policy %s", key)
	return nil
}

// policyToIPRule converts a routing policy to an IP rule
func (m *manager) policyToIPRule(policy RoutingPolicy, tableID int) IPRule {
	rule := IPRule{
		Priority: policy.Priority,
		Table:    tableID,
		Action:   ActionToTable,
	}

	// Determine address family based on source/destination networks
	hasIPv4 := false
	hasIPv6 := false

	// Check source networks
	for _, network := range policy.Match.Source.Networks {
		if isIPv6Network(network) {
			hasIPv6 = true
		} else {
			hasIPv4 = true
		}
	}

	// Check destination networks
	for _, network := range policy.Match.Destination.Networks {
		if isIPv6Network(network) {
			hasIPv6 = true
		} else {
			hasIPv4 = true
		}
	}

	// Set family
	if hasIPv4 && hasIPv6 {
		rule.Family = FamilyAll
	} else if hasIPv6 {
		rule.Family = FamilyIPv6
	} else if hasIPv4 {
		rule.Family = FamilyIPv4
	} else {
		rule.Family = FamilyAll
	}

	// Set source network (use first one if multiple)
	if len(policy.Match.Source.Networks) > 0 {
		rule.Src = policy.Match.Source.Networks[0]
	}

	// Set destination network (use first one if multiple)
	if len(policy.Match.Destination.Networks) > 0 {
		rule.Dst = policy.Match.Destination.Networks[0]
	}

	// Set input interface (use first one if multiple)
	if len(policy.Match.Source.Interfaces) > 0 {
		rule.IifName = policy.Match.Source.Interfaces[0]
	}

	// Set fwmark if specified in action
	if policy.Action.Mark != 0 {
		rule.Mark = policy.Action.Mark
		rule.Mask = 0xFFFFFFFF
	}

	// Set TOS/DSCP if specified in action
	if policy.Action.DSCP != 0 {
		// Convert DSCP to TOS (DSCP is upper 6 bits of TOS)
		rule.Tos = policy.Action.DSCP << 2
	}

	return rule
}
