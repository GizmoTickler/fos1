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
}

// NewManager creates a new policy manager
func NewManager(routeManager routing.RouteManager) Manager {
	return &manager{
		policies:     make(map[string]RoutingPolicy),
		statuses:     make(map[string]*PolicyStatus),
		routeManager: routeManager,
		policyEngine: newEngine(),
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
	// Create a route for the policy
	route := routing.Route{
		Destination: "0.0.0.0/0", // Default route
		NextHops: []routing.NextHop{
			{
				Address: policy.Action.NextHop,
			},
		},
		Metric:    policy.Priority,
		Protocol:  "policy",
		VRF:       policy.VRF,
		Tags:      []string{"policy", fmt.Sprintf("policy-%s", policy.Name)},
		Temporary: true,
	}

	// Add the route
	return m.routeManager.AddRoute(route)
}

// removeRouteAction removes a route action
func (m *manager) removeRouteAction(policy RoutingPolicy) error {
	// Create route parameters
	routeParams := routing.RouteParams{
		VRF: policy.VRF,
	}

	// Delete the route
	return m.routeManager.DeleteRoute("0.0.0.0/0", routeParams)
}

// applyTableAction applies a table action
func (m *manager) applyTableAction(policy RoutingPolicy) error {
	// In a real implementation, this would create a rule to use a specific routing table
	// For now, just log the action
	klog.Infof("Applied table action for policy %s/%s: use table %s", policy.Namespace, policy.Name, policy.Action.Table)
	return nil
}

// removeTableAction removes a table action
func (m *manager) removeTableAction(policy RoutingPolicy) error {
	// In a real implementation, this would remove the rule to use a specific routing table
	// For now, just log the action
	klog.Infof("Removed table action for policy %s/%s: use table %s", policy.Namespace, policy.Name, policy.Action.Table)
	return nil
}

// applyNATAction applies a NAT action
func (m *manager) applyNATAction(policy RoutingPolicy) error {
	// In a real implementation, this would create a NAT rule
	// For now, just log the action
	klog.Infof("Applied NAT action for policy %s/%s", policy.Namespace, policy.Name)
	return nil
}

// removeNATAction removes a NAT action
func (m *manager) removeNATAction(policy RoutingPolicy) error {
	// In a real implementation, this would remove the NAT rule
	// For now, just log the action
	klog.Infof("Removed NAT action for policy %s/%s", policy.Namespace, policy.Name)
	return nil
}
