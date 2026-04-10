package cilium

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// RouterOptions contains configuration options for the Router
type RouterOptions struct {
	// EnableVRF enables VRF support
	EnableVRF bool

	// EnablePBR enables policy-based routing
	EnablePBR bool

	// PollInterval is the interval at which the router polls for changes
	PollInterval time.Duration

	// MaxRoutes is the maximum number of routes to process in one batch
	MaxRoutes int
}

// DefaultRouterOptions returns default router options
func DefaultRouterOptions() RouterOptions {
	return RouterOptions{
		EnableVRF:    true,
		EnablePBR:    true,
		PollInterval: 30 * time.Second,
		MaxRoutes:    1000,
	}
}

// VRF represents a Virtual Routing and Forwarding instance
type VRF struct {
	// ID is the VRF ID
	ID int

	// Name is the VRF name
	Name string

	// Tables is a list of routing tables in this VRF
	Tables []int

	// Interfaces is a list of interfaces in this VRF
	Interfaces []string
}

// RoutingPolicyRule represents a policy-based routing rule
type RoutingPolicyRule struct {
	// Priority is the rule priority (lower values have higher priority)
	Priority int

	// Table is the routing table to use
	Table int

	// SourceIP is the source IP address/prefix
	SourceIP *net.IPNet

	// DestinationIP is the destination IP address/prefix
	DestinationIP *net.IPNet

	// InputInterface is the input interface name
	InputInterface string

	// OutputInterface is the output interface name
	OutputInterface string
}

// Router manages routing functionality through Cilium
type Router struct {
	// client is the Cilium client
	client CiliumClient

	// options contains router configuration options
	options RouterOptions

	// routeSynchronizer is used to synchronize routes
	routeSynchronizer *RouteSynchronizer

	// vrfs is a map of VRF ID to VRF
	vrfs map[int]*VRF

	// policyRules is a list of policy-based routing rules
	policyRules []RoutingPolicyRule

	// mutex is used to synchronize access to the router state
	mutex sync.RWMutex

	// ctx is the router context
	ctx context.Context

	// cancel is the context cancel function
	cancel context.CancelFunc
}

// NewRouter creates a new router with the given options
func NewRouter(client CiliumClient, routeSynchronizer *RouteSynchronizer, options RouterOptions) *Router {
	ctx, cancel := context.WithCancel(context.Background())
	return &Router{
		client:            client,
		options:           options,
		routeSynchronizer: routeSynchronizer,
		vrfs:              make(map[int]*VRF),
		policyRules:       []RoutingPolicyRule{},
		ctx:               ctx,
		cancel:            cancel,
	}
}

// Start starts the router
func (r *Router) Start() error {
	klog.Info("Starting Router")

	// Initialize default VRF
	r.vrfs[0] = &VRF{
		ID:        0,
		Name:      "default",
		Tables:    []int{254}, // Main table
		Interfaces: []string{},
	}

	// Start background processing if needed
	if r.options.EnableVRF || r.options.EnablePBR {
		go r.processingLoop()
	}

	return nil
}

// Stop stops the router
func (r *Router) Stop() {
	klog.Info("Stopping Router")
	r.cancel()
}

// processingLoop periodically processes VRF and policy rules
func (r *Router) processingLoop() {
	ticker := time.NewTicker(r.options.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.syncVRFs()
			r.syncPolicyRules()
		case <-r.ctx.Done():
			return
		}
	}
}

// syncVRFs synchronizes VRFs with Cilium
func (r *Router) syncVRFs() {
	if !r.options.EnableVRF {
		return
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for vrfID, vrf := range r.vrfs {
		if err := r.routeSynchronizer.SyncRoutesForVRF(r.ctx, vrfID); err != nil {
			klog.Errorf("Failed to sync routes for VRF %s (ID %d): %v", vrf.Name, vrfID, err)
		}
	}
}

// syncPolicyRules synchronizes policy-based routing rules with Cilium.
//
// This method is the authoritative enforcement path for policy-based routing
// rules. It applies each rule as a CiliumNetworkPolicy, ensuring the Cilium
// control plane has the current desired state. The operation is idempotent:
// re-applying the same rules results in no-op updates via kubectl apply.
func (r *Router) syncPolicyRules() {
	if !r.options.EnablePBR {
		return
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	ctx := r.ctx

	for _, rule := range r.policyRules {
		policyName := fmt.Sprintf("pbr-rule-pri%d-tbl%d", rule.Priority, rule.Table)

		labels := map[string]string{
			"app":       "fos1",
			"component": "pbr-rule",
			"priority":  fmt.Sprintf("%d", rule.Priority),
			"table":     fmt.Sprintf("%d", rule.Table),
		}

		fromEndpoints := []Endpoint{}
		if rule.SourceIP != nil {
			fromEndpoints = append(fromEndpoints, Endpoint{
				Labels: map[string]string{"source-cidr": rule.SourceIP.String()},
			})
		}
		if rule.InputInterface != "" {
			fromEndpoints = append(fromEndpoints, Endpoint{
				Labels: map[string]string{"interface": rule.InputInterface},
			})
		}

		toEndpoints := []Endpoint{}
		if rule.DestinationIP != nil {
			toEndpoints = append(toEndpoints, Endpoint{
				Labels: map[string]string{"destination-cidr": rule.DestinationIP.String()},
			})
		}
		if rule.OutputInterface != "" {
			toEndpoints = append(toEndpoints, Endpoint{
				Labels: map[string]string{"interface": rule.OutputInterface},
			})
		}

		ciliumPolicy := &CiliumPolicy{
			Name:   policyName,
			Labels: labels,
			Rules: []CiliumRule{
				{
					FromEndpoints: fromEndpoints,
					ToEndpoints:   toEndpoints,
				},
			},
		}

		if err := r.client.ApplyNetworkPolicy(ctx, ciliumPolicy); err != nil {
			klog.Errorf("Failed to sync policy rule priority %d table %d: %v", rule.Priority, rule.Table, err)
		} else {
			klog.V(4).Infof("Synced policy rule: priority %d, table %d", rule.Priority, rule.Table)
		}
	}
}

// AddVRF adds a new VRF
func (r *Router) AddVRF(name string, tables []int, interfaces []string) (int, error) {
	if !r.options.EnableVRF {
		return 0, fmt.Errorf("VRF support is disabled")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Find an available VRF ID
	vrfID := r.findAvailableVRFID()

	// Create the VRF
	r.vrfs[vrfID] = &VRF{
		ID:         vrfID,
		Name:       name,
		Tables:     tables,
		Interfaces: interfaces,
	}

	// Configure Cilium for this VRF by applying a network policy that
	// identifies traffic belonging to this VRF domain.
	vrfLabel := fmt.Sprintf("vrf-%d", vrfID)
	policyName := fmt.Sprintf("vrf-%s-identity", name)
	ciliumPolicy := &CiliumPolicy{
		Name: policyName,
		Labels: map[string]string{
			"app":       "fos1",
			"component": "vrf-identity",
			"vrf":       name,
			"vrf-id":    fmt.Sprintf("%d", vrfID),
		},
		Rules: []CiliumRule{},
	}

	// Add per-interface rules for VRF membership
	for _, iface := range interfaces {
		ciliumPolicy.Rules = append(ciliumPolicy.Rules, CiliumRule{
			FromEndpoints: []Endpoint{
				{Labels: map[string]string{"interface": iface}},
			},
			ToEndpoints: []Endpoint{
				{Labels: map[string]string{"vrf": vrfLabel}},
			},
		})
	}

	ctx := r.ctx
	if err := r.client.ApplyNetworkPolicy(ctx, ciliumPolicy); err != nil {
		// Roll back the in-memory state on Cilium failure
		delete(r.vrfs, vrfID)
		return 0, fmt.Errorf("failed to apply VRF identity policy for %s: %w", name, err)
	}

	klog.Infof("Added VRF %s with ID %d (label: %s)", name, vrfID, vrfLabel)

	return vrfID, nil
}

// DeleteVRF deletes a VRF
func (r *Router) DeleteVRF(vrfID int) error {
	if !r.options.EnableVRF {
		return fmt.Errorf("VRF support is disabled")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if the VRF exists
	vrf, exists := r.vrfs[vrfID]
	if !exists {
		return fmt.Errorf("VRF with ID %d does not exist", vrfID)
	}

	// Don't allow deletion of the default VRF
	if vrfID == 0 {
		return fmt.Errorf("cannot delete the default VRF")
	}

	// Remove the VRF from Cilium by cleaning up routes associated with this VRF.
	ctx := r.ctx
	vrfRoutes, err := r.client.ListVRFRoutes(ctx, vrfID)
	if err != nil {
		klog.Warningf("Failed to list routes for VRF %s (ID %d) during deletion: %v", vrf.Name, vrfID, err)
	} else {
		for _, route := range vrfRoutes {
			if delErr := r.client.DeleteVRFRoute(route, vrfID); delErr != nil {
				klog.Warningf("Failed to delete VRF route during VRF %s deletion: %v", vrf.Name, delErr)
			}
		}
	}

	delete(r.vrfs, vrfID)
	klog.Infof("Deleted VRF %s with ID %d", vrf.Name, vrfID)

	return nil
}

// AddPolicyRule adds a new policy-based routing rule
func (r *Router) AddPolicyRule(rule RoutingPolicyRule) error {
	if !r.options.EnablePBR {
		return fmt.Errorf("policy-based routing is disabled")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check that the table exists
	tableExists := false
	for _, vrf := range r.vrfs {
		for _, table := range vrf.Tables {
			if table == rule.Table {
				tableExists = true
				break
			}
		}
		if tableExists {
			break
		}
	}

	if !tableExists {
		return fmt.Errorf("routing table %d does not exist", rule.Table)
	}

	// Apply the policy rule through Cilium immediately.
	policyName := fmt.Sprintf("pbr-rule-pri%d-tbl%d", rule.Priority, rule.Table)
	labels := map[string]string{
		"app":       "fos1",
		"component": "pbr-rule",
		"priority":  fmt.Sprintf("%d", rule.Priority),
		"table":     fmt.Sprintf("%d", rule.Table),
	}

	fromEndpoints := []Endpoint{}
	if rule.SourceIP != nil {
		fromEndpoints = append(fromEndpoints, Endpoint{
			Labels: map[string]string{"source-cidr": rule.SourceIP.String()},
		})
	}
	if rule.InputInterface != "" {
		fromEndpoints = append(fromEndpoints, Endpoint{
			Labels: map[string]string{"interface": rule.InputInterface},
		})
	}

	ciliumPolicy := &CiliumPolicy{
		Name:   policyName,
		Labels: labels,
		Rules: []CiliumRule{
			{
				FromEndpoints: fromEndpoints,
			},
		},
	}

	ctx := r.ctx
	if err := r.client.ApplyNetworkPolicy(ctx, ciliumPolicy); err != nil {
		return fmt.Errorf("failed to apply policy rule priority %d to Cilium: %w", rule.Priority, err)
	}

	r.policyRules = append(r.policyRules, rule)
	klog.Infof("Added policy rule with priority %d to table %d", rule.Priority, rule.Table)

	return nil
}

// DeletePolicyRule deletes a policy-based routing rule
func (r *Router) DeletePolicyRule(priority int) error {
	if !r.options.EnablePBR {
		return fmt.Errorf("policy-based routing is disabled")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Find the rule with the given priority
	found := false
	newRules := make([]RoutingPolicyRule, 0, len(r.policyRules))
	for _, rule := range r.policyRules {
		if rule.Priority == priority {
			found = true
			continue
		}
		newRules = append(newRules, rule)
	}

	if !found {
		return fmt.Errorf("policy rule with priority %d not found", priority)
	}

	// Remove the rule from Cilium
	// In a real implementation, this would use Cilium's API to remove the rule
	r.policyRules = newRules
	klog.Infof("Deleted policy rule with priority %d", priority)

	return nil
}

// AddRoute adds a route to the router
func (r *Router) AddRoute(route Route) error {
	// Add the route to Cilium
	return r.routeSynchronizer.addRouteToCilium(route)
}

// DeleteRoute deletes a route from the router
func (r *Router) DeleteRoute(route Route) error {
	// Delete the route from Cilium
	return r.routeSynchronizer.removeRouteFromCilium(route)
}

// AddRouteToVRF adds a route to a specific VRF
func (r *Router) AddRouteToVRF(route Route, vrfID int) error {
	if !r.options.EnableVRF {
		return fmt.Errorf("VRF support is disabled")
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Check if the VRF exists
	_, exists := r.vrfs[vrfID]
	if !exists {
		return fmt.Errorf("VRF with ID %d does not exist", vrfID)
	}

	// Add the route to the VRF
	return r.routeSynchronizer.addVRFRouteToCilium(route, vrfID)
}

// findAvailableVRFID finds an available VRF ID
func (r *Router) findAvailableVRFID() int {
	// Start from 1 since 0 is reserved for the default VRF
	vrfID := 1
	for {
		if _, exists := r.vrfs[vrfID]; !exists {
			return vrfID
		}
		vrfID++
	}
}
