package controllers

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"

	"k8s.io/client-go/kubernetes"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/network/routing"
	"github.com/GizmoTickler/fos1/pkg/network/routing/frr"
	"github.com/GizmoTickler/fos1/pkg/network/routing/multiwan"
	"github.com/GizmoTickler/fos1/pkg/network/routing/policy"
	"github.com/GizmoTickler/fos1/pkg/network/routing/protocols"
	"github.com/GizmoTickler/fos1/pkg/traffic"
)

// RoutingController manages all routing-related controllers
type RoutingController struct {
	dynamicClient      dynamic.Interface
	ciliumClient       cilium.CiliumClient
	routeManager       routing.RouteManager
	protocolManager    routing.ProtocolManager
	routeSynchronizer  *routing.RouteSynchronizer
	bgpController      *BGPController
	ospfController     *OSPFController
	policyController   *PolicyController
	multiWANController *MultiWANController
	qosController      *QoSController
	trafficManager     traffic.Manager
	trafficMonitor     *traffic.Monitor
	stopCh             chan struct{}
}

// NewRoutingController creates a new routing controller
//
// The kubeClient parameter is required by the QoS sub-controller, which
// (post Sprint 30 / Ticket 45) patches pod annotations via the standard
// kubernetes client. Pass nil only in code paths that don't exercise
// NewQoSController; otherwise reconcile will error out.
func NewRoutingController(
	dynamicClient dynamic.Interface,
	ciliumClient cilium.CiliumClient,
	kubeClient kubernetes.Interface,
) (*RoutingController, error) {
	if ciliumClient == nil {
		return nil, fmt.Errorf("cilium client is required for routing controller")
	}

	// Create FRR client
	frrClient := frr.NewClient()

	// Create route manager
	routeManager := routing.NewRouteManager()

	// Create protocol manager
	protocolManager := protocols.NewManager(frrClient)

	// Create Cilium synchronizer
	ciliumSynchronizer := &realCiliumSynchronizer{client: ciliumClient}

	// Create route synchronizer
	routeSynchronizer := routing.NewRouteSynchronizer(
		routeManager,
		ciliumSynchronizer,
		30*time.Second,
	)

	// Create policy manager
	policyManager := policy.NewManager(routeManager)

	// Create multi-WAN manager
	wanManager := multiwan.NewManager(routeManager)

	// Create BGP controller
	bgpController := NewBGPController(
		dynamicClient,
		protocolManager,
	)

	// Create OSPF controller
	ospfController := NewOSPFController(
		dynamicClient,
		protocolManager,
	)

	// Create policy controller
	policyController := NewPolicyController(
		dynamicClient,
		policyManager,
	)

	// Create multi-WAN controller
	multiWANController := NewMultiWANController(
		dynamicClient,
		wanManager,
	)

	// Create traffic classifier
	trafficClassifier := traffic.NewClassifier()

	// Create bandwidth allocator
	bandwidthAllocator := traffic.NewBandwidthAllocator()

	// Create traffic manager
	trafficManager := traffic.NewManager(trafficClassifier, bandwidthAllocator, 30*time.Second)

	// Create QoS controller (Cilium Bandwidth Manager backend — Sprint 30
	// / Ticket 45). No tc-backed QoS manager is constructed any more; pod
	// annotations are patched directly via the kubernetes clientset.
	qosController := NewQoSController(
		dynamicClient,
		kubeClient,
	)

	// Create traffic monitor
	trafficMonitor := traffic.NewMonitor(trafficManager, 30*time.Second)

	return &RoutingController{
		dynamicClient:      dynamicClient,
		ciliumClient:       ciliumClient,
		routeManager:       routeManager,
		protocolManager:    protocolManager,
		routeSynchronizer:  routeSynchronizer,
		bgpController:      bgpController,
		ospfController:     ospfController,
		policyController:   policyController,
		multiWANController: multiWANController,
		qosController:      qosController,
		trafficManager:     trafficManager,
		trafficMonitor:     trafficMonitor,
		stopCh:             make(chan struct{}),
	}, nil
}

// Start starts the routing controller
func (c *RoutingController) Start(workers int) {
	klog.Info("Starting routing controller")

	// Start the route synchronizer
	c.routeSynchronizer.Start()

	// Start the BGP controller
	go c.bgpController.Run(workers)

	// Start the OSPF controller
	go c.ospfController.Run(workers)

	// Start the policy controller
	go c.policyController.Run(workers)

	// Start the multi-WAN controller
	go c.multiWANController.Run(workers)

	// Start the QoS controller
	go c.qosController.Run(workers)

	// Start the traffic monitor
	c.trafficMonitor.Start()

	// Configure router ID
	ctx := context.Background()
	frrClient := frr.NewClient()
	if err := frrClient.ConfigureRouter(ctx, "192.168.1.1"); err != nil {
		klog.Errorf("Failed to configure router ID: %v", err)
	}

	klog.Info("Routing controller started")
}

// Stop stops the routing controller
func (c *RoutingController) Stop() {
	klog.Info("Stopping routing controller")

	// Stop the BGP controller
	c.bgpController.Stop()

	// Stop the OSPF controller
	c.ospfController.Stop()

	// Stop the policy controller
	c.policyController.Stop()

	// Stop the multi-WAN controller
	c.multiWANController.Stop()

	// Stop the QoS controller
	c.qosController.Stop()

	// Stop the traffic monitor
	c.trafficMonitor.Stop()

	// Stop the route synchronizer
	c.routeSynchronizer.Stop()

	close(c.stopCh)

	klog.Info("Routing controller stopped")
}

// realCiliumSynchronizer implements routing.CiliumSynchronizer using the
// Cilium-first control plane contract (ADR-0001). All route and VRF
// enforcement flows through the CiliumClient interface.
//
// Ownership model:
//   - Cilium is the authoritative enforcement path for routing and VRF policies.
//   - Kernel route helpers (pkg/network/routing, pkg/network/routing/policy)
//     are internal support code only and must not define alternate active
//     control paths.
type realCiliumSynchronizer struct {
	client cilium.CiliumClient
}

func (s *realCiliumSynchronizer) SyncRoute(route routing.Route) error {
	cRoute, err := routingToCiliumRoute(route)
	if err != nil {
		return err
	}
	return s.client.AddRoute(cRoute)
}

func (s *realCiliumSynchronizer) RemoveRoute(destination string, routeParams routing.RouteParams) error {
	_, dst, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination %s: %w", destination, err)
	}
	return s.client.DeleteRoute(cilium.Route{Destination: dst, Table: routingTableToID(routeParams.Table), VRF: routeParams.VRF})
}

func (s *realCiliumSynchronizer) SyncRoutingTable(tableName string, vrf string) error {
	ctx := context.Background()
	if vrf != "" && vrf != "main" {
		_, err := s.client.ListVRFRoutes(ctx, 0)
		return err
	}
	_, err := s.client.ListRoutes(ctx)
	return err
}

func (s *realCiliumSynchronizer) GetCiliumRoutes() ([]*routing.Route, error) {
	routes, err := s.client.ListRoutes(context.Background())
	if err != nil {
		return nil, err
	}
	result := make([]*routing.Route, 0, len(routes))
	for _, route := range routes {
		result = append(result, ciliumToRoutingRoute(route))
	}
	return result, nil
}

// SyncVRFPolicies synchronizes VRF isolation policies with Cilium.
//
// Ownership model: Cilium is the authoritative enforcement path for VRF
// policy rules. Kernel helpers (pkg/network/routing/policy) are internal
// support code only and must not define an alternate active control path.
//
// VRF identity semantics:
//   - VRF name maps to a deterministic table ID via VRFTableID().
//   - The VRF label applied to Cilium routes uses the format "vrf-<tableID>".
//   - Each interface listed in the VRF gets a policy rule directing its
//     traffic to the VRF routing table.
//
// Reconciliation is idempotent: existing routes and policy rules that
// already match the desired state are left untouched; missing entries are
// added; stale entries are removed.
func (s *realCiliumSynchronizer) SyncVRFPolicies(vrf routing.VRF) error {
	klog.V(4).Infof("Synchronizing VRF %s policies with Cilium", vrf.Name)

	tableID := VRFTableID(vrf)
	if tableID < 1 || tableID > 252 {
		return fmt.Errorf("VRF %s resolved to invalid table ID %d (must be 1-252)", vrf.Name, tableID)
	}

	vrfLabel := fmt.Sprintf("vrf-%d", tableID)
	ctx := context.Background()

	// --- Step 1: Reconcile routes for this VRF via Cilium ---

	// Fetch existing Cilium routes for this VRF.
	existingRoutes, err := s.client.ListVRFRoutes(ctx, tableID)
	if err != nil {
		return fmt.Errorf("failed to list VRF routes for %s (table %d): %w", vrf.Name, tableID, err)
	}

	// Build an index of existing routes by destination for idempotent diffing.
	existingByDest := make(map[string]cilium.Route, len(existingRoutes))
	for _, r := range existingRoutes {
		if r.Destination != nil {
			existingByDest[r.Destination.String()] = r
		}
	}

	// Build the desired set of routes from the VRF's route leak destinations.
	desiredDests := make(map[string]struct{})
	for _, leak := range vrf.LeakRoutes {
		for _, dest := range leak.Destinations {
			_, dst, err := net.ParseCIDR(dest)
			if err != nil {
				klog.Warningf("Skipping invalid leak destination %q in VRF %s: %v", dest, vrf.Name, err)
				continue
			}
			destStr := dst.String()
			desiredDests[destStr] = struct{}{}

			// Add route if it does not already exist in Cilium.
			if _, exists := existingByDest[destStr]; !exists {
				route := cilium.Route{
					Destination: dst,
					Table:       tableID,
					VRF:         vrfLabel,
					Type:        "static",
				}
				if err := s.client.AddVRFRoute(route, tableID); err != nil {
					return fmt.Errorf("failed to add VRF route %s to table %d: %w", destStr, tableID, err)
				}
				klog.V(4).Infof("Added VRF route %s to table %d (VRF %s)", destStr, tableID, vrf.Name)
			}
		}
	}

	// Remove stale routes that exist in Cilium but are no longer desired.
	for destStr, existingRoute := range existingByDest {
		if _, wanted := desiredDests[destStr]; !wanted {
			if err := s.client.DeleteVRFRoute(existingRoute, tableID); err != nil {
				return fmt.Errorf("failed to remove stale VRF route %s from table %d: %w", destStr, tableID, err)
			}
			klog.V(4).Infof("Removed stale VRF route %s from table %d (VRF %s)", destStr, tableID, vrf.Name)
		}
	}

	// --- Step 2: Reconcile per-interface policy rules ---

	// Build the desired set of policy rules sorted by interface name for
	// deterministic ordering. Each interface gets a rule directing traffic
	// into the VRF's routing table.
	sortedIfaces := make([]string, len(vrf.Interfaces))
	copy(sortedIfaces, vrf.Interfaces)
	sort.Strings(sortedIfaces)

	for i, iface := range sortedIfaces {
		// Priority is deterministic: base priority from table ID + interface index.
		// This keeps rule ordering stable across reconciliation runs.
		priority := tableID*100 + i

		rule := cilium.RoutingPolicyRule{
			Priority:       priority,
			Table:          tableID,
			InputInterface: iface,
		}

		// Apply the rule via Cilium network policy to enforce VRF isolation.
		policyName := fmt.Sprintf("vrf-%s-iface-%s", vrf.Name, iface)
		ciliumPolicy := &cilium.CiliumPolicy{
			Name: policyName,
			Labels: map[string]string{
				"app":       "fos1",
				"component": "vrf-policy",
				"vrf":       vrf.Name,
				"vrf-table": fmt.Sprintf("%d", tableID),
				"interface": iface,
			},
			Rules: []cilium.CiliumRule{
				{
					FromEndpoints: []cilium.Endpoint{
						{Labels: map[string]string{"interface": iface}},
					},
					ToEndpoints: []cilium.Endpoint{
						{Labels: map[string]string{"vrf": vrfLabel}},
					},
				},
			},
		}

		if err := s.client.ApplyNetworkPolicy(ctx, ciliumPolicy); err != nil {
			return fmt.Errorf("failed to apply VRF policy rule for interface %s (VRF %s, priority %d, table %d): %w",
				iface, vrf.Name, rule.Priority, rule.Table, err)
		}
		klog.V(4).Infof("Applied VRF policy for interface %s -> table %d (VRF %s)", iface, tableID, vrf.Name)
	}

	klog.Infof("VRF %s (table %d) synchronized: %d desired routes, %d interfaces",
		vrf.Name, tableID, len(desiredDests), len(vrf.Interfaces))
	return nil
}

// VRFTableID returns the deterministic routing table ID for a VRF.
//
// VRF identity semantics:
//   - If the VRF has an explicit TableID set (1-252), it is used directly.
//   - If the VRF name is a numeric string, that value is used.
//   - Otherwise, a deterministic hash of the VRF name is mapped to the
//     custom table range (1-252).
//
// This function is the single source of truth for VRF-to-table mapping.
func VRFTableID(vrf routing.VRF) int {
	// Explicit table ID takes precedence.
	if vrf.TableID >= 1 && vrf.TableID <= 252 {
		return vrf.TableID
	}

	// Try parsing the name as a numeric table ID.
	if id, err := strconv.Atoi(vrf.Name); err == nil && id >= 1 && id <= 252 {
		return id
	}

	// Deterministic hash for string names.
	return vrfNameToTableID(vrf.Name)
}

// vrfNameToTableID maps a VRF name to a table ID in the custom range (1-252)
// using a simple deterministic hash (FNV-inspired).
func vrfNameToTableID(name string) int {
	var h uint32 = 2166136261 // FNV offset basis
	for i := 0; i < len(name); i++ {
		h ^= uint32(name[i])
		h *= 16777619 // FNV prime
	}
	// Map to range 1-252
	return int(h%252) + 1
}

func routingToCiliumRoute(route routing.Route) (cilium.Route, error) {
	_, dst, err := net.ParseCIDR(route.Destination)
	if err != nil {
		return cilium.Route{}, fmt.Errorf("invalid route destination %s: %w", route.Destination, err)
	}

	var gateway net.IP
	outputIface := ""
	if len(route.NextHops) > 0 {
		outputIface = route.NextHops[0].Interface
		if route.NextHops[0].Address != "" {
			gateway = net.ParseIP(route.NextHops[0].Address)
			if gateway == nil {
				return cilium.Route{}, fmt.Errorf("invalid gateway %s", route.NextHops[0].Address)
			}
		}
	}

	return cilium.Route{
		Destination: dst,
		Gateway:     gateway,
		OutputIface: outputIface,
		Priority:    route.Metric,
		Table:       routingTableToID(route.Table),
		Type:        route.Protocol,
		VRF:         route.VRF,
	}, nil
}

func ciliumToRoutingRoute(route cilium.Route) *routing.Route {
	destination := ""
	if route.Destination != nil {
		destination = route.Destination.String()
	}
	converted := &routing.Route{
		Destination: destination,
		Metric:      route.Priority,
		Protocol:    route.Type,
		VRF:         route.VRF,
		Table:       strconv.Itoa(route.Table),
	}
	if route.Gateway != nil {
		converted.NextHops = []routing.NextHop{{Address: route.Gateway.String(), Interface: route.OutputIface, Weight: 1}}
	}
	return converted
}

// routingTableToID converts a table name to its numeric ID.
//
// Well-known tables:
//   - "" or "main" -> 254
//   - "local"      -> 255
//   - "default"    -> 253
//
// Numeric strings are parsed directly. Non-numeric names are mapped via a
// deterministic hash to the custom table range (1-252), consistent with
// VRFTableID semantics.
func routingTableToID(table string) int {
	switch strings.ToLower(strings.TrimSpace(table)) {
	case "", "main":
		return 254
	case "local":
		return 255
	case "default":
		return 253
	default:
		if id, err := strconv.Atoi(table); err == nil {
			return id
		}
		// Deterministic hash for named tables, same algorithm as vrfNameToTableID.
		return vrfNameToTableID(table)
	}
}
