package cilium

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
)

// RouteSynchronizer ensures routes are synchronized between kernel routing tables
// and Cilium's eBPF maps
type RouteSynchronizer struct {
	client     CiliumClient
	pollPeriod time.Duration
	ctx        context.Context
	cancel     context.CancelFunc
}

type routeManifestList struct {
	Items []routeManifest `json:"items"`
}

type routeManifest struct {
	Metadata routeManifestMetadata `json:"metadata"`
	Spec     routeManifestSpec     `json:"spec"`
}

type routeManifestMetadata struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
}

type routeManifestSpec struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
	Table       string `json:"table"`
	VRF         string `json:"vrf"`
	Type        string `json:"type"`
}

func routeFromManifest(item routeManifest) (Route, error) {
	_, destination, err := net.ParseCIDR(item.Spec.Destination)
	if err != nil {
		return Route{}, fmt.Errorf("invalid route destination %q: %w", item.Spec.Destination, err)
	}

	var tableID int
	if item.Spec.Table != "" {
		if t, err := strconv.Atoi(item.Spec.Table); err == nil {
			tableID = t
		} else {
			switch item.Spec.Table {
			case "main":
				tableID = 254
			case "local":
				tableID = 255
			case "default":
				tableID = 253
			default:
				return Route{}, fmt.Errorf("unsupported route table %q", item.Spec.Table)
			}
		}
	}

	return Route{
		Destination: destination,
		Gateway:     net.ParseIP(item.Spec.Gateway),
		OutputIface: item.Spec.Interface,
		Priority:    item.Spec.Metric,
		Table:       tableID,
		Type:        item.Spec.Type,
		VRF:         item.Spec.VRF,
	}, nil
}

// RouteTable represents a routing table with its routes
type RouteTable struct {
	ID     int
	Name   string
	Routes []Route
}

// Route represents a route entry
type Route struct {
	Namespace   string
	Name        string
	Destination *net.IPNet
	Gateway     net.IP
	InputIface  string
	OutputIface string
	Priority    int
	Table       int
	Type        string // "static", "dynamic", "policy"
	VRF         string
}

const (
	// RouteSyncActionUpsert indicates that a route should be created or updated
	RouteSyncActionUpsert = "upsert"

	// RouteSyncActionDelete indicates that a route should be deleted
	RouteSyncActionDelete = "delete"
)

// RouteSync represents a route synchronization request
type RouteSync struct {
	// Namespace is the namespace of the Route CRD
	Namespace string

	// Name is the name of the Route CRD
	Name string

	// Route is the route to synchronize
	Route Route

	// Action is the action to perform (upsert or delete)
	Action string

	// Destination is a string representation of the destination CIDR
	Destination string

	// Gateway is the gateway IP address
	Gateway net.IP

	// Interface is the output interface name
	Interface string

	// Metric is the route metric/priority
	Metric int

	// TableID is the routing table ID
	TableID int

	// VRF is the VRF name for policy-based routing
	VRF string
}

// NewRouteSynchronizer creates a new route synchronizer
func NewRouteSynchronizer(client CiliumClient, pollPeriod time.Duration) *RouteSynchronizer {
	ctx, cancel := context.WithCancel(context.Background())
	return &RouteSynchronizer{
		client:     client,
		pollPeriod: pollPeriod,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start begins the synchronization process
func (s *RouteSynchronizer) Start() error {
	log.Println("Starting Cilium route synchronizer")

	// Initial synchronization
	if err := s.synchronizeRoutes(); err != nil {
		return fmt.Errorf("initial route synchronization failed: %w", err)
	}

	// Start background synchronization
	go s.synchronizationLoop()

	return nil
}

// Stop stops the synchronization process
func (s *RouteSynchronizer) Stop() {
	s.cancel()
	log.Println("Cilium route synchronizer stopped")
}

// synchronizationLoop periodically synchronizes routes
func (s *RouteSynchronizer) synchronizationLoop() {
	ticker := time.NewTicker(s.pollPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.synchronizeRoutes(); err != nil {
				log.Printf("Route synchronization error: %v", err)
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// synchronizeRoutes performs the actual route synchronization
func (s *RouteSynchronizer) synchronizeRoutes() error {
	// 1. Get routes from kernel routing tables
	kernelRoutes, err := s.getKernelRoutes()
	if err != nil {
		return fmt.Errorf("failed to get kernel routes: %w", err)
	}

	// 2. Get routes from Cilium's eBPF maps
	ciliumRoutes, err := s.getCiliumRoutes()
	if err != nil {
		return fmt.Errorf("failed to get Cilium routes: %w", err)
	}

	// 3. Calculate differences
	routesToAdd, routesToRemove := s.calculateDiff(kernelRoutes, ciliumRoutes)

	// 4. Apply changes
	if err := s.applyChanges(routesToAdd, routesToRemove); err != nil {
		return fmt.Errorf("failed to apply route changes: %w", err)
	}

	log.Printf("Route synchronization completed: added %d, removed %d",
		len(routesToAdd), len(routesToRemove))
	return nil
}

// getKernelRoutes gets routes from kernel routing tables
func (s *RouteSynchronizer) getKernelRoutes() ([]Route, error) {
	return nil, fmt.Errorf("kernel route discovery is not supported by RouteSynchronizer; use SyncRoute with explicit route details or add a real kernel route source")
}

// getCiliumRoutes gets routes from Cilium's eBPF maps
func (s *RouteSynchronizer) getCiliumRoutes() ([]Route, error) {
	return s.client.ListRoutes(s.ctx)
}

// calculateDiff calculates which routes need to be added or removed
func (s *RouteSynchronizer) calculateDiff(kernelRoutes, ciliumRoutes []Route) ([]Route, []Route) {
	kernelByKey := make(map[string]Route, len(kernelRoutes))
	for _, route := range kernelRoutes {
		kernelByKey[routeSyncKey(route)] = route
	}

	ciliumByKey := make(map[string]Route, len(ciliumRoutes))
	for _, route := range ciliumRoutes {
		ciliumByKey[routeSyncKey(route)] = route
	}

	routesToAdd := make([]Route, 0)
	for key, route := range kernelByKey {
		if _, exists := ciliumByKey[key]; !exists {
			routesToAdd = append(routesToAdd, route)
		}
	}

	routesToRemove := make([]Route, 0)
	for key, route := range ciliumByKey {
		if _, exists := kernelByKey[key]; !exists {
			routesToRemove = append(routesToRemove, route)
		}
	}

	return routesToAdd, routesToRemove
}

func routeSyncKey(route Route) string {
	return fmt.Sprintf(
		"%s|gw=%s|out=%s|in=%s|table=%d|prio=%d|type=%s|vrf=%s",
		routeNameForRoute(route),
		normalizeRouteGateway(route.Gateway),
		route.OutputIface,
		route.InputIface,
		route.Table,
		route.Priority,
		route.Type,
		route.VRF,
	)
}

// applyChanges applies route changes to Cilium
func (s *RouteSynchronizer) applyChanges(routesToAdd, routesToRemove []Route) error {
	// Apply route changes to Cilium
	for _, route := range routesToAdd {
		if err := s.addRouteToCilium(route); err != nil {
			return fmt.Errorf("failed to add route to Cilium: %w", err)
		}
	}

	for _, route := range routesToRemove {
		if err := s.removeRouteFromCilium(route); err != nil {
			return fmt.Errorf("failed to remove route from Cilium: %w", err)
		}
	}

	return nil
}

// addRouteToCilium adds a route to Cilium
func (s *RouteSynchronizer) addRouteToCilium(route Route) error {
	return s.client.AddRoute(route)
}

// removeRouteFromCilium removes a route from Cilium
func (s *RouteSynchronizer) removeRouteFromCilium(route Route) error {
	return s.client.DeleteRoute(route)
}

// SyncRoutesForVRF synchronizes routes for a specific VRF
func (s *RouteSynchronizer) SyncRoutesForVRF(ctx context.Context, vrfID int) error {
	// Get routes for the specific VRF
	vrfRoutes, err := s.getRoutesForVRF(ctx, vrfID)
	if err != nil {
		return fmt.Errorf("failed to get routes for VRF %d: %w", vrfID, err)
	}

	// Apply VRF routes to Cilium with VRF-specific policy
	for _, route := range vrfRoutes {
		if err := s.addVRFRouteToCilium(route, vrfID); err != nil {
			return fmt.Errorf("failed to add VRF route to Cilium: %w", err)
		}
	}

	return nil
}

// getRoutesForVRF gets routes for a specific VRF
func (s *RouteSynchronizer) getRoutesForVRF(ctx context.Context, vrfID int) ([]Route, error) {
	return s.client.ListVRFRoutes(ctx, vrfID)
}

// addVRFRouteToCilium adds a VRF route to Cilium
func (s *RouteSynchronizer) addVRFRouteToCilium(route Route, vrfID int) error {
	return s.client.AddVRFRoute(route, vrfID)
}

// SyncRoute synchronizes a single route with Cilium
func (s *RouteSynchronizer) SyncRoute(ctx context.Context, routeSync *RouteSync) error {
	log.Printf("Synchronizing route %s/%s with action %s", routeSync.Namespace, routeSync.Name, routeSync.Action)

	// Handle the action
	switch routeSync.Action {
	case RouteSyncActionUpsert:
		// If the route is provided directly, use it
		if routeSync.Route.Destination != nil {
			route := routeSync.Route
			if routeSync.VRF != "" {
				route.VRF = routeSync.VRF
			}
			return s.addRouteToCilium(route)
		}

		// Otherwise, construct a route from the provided fields
		if routeSync.Destination != "" {
			_, destination, err := net.ParseCIDR(routeSync.Destination)
			if err != nil {
				return fmt.Errorf("invalid destination CIDR %s: %w", routeSync.Destination, err)
			}

			route := Route{
				Destination: destination,
				Gateway:     routeSync.Gateway,
				OutputIface: routeSync.Interface,
				Priority:    routeSync.Metric,
				Table:       routeSync.TableID,
				Type:        "static",
				VRF:         routeSync.VRF,
			}
			return s.addRouteToCilium(route)
		}

		return fmt.Errorf("no route information provided for upsert action")

	case RouteSyncActionDelete:
		// For deletion, we need to construct a route key to identify the route
		// This could be based on the namespace/name or destination/gateway/interface
		routeKey := fmt.Sprintf("%s/%s", routeSync.Namespace, routeSync.Name)
		log.Printf("Deleting route with key: %s", routeKey)

		// For an actual implementation, we would need to look up the route details
		// from a state store or from Cilium to get the full route object

		// If we have the destination CIDR, we can construct a partial route object
		if routeSync.Route.Destination != nil {
			route := routeSync.Route
			if routeSync.VRF != "" && route.VRF == "" {
				route.VRF = routeSync.VRF
			}
			return s.removeRouteFromCilium(route)
		} else if routeSync.Destination != "" {
			_, destination, err := net.ParseCIDR(routeSync.Destination)
			if err != nil {
				return fmt.Errorf("invalid destination CIDR %s: %w", routeSync.Destination, err)
			}

			route := Route{
				Destination: destination,
				Gateway:     routeSync.Gateway,
				OutputIface: routeSync.Interface,
				Table:       routeSync.TableID,
				VRF:         routeSync.VRF,
			}

			return s.removeRouteFromCilium(route)
		}

		return fmt.Errorf("route deletion requires destination or full route details; namespace/name lookup for %s is not implemented", routeKey)

	default:
		return fmt.Errorf("unknown action: %s", routeSync.Action)
	}
}
