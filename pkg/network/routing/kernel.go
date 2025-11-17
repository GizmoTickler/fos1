package routing

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// KernelRouteManager manages routes using netlink
type KernelRouteManager struct {
	// routeUpdateChan receives route updates from the kernel
	routeUpdateChan chan netlink.RouteUpdate
	// done signals when to stop monitoring
	done chan struct{}
	// routeUpdateCallbacks are callbacks for route updates
	routeUpdateCallbacks []func(netlink.RouteUpdate)
}

// NewKernelRouteManager creates a new kernel route manager
func NewKernelRouteManager() *KernelRouteManager {
	return &KernelRouteManager{
		routeUpdateChan:      make(chan netlink.RouteUpdate),
		done:                 make(chan struct{}),
		routeUpdateCallbacks: make([]func(netlink.RouteUpdate), 0),
	}
}

// Start begins monitoring route changes
func (m *KernelRouteManager) Start(ctx context.Context) error {
	// Subscribe to route updates
	if err := netlink.RouteSubscribe(m.routeUpdateChan, m.done); err != nil {
		return fmt.Errorf("failed to subscribe to route updates: %w", err)
	}

	// Start monitoring goroutine
	go m.monitorRoutes(ctx)

	klog.Info("Kernel route manager started")
	return nil
}

// Stop stops monitoring route changes
func (m *KernelRouteManager) Stop() {
	close(m.done)
	klog.Info("Kernel route manager stopped")
}

// RegisterRouteUpdateCallback registers a callback for route updates
func (m *KernelRouteManager) RegisterRouteUpdateCallback(callback func(netlink.RouteUpdate)) {
	m.routeUpdateCallbacks = append(m.routeUpdateCallbacks, callback)
}

// monitorRoutes monitors route changes and invokes callbacks
func (m *KernelRouteManager) monitorRoutes(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			klog.Info("Route monitoring stopped due to context cancellation")
			return
		case <-m.done:
			klog.Info("Route monitoring stopped")
			return
		case update := <-m.routeUpdateChan:
			klog.V(4).Infof("Route update received: dst=%s type=%d", update.Route.Dst, update.Type)
			// Invoke all registered callbacks
			for _, callback := range m.routeUpdateCallbacks {
				callback(update)
			}
		}
	}
}

// AddRoute adds a route to the kernel routing table
func (m *KernelRouteManager) AddRoute(route Route) error {
	netlinkRoute, err := m.routeToNetlink(route)
	if err != nil {
		return fmt.Errorf("failed to convert route to netlink: %w", err)
	}

	// Handle multi-path routes (ECMP)
	if len(route.NextHops) > 1 {
		return m.addECMPRoute(route)
	}

	// Add the route
	if err := netlink.RouteAdd(netlinkRoute); err != nil {
		// Check if route already exists
		if err == syscall.EEXIST {
			klog.V(4).Infof("Route to %s already exists, replacing it", route.Destination)
			if err := netlink.RouteReplace(netlinkRoute); err != nil {
				return fmt.Errorf("failed to replace route to %s: %w", route.Destination, err)
			}
			return nil
		}
		return fmt.Errorf("failed to add route to %s: %w", route.Destination, err)
	}

	klog.Infof("Added route to %s via %s (metric: %d, table: %s)",
		route.Destination,
		route.NextHops[0].Address,
		route.Metric,
		route.Table)
	return nil
}

// addECMPRoute adds a multi-path (ECMP) route
func (m *KernelRouteManager) addECMPRoute(route Route) error {
	klog.V(4).Infof("Adding ECMP route to %s with %d next hops", route.Destination, len(route.NextHops))

	// Parse destination
	_, dst, err := net.ParseCIDR(route.Destination)
	if err != nil {
		return fmt.Errorf("invalid destination %s: %w", route.Destination, err)
	}

	// Create multi-path route
	netlinkRoute := &netlink.Route{
		Dst:      dst,
		Priority: route.Metric,
		Table:    m.getTableID(route.Table),
		Scope:    m.getScopeID(route.Scope),
		Protocol: m.getProtocolID(route.Protocol),
	}

	// Add all next hops
	for _, nextHop := range route.NextHops {
		var gw net.IP
		if nextHop.Address != "" {
			gw = net.ParseIP(nextHop.Address)
			if gw == nil {
				return fmt.Errorf("invalid next hop address: %s", nextHop.Address)
			}
		}

		// Get link index if interface is specified
		var linkIndex int
		if nextHop.Interface != "" {
			link, err := netlink.LinkByName(nextHop.Interface)
			if err != nil {
				return fmt.Errorf("failed to get link %s: %w", nextHop.Interface, err)
			}
			linkIndex = link.Attrs().Index
		}

		// Create next hop
		nh := &netlink.NexthopInfo{
			Gw:       gw,
			LinkIndex: linkIndex,
			Hops:     nextHop.Weight,
		}
		netlinkRoute.MultiPath = append(netlinkRoute.MultiPath, nh)
	}

	// Add the multi-path route
	if err := netlink.RouteAdd(netlinkRoute); err != nil {
		if err == syscall.EEXIST {
			klog.V(4).Infof("ECMP route to %s already exists, replacing it", route.Destination)
			if err := netlink.RouteReplace(netlinkRoute); err != nil {
				return fmt.Errorf("failed to replace ECMP route to %s: %w", route.Destination, err)
			}
			return nil
		}
		return fmt.Errorf("failed to add ECMP route to %s: %w", route.Destination, err)
	}

	klog.Infof("Added ECMP route to %s with %d next hops", route.Destination, len(route.NextHops))
	return nil
}

// DeleteRoute removes a route from the kernel routing table
func (m *KernelRouteManager) DeleteRoute(destination string, routeParams RouteParams) error {
	// Parse destination
	_, dst, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination %s: %w", destination, err)
	}

	// Create route structure for deletion
	netlinkRoute := &netlink.Route{
		Dst:   dst,
		Table: m.getTableID(routeParams.Table),
	}

	// Delete the route
	if err := netlink.RouteDel(netlinkRoute); err != nil {
		if err == syscall.ESRCH {
			// Route doesn't exist, that's okay
			klog.V(4).Infof("Route to %s doesn't exist in kernel", destination)
			return nil
		}
		return fmt.Errorf("failed to delete route to %s: %w", destination, err)
	}

	klog.Infof("Deleted route to %s from table %s", destination, routeParams.Table)
	return nil
}

// GetRoute retrieves a route from the kernel routing table
func (m *KernelRouteManager) GetRoute(destination string, routeParams RouteParams) (*Route, error) {
	// Parse destination
	_, dst, err := net.ParseCIDR(destination)
	if err != nil {
		return nil, fmt.Errorf("invalid destination %s: %w", destination, err)
	}

	// Get route from kernel
	routes, err := netlink.RouteGet(dst.IP)
	if err != nil {
		return nil, fmt.Errorf("failed to get route to %s: %w", destination, err)
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("no route found to %s", destination)
	}

	// Convert the first route to our Route type
	return m.netlinkToRoute(&routes[0]), nil
}

// ListRoutes lists routes from the kernel routing table
func (m *KernelRouteManager) ListRoutes(filter RouteFilter) ([]*Route, error) {
	// Determine which link to filter by
	var link netlink.Link
	var err error

	// Get all routes
	var netlinkRoutes []netlink.Route

	tableID := m.getTableID(filter.Table)

	// List routes by table
	if link != nil {
		netlinkRoutes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
	} else {
		// Get all routes with specified table filter
		filterMask := netlink.RT_FILTER_TABLE
		if tableID > 0 {
			netlinkRoutes, err = netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: tableID}, filterMask)
		} else {
			// Get all routes (main table)
			netlinkRoutes, err = netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, filterMask)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	// Convert netlink routes to our Route type
	var routes []*Route
	for i := range netlinkRoutes {
		route := m.netlinkToRoute(&netlinkRoutes[i])

		// Apply filters
		if m.routeMatchesFilter(route, filter) {
			routes = append(routes, route)
		}
	}

	return routes, nil
}

// GetRoutingTable retrieves all routes from a specific routing table
func (m *KernelRouteManager) GetRoutingTable(tableName string, vrf string) ([]*Route, error) {
	tableID := m.getTableID(tableName)

	// List routes by table
	filterMask := netlink.RT_FILTER_TABLE
	netlinkRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: tableID}, filterMask)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes for table %s: %w", tableName, err)
	}

	// Convert netlink routes to our Route type
	var routes []*Route
	for i := range netlinkRoutes {
		route := m.netlinkToRoute(&netlinkRoutes[i])

		// Filter by VRF if specified
		if vrf != "" && route.VRF != vrf {
			continue
		}

		routes = append(routes, route)
	}

	return routes, nil
}

// routeToNetlink converts our Route type to netlink.Route
func (m *KernelRouteManager) routeToNetlink(route Route) (*netlink.Route, error) {
	// Parse destination
	_, dst, err := net.ParseCIDR(route.Destination)
	if err != nil {
		return nil, fmt.Errorf("invalid destination %s: %w", route.Destination, err)
	}

	netlinkRoute := &netlink.Route{
		Dst:      dst,
		Priority: route.Metric,
		Table:    m.getTableID(route.Table),
		Scope:    m.getScopeID(route.Scope),
		Protocol: m.getProtocolID(route.Protocol),
	}

	// Add next hop if specified
	if len(route.NextHops) > 0 {
		nextHop := route.NextHops[0]

		if nextHop.Address != "" {
			gw := net.ParseIP(nextHop.Address)
			if gw == nil {
				return nil, fmt.Errorf("invalid next hop address: %s", nextHop.Address)
			}
			netlinkRoute.Gw = gw
		}

		// Get link index if interface is specified
		if nextHop.Interface != "" {
			link, err := netlink.LinkByName(nextHop.Interface)
			if err != nil {
				return nil, fmt.Errorf("failed to get link %s: %w", nextHop.Interface, err)
			}
			netlinkRoute.LinkIndex = link.Attrs().Index
		}
	}

	return netlinkRoute, nil
}

// netlinkToRoute converts netlink.Route to our Route type
func (m *KernelRouteManager) netlinkToRoute(netlinkRoute *netlink.Route) *Route {
	route := &Route{
		Metric:   netlinkRoute.Priority,
		Table:    m.getTableName(netlinkRoute.Table),
		Scope:    m.getScopeName(netlinkRoute.Scope),
		Protocol: m.getProtocolName(netlinkRoute.Protocol),
	}

	// Set destination
	if netlinkRoute.Dst != nil {
		route.Destination = netlinkRoute.Dst.String()
	}

	// Handle multi-path routes
	if len(netlinkRoute.MultiPath) > 0 {
		for _, nh := range netlinkRoute.MultiPath {
			nextHop := NextHop{
				Weight: nh.Hops,
			}

			if nh.Gw != nil {
				nextHop.Address = nh.Gw.String()
			}

			if nh.LinkIndex > 0 {
				link, err := netlink.LinkByIndex(nh.LinkIndex)
				if err == nil {
					nextHop.Interface = link.Attrs().Name
				}
			}

			route.NextHops = append(route.NextHops, nextHop)
		}
	} else {
		// Single next hop
		nextHop := NextHop{}

		if netlinkRoute.Gw != nil {
			nextHop.Address = netlinkRoute.Gw.String()
		}

		if netlinkRoute.LinkIndex > 0 {
			link, err := netlink.LinkByIndex(netlinkRoute.LinkIndex)
			if err == nil {
				nextHop.Interface = link.Attrs().Name
			}
		}

		if nextHop.Address != "" || nextHop.Interface != "" {
			route.NextHops = append(route.NextHops, nextHop)
		}
	}

	return route
}

// getTableID converts table name to table ID
func (m *KernelRouteManager) getTableID(tableName string) int {
	if tableName == "" || tableName == "main" {
		return unix.RT_TABLE_MAIN
	}
	if tableName == "local" {
		return unix.RT_TABLE_LOCAL
	}
	if tableName == "default" {
		return unix.RT_TABLE_DEFAULT
	}
	// For custom tables, we'd need to parse the ID or look it up
	// For now, assume main table
	return unix.RT_TABLE_MAIN
}

// getTableName converts table ID to table name
func (m *KernelRouteManager) getTableName(tableID int) string {
	switch tableID {
	case unix.RT_TABLE_MAIN:
		return "main"
	case unix.RT_TABLE_LOCAL:
		return "local"
	case unix.RT_TABLE_DEFAULT:
		return "default"
	default:
		return fmt.Sprintf("table_%d", tableID)
	}
}

// getScopeID converts scope name to scope ID
func (m *KernelRouteManager) getScopeID(scopeName string) netlink.Scope {
	switch scopeName {
	case "global":
		return netlink.SCOPE_UNIVERSE
	case "site":
		return netlink.SCOPE_SITE
	case "link":
		return netlink.SCOPE_LINK
	case "host":
		return netlink.SCOPE_HOST
	default:
		return netlink.SCOPE_UNIVERSE
	}
}

// getScopeName converts scope ID to scope name
func (m *KernelRouteManager) getScopeName(scope netlink.Scope) string {
	switch scope {
	case netlink.SCOPE_UNIVERSE:
		return "global"
	case netlink.SCOPE_SITE:
		return "site"
	case netlink.SCOPE_LINK:
		return "link"
	case netlink.SCOPE_HOST:
		return "host"
	default:
		return "global"
	}
}

// getProtocolID converts protocol name to protocol ID
func (m *KernelRouteManager) getProtocolID(protocolName string) netlink.RouteProtocol {
	switch protocolName {
	case "kernel":
		return netlink.RouteProtocol(unix.RTPROT_KERNEL)
	case "boot":
		return netlink.RouteProtocol(unix.RTPROT_BOOT)
	case "static":
		return netlink.RouteProtocol(unix.RTPROT_STATIC)
	case "bgp":
		return netlink.RouteProtocol(unix.RTPROT_BGP)
	case "ospf":
		return netlink.RouteProtocol(unix.RTPROT_OSPF)
	default:
		return netlink.RouteProtocol(unix.RTPROT_STATIC)
	}
}

// getProtocolName converts protocol ID to protocol name
func (m *KernelRouteManager) getProtocolName(protocolID netlink.RouteProtocol) string {
	switch int(protocolID) {
	case unix.RTPROT_KERNEL:
		return "kernel"
	case unix.RTPROT_BOOT:
		return "boot"
	case unix.RTPROT_STATIC:
		return "static"
	case unix.RTPROT_BGP:
		return "bgp"
	case unix.RTPROT_OSPF:
		return "ospf"
	default:
		return "static"
	}
}

// routeMatchesFilter checks if a route matches the given filter
func (m *KernelRouteManager) routeMatchesFilter(route *Route, filter RouteFilter) bool {
	// Destination filter
	if filter.Destination != "" && route.Destination != filter.Destination {
		return false
	}

	// NextHop filter
	if filter.NextHop != "" {
		match := false
		for _, nextHop := range route.NextHops {
			if nextHop.Address == filter.NextHop {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	// Protocol filter
	if filter.Protocol != "" && route.Protocol != filter.Protocol {
		return false
	}

	// VRF filter
	if filter.VRF != "" && route.VRF != filter.VRF {
		return false
	}

	// Tag filter
	if filter.Tag != "" {
		match := false
		for _, tag := range route.Tags {
			if tag == filter.Tag {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	return true
}
