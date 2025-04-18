// Package wan provides functionality for managing WAN interfaces.
package wan

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/varuntirumala1/fos1/pkg/hardware/types"
)

// Manager implements the types.WANManager interface.
type Manager struct {
	wanInterfaces map[string]*wanInterface
	wanMu         sync.RWMutex
	activeWAN     string
	monitorCtx    context.Context
	monitorCancel context.CancelFunc
}

// wanInterface represents a WAN interface.
type wanInterface struct {
	config     types.WANInterfaceConfig
	status     types.WANStatus
	monitoring bool
}

// NewManager creates a new WAN Manager.
func NewManager() (*Manager, error) {
	return &Manager{
		wanInterfaces: make(map[string]*wanInterface),
	}, nil
}

// Initialize initializes the WAN Manager.
func (m *Manager) Initialize(ctx context.Context) error {
	// Create monitoring context
	m.monitorCtx, m.monitorCancel = context.WithCancel(context.Background())
	return nil
}

// Shutdown shuts down the WAN Manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	// Cancel monitoring
	if m.monitorCancel != nil {
		m.monitorCancel()
	}
	return nil
}

// AddWANInterface adds a new WAN interface.
func (m *Manager) AddWANInterface(config types.WANInterfaceConfig) error {
	// Validate interface exists
	if _, err := netlink.LinkByName(config.Name); err != nil {
		return fmt.Errorf("interface %s not found: %w", config.Name, err)
	}

	// Create WAN interface
	wan := &wanInterface{
		config: config,
		status: types.WANStatus{
			Name:            config.Name,
			State:           "initializing",
			LastStateChange: time.Now().Format(time.RFC3339),
			Active:          false,
		},
	}

	m.wanMu.Lock()
	defer m.wanMu.Unlock()

	// Store WAN interface
	m.wanInterfaces[config.Name] = wan

	// If this is the first WAN interface, make it active
	if len(m.wanInterfaces) == 1 || config.Weight > 0 {
		if m.activeWAN == "" {
			m.activeWAN = config.Name
			wan.status.Active = true
			wan.status.State = "active"
		}
	}

	// Start monitoring if enabled
	if config.MonitorEnabled {
		go m.monitorWANInterface(m.monitorCtx, wan)
	}

	return nil
}

// RemoveWANInterface removes a WAN interface.
func (m *Manager) RemoveWANInterface(name string) error {
	m.wanMu.Lock()
	defer m.wanMu.Unlock()

	wan, ok := m.wanInterfaces[name]
	if !ok {
		return fmt.Errorf("WAN interface %s not found", name)
	}

	// If this is the active WAN, select a new active WAN
	if m.activeWAN == name {
		m.activeWAN = ""
		wan.status.Active = false

		// Find highest weight WAN interface
		var bestWAN string
		var bestWeight int
		for ifName, iface := range m.wanInterfaces {
			if ifName != name && iface.config.Weight > bestWeight {
				bestWAN = ifName
				bestWeight = iface.config.Weight
			}
		}

		if bestWAN != "" {
			m.activeWAN = bestWAN
			m.wanInterfaces[bestWAN].status.Active = true
			m.wanInterfaces[bestWAN].status.State = "active"
		}
	}

	// Remove WAN interface
	delete(m.wanInterfaces, name)

	return nil
}

// GetWANStatus gets the status of a WAN interface.
func (m *Manager) GetWANStatus(name string) (*types.WANStatus, error) {
	m.wanMu.RLock()
	defer m.wanMu.RUnlock()

	wan, ok := m.wanInterfaces[name]
	if !ok {
		return nil, fmt.Errorf("WAN interface %s not found", name)
	}

	return &wan.status, nil
}

// GetWANInterface gets information about a WAN interface.
func (m *Manager) GetWANInterface(name string) (*types.WANInterfaceInfo, error) {
	m.wanMu.RLock()
	defer m.wanMu.RUnlock()

	wan, ok := m.wanInterfaces[name]
	if !ok {
		return nil, fmt.Errorf("WAN interface %s not found", name)
	}

	// Create interface info
	info := &types.WANInterfaceInfo{
		Name:              wan.config.Name,
		Type:              wan.config.Type,
		PhysicalInterface: wan.config.PhysicalInterface,
		State:             wan.status.State,
		MTU:               wan.config.MTU,
		Weight:            wan.config.Weight,
		Priority:          wan.config.Priority,
		Gateway:           wan.config.Gateway,
		DNS:               wan.config.DNS,
		Metric:            wan.config.Metric,
		Statistics: types.WANStatistics{
			RxPackets:            wan.status.PacketsReceived,
			TxPackets:            wan.status.PacketsSent,
			RxBytes:              wan.status.BytesReceived,
			TxBytes:              wan.status.BytesSent,
			RxErrors:             0,
			TxErrors:             0,
			Uptime:               0,
			ConnectionCount:      0,
			LastConnectedTime:    0,
			LastDisconnectedTime: 0,
		},
	}

	return info, nil
}

// SetActiveWAN sets the active WAN interface.
func (m *Manager) SetActiveWAN(name string) error {
	m.wanMu.Lock()
	defer m.wanMu.Unlock()

	wan, ok := m.wanInterfaces[name]
	if !ok {
		return fmt.Errorf("WAN interface %s not found", name)
	}

	// Update current active WAN
	if m.activeWAN != "" && m.activeWAN != name {
		currentWAN, ok := m.wanInterfaces[m.activeWAN]
		if ok {
			currentWAN.status.Active = false
			currentWAN.status.State = "standby"
		}
	}

	// Set new active WAN
	m.activeWAN = name
	wan.status.Active = true
	wan.status.State = "active"
	wan.status.LastStateChange = time.Now().Format(time.RFC3339)

	// Setup routing (implement actual routing changes)
	if err := m.setupActiveWANRouting(name); err != nil {
		return fmt.Errorf("failed to setup routing: %w", err)
	}

	return nil
}

// ListWANInterfaces lists all WAN interfaces.
func (m *Manager) ListWANInterfaces() ([]string, error) {
	m.wanMu.RLock()
	defer m.wanMu.RUnlock()

	wans := make([]string, 0, len(m.wanInterfaces))
	for name := range m.wanInterfaces {
		wans = append(wans, name)
	}

	return wans, nil
}

// ListWANInterfaceStatuses lists all WAN interface statuses.
func (m *Manager) ListWANInterfaceStatuses() ([]types.WANInterfaceStatus, error) {
	m.wanMu.RLock()
	defer m.wanMu.RUnlock()

	wans := make([]types.WANInterfaceStatus, 0, len(m.wanInterfaces))
	for _, wan := range m.wanInterfaces {
		wans = append(wans, types.WANInterfaceStatus{
			Name:            wan.config.Name,
			State:           wan.status.State,
			LastStateChange: wan.status.LastStateChange,
			Active:          wan.status.Active,
		})
	}

	return wans, nil
}

// SetWANInterfaceState sets the state of a WAN interface.
func (m *Manager) SetWANInterfaceState(name string, up bool) error {
	m.wanMu.Lock()
	defer m.wanMu.Unlock()

	wan, ok := m.wanInterfaces[name]
	if !ok {
		return fmt.Errorf("WAN interface %s not found", name)
	}

	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", name, err)
	}

	// Set the link state
	if up {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to set link %s up: %w", name, err)
		}
		wan.status.State = "up"
	} else {
		if err := netlink.LinkSetDown(link); err != nil {
			return fmt.Errorf("failed to set link %s down: %w", name, err)
		}
		wan.status.State = "down"
	}

	wan.status.LastStateChange = time.Now().Format(time.RFC3339)

	return nil
}

// StartMonitoring starts monitoring WAN interfaces.
func (m *Manager) StartMonitoring(ctx context.Context) error {
	m.wanMu.RLock()
	defer m.wanMu.RUnlock()

	for _, wan := range m.wanInterfaces {
		if wan.config.MonitorEnabled && !wan.monitoring {
			go m.monitorWANInterface(m.monitorCtx, wan)
		}
	}

	return nil
}

// monitorWANInterface monitors a WAN interface.
func (m *Manager) monitorWANInterface(ctx context.Context, wan *wanInterface) {
	wan.monitoring = true
	defer func() {
		wan.monitoring = false
	}()

	// Set default interval if not specified
	interval := wan.config.MonitorInterval
	if interval <= 0 {
		interval = 10 // Default to 10 seconds
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	// Use the configured monitor targets or default to gateway and 8.8.8.8
	targets := wan.config.MonitorTargets
	if len(targets) == 0 {
		targets = []string{wan.config.Gateway, "8.8.8.8"}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check connectivity
			state, latency, packetLoss, jitter := m.checkConnectivity(wan.config.Name, targets)

			m.wanMu.Lock()
			// Update status
			oldState := wan.status.State
			wan.status.State = state
			wan.status.Latency = latency
			wan.status.PacketLoss = packetLoss
			wan.status.Jitter = jitter

			// Handle state changes
			if oldState != state {
				wan.status.LastStateChange = time.Now().Format(time.RFC3339)

				// If this WAN was active and is now down, trigger failover
				if wan.status.Active && state == "down" {
					m.handleWANFailover(wan.config.Name)
				}

				// If this WAN is now up and it has higher weight than current active, trigger failover
				if state == "up" && !wan.status.Active && wan.config.Failover {
					activeWAN, ok := m.wanInterfaces[m.activeWAN]
					if !ok || activeWAN.config.Weight < wan.config.Weight {
						m.handleWANFailover("")
					}
				}
			}
			m.wanMu.Unlock()
		}
	}
}

// checkConnectivity checks the connectivity of a WAN interface.
func (m *Manager) checkConnectivity(ifName string, targets []string) (string, int, float64, int) {
	var totalLatency int
	var totalJitter int
	var successCount int
	var totalPackets int

	for _, target := range targets {
		// Skip empty targets
		if target == "" {
			continue
		}

		// Ping target
		cmd := exec.Command("ping", "-c", "3", "-I", ifName, target)
		output, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}

		// Parse ping output
		latency, jitter, packets := parsePingOutput(string(output))
		totalLatency += latency
		totalJitter += jitter
		successCount++
		totalPackets += packets
	}

	// Calculate average values
	var avgLatency int
	var avgJitter int
	var packetLoss float64

	if successCount > 0 {
		avgLatency = totalLatency / successCount
		avgJitter = totalJitter / successCount
	}

	if totalPackets > 0 {
		packetLoss = 100.0 * (1.0 - float64(successCount*3)/float64(totalPackets))
	} else {
		packetLoss = 100.0
	}

	// Determine state based on connectivity
	var state string
	if successCount == 0 {
		state = "down"
	} else if packetLoss > 50 {
		state = "degraded"
	} else {
		state = "up"
	}

	return state, avgLatency, packetLoss, avgJitter
}

// handleWANFailover handles WAN failover.
func (m *Manager) handleWANFailover(excludeWAN string) {
	// Find highest weight WAN interface that is up
	var bestWAN string
	var bestWeight int

	for ifName, iface := range m.wanInterfaces {
		if ifName != excludeWAN && iface.status.State == "up" && iface.config.Weight > bestWeight {
			bestWAN = ifName
			bestWeight = iface.config.Weight
		}
	}

	// If found a better WAN, switch to it
	if bestWAN != "" && bestWAN != m.activeWAN {
		// Update current active WAN
		if m.activeWAN != "" {
			currentWAN, ok := m.wanInterfaces[m.activeWAN]
			if ok {
				currentWAN.status.Active = false
				if currentWAN.status.State != "down" {
					currentWAN.status.State = "standby"
				}
			}
		}

		// Set new active WAN
		m.activeWAN = bestWAN
		m.wanInterfaces[bestWAN].status.Active = true
		m.wanInterfaces[bestWAN].status.State = "active"
		m.wanInterfaces[bestWAN].status.LastStateChange = time.Now().Format(time.RFC3339)

		// Setup routing (implement actual routing changes)
		if err := m.setupActiveWANRouting(bestWAN); err != nil {
			fmt.Printf("Failed to setup routing for WAN %s: %v\n", bestWAN, err)
		}
	}
}

// setupActiveWANRouting sets up routing for the active WAN.
func (m *Manager) setupActiveWANRouting(name string) error {
	// Get the WAN interface
	wan, ok := m.wanInterfaces[name]
	if !ok {
		return fmt.Errorf("WAN interface %s not found", name)
	}

	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", name, err)
	}

	// Get the gateway
	gateway := wan.config.Gateway

	// If gateway is not specified, try to find it from interface routes
	if gateway == "" {
		routes, err := netlink.RouteList(link, unix.AF_INET)
		if err != nil {
			return fmt.Errorf("failed to list routes: %w", err)
		}

		for _, route := range routes {
			if route.Dst == nil || route.Dst.IP.Equal(net.IPv4zero) {
				gateway = route.Gw.String()
				break
			}
		}

		if gateway == "" {
			return fmt.Errorf("failed to find gateway for interface %s", name)
		}
	}

	// Delete existing default route
	existingRoutes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}

	for _, route := range existingRoutes {
		if route.Dst == nil || route.Dst.IP.Equal(net.IPv4zero) {
			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("failed to delete default route: %w", err)
			}
		}
	}

	// Create new default route
	_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
	gatewayIP := net.ParseIP(gateway)

	route := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       defaultDst,
		Gw:        gatewayIP,
	}

	if err := netlink.RouteAdd(&route); err != nil {
		return fmt.Errorf("failed to add default route: %w", err)
	}

	return nil
}

// GetWANStatistics gets statistics for a WAN interface.
func (m *Manager) GetWANStatistics(name string) (*types.WANStatistics, error) {
	m.wanMu.RLock()
	defer m.wanMu.RUnlock()

	_, ok := m.wanInterfaces[name]
	if !ok {
		return nil, fmt.Errorf("WAN interface %s not found", name)
	}

	// Get link statistics
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get link %s: %w", name, err)
	}

	stats := link.Attrs().Statistics
	if stats == nil {
		stats = &netlink.LinkStatistics{}
	}

	// Create statistics
	return &types.WANStatistics{
		RxPackets:            stats.RxPackets,
		TxPackets:            stats.TxPackets,
		RxBytes:              stats.RxBytes,
		TxBytes:              stats.TxBytes,
		RxErrors:             stats.RxErrors,
		TxErrors:             stats.TxErrors,
		Uptime:               0, // Not implemented yet
		ConnectionCount:      0, // Not implemented yet
		LastConnectedTime:    0, // Not implemented yet
		LastDisconnectedTime: 0, // Not implemented yet
	}, nil
}

// TestWANConnectivity tests connectivity for a WAN interface.
func (m *Manager) TestWANConnectivity(name string) (*types.WANConnectivityResult, error) {
	m.wanMu.RLock()
	wan, ok := m.wanInterfaces[name]
	if !ok {
		m.wanMu.RUnlock()
		return nil, fmt.Errorf("WAN interface %s not found", name)
	}

	// Use the configured monitor targets or default to gateway and 8.8.8.8
	targets := wan.config.MonitorTargets
	if len(targets) == 0 {
		targets = []string{wan.config.Gateway, "8.8.8.8"}
	}
	m.wanMu.RUnlock()

	// Test connectivity
	state, latency, packetLoss, _ := m.checkConnectivity(name, targets)

	// Create result
	result := &types.WANConnectivityResult{
		Success:    state == "up",
		Latency:    latency,
		PacketLoss: packetLoss,
		DNSLatency: 0, // Not implemented yet
		Bandwidth:  0, // Not implemented yet
	}

	if state == "down" {
		result.Error = "Interface is down or unreachable"
	} else if state == "degraded" {
		result.Error = "Interface has high packet loss"
	}

	return result, nil
}

// parsePingOutput parses ping output to extract latency, jitter, and packet count.
func parsePingOutput(output string) (int, int, int) {
	var latency int
	var jitter int
	var packets int

	// Count packets
	if strings.Contains(output, "packets transmitted") {
		parts := strings.Split(output, "packets transmitted")
		if len(parts) > 0 {
			packetStr := strings.TrimSpace(strings.Split(parts[0], " ")[0])
			if p, err := strconv.Atoi(packetStr); err == nil {
				packets = p
			}
		}
	}

	// Get latency
	if strings.Contains(output, "min/avg/max") {
		parts := strings.Split(output, "min/avg/max")
		if len(parts) > 1 {
			statsParts := strings.Split(parts[1], "=")
			if len(statsParts) > 1 {
				stats := strings.TrimSpace(statsParts[1])
				statValues := strings.Split(stats, "/")
				if len(statValues) > 2 {
					if avg, err := strconv.ParseFloat(statValues[1], 64); err == nil {
						latency = int(avg)
					}
					if mdev, err := strconv.ParseFloat(statValues[3], 64); err == nil {
						jitter = int(mdev)
					}
				}
			}
		}
	}

	return latency, jitter, packets
}
