//go:build linux

// Package nic provides functionality for managing network interfaces.
package nic

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// ethtoolClient is the subset of github.com/safchain/ethtool used by the NIC
// manager. It exists purely as a mocking seam for unit tests, mirroring the
// pattern established in pkg/hardware/offload/manager.go.
type ethtoolClient interface {
	Features(string) (map[string]bool, error)
	Change(string, map[string]bool) error
	Stats(string) (map[string]uint64, error)
	DriverName(string) (string, error)
	Close()
}

// linkProvider is the subset of netlink used by the NIC manager, factored into
// an interface so tests can inject deterministic link statistics without
// needing CAP_NET_ADMIN.
type linkProvider interface {
	LinkByName(name string) (netlink.Link, error)
}

type defaultLinkProvider struct{}

func (defaultLinkProvider) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

// Manager implements the types.NICManager interface.
type Manager struct {
	interfaces     map[string]*types.NetworkInterface
	interfacesMu   sync.RWMutex
	monitoringDone chan struct{}
	ethtool        ethtoolClient
	links          linkProvider
}

// NewManager creates a new NIC Manager wired to the real ethtool and netlink
// handles. It returns an explicit error if the ethtool netlink socket cannot
// be opened (for example, when running as a non-root user in a restricted
// namespace).
func NewManager() (*Manager, error) {
	ethtoolHandler, err := ethtool.NewEthtool()
	if err != nil {
		return nil, fmt.Errorf("failed to create ethtool handler: %w", err)
	}

	return &Manager{
		interfaces:     make(map[string]*types.NetworkInterface),
		monitoringDone: make(chan struct{}),
		ethtool:        ethtoolHandler,
		links:          defaultLinkProvider{},
	}, nil
}

// Initialize initializes the NIC Manager.
func (m *Manager) Initialize(ctx context.Context) error {
	// Discover all physical interfaces
	if err := m.discoverInterfaces(); err != nil {
		return fmt.Errorf("failed to discover interfaces: %w", err)
	}

	return nil
}

// Shutdown shuts down the NIC Manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	// Signal monitoring to stop
	select {
	case <-m.monitoringDone:
		// already closed
	default:
		close(m.monitoringDone)
	}

	// Close ethtool handler
	if m.ethtool != nil {
		m.ethtool.Close()
	}

	return nil
}

// GetNICInfo gets information about a network interface.
//
// Features and statistics come from real ethtool / netlink queries. If neither
// the driver nor the kernel expose any feature flags for the interface, the
// returned NICInfo.Features map will be empty and ErrNICFeatureNotSupported is
// wrapped into a warning-only log (the call still succeeds with populated
// address / MTU / MAC fields).
func (m *Manager) GetNICInfo(name string) (*types.NICInfo, error) {
	iface, err := m.GetInterface(name)
	if err != nil {
		return nil, err
	}

	features := make(map[string]bool)
	if m.ethtool != nil {
		featureMap, ferr := m.ethtool.Features(name)
		if ferr == nil {
			features = featureMap
		}
	}

	driver := ""
	if m.ethtool != nil {
		if drv, derr := m.ethtool.DriverName(name); derr == nil {
			driver = drv
		}
	}

	return &types.NICInfo{
		Name:       iface.Name,
		Type:       string(iface.Type),
		Driver:     driver,
		MACAddress: iface.MAC,
		MTU:        iface.MTU,
		State:      iface.State,
		Features:   features,
		Statistics: types.NICStatistics{
			RxPackets:  iface.Statistics.RxPackets,
			TxPackets:  iface.Statistics.TxPackets,
			RxBytes:    iface.Statistics.RxBytes,
			TxBytes:    iface.Statistics.TxBytes,
			RxErrors:   iface.Statistics.RxErrors,
			TxErrors:   iface.Statistics.TxErrors,
			RxDropped:  iface.Statistics.RxDropped,
			TxDropped:  iface.Statistics.TxDropped,
			Collisions: iface.Statistics.Collisions,
		},
	}, nil
}

// ListNICs lists all network interfaces.
func (m *Manager) ListNICs() ([]string, error) {
	m.interfacesMu.RLock()
	defer m.interfacesMu.RUnlock()

	names := make([]string, 0, len(m.interfaces))
	for name := range m.interfaces {
		names = append(names, name)
	}

	return names, nil
}

// SetLinkState sets the state of a network interface.
func (m *Manager) SetLinkState(name string, up bool) error {
	h, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer h.Delete()

	link, err := h.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", name, err)
	}

	if up {
		return h.LinkSetUp(link)
	}
	return h.LinkSetDown(link)
}

// SetMTU sets the MTU of a network interface.
func (m *Manager) SetMTU(name string, mtu int) error {
	h, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer h.Delete()

	link, err := h.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", name, err)
	}

	return h.LinkSetMTU(link, mtu)
}

// GetStatistics gets statistics for a network interface.
//
// The manager reads from two sources, in order:
//  1. netlink link-level statistics (always present when the link exists),
//  2. ethtool -S device counters (optional per-driver enrichment such as
//     multicast counters that netlink does not surface).
//
// If neither source returns any data the manager returns a wrapped
// ErrNICStatisticsNotSupported so callers can distinguish "driver does not
// expose counters" from transient ioctl errors.
func (m *Manager) GetStatistics(name string) (*types.NICStatistics, error) {
	link, err := m.links.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("get link %s: %w", name, err)
	}

	stats := &types.NICStatistics{}
	populated := false

	if linkStats := link.Attrs().Statistics; linkStats != nil {
		stats.RxPackets = linkStats.RxPackets
		stats.TxPackets = linkStats.TxPackets
		stats.RxBytes = linkStats.RxBytes
		stats.TxBytes = linkStats.TxBytes
		stats.RxErrors = linkStats.RxErrors
		stats.TxErrors = linkStats.TxErrors
		stats.RxDropped = linkStats.RxDropped
		stats.TxDropped = linkStats.TxDropped
		stats.Multicast = linkStats.Multicast
		stats.Collisions = linkStats.Collisions
		populated = populated ||
			stats.RxPackets != 0 || stats.TxPackets != 0 ||
			stats.RxBytes != 0 || stats.TxBytes != 0 ||
			stats.RxErrors != 0 || stats.TxErrors != 0 ||
			stats.RxDropped != 0 || stats.TxDropped != 0 ||
			stats.Multicast != 0 || stats.Collisions != 0
	}

	// Enrich / cross-check via ethtool counters when they are exposed.
	if m.ethtool != nil {
		raw, ethErr := m.ethtool.Stats(name)
		if ethErr != nil {
			// ethtool failure is non-fatal when netlink already gave us data;
			// only propagate when we have no populated values at all.
			if !populated {
				return nil, fmt.Errorf("ethtool stats for %s: %w", name, ethErr)
			}
		} else if len(raw) > 0 {
			populated = true
			// Only overwrite netlink-derived values when ethtool actually has
			// a corresponding counter (driver-specific names vary).
			if v, ok := raw["multicast"]; ok {
				stats.Multicast = v
			}
		}
	}

	if !populated {
		return nil, fmt.Errorf("%w: interface %s", ErrNICStatisticsNotSupported, name)
	}

	return stats, nil
}

// ConfigureInterface configures a network interface.
func (m *Manager) ConfigureInterface(name string, config types.InterfaceConfig) error {
	// Create netlink handle
	h, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer h.Delete()

	// Get interface
	link, err := h.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", name, err)
	}

	// Configure MTU
	if config.MTU > 0 {
		if err := h.LinkSetMTU(link, config.MTU); err != nil {
			return fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	// Configure hardware offloading if supported
	if config.EnableOffload {
		if err := m.configureOffload(name, config.OffloadFeatures); err != nil {
			return fmt.Errorf("failed to configure offload: %w", err)
		}
	}

	// Set interface up/down
	if config.Enabled {
		if err := h.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to set interface up: %w", err)
		}
	} else {
		if err := h.LinkSetDown(link); err != nil {
			return fmt.Errorf("failed to set interface down: %w", err)
		}
	}

	// Configure IP addresses
	if len(config.Addresses) > 0 {
		// First, remove all existing addresses
		addrs, err := h.AddrList(link, 0)
		if err != nil {
			return fmt.Errorf("failed to list addresses: %w", err)
		}

		for _, addr := range addrs {
			if err := h.AddrDel(link, &addr); err != nil {
				return fmt.Errorf("failed to remove address %s: %w", addr.String(), err)
			}
		}

		// Add new addresses
		for _, addrStr := range config.Addresses {
			addr, err := netlink.ParseAddr(addrStr)
			if err != nil {
				return fmt.Errorf("failed to parse address %s: %w", addrStr, err)
			}

			if err := h.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("failed to add address %s: %w", addrStr, err)
			}
		}
	}

	// Update interface in cache
	m.updateInterfaceInfo(name)

	return nil
}

// GetInterface returns information about a network interface.
func (m *Manager) GetInterface(name string) (*types.NetworkInterface, error) {
	m.interfacesMu.RLock()
	defer m.interfacesMu.RUnlock()

	iface, ok := m.interfaces[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNICNotFound, name)
	}

	return iface, nil
}

// ListInterfaces returns a list of all network interfaces.
func (m *Manager) ListInterfaces() ([]*types.NetworkInterface, error) {
	m.interfacesMu.RLock()
	defer m.interfacesMu.RUnlock()

	interfaces := make([]*types.NetworkInterface, 0, len(m.interfaces))
	for _, iface := range m.interfaces {
		interfaces = append(interfaces, iface)
	}

	return interfaces, nil
}

// MonitorInterfaces starts monitoring network interfaces.
func (m *Manager) MonitorInterfaces(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.monitoringDone:
			return nil
		case <-ticker.C:
			if err := m.updateAllInterfaces(); err != nil {
				fmt.Printf("Error updating interfaces: %v\n", err)
			}
		}
	}
}

// discoverInterfaces discovers all network interfaces.
func (m *Manager) discoverInterfaces() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}

	m.interfacesMu.Lock()
	defer m.interfacesMu.Unlock()

	for _, link := range links {
		// Skip loopback and non-physical interfaces
		if link.Attrs().Name == "lo" || link.Type() != "device" {
			continue
		}

		iface := &types.NetworkInterface{
			Name: link.Attrs().Name,
			Type: types.InterfaceTypePhysical,
			MAC:  link.Attrs().HardwareAddr.String(),
			MTU:  link.Attrs().MTU,
		}

		// Get interface state
		if link.Attrs().Flags&net.FlagUp != 0 {
			iface.Enabled = true
			iface.State = "up"
		} else {
			iface.Enabled = false
			iface.State = "down"
		}

		// Get IP addresses
		addrs, err := netlink.AddrList(link, 0)
		if err != nil {
			return fmt.Errorf("failed to list addresses for %s: %w", link.Attrs().Name, err)
		}

		for _, addr := range addrs {
			iface.Addresses = append(iface.Addresses, addr.IPNet.String())
		}

		// Get interface statistics
		stats := link.Attrs().Statistics
		if stats != nil {
			iface.Statistics = types.InterfaceStatistics{
				RxBytes:    stats.RxBytes,
				RxPackets:  stats.RxPackets,
				RxErrors:   stats.RxErrors,
				RxDropped:  stats.RxDropped,
				TxBytes:    stats.TxBytes,
				TxPackets:  stats.TxPackets,
				TxErrors:   stats.TxErrors,
				TxDropped:  stats.TxDropped,
				Collisions: stats.Collisions,
			}
		}

		// Get offload features (best-effort; lack of features does not abort
		// discovery — some virtual devices legitimately expose none).
		offload, err := m.getOffloadFeatures(link.Attrs().Name)
		if err != nil {
			fmt.Printf("Failed to get offload features for %s: %v\n", link.Attrs().Name, err)
		} else {
			iface.OffloadFeatures = offload
		}

		m.interfaces[link.Attrs().Name] = iface
	}

	return nil
}

// updateInterfaceInfo updates information about a network interface.
func (m *Manager) updateInterfaceInfo(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", name, err)
	}

	m.interfacesMu.Lock()
	defer m.interfacesMu.Unlock()

	iface, ok := m.interfaces[name]
	if !ok {
		iface = &types.NetworkInterface{
			Name: name,
			Type: types.InterfaceTypePhysical,
		}
		m.interfaces[name] = iface
	}

	iface.MAC = link.Attrs().HardwareAddr.String()
	iface.MTU = link.Attrs().MTU

	// Get interface state
	if link.Attrs().Flags&net.FlagUp != 0 {
		iface.Enabled = true
		iface.State = "up"
	} else {
		iface.Enabled = false
		iface.State = "down"
	}

	// Get IP addresses
	addrs, err := netlink.AddrList(link, 0)
	if err != nil {
		return fmt.Errorf("failed to list addresses for %s: %w", name, err)
	}

	iface.Addresses = []string{} // Clear existing addresses
	for _, addr := range addrs {
		iface.Addresses = append(iface.Addresses, addr.IPNet.String())
	}

	// Get interface statistics
	stats := link.Attrs().Statistics
	if stats != nil {
		iface.Statistics = types.InterfaceStatistics{
			RxBytes:    stats.RxBytes,
			RxPackets:  stats.RxPackets,
			RxErrors:   stats.RxErrors,
			RxDropped:  stats.RxDropped,
			TxBytes:    stats.TxBytes,
			TxPackets:  stats.TxPackets,
			TxErrors:   stats.TxErrors,
			TxDropped:  stats.TxDropped,
			Collisions: stats.Collisions,
		}
	}

	// Get offload features
	offload, err := m.getOffloadFeatures(name)
	if err != nil {
		fmt.Printf("Failed to get offload features for %s: %v\n", name, err)
	} else {
		iface.OffloadFeatures = offload
	}

	return nil
}

// updateAllInterfaces updates information about all network interfaces.
func (m *Manager) updateAllInterfaces() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}

	for _, link := range links {
		// Skip loopback and non-physical interfaces
		if link.Attrs().Name == "lo" || link.Type() != "device" {
			continue
		}

		if err := m.updateInterfaceInfo(link.Attrs().Name); err != nil {
			fmt.Printf("Error updating interface %s: %v\n", link.Attrs().Name, err)
		}
	}

	return nil
}

// getOffloadFeatures gets hardware offloading features for an interface. When
// ethtool reports no feature flags (for example on tun/tap or driver-stripped
// virtio devices), the function returns an empty struct and wraps
// ErrNICFeatureNotSupported so the caller can log a downgrade rather than
// pretending the features are "all disabled".
func (m *Manager) getOffloadFeatures(ifName string) (types.OffloadFeatures, error) {
	features := types.OffloadFeatures{}

	// Get hardware offloading features using ethtool
	featureMap, err := m.ethtool.Features(ifName)
	if err != nil {
		return features, fmt.Errorf("failed to get feature states for %s: %w", ifName, err)
	}

	if len(featureMap) == 0 {
		return features, fmt.Errorf("%w: interface %s", ErrNICFeatureNotSupported, ifName)
	}

	// Map ethtool features to our OffloadFeatures struct.
	// Note: The exact mapping will depend on the actual feature names which can vary by driver.
	for feature, enabled := range featureMap {
		switch feature {
		case "tx-checksumming":
			features.TxChecksum = enabled
		case "rx-checksumming":
			features.RxChecksum = enabled
		case "tcp-segmentation-offload":
			features.TSO = enabled
		case "generic-segmentation-offload":
			features.GSO = enabled
		case "generic-receive-offload":
			features.GRO = enabled
		case "large-receive-offload":
			features.LRO = enabled
		case "rx-packet-steering":
			features.RPS = enabled
		case "tx-packet-steering":
			features.XPS = enabled
		case "rx-flow-hash-filter":
			features.NTUPLE = enabled
		case "receive-flow-steering":
			features.RFS = enabled
		}
	}

	return features, nil
}

// configureOffload configures hardware offloading features for an interface.
func (m *Manager) configureOffload(ifName string, features types.OffloadFeatures) error {
	// Get current features
	featureMap, err := m.ethtool.Features(ifName)
	if err != nil {
		return fmt.Errorf("failed to get feature states: %w", err)
	}

	if len(featureMap) == 0 {
		return fmt.Errorf("%w: interface %s", ErrNICFeatureNotSupported, ifName)
	}

	// Prepare features to change
	changes := make(map[string]bool)

	// Map our OffloadFeatures struct to ethtool features
	// Note: The exact mapping will depend on the actual feature names which can vary by driver
	if val, ok := featureMap["tx-checksumming"]; ok && val != features.TxChecksum {
		changes["tx-checksumming"] = features.TxChecksum
	}
	if val, ok := featureMap["rx-checksumming"]; ok && val != features.RxChecksum {
		changes["rx-checksumming"] = features.RxChecksum
	}
	if val, ok := featureMap["tcp-segmentation-offload"]; ok && val != features.TSO {
		changes["tcp-segmentation-offload"] = features.TSO
	}
	if val, ok := featureMap["generic-segmentation-offload"]; ok && val != features.GSO {
		changes["generic-segmentation-offload"] = features.GSO
	}
	if val, ok := featureMap["generic-receive-offload"]; ok && val != features.GRO {
		changes["generic-receive-offload"] = features.GRO
	}
	if val, ok := featureMap["large-receive-offload"]; ok && val != features.LRO {
		changes["large-receive-offload"] = features.LRO
	}
	if val, ok := featureMap["rx-packet-steering"]; ok && val != features.RPS {
		changes["rx-packet-steering"] = features.RPS
	}
	if val, ok := featureMap["tx-packet-steering"]; ok && val != features.XPS {
		changes["tx-packet-steering"] = features.XPS
	}
	if val, ok := featureMap["rx-flow-hash-filter"]; ok && val != features.NTUPLE {
		changes["rx-flow-hash-filter"] = features.NTUPLE
	}
	if val, ok := featureMap["receive-flow-steering"]; ok && val != features.RFS {
		changes["receive-flow-steering"] = features.RFS
	}

	// Apply changes
	if len(changes) > 0 {
		if err := m.ethtool.Change(ifName, changes); err != nil {
			return fmt.Errorf("failed to change offload features: %w", err)
		}
	}

	return nil
}
