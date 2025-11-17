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

// Manager implements the types.NICManager interface.
type Manager struct {
	interfaces     map[string]*types.NetworkInterface
	interfacesMu   sync.RWMutex
	monitoringDone chan struct{}
	ethtool        *ethtool.Ethtool
}

// NewManager creates a new NIC Manager.
func NewManager() (*Manager, error) {
	ethtoolHandler, err := ethtool.NewEthtool()
	if err != nil {
		return nil, fmt.Errorf("failed to create ethtool handler: %w", err)
	}

	return &Manager{
		interfaces:     make(map[string]*types.NetworkInterface),
		monitoringDone: make(chan struct{}),
		ethtool:        ethtoolHandler,
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
	close(m.monitoringDone)

	// Close ethtool handler
	if m.ethtool != nil {
		m.ethtool.Close()
	}

	return nil
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
		return nil, fmt.Errorf("interface %s not found", name)
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

		// Get offload features
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
		iface.Statistics = hardware.InterfaceStatistics{
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

// getOffloadFeatures gets hardware offloading features for an interface.
func (m *Manager) getOffloadFeatures(ifName string) (types.OffloadFeatures, error) {
	features := types.OffloadFeatures{}

	// Get hardware offloading features using ethtool
	txcsum, err := m.ethtool.GetFeaturesNames(ifName)
	if err != nil {
		return features, fmt.Errorf("failed to get features: %w", err)
	}

	featureMap, err := m.ethtool.Features(ifName)
	if err != nil {
		return features, fmt.Errorf("failed to get feature states: %w", err)
	}

	// Map ethtool features to our OffloadFeatures struct
	// Note: The exact mapping will depend on the actual feature names which can vary by driver
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
	for feature, enabled := range changes {
		if err := m.ethtool.Change(ifName, feature, enabled); err != nil {
			return fmt.Errorf("failed to change feature %s to %v: %w", feature, enabled, err)
		}
	}

	return nil
}
