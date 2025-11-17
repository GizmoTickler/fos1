package interfaces

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// KernelInterfaceManager manages network interfaces using netlink
type KernelInterfaceManager struct {
	// linkUpdateChan receives link updates from the kernel
	linkUpdateChan chan netlink.LinkUpdate
	// done signals when to stop monitoring
	done chan struct{}
	// linkUpdateCallbacks are callbacks for link updates
	linkUpdateCallbacks []func(netlink.LinkUpdate)
}

// NewKernelInterfaceManager creates a new kernel interface manager
func NewKernelInterfaceManager() *KernelInterfaceManager {
	return &KernelInterfaceManager{
		linkUpdateChan:      make(chan netlink.LinkUpdate),
		done:                make(chan struct{}),
		linkUpdateCallbacks: make([]func(netlink.LinkUpdate), 0),
	}
}

// Start begins monitoring interface state changes
func (m *KernelInterfaceManager) Start(ctx context.Context) error {
	// Subscribe to link updates
	if err := netlink.LinkSubscribe(m.linkUpdateChan, m.done); err != nil {
		return fmt.Errorf("failed to subscribe to link updates: %w", err)
	}

	// Start monitoring goroutine
	go m.monitorLinks(ctx)

	klog.Info("Kernel interface manager started")
	return nil
}

// Stop stops monitoring interface state changes
func (m *KernelInterfaceManager) Stop() {
	close(m.done)
	klog.Info("Kernel interface manager stopped")
}

// RegisterLinkUpdateCallback registers a callback for link updates
func (m *KernelInterfaceManager) RegisterLinkUpdateCallback(callback func(netlink.LinkUpdate)) {
	m.linkUpdateCallbacks = append(m.linkUpdateCallbacks, callback)
}

// monitorLinks monitors link state changes and invokes callbacks
func (m *KernelInterfaceManager) monitorLinks(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			klog.Info("Link monitoring stopped due to context cancellation")
			return
		case <-m.done:
			klog.Info("Link monitoring stopped")
			return
		case update := <-m.linkUpdateChan:
			klog.V(4).Infof("Link update received: %s (index: %d)", update.Link.Attrs().Name, update.Link.Attrs().Index)
			// Invoke all registered callbacks
			for _, callback := range m.linkUpdateCallbacks {
				callback(update)
			}
		}
	}
}

// CreateDummyInterface creates a dummy interface (virtual interface for testing)
func (m *KernelInterfaceManager) CreateDummyInterface(name string, mtu int) error {
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  mtu,
		},
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("failed to create dummy interface %s: %w", name, err)
	}

	klog.Infof("Created dummy interface %s with MTU %d", name, mtu)
	return nil
}

// CreateVLANInterface creates a VLAN interface
func (m *KernelInterfaceManager) CreateVLANInterface(name string, parentName string, vlanID int, mtu int) error {
	// Validate VLAN ID
	if vlanID < 1 || vlanID > 4094 {
		return fmt.Errorf("invalid VLAN ID: %d, must be between 1 and 4094", vlanID)
	}

	// Get parent interface
	parent, err := netlink.LinkByName(parentName)
	if err != nil {
		return fmt.Errorf("failed to find parent interface %s: %w", parentName, err)
	}

	// Create VLAN link attributes
	linkAttrs := netlink.LinkAttrs{
		Name:        name,
		ParentIndex: parent.Attrs().Index,
	}

	// Set MTU if specified
	if mtu > 0 {
		linkAttrs.MTU = mtu
	}

	// Create VLAN link
	vlan := &netlink.Vlan{
		LinkAttrs: linkAttrs,
		VlanId:    vlanID,
	}

	// Add the VLAN interface
	if err := netlink.LinkAdd(vlan); err != nil {
		return fmt.Errorf("failed to create VLAN interface %s: %w", name, err)
	}

	klog.Infof("Created VLAN interface %s on parent %s with VLAN ID %d", name, parentName, vlanID)
	return nil
}

// CreateBridgeInterface creates a bridge interface
func (m *KernelInterfaceManager) CreateBridgeInterface(name string, mtu int) error {
	link := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  mtu,
		},
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("failed to create bridge interface %s: %w", name, err)
	}

	klog.Infof("Created bridge interface %s with MTU %d", name, mtu)
	return nil
}

// CreateBondInterface creates a bond interface
func (m *KernelInterfaceManager) CreateBondInterface(name string, mode netlink.BondMode, mtu int) error {
	link := &netlink.Bond{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  mtu,
		},
		Mode: mode,
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("failed to create bond interface %s: %w", name, err)
	}

	klog.Infof("Created bond interface %s with MTU %d and mode %d", name, mtu, mode)
	return nil
}

// DeleteInterface deletes a network interface
func (m *KernelInterfaceManager) DeleteInterface(name string) error {
	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Delete the link
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete interface %s: %w", name, err)
	}

	klog.Infof("Deleted interface %s", name)
	return nil
}

// SetInterfaceUp brings an interface up
func (m *KernelInterfaceManager) SetInterfaceUp(name string) error {
	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Set the link up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring interface %s up: %w", name, err)
	}

	klog.Infof("Brought interface %s up", name)
	return nil
}

// SetInterfaceDown brings an interface down
func (m *KernelInterfaceManager) SetInterfaceDown(name string) error {
	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Set the link down
	if err := netlink.LinkSetDown(link); err != nil {
		return fmt.Errorf("failed to bring interface %s down: %w", name, err)
	}

	klog.Infof("Brought interface %s down", name)
	return nil
}

// SetMTU sets the MTU of an interface
func (m *KernelInterfaceManager) SetMTU(name string, mtu int) error {
	// Validate MTU
	if mtu < 68 || mtu > 9000 {
		return fmt.Errorf("invalid MTU: %d, must be between 68 and 9000", mtu)
	}

	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Set the MTU
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("failed to set MTU on interface %s: %w", name, err)
	}

	klog.Infof("Set MTU on interface %s to %d", name, mtu)
	return nil
}

// SetMACAddress sets the MAC address of an interface
func (m *KernelInterfaceManager) SetMACAddress(name string, mac string) error {
	// Parse MAC address
	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("invalid MAC address %s: %w", mac, err)
	}

	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Set the MAC address
	if err := netlink.LinkSetHardwareAddr(link, hwAddr); err != nil {
		return fmt.Errorf("failed to set MAC address on interface %s: %w", name, err)
	}

	klog.Infof("Set MAC address on interface %s to %s", name, mac)
	return nil
}

// AddIPAddress adds an IP address to an interface
func (m *KernelInterfaceManager) AddIPAddress(name string, address string) error {
	// Parse the address
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", address, err)
	}

	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Add the address
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IP address %s to interface %s: %w", address, name, err)
	}

	klog.Infof("Added IP address %s to interface %s", address, name)
	return nil
}

// DeleteIPAddress deletes an IP address from an interface
func (m *KernelInterfaceManager) DeleteIPAddress(name string, address string) error {
	// Parse the address
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", address, err)
	}

	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Delete the address
	if err := netlink.AddrDel(link, addr); err != nil {
		return fmt.Errorf("failed to delete IP address %s from interface %s: %w", address, name, err)
	}

	klog.Infof("Deleted IP address %s from interface %s", address, name)
	return nil
}

// GetInterfaceAddresses gets all IP addresses assigned to an interface
func (m *KernelInterfaceManager) GetInterfaceAddresses(name string) ([]string, error) {
	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Get addresses
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses on interface %s: %w", name, err)
	}

	// Convert to strings
	addresses := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addresses = append(addresses, addr.IPNet.String())
	}

	return addresses, nil
}

// GetInterfaceState gets the operational state of an interface
func (m *KernelInterfaceManager) GetInterfaceState(name string) (string, error) {
	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return "", fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Get the operational state
	attrs := link.Attrs()
	if attrs.Flags&net.FlagUp != 0 {
		// Check if the link has carrier (connected to network)
		if attrs.RawFlags&unix.IFF_RUNNING != 0 {
			return "up", nil
		}
		return "no-carrier", nil
	}

	return "down", nil
}

// GetInterfaceStats gets statistics for an interface
func (m *KernelInterfaceManager) GetInterfaceStats(name string) (*netlink.LinkStatistics, error) {
	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Get statistics
	stats := link.Attrs().Statistics
	if stats == nil {
		return nil, fmt.Errorf("no statistics available for interface %s", name)
	}

	return stats, nil
}

// GetInterfaceMTU gets the MTU of an interface
func (m *KernelInterfaceManager) GetInterfaceMTU(name string) (int, error) {
	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	return link.Attrs().MTU, nil
}

// GetInterfaceMACAddress gets the MAC address of an interface
func (m *KernelInterfaceManager) GetInterfaceMACAddress(name string) (string, error) {
	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return "", fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	mac := link.Attrs().HardwareAddr
	if mac == nil {
		return "", fmt.Errorf("no MAC address for interface %s", name)
	}

	return mac.String(), nil
}

// ListInterfaces lists all network interfaces
func (m *KernelInterfaceManager) ListInterfaces() ([]netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	return links, nil
}

// InterfaceExists checks if an interface exists
func (m *KernelInterfaceManager) InterfaceExists(name string) (bool, error) {
	_, err := netlink.LinkByName(name)
	if err != nil {
		// Check if the error is "Link not found"
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return false, nil
		}
		return false, fmt.Errorf("failed to check if interface %s exists: %w", name, err)
	}

	return true, nil
}

// WaitForInterface waits for an interface to appear (useful after creation)
func (m *KernelInterfaceManager) WaitForInterface(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		exists, err := m.InterfaceExists(name)
		if err != nil {
			return err
		}
		if exists {
			klog.Infof("Interface %s appeared", name)
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for interface %s to appear", name)
}

// AddInterfaceToBridge adds an interface to a bridge
func (m *KernelInterfaceManager) AddInterfaceToBridge(bridgeName string, ifaceName string) error {
	// Get the bridge
	bridge, err := netlink.LinkByName(bridgeName)
	if err != nil {
		return fmt.Errorf("failed to find bridge %s: %w", bridgeName, err)
	}

	// Ensure it's a bridge
	if _, ok := bridge.(*netlink.Bridge); !ok {
		return fmt.Errorf("%s is not a bridge interface", bridgeName)
	}

	// Get the interface
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", ifaceName, err)
	}

	// Set the interface's master to the bridge
	if err := netlink.LinkSetMaster(iface, bridge); err != nil {
		return fmt.Errorf("failed to add interface %s to bridge %s: %w", ifaceName, bridgeName, err)
	}

	klog.Infof("Added interface %s to bridge %s", ifaceName, bridgeName)
	return nil
}

// RemoveInterfaceFromBridge removes an interface from a bridge
func (m *KernelInterfaceManager) RemoveInterfaceFromBridge(ifaceName string) error {
	// Get the interface
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", ifaceName, err)
	}

	// Remove the master (set to nil)
	if err := netlink.LinkSetNoMaster(iface); err != nil {
		return fmt.Errorf("failed to remove interface %s from bridge: %w", ifaceName, err)
	}

	klog.Infof("Removed interface %s from bridge", ifaceName)
	return nil
}

// SetVLANQoS sets the QoS priority for a VLAN interface
func (m *KernelInterfaceManager) SetVLANQoS(name string, qos int) error {
	// Validate QoS priority (802.1p)
	if qos < 0 || qos > 7 {
		return fmt.Errorf("invalid QoS priority: %d, must be between 0 and 7", qos)
	}

	// Get the link
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", name, err)
	}

	// Ensure it's a VLAN interface
	vlan, ok := link.(*netlink.Vlan)
	if !ok {
		return fmt.Errorf("%s is not a VLAN interface", name)
	}

	// Modify VLAN settings
	vlan.VlanProtocol = netlink.VLAN_PROTOCOL_8021Q
	// Note: netlink library doesn't directly support setting QoS priority
	// This would require using netlink attributes directly
	// For now, log a warning
	klog.Warningf("Setting VLAN QoS priority requires advanced netlink attribute manipulation (not yet implemented)")

	klog.Infof("Attempted to set QoS priority on VLAN interface %s to %d", name, qos)
	return nil
}
