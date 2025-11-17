package ipam

import (
	"context"
	"fmt"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// KernelAddressManager manages IP addresses using netlink
type KernelAddressManager struct {
	// addrUpdateChan receives address updates from the kernel
	addrUpdateChan chan netlink.AddrUpdate
	// done signals when to stop monitoring
	done chan struct{}
	// addrUpdateCallbacks are callbacks for address updates
	addrUpdateCallbacks []func(AddressUpdate)
}

// NewKernelAddressManager creates a new kernel address manager
func NewKernelAddressManager() *KernelAddressManager {
	return &KernelAddressManager{
		addrUpdateChan:      make(chan netlink.AddrUpdate),
		done:                make(chan struct{}),
		addrUpdateCallbacks: make([]func(AddressUpdate), 0),
	}
}

// Start begins monitoring address changes
func (m *KernelAddressManager) Start(ctx context.Context) error {
	// Subscribe to address updates
	if err := netlink.AddrSubscribe(m.addrUpdateChan, m.done); err != nil {
		return fmt.Errorf("failed to subscribe to address updates: %w", err)
	}

	// Start monitoring goroutine
	go m.monitorAddresses(ctx)

	klog.Info("Kernel address manager started")
	return nil
}

// Stop stops monitoring address changes
func (m *KernelAddressManager) Stop() {
	close(m.done)
	klog.Info("Kernel address manager stopped")
}

// RegisterAddressUpdateCallback registers a callback for address updates
func (m *KernelAddressManager) RegisterAddressUpdateCallback(callback func(AddressUpdate)) {
	m.addrUpdateCallbacks = append(m.addrUpdateCallbacks, callback)
}

// monitorAddresses monitors address changes and invokes callbacks
func (m *KernelAddressManager) monitorAddresses(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			klog.Info("Address monitoring stopped due to context cancellation")
			return
		case <-m.done:
			klog.Info("Address monitoring stopped")
			return
		case update := <-m.addrUpdateChan:
			klog.V(4).Infof("Address update received: %s on link %d, new=%v",
				update.LinkAddress.String(), update.LinkIndex, update.NewAddr)

			// Convert netlink update to our AddressUpdate type
			addrUpdate := m.convertNetlinkUpdate(update)
			if addrUpdate != nil {
				// Invoke all registered callbacks
				for _, callback := range m.addrUpdateCallbacks {
					callback(*addrUpdate)
				}
			}
		}
	}
}

// convertNetlinkUpdate converts a netlink.AddrUpdate to our AddressUpdate type
func (m *KernelAddressManager) convertNetlinkUpdate(update netlink.AddrUpdate) *AddressUpdate {
	// Get the link name
	link, err := netlink.LinkByIndex(update.LinkIndex)
	if err != nil {
		klog.Warningf("Failed to get link for index %d: %v", update.LinkIndex, err)
		return nil
	}

	// Create a netlink.Addr from the update
	addr := netlink.Addr{
		IPNet: &update.LinkAddress,
	}

	// Convert the address
	ipAddr := m.netlinkAddrToIPAddress(addr, link.Attrs().Name)

	// Determine update type
	var updateType AddressUpdateType
	if update.NewAddr {
		updateType = AddressAdded
	} else {
		updateType = AddressDeleted
	}

	return &AddressUpdate{
		Interface: link.Attrs().Name,
		Address:   ipAddr,
		Type:      updateType,
		Timestamp: time.Now(),
	}
}

// AddAddress adds an IP address to an interface
func (m *KernelAddressManager) AddAddress(iface string, address string, flags AddressFlags) error {
	// Parse the address
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", address, err)
	}

	// Get the link
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", iface, err)
	}

	// Set flags on the address
	m.applyFlagsToNetlinkAddr(addr, flags)

	// Add the address
	if err := netlink.AddrAdd(link, addr); err != nil {
		// Check if address already exists
		if err == syscall.EEXIST {
			klog.V(4).Infof("Address %s already exists on interface %s", address, iface)
			return nil
		}
		return fmt.Errorf("failed to add IP address %s to interface %s: %w", address, iface, err)
	}

	klog.Infof("Added IP address %s to interface %s", address, iface)
	return nil
}

// DeleteAddress deletes an IP address from an interface
func (m *KernelAddressManager) DeleteAddress(iface string, address string) error {
	// Parse the address
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", address, err)
	}

	// Get the link
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", iface, err)
	}

	// Delete the address
	if err := netlink.AddrDel(link, addr); err != nil {
		// Check if address doesn't exist
		if err == syscall.EADDRNOTAVAIL {
			klog.V(4).Infof("Address %s does not exist on interface %s", address, iface)
			return nil
		}
		return fmt.Errorf("failed to delete IP address %s from interface %s: %w", address, iface, err)
	}

	klog.Infof("Deleted IP address %s from interface %s", address, iface)
	return nil
}

// ListAddresses lists all IP addresses on an interface
func (m *KernelAddressManager) ListAddresses(iface string, family AddressFamily) ([]*IPAddress, error) {
	// Get the link
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", iface, err)
	}

	// Determine netlink family
	var netlinkFamily int
	switch family {
	case FamilyIPv4:
		netlinkFamily = netlink.FAMILY_V4
	case FamilyIPv6:
		netlinkFamily = netlink.FAMILY_V6
	case FamilyAll:
		netlinkFamily = netlink.FAMILY_ALL
	default:
		netlinkFamily = netlink.FAMILY_ALL
	}

	// Get addresses
	addrs, err := netlink.AddrList(link, netlinkFamily)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses on interface %s: %w", iface, err)
	}

	// Convert to our IPAddress type
	addresses := make([]*IPAddress, 0, len(addrs))
	for _, addr := range addrs {
		ipAddr := m.netlinkAddrToIPAddress(addr, iface)
		addresses = append(addresses, ipAddr)
	}

	return addresses, nil
}

// GetAddress gets a specific IP address on an interface
func (m *KernelAddressManager) GetAddress(iface string, address string) (*IPAddress, error) {
	// Parse the address
	searchAddr, err := netlink.ParseAddr(address)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address %s: %w", address, err)
	}

	// List all addresses
	addresses, err := m.ListAddresses(iface, FamilyAll)
	if err != nil {
		return nil, err
	}

	// Find matching address
	for _, addr := range addresses {
		if addr.Address == searchAddr.String() {
			return addr, nil
		}
	}

	return nil, fmt.Errorf("address %s not found on interface %s", address, iface)
}

// ReplaceAddress replaces an IP address on an interface
func (m *KernelAddressManager) ReplaceAddress(iface string, oldAddress string, newAddress string, flags AddressFlags) error {
	// Delete the old address
	if err := m.DeleteAddress(iface, oldAddress); err != nil {
		klog.Warningf("Failed to delete old address %s: %v", oldAddress, err)
	}

	// Add the new address
	return m.AddAddress(iface, newAddress, flags)
}

// SetAddressLabel sets the label for an IP address
func (m *KernelAddressManager) SetAddressLabel(iface string, address string, label string) error {
	// Parse the address
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", address, err)
	}

	// Get the link
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", iface, err)
	}

	// Set label
	addr.Label = label

	// Delete and re-add with label (netlink doesn't support updating labels)
	if err := netlink.AddrDel(link, addr); err != nil {
		return fmt.Errorf("failed to delete address for label update: %w", err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to re-add address with label: %w", err)
	}

	klog.Infof("Set label %s on address %s on interface %s", label, address, iface)
	return nil
}

// CheckDuplicateAddress checks if an address is a duplicate (DAD failed)
func (m *KernelAddressManager) CheckDuplicateAddress(iface string, address string) (bool, error) {
	// Get the address
	ipAddr, err := m.GetAddress(iface, address)
	if err != nil {
		return false, err
	}

	// Check if DAD failed
	return ipAddr.IsDuplicate(), nil
}

// WaitForDAD waits for Duplicate Address Detection to complete
func (m *KernelAddressManager) WaitForDAD(iface string, address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		ipAddr, err := m.GetAddress(iface, address)
		if err != nil {
			return err
		}

		// Check if DAD completed
		if !ipAddr.IsTentative() {
			// Check if DAD failed
			if ipAddr.IsDuplicate() {
				return fmt.Errorf("duplicate address detected: %s on %s", address, iface)
			}
			klog.Infof("DAD completed successfully for %s on %s", address, iface)
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for DAD to complete for %s on %s", address, iface)
}

// FlushAddresses removes all IP addresses from an interface
func (m *KernelAddressManager) FlushAddresses(iface string, family AddressFamily) error {
	// Get all addresses
	addresses, err := m.ListAddresses(iface, family)
	if err != nil {
		return err
	}

	// Delete each address
	for _, addr := range addresses {
		if err := m.DeleteAddress(iface, addr.Address); err != nil {
			klog.Warningf("Failed to delete address %s: %v", addr.Address, err)
		}
	}

	klog.Infof("Flushed all %s addresses from interface %s", family.String(), iface)
	return nil
}

// netlinkAddrToIPAddress converts a netlink.Addr to our IPAddress type
func (m *KernelAddressManager) netlinkAddrToIPAddress(addr netlink.Addr, iface string) *IPAddress {
	ipAddr := &IPAddress{
		Interface: iface,
		Address:   addr.IPNet.String(),
		IP:        addr.IP,
		Network:   addr.IPNet,
		Label:     addr.Label,
		Broadcast: addr.Broadcast,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Determine family
	if addr.IP.To4() != nil {
		ipAddr.Family = FamilyIPv4
	} else {
		ipAddr.Family = FamilyIPv6
	}

	// Determine scope
	ipAddr.Scope = m.convertNetlinkScope(addr.Scope)

	// Parse flags
	ipAddr.Flags = m.parseNetlinkFlags(addr.Flags)

	// Determine state based on flags
	if ipAddr.Flags.DadFailed {
		ipAddr.State = StateDuplicate
	} else if ipAddr.Flags.Tentative {
		ipAddr.State = StateTentative
	} else if ipAddr.Flags.Deprecated {
		ipAddr.State = StateDeprecated
	} else {
		ipAddr.State = StateValid
	}

	// Set lifetimes
	if addr.PreferedLft != 0xFFFFFFFF {
		ipAddr.PreferredLifetime = time.Duration(addr.PreferedLft) * time.Second
	}
	if addr.ValidLft != 0xFFFFFFFF {
		ipAddr.ValidLifetime = time.Duration(addr.ValidLft) * time.Second
	}

	return ipAddr
}

// convertNetlinkScope converts netlink scope to our AddressScope
func (m *KernelAddressManager) convertNetlinkScope(scope int) AddressScope {
	switch netlink.Scope(scope) {
	case netlink.SCOPE_UNIVERSE:
		return ScopeGlobal
	case netlink.SCOPE_SITE:
		return ScopeSite
	case netlink.SCOPE_LINK:
		return ScopeLink
	case netlink.SCOPE_HOST:
		return ScopeHost
	default:
		return ScopeGlobal
	}
}

// parseNetlinkFlags parses netlink address flags to our AddressFlags
func (m *KernelAddressManager) parseNetlinkFlags(flags int) AddressFlags {
	return AddressFlags{
		Permanent:      flags&unix.IFA_F_PERMANENT != 0,
		Secondary:      flags&unix.IFA_F_SECONDARY != 0,
		Temporary:      flags&unix.IFA_F_TEMPORARY != 0,
		Deprecated:     flags&unix.IFA_F_DEPRECATED != 0,
		Tentative:      flags&unix.IFA_F_TENTATIVE != 0,
		DadFailed:      flags&unix.IFA_F_DADFAILED != 0,
		HomeAddress:    flags&unix.IFA_F_HOMEADDRESS != 0,
		Optimistic:     flags&unix.IFA_F_OPTIMISTIC != 0,
		NoPrefixRoute:  flags&unix.IFA_F_NOPREFIXROUTE != 0,
		ManagementTemp: flags&unix.IFA_F_MANAGETEMPADDR != 0,
	}
}

// applyFlagsToNetlinkAddr applies our AddressFlags to a netlink.Addr
func (m *KernelAddressManager) applyFlagsToNetlinkAddr(addr *netlink.Addr, flags AddressFlags) {
	var netlinkFlags int

	if flags.Permanent {
		netlinkFlags |= unix.IFA_F_PERMANENT
	}
	if flags.Secondary {
		netlinkFlags |= unix.IFA_F_SECONDARY
	}
	if flags.Temporary {
		netlinkFlags |= unix.IFA_F_TEMPORARY
	}
	if flags.Deprecated {
		netlinkFlags |= unix.IFA_F_DEPRECATED
	}
	if flags.Tentative {
		netlinkFlags |= unix.IFA_F_TENTATIVE
	}
	if flags.HomeAddress {
		netlinkFlags |= unix.IFA_F_HOMEADDRESS
	}
	if flags.Optimistic {
		netlinkFlags |= unix.IFA_F_OPTIMISTIC
	}
	if flags.NoPrefixRoute {
		netlinkFlags |= unix.IFA_F_NOPREFIXROUTE
	}
	if flags.ManagementTemp {
		netlinkFlags |= unix.IFA_F_MANAGETEMPADDR
	}

	addr.Flags = netlinkFlags
}
