package ipam

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

// Manager manages IP addresses and subnets
type Manager struct {
	// mu protects the manager state
	mu sync.RWMutex
	// subnets tracks all managed subnets
	subnets map[string]*Subnet
	// addresses tracks all managed addresses by interface
	addresses map[string]map[string]*IPAddress
	// kernelMgr manages kernel address operations
	kernelMgr *KernelAddressManager
	// ctx is the context for the manager
	ctx context.Context
	// cancel cancels the context
	cancel context.CancelFunc
}

// NewManager creates a new IP address manager
func NewManager(ctx context.Context) (*Manager, error) {
	kernelMgr := NewKernelAddressManager()

	managerCtx, cancel := context.WithCancel(ctx)

	mgr := &Manager{
		subnets:   make(map[string]*Subnet),
		addresses: make(map[string]map[string]*IPAddress),
		kernelMgr: kernelMgr,
		ctx:       managerCtx,
		cancel:    cancel,
	}

	// Register callback for address updates
	kernelMgr.RegisterAddressUpdateCallback(mgr.handleAddressUpdate)

	// Start monitoring
	if err := kernelMgr.Start(managerCtx); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start kernel address manager: %w", err)
	}

	klog.Info("IPAM manager started")
	return mgr, nil
}

// Stop stops the IPAM manager
func (m *Manager) Stop() {
	if m.kernelMgr != nil {
		m.kernelMgr.Stop()
	}
	if m.cancel != nil {
		m.cancel()
	}
	klog.Info("IPAM manager stopped")
}

// handleAddressUpdate handles address updates from the kernel
func (m *Manager) handleAddressUpdate(update AddressUpdate) {
	m.mu.Lock()
	defer m.mu.Unlock()

	klog.V(4).Infof("Address update: %s %s on %s",
		update.Type.String(), update.Address.Address, update.Interface)

	// Update our tracking
	if _, exists := m.addresses[update.Interface]; !exists {
		m.addresses[update.Interface] = make(map[string]*IPAddress)
	}

	switch update.Type {
	case AddressAdded, AddressUpdated:
		m.addresses[update.Interface][update.Address.Address] = update.Address
	case AddressDeleted:
		delete(m.addresses[update.Interface], update.Address.Address)
	}
}

// AddSubnet adds a subnet to the manager
func (m *Manager) AddSubnet(subnet *Subnet) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if subnet.CIDR == "" {
		return fmt.Errorf("subnet CIDR is required")
	}

	// Parse the CIDR
	_, network, err := net.ParseCIDR(subnet.CIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR %s: %w", subnet.CIDR, err)
	}

	subnet.Network = network

	// Determine family
	if network.IP.To4() != nil {
		subnet.Family = FamilyIPv4
	} else {
		subnet.Family = FamilyIPv6
	}

	// Initialize allocations and reserved maps if nil
	if subnet.Allocations == nil {
		subnet.Allocations = make(map[string]*IPAddress)
	}
	if subnet.Reserved == nil {
		subnet.Reserved = make(map[string]bool)
	}

	// Calculate default start and end IPs if not specified
	if subnet.StartIP == nil || subnet.EndIP == nil {
		start, end := m.calculateSubnetRange(network)
		if subnet.StartIP == nil {
			subnet.StartIP = start
		}
		if subnet.EndIP == nil {
			subnet.EndIP = end
		}
	}

	// Reserve network and broadcast addresses for IPv4
	if subnet.IsIPv4() {
		// Reserve network address
		networkAddr := network.IP.String()
		subnet.Reserved[networkAddr] = true

		// Reserve broadcast address
		broadcastAddr := m.calculateBroadcast(network).String()
		subnet.Reserved[broadcastAddr] = true

		// Reserve gateway if specified
		if subnet.Gateway != nil {
			subnet.Reserved[subnet.Gateway.String()] = true
		}
	}

	// Store the subnet
	m.subnets[subnet.CIDR] = subnet

	klog.Infof("Added subnet %s (%s) with %d available addresses",
		subnet.CIDR, subnet.Family.String(), subnet.Available())
	return nil
}

// RemoveSubnet removes a subnet from the manager
func (m *Manager) RemoveSubnet(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	subnet, exists := m.subnets[cidr]
	if !exists {
		return fmt.Errorf("subnet %s does not exist", cidr)
	}

	// Check if there are active allocations
	if len(subnet.Allocations) > 0 {
		return fmt.Errorf("cannot remove subnet %s: %d active allocations", cidr, len(subnet.Allocations))
	}

	delete(m.subnets, cidr)

	klog.Infof("Removed subnet %s", cidr)
	return nil
}

// GetSubnet gets a subnet by CIDR
func (m *Manager) GetSubnet(cidr string) (*Subnet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	subnet, exists := m.subnets[cidr]
	if !exists {
		return nil, fmt.Errorf("subnet %s does not exist", cidr)
	}

	return subnet, nil
}

// ListSubnets lists all subnets
func (m *Manager) ListSubnets() []*Subnet {
	m.mu.RLock()
	defer m.mu.RUnlock()

	subnets := make([]*Subnet, 0, len(m.subnets))
	for _, subnet := range m.subnets {
		subnets = append(subnets, subnet)
	}

	return subnets
}

// AllocateAddress allocates an IP address
func (m *Manager) AllocateAddress(req AllocationRequest) (*IPAddress, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find or auto-detect subnet
	var subnet *Subnet
	var err error

	if req.Subnet != "" {
		// Use specified subnet
		subnet, err = m.findSubnet(req.Subnet)
		if err != nil {
			return nil, err
		}
	} else {
		// Auto-detect subnet based on family
		subnet, err = m.findAvailableSubnet(req.Family)
		if err != nil {
			return nil, err
		}
	}

	// Allocate an IP from the subnet
	var ip net.IP
	if req.PreferredIP != nil && subnet.Contains(req.PreferredIP) {
		// Check if preferred IP is available
		if m.isIPAvailable(subnet, req.PreferredIP) {
			ip = req.PreferredIP
		} else {
			return nil, fmt.Errorf("preferred IP %s is not available", req.PreferredIP.String())
		}
	} else {
		// Find next available IP
		ip, err = m.findNextAvailableIP(subnet)
		if err != nil {
			return nil, err
		}
	}

	// Create the IP address
	prefixLen, _ := subnet.Network.Mask.Size()
	address := fmt.Sprintf("%s/%d", ip.String(), prefixLen)

	// Set flags
	flags := AddressFlags{
		Permanent: req.Permanent,
	}

	// Add the address to the kernel
	if err := m.kernelMgr.AddAddress(req.Interface, address, flags); err != nil {
		return nil, fmt.Errorf("failed to add address to kernel: %w", err)
	}

	// Wait for DAD to complete for IPv6
	if subnet.IsIPv6() && !flags.Optimistic {
		if err := m.kernelMgr.WaitForDAD(req.Interface, address, 5*time.Second); err != nil {
			// DAD failed, remove the address
			_ = m.kernelMgr.DeleteAddress(req.Interface, address)
			return nil, fmt.Errorf("DAD failed: %w", err)
		}
	}

	// Create the IPAddress object
	ipAddr := &IPAddress{
		Interface:         req.Interface,
		Address:           address,
		IP:                ip,
		Network:           subnet.Network,
		Family:            subnet.Family,
		Scope:             req.Scope,
		State:             StateValid,
		Label:             req.Label,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		Flags:             flags,
		PreferredLifetime: 0,
		ValidLifetime:     0,
	}

	// Track the allocation
	subnet.Allocations[ip.String()] = ipAddr

	// Track in our address map
	if _, exists := m.addresses[req.Interface]; !exists {
		m.addresses[req.Interface] = make(map[string]*IPAddress)
	}
	m.addresses[req.Interface][address] = ipAddr

	klog.Infof("Allocated IP address %s on interface %s from subnet %s",
		address, req.Interface, subnet.CIDR)

	return ipAddr, nil
}

// ReleaseAddress releases an allocated IP address
func (m *Manager) ReleaseAddress(iface string, address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the subnet for this address
	var subnet *Subnet
	var ip net.IP

	parsedAddr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("invalid address %s: %w", address, err)
	}
	ip = parsedAddr.IP

	for _, s := range m.subnets {
		if s.Contains(ip) {
			subnet = s
			break
		}
	}

	if subnet == nil {
		return fmt.Errorf("no subnet found for address %s", address)
	}

	// Remove from subnet allocations
	delete(subnet.Allocations, ip.String())

	// Remove from our tracking
	if addrs, exists := m.addresses[iface]; exists {
		delete(addrs, address)
	}

	// Remove from kernel
	if err := m.kernelMgr.DeleteAddress(iface, address); err != nil {
		return fmt.Errorf("failed to delete address from kernel: %w", err)
	}

	klog.Infof("Released IP address %s from interface %s", address, iface)
	return nil
}

// AddAddress adds an IP address to an interface (without allocation tracking)
func (m *Manager) AddAddress(iface string, address string, flags AddressFlags) error {
	// Add the address to the kernel
	if err := m.kernelMgr.AddAddress(iface, address, flags); err != nil {
		return err
	}

	klog.Infof("Added IP address %s to interface %s", address, iface)
	return nil
}

// DeleteAddress deletes an IP address from an interface
func (m *Manager) DeleteAddress(iface string, address string) error {
	return m.kernelMgr.DeleteAddress(iface, address)
}

// ListAddresses lists all IP addresses on an interface
func (m *Manager) ListAddresses(iface string, family AddressFamily) ([]*IPAddress, error) {
	return m.kernelMgr.ListAddresses(iface, family)
}

// GetAddress gets a specific IP address on an interface
func (m *Manager) GetAddress(iface string, address string) (*IPAddress, error) {
	return m.kernelMgr.GetAddress(iface, address)
}

// SyncAddresses synchronizes our state with the kernel
func (m *Manager) SyncAddresses(iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get addresses from kernel
	kernelAddrs, err := m.kernelMgr.ListAddresses(iface, FamilyAll)
	if err != nil {
		return fmt.Errorf("failed to list kernel addresses: %w", err)
	}

	// Update our tracking
	if _, exists := m.addresses[iface]; !exists {
		m.addresses[iface] = make(map[string]*IPAddress)
	}

	// Clear existing tracking for this interface
	m.addresses[iface] = make(map[string]*IPAddress)

	// Add kernel addresses to our tracking
	for _, addr := range kernelAddrs {
		m.addresses[iface][addr.Address] = addr
	}

	klog.Infof("Synchronized %d addresses for interface %s", len(kernelAddrs), iface)
	return nil
}

// ReserveIP reserves an IP address in a subnet (prevents allocation)
func (m *Manager) ReserveIP(cidr string, ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	subnet, exists := m.subnets[cidr]
	if !exists {
		return fmt.Errorf("subnet %s does not exist", cidr)
	}

	if !subnet.Contains(ip) {
		return fmt.Errorf("IP %s is not in subnet %s", ip.String(), cidr)
	}

	subnet.Reserved[ip.String()] = true

	klog.Infof("Reserved IP %s in subnet %s", ip.String(), cidr)
	return nil
}

// UnreserveIP unreserves an IP address in a subnet
func (m *Manager) UnreserveIP(cidr string, ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	subnet, exists := m.subnets[cidr]
	if !exists {
		return fmt.Errorf("subnet %s does not exist", cidr)
	}

	delete(subnet.Reserved, ip.String())

	klog.Infof("Unreserved IP %s in subnet %s", ip.String(), cidr)
	return nil
}

// Helper functions

func (m *Manager) findSubnet(cidr string) (*Subnet, error) {
	subnet, exists := m.subnets[cidr]
	if !exists {
		return nil, fmt.Errorf("subnet %s not found", cidr)
	}
	return subnet, nil
}

func (m *Manager) findAvailableSubnet(family AddressFamily) (*Subnet, error) {
	for _, subnet := range m.subnets {
		if family == FamilyAll || subnet.Family == family {
			if subnet.Available() > 0 {
				return subnet, nil
			}
		}
	}
	return nil, fmt.Errorf("no available subnet for family %s", family.String())
}

func (m *Manager) isIPAvailable(subnet *Subnet, ip net.IP) bool {
	ipStr := ip.String()

	// Check if already allocated
	if _, allocated := subnet.Allocations[ipStr]; allocated {
		return false
	}

	// Check if reserved
	if subnet.Reserved[ipStr] {
		return false
	}

	return true
}

func (m *Manager) findNextAvailableIP(subnet *Subnet) (net.IP, error) {
	// Start from subnet.StartIP and iterate to subnet.EndIP
	ip := make(net.IP, len(subnet.StartIP))
	copy(ip, subnet.StartIP)

	for {
		// Check if IP is available
		if m.isIPAvailable(subnet, ip) {
			return ip, nil
		}

		// Increment IP
		m.incrementIP(ip)

		// Check if we've exceeded EndIP
		if m.ipGreaterThan(ip, subnet.EndIP) {
			return nil, fmt.Errorf("no available IPs in subnet %s", subnet.CIDR)
		}
	}
}

func (m *Manager) incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func (m *Manager) ipGreaterThan(ip1, ip2 net.IP) bool {
	if len(ip1) != len(ip2) {
		return false
	}
	for i := 0; i < len(ip1); i++ {
		if ip1[i] > ip2[i] {
			return true
		}
		if ip1[i] < ip2[i] {
			return false
		}
	}
	return false
}

func (m *Manager) calculateSubnetRange(network *net.IPNet) (net.IP, net.IP) {
	ip := network.IP
	mask := network.Mask

	// Calculate network address
	networkAddr := ip.Mask(mask)

	// Calculate broadcast address (for IPv4) or last address
	broadcastAddr := make(net.IP, len(networkAddr))
	copy(broadcastAddr, networkAddr)

	for i := 0; i < len(mask); i++ {
		broadcastAddr[i] |= ^mask[i]
	}

	// For IPv4, start from network+1 and end at broadcast-1
	// For IPv6, start from network+1 and end at last address
	startIP := make(net.IP, len(networkAddr))
	copy(startIP, networkAddr)
	m.incrementIP(startIP)

	endIP := make(net.IP, len(broadcastAddr))
	copy(endIP, broadcastAddr)

	if ip.To4() != nil {
		// For IPv4, exclude broadcast
		endIP[len(endIP)-1]--
	}

	return startIP, endIP
}

func (m *Manager) calculateBroadcast(network *net.IPNet) net.IP {
	networkAddr := network.IP.Mask(network.Mask)
	broadcastAddr := make(net.IP, len(networkAddr))
	copy(broadcastAddr, networkAddr)

	for i := 0; i < len(network.Mask); i++ {
		broadcastAddr[i] |= ^network.Mask[i]
	}

	return broadcastAddr
}
