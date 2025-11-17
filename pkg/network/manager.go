package network

import (
	"context"
	"fmt"
	"sync"

	"github.com/GizmoTickler/fos1/pkg/network/interfaces"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

// InterfaceConfig contains configuration for a network interface
type InterfaceConfig struct {
	MTU       int
	Addresses []string
	Enabled   bool
}

// VLANConfig contains configuration specific to VLAN interfaces
type VLANConfig struct {
	Parent      string
	VLANID      int
	QoSPriority int
	DSCP        int
}

// NetworkInterface represents a physical or virtual network interface
type NetworkInterface struct {
	Name            string
	Type            string // "physical", "vlan", "bridge", "bond"
	OperationalState string
	Config          InterfaceConfig
	VLANConfig      *VLANConfig // Only for VLAN interfaces
	ActualMTU       int
	ErrorMessage    string
}

// NetworkInterfaceManager manages network interfaces
type NetworkInterfaceManager struct {
	interfaces    map[string]*NetworkInterface
	mu            sync.RWMutex
	kernelManager *interfaces.KernelInterfaceManager
	ctx           context.Context
}

// NewNetworkInterfaceManager creates a new NetworkInterfaceManager
func NewNetworkInterfaceManager(ctx context.Context) (*NetworkInterfaceManager, error) {
	kernelMgr := interfaces.NewKernelInterfaceManager()

	manager := &NetworkInterfaceManager{
		interfaces:    make(map[string]*NetworkInterface),
		kernelManager: kernelMgr,
		ctx:           ctx,
	}

	// Register callback for link updates
	kernelMgr.RegisterLinkUpdateCallback(manager.handleLinkUpdate)

	// Start monitoring
	if err := kernelMgr.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start kernel interface manager: %w", err)
	}

	return manager, nil
}

// Stop stops the network interface manager
func (m *NetworkInterfaceManager) Stop() {
	if m.kernelManager != nil {
		m.kernelManager.Stop()
	}
}

// handleLinkUpdate handles link state updates from the kernel
func (m *NetworkInterfaceManager) handleLinkUpdate(update netlink.LinkUpdate) {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := update.Link.Attrs().Name
	netIf, exists := m.interfaces[name]
	if !exists {
		// Interface not tracked by us, ignore
		return
	}

	// Update operational state based on flags
	attrs := update.Link.Attrs()
	if attrs.Flags&1 != 0 { // IFF_UP
		netIf.OperationalState = "up"
		netIf.Config.Enabled = true
	} else {
		netIf.OperationalState = "down"
		netIf.Config.Enabled = false
	}

	// Update MTU
	if attrs.MTU > 0 {
		netIf.ActualMTU = attrs.MTU
	}

	klog.V(4).Infof("Updated interface %s state to %s", name, netIf.OperationalState)
}

// CreateInterface creates a new network interface
func (m *NetworkInterfaceManager) CreateInterface(name string, interfaceType string, config InterfaceConfig) (*NetworkInterface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if interface already exists
	if _, exists := m.interfaces[name]; exists {
		return nil, fmt.Errorf("interface %s already exists", name)
	}

	// Create interface in kernel based on type
	var err error
	switch interfaceType {
	case "dummy":
		// Create dummy interface (for testing)
		mtu := config.MTU
		if mtu == 0 {
			mtu = 1500 // Default MTU
		}
		err = m.kernelManager.CreateDummyInterface(name, mtu)
	case "bridge":
		mtu := config.MTU
		if mtu == 0 {
			mtu = 1500
		}
		err = m.kernelManager.CreateBridgeInterface(name, mtu)
	case "bond":
		mtu := config.MTU
		if mtu == 0 {
			mtu = 1500
		}
		// Default to balance-rr mode (mode 0)
		err = m.kernelManager.CreateBondInterface(name, netlink.BOND_MODE_BALANCE_RR, mtu)
	case "physical":
		// Physical interfaces cannot be created, they must already exist
		exists, checkErr := m.kernelManager.InterfaceExists(name)
		if checkErr != nil {
			return nil, fmt.Errorf("failed to check if physical interface %s exists: %w", name, checkErr)
		}
		if !exists {
			return nil, fmt.Errorf("physical interface %s does not exist", name)
		}
	default:
		return nil, fmt.Errorf("unsupported interface type: %s", interfaceType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create interface %s in kernel: %w", name, err)
	}

	// Create interface struct
	netIf := &NetworkInterface{
		Name:             name,
		Type:             interfaceType,
		OperationalState: "down",
		Config:           config,
		ActualMTU:        config.MTU,
	}

	// Apply configuration if interface was created
	if interfaceType != "physical" {
		// Apply MTU if specified
		if config.MTU > 0 {
			if err := m.kernelManager.SetMTU(name, config.MTU); err != nil {
				klog.Warningf("Failed to set MTU on interface %s: %v", name, err)
			}
		}

		// Add IP addresses
		for _, addr := range config.Addresses {
			if err := m.kernelManager.AddIPAddress(name, addr); err != nil {
				klog.Warningf("Failed to add IP address %s to interface %s: %v", addr, name, err)
			}
		}

		// Bring interface up if enabled
		if config.Enabled {
			if err := m.kernelManager.SetInterfaceUp(name); err != nil {
				klog.Warningf("Failed to bring interface %s up: %v", name, err)
			} else {
				netIf.OperationalState = "up"
			}
		}
	}

	// Get actual MTU from kernel
	if actualMTU, err := m.kernelManager.GetInterfaceMTU(name); err == nil {
		netIf.ActualMTU = actualMTU
	}

	// Store interface
	m.interfaces[name] = netIf

	klog.Infof("Created interface %s of type %s", name, interfaceType)
	return netIf, nil
}

// CreateVLAN creates a VLAN interface
func (m *NetworkInterfaceManager) CreateVLAN(name string, config InterfaceConfig, vlanConfig VLANConfig) (*NetworkInterface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if VLAN interface already exists
	if _, exists := m.interfaces[name]; exists {
		return nil, fmt.Errorf("interface %s already exists", name)
	}

	// Check if parent is specified
	if vlanConfig.Parent == "" {
		return nil, fmt.Errorf("parent interface must be specified for VLAN interface")
	}

	// Check if VLAN ID is valid
	if vlanConfig.VLANID < 1 || vlanConfig.VLANID > 4094 {
		return nil, fmt.Errorf("invalid VLAN ID: %d, must be between 1 and 4094", vlanConfig.VLANID)
	}

	// Check if parent interface exists in kernel
	parentExists, err := m.kernelManager.InterfaceExists(vlanConfig.Parent)
	if err != nil {
		return nil, fmt.Errorf("failed to check parent interface %s: %w", vlanConfig.Parent, err)
	}

	if !parentExists {
		// Create pending interface
		vlanIf := &NetworkInterface{
			Name:             name,
			Type:             "vlan",
			OperationalState: "pending",
			Config:           config,
			VLANConfig:       &vlanConfig,
			ErrorMessage:     fmt.Sprintf("waiting for parent interface %s", vlanConfig.Parent),
		}
		m.interfaces[name] = vlanIf
		klog.Warningf("Created pending VLAN interface %s, waiting for parent %s", name, vlanConfig.Parent)
		return vlanIf, nil
	}

	// Get parent MTU from kernel
	parentMTU, err := m.kernelManager.GetInterfaceMTU(vlanConfig.Parent)
	if err != nil {
		return nil, fmt.Errorf("failed to get parent interface MTU: %w", err)
	}

	// Calculate MTU if not explicitly set
	vlanMTU := config.MTU
	if vlanMTU == 0 {
		vlanMTU = parentMTU - 4 // VLAN header is 4 bytes
	} else if vlanMTU > parentMTU-4 {
		klog.Warningf("Requested VLAN MTU %d exceeds parent MTU - 4 (%d), using %d", vlanMTU, parentMTU-4, parentMTU-4)
		vlanMTU = parentMTU - 4
	}

	// Create VLAN interface in kernel
	if err := m.kernelManager.CreateVLANInterface(name, vlanConfig.Parent, vlanConfig.VLANID, vlanMTU); err != nil {
		return nil, fmt.Errorf("failed to create VLAN interface in kernel: %w", err)
	}

	// Create interface struct
	vlanIf := &NetworkInterface{
		Name:             name,
		Type:             "vlan",
		OperationalState: "down",
		Config:           config,
		VLANConfig:       &vlanConfig,
		ActualMTU:        vlanMTU,
	}

	// Add IP addresses
	for _, addr := range config.Addresses {
		if err := m.kernelManager.AddIPAddress(name, addr); err != nil {
			klog.Warningf("Failed to add IP address %s to VLAN interface %s: %v", addr, name, err)
		}
	}

	// Bring interface up if enabled
	if config.Enabled {
		if err := m.kernelManager.SetInterfaceUp(name); err != nil {
			klog.Warningf("Failed to bring VLAN interface %s up: %v", name, err)
		} else {
			vlanIf.OperationalState = "up"
		}
	}

	// Store interface
	m.interfaces[name] = vlanIf

	klog.Infof("Created VLAN interface %s on parent %s with ID %d", name, vlanConfig.Parent, vlanConfig.VLANID)
	return vlanIf, nil
}

// DeleteInterface deletes a network interface
func (m *NetworkInterfaceManager) DeleteInterface(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if interface exists in our tracking
	netIf, exists := m.interfaces[name]
	if !exists {
		return fmt.Errorf("interface %s does not exist", name)
	}

	// Don't delete physical interfaces from kernel
	if netIf.Type != "physical" {
		// Delete interface from kernel
		if err := m.kernelManager.DeleteInterface(name); err != nil {
			return fmt.Errorf("failed to delete interface %s from kernel: %w", name, err)
		}
	}

	// Remove from tracking
	delete(m.interfaces, name)

	klog.Infof("Deleted interface %s", name)
	return nil
}

// GetInterface gets a network interface
func (m *NetworkInterfaceManager) GetInterface(name string) (*NetworkInterface, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if interface exists
	netIf, exists := m.interfaces[name]
	if !exists {
		return nil, fmt.Errorf("interface %s does not exist", name)
	}

	return netIf, nil
}

// ListInterfaces lists all network interfaces
func (m *NetworkInterfaceManager) ListInterfaces() ([]*NetworkInterface, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	interfaces := make([]*NetworkInterface, 0, len(m.interfaces))
	for _, netIf := range m.interfaces {
		interfaces = append(interfaces, netIf)
	}

	return interfaces, nil
}

// UpdateInterface updates a network interface configuration
func (m *NetworkInterfaceManager) UpdateInterface(name string, config InterfaceConfig) (*NetworkInterface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if interface exists
	netIf, exists := m.interfaces[name]
	if !exists {
		return nil, fmt.Errorf("interface %s does not exist", name)
	}

	// Update MTU if specified and changed
	if config.MTU > 0 && config.MTU != netIf.Config.MTU {
		// For VLAN interfaces, check against parent MTU
		mtuToSet := config.MTU
		if netIf.Type == "vlan" && netIf.VLANConfig != nil {
			parentMTU, err := m.kernelManager.GetInterfaceMTU(netIf.VLANConfig.Parent)
			if err == nil {
				if config.MTU > parentMTU-4 {
					mtuToSet = parentMTU - 4
					netIf.ErrorMessage = fmt.Sprintf("requested MTU %d exceeds parent MTU - 4 (%d), using %d",
						config.MTU, parentMTU-4, mtuToSet)
					klog.Warningf("VLAN interface %s: %s", name, netIf.ErrorMessage)
				} else {
					netIf.ErrorMessage = ""
				}
			}
		}

		// Set MTU in kernel
		if err := m.kernelManager.SetMTU(name, mtuToSet); err != nil {
			klog.Warningf("Failed to set MTU on interface %s: %v", name, err)
		} else {
			netIf.ActualMTU = mtuToSet
		}
	}

	// Update IP addresses
	// Get current addresses from kernel
	currentAddrs, err := m.kernelManager.GetInterfaceAddresses(name)
	if err == nil {
		// Remove addresses that are no longer in the config
		for _, currentAddr := range currentAddrs {
			found := false
			for _, newAddr := range config.Addresses {
				if currentAddr == newAddr {
					found = true
					break
				}
			}
			if !found {
				if err := m.kernelManager.DeleteIPAddress(name, currentAddr); err != nil {
					klog.Warningf("Failed to delete IP address %s from interface %s: %v", currentAddr, name, err)
				}
			}
		}

		// Add new addresses
		for _, newAddr := range config.Addresses {
			found := false
			for _, currentAddr := range currentAddrs {
				if newAddr == currentAddr {
					found = true
					break
				}
			}
			if !found {
				if err := m.kernelManager.AddIPAddress(name, newAddr); err != nil {
					klog.Warningf("Failed to add IP address %s to interface %s: %v", newAddr, name, err)
				}
			}
		}
	}

	// Update interface state if Enabled changed
	if config.Enabled != netIf.Config.Enabled {
		if config.Enabled {
			if err := m.kernelManager.SetInterfaceUp(name); err != nil {
				klog.Warningf("Failed to bring interface %s up: %v", name, err)
			} else {
				netIf.OperationalState = "up"
			}
		} else {
			if err := m.kernelManager.SetInterfaceDown(name); err != nil {
				klog.Warningf("Failed to bring interface %s down: %v", name, err)
			} else {
				netIf.OperationalState = "down"
			}
		}
	}

	// Update configuration
	netIf.Config = config

	klog.Infof("Updated interface %s configuration", name)
	return netIf, nil
}

// SetInterfaceUp sets a network interface up
func (m *NetworkInterfaceManager) SetInterfaceUp(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if interface exists
	netIf, exists := m.interfaces[name]
	if !exists {
		return fmt.Errorf("interface %s does not exist", name)
	}

	// Set interface up in kernel
	if err := m.kernelManager.SetInterfaceUp(name); err != nil {
		return fmt.Errorf("failed to set interface %s up: %w", name, err)
	}

	// Update state
	netIf.OperationalState = "up"
	netIf.Config.Enabled = true

	klog.Infof("Set interface %s up", name)
	return nil
}

// SetInterfaceDown sets a network interface down
func (m *NetworkInterfaceManager) SetInterfaceDown(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if interface exists
	netIf, exists := m.interfaces[name]
	if !exists {
		return fmt.Errorf("interface %s does not exist", name)
	}

	// Set interface down in kernel
	if err := m.kernelManager.SetInterfaceDown(name); err != nil {
		return fmt.Errorf("failed to set interface %s down: %w", name, err)
	}

	// Update state
	netIf.OperationalState = "down"
	netIf.Config.Enabled = false

	klog.Infof("Set interface %s down", name)
	return nil
}

// GetAllVLANInterfaces gets all VLAN interfaces
func (m *NetworkInterfaceManager) GetAllVLANInterfaces() ([]*NetworkInterface, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vlanInterfaces := make([]*NetworkInterface, 0)
	for _, netIf := range m.interfaces {
		if netIf.Type == "vlan" {
			vlanInterfaces = append(vlanInterfaces, netIf)
		}
	}

	return vlanInterfaces, nil
}

// CheckParentUpdates checks if any pending VLAN interfaces can be activated
func (m *NetworkInterfaceManager) CheckParentUpdates(parentName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	parent, exists := m.interfaces[parentName]
	if !exists {
		return fmt.Errorf("parent interface %s does not exist", parentName)
	}

	// Check if any VLAN interfaces are waiting for this parent
	for _, netIf := range m.interfaces {
		if netIf.Type == "vlan" && netIf.VLANConfig != nil && netIf.VLANConfig.Parent == parentName && netIf.OperationalState == "pending" {
			// Parent is now available, update MTU
			if netIf.Config.MTU == 0 || netIf.Config.MTU > parent.ActualMTU-4 {
				netIf.ActualMTU = parent.ActualMTU - 4
				netIf.ErrorMessage = fmt.Sprintf("using parent MTU - 4 (%d)", netIf.ActualMTU)
			} else {
				netIf.ActualMTU = netIf.Config.MTU
				netIf.ErrorMessage = ""
			}

			// Set state to down (ready to be brought up)
			netIf.OperationalState = "down"
			klog.Infof("VLAN interface %s is now ready (parent %s is available)", netIf.Name, parentName)
		}
	}

	return nil
}
