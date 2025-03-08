package network

import (
	"fmt"
	"sync"

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
	interfaces map[string]*NetworkInterface
	mu         sync.RWMutex
}

// NewNetworkInterfaceManager creates a new NetworkInterfaceManager
func NewNetworkInterfaceManager() *NetworkInterfaceManager {
	return &NetworkInterfaceManager{
		interfaces: make(map[string]*NetworkInterface),
	}
}

// CreateInterface creates a new network interface
func (m *NetworkInterfaceManager) CreateInterface(name string, interfaceType string, config InterfaceConfig) (*NetworkInterface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if interface already exists
	if _, exists := m.interfaces[name]; exists {
		return nil, fmt.Errorf("interface %s already exists", name)
	}

	// Create interface struct
	netIf := &NetworkInterface{
		Name:            name,
		Type:            interfaceType,
		OperationalState: "down",
		Config:          config,
		ActualMTU:       config.MTU,
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

	// Check if parent interface exists
	parent, exists := m.interfaces[vlanConfig.Parent]
	if !exists {
		// Create pending interface
		vlanIf := &NetworkInterface{
			Name:            name,
			Type:            "vlan",
			OperationalState: "pending",
			Config:          config,
			VLANConfig:      &vlanConfig,
			ErrorMessage:    fmt.Sprintf("waiting for parent interface %s", vlanConfig.Parent),
		}
		m.interfaces[name] = vlanIf
		klog.Warningf("Created pending VLAN interface %s, waiting for parent %s", name, vlanConfig.Parent)
		return vlanIf, nil
	}

	// Create interface struct
	vlanIf := &NetworkInterface{
		Name:            name,
		Type:            "vlan",
		OperationalState: "down",
		Config:          config,
		VLANConfig:      &vlanConfig,
	}

	// Calculate MTU if not explicitly set
	if config.MTU == 0 {
		vlanIf.ActualMTU = parent.ActualMTU - 4 // VLAN header is 4 bytes
	} else {
		// Validate VLAN MTU doesn't exceed parent MTU - 4
		if config.MTU > parent.ActualMTU - 4 {
			vlanIf.ActualMTU = parent.ActualMTU - 4
			vlanIf.ErrorMessage = fmt.Sprintf("requested MTU %d exceeds parent MTU - 4 (%d), using %d", 
				config.MTU, parent.ActualMTU - 4, vlanIf.ActualMTU)
			klog.Warningf("VLAN interface %s: %s", name, vlanIf.ErrorMessage)
		} else {
			vlanIf.ActualMTU = config.MTU
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

	// Check if interface exists
	if _, exists := m.interfaces[name]; !exists {
		return fmt.Errorf("interface %s does not exist", name)
	}

	// Delete interface
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

	// Update configuration
	netIf.Config = config

	// Update MTU if specified
	if config.MTU > 0 {
		// For VLAN interfaces, check against parent MTU
		if netIf.Type == "vlan" && netIf.VLANConfig != nil {
			parent, exists := m.interfaces[netIf.VLANConfig.Parent]
			if exists {
				if config.MTU > parent.ActualMTU - 4 {
					netIf.ActualMTU = parent.ActualMTU - 4
					netIf.ErrorMessage = fmt.Sprintf("requested MTU %d exceeds parent MTU - 4 (%d), using %d", 
						config.MTU, parent.ActualMTU - 4, netIf.ActualMTU)
					klog.Warningf("VLAN interface %s: %s", name, netIf.ErrorMessage)
				} else {
					netIf.ActualMTU = config.MTU
					netIf.ErrorMessage = ""
				}
			} else {
				netIf.ActualMTU = config.MTU
			}
		} else {
			netIf.ActualMTU = config.MTU
		}
	}

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

	// Set state to up
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

	// Set state to down
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
