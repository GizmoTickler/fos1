package vlan

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

// VLANManagerImpl implements the VLANManager interface
type VLANManagerImpl struct {
	interfaces map[string]*VLANInterface
	subscriptions map[string]VLANEventHandler
	trunkConfigs map[string]*TrunkConfig
	mu sync.RWMutex
	eventCh chan VLANEvent
	nextSubID int
	qosManager *QoSManager
	statsCollector *StatsCollector
}

// NewVLANManagerImpl creates a new VLAN manager implementation
func NewVLANManagerImpl() *VLANManagerImpl {
	manager := &VLANManagerImpl{
		interfaces: make(map[string]*VLANInterface),
		subscriptions: make(map[string]VLANEventHandler),
		trunkConfigs: make(map[string]*TrunkConfig),
		eventCh: make(chan VLANEvent, 100),
		nextSubID: 1,
		qosManager: NewQoSManager(),
		statsCollector: NewStatsCollector(),
	}

	// Start event dispatcher goroutine
	go manager.dispatchEvents()

	return manager
}

// dispatchEvents dispatches VLAN events to subscribers
func (m *VLANManagerImpl) dispatchEvents() {
	for event := range m.eventCh {
		m.mu.RLock()
		handlers := make([]VLANEventHandler, 0, len(m.subscriptions))
		for _, handler := range m.subscriptions {
			handlers = append(handlers, handler)
		}
		m.mu.RUnlock()
		
		// Notify all subscribers
		for _, handler := range handlers {
			go handler(event)
		}
	}
}

// sendEvent sends an event to the event channel
func (m *VLANManagerImpl) sendEvent(event VLANEvent) {
	select {
	case m.eventCh <- event:
		// Event sent successfully
	default:
		// Channel is full, log a warning
		klog.Warningf("Event channel is full, dropping event: %s for interface %s",
			event.Type, event.Interface.Name)
	}
}

// CreateVLAN creates a new VLAN interface
func (m *VLANManagerImpl) CreateVLAN(parent string, vlanID int, name string, config VLANConfig) (*VLANInterface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	klog.Infof("Creating VLAN interface %s with ID %d on parent %s", name, vlanID, parent)
	
	// Check if interface already exists
	if _, exists := m.interfaces[name]; exists {
		return nil, fmt.Errorf("VLAN interface %s already exists", name)
	}
	
	// Validate VLAN ID
	if vlanID < 1 || vlanID > 4094 {
		return nil, fmt.Errorf("invalid VLAN ID %d, must be between 1 and 4094", vlanID)
	}
	
	// Get parent link
	parentLink, err := netlink.LinkByName(parent)
	if err != nil {
		klog.Warningf("Failed to get parent interface %s: %v", parent, err)
		
		// Create a pending interface instead of failing
		vlanIf := &VLANInterface{
			Name:             name,
			Parent:           parent,
			VLANID:           vlanID,
			OperationalState: string(VLANStatePending),
			Config:           config,
			ErrorMessage:     fmt.Sprintf("Parent interface %s not found, VLAN will be created when parent is available", parent),
		}
		
		// Save the pending interface
		m.interfaces[name] = vlanIf
		
		// Send event
		m.sendEvent(VLANEvent{
			Type:      VLANEventCreated,
			Interface: vlanIf,
			Message:   fmt.Sprintf("Created pending VLAN interface %s", name),
			Timestamp: getCurrentTimestamp(),
		})
		
		return vlanIf, nil
	}
	
	// Create the VLAN interface
	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        name,
			ParentIndex: parentLink.Attrs().Index,
			MTU:         config.MTU,
		},
		VlanId:       vlanID,
		VlanProtocol: netlink.VLAN_PROTOCOL_8021Q,
	}
	
	if err := netlink.LinkAdd(vlan); err != nil {
		return nil, fmt.Errorf("failed to add VLAN interface %s: %w", name, err)
	}
	
	// Set the QoS priority if specified (802.1p)
	if config.QoSPriority >= 0 && config.QoSPriority <= 7 {
		klog.Infof("Setting 802.1p QoS priority %d for VLAN interface %s", config.QoSPriority, name)

		if err := m.qosManager.SetVLANPriority(name, config.QoSPriority); err != nil {
			klog.Warningf("Failed to set 802.1p priority for VLAN interface %s: %v", name, err)
		}
	}
	
	// Set link state
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get newly created VLAN interface %s: %w", name, err)
	}
	
	if config.State == "up" {
		if err := netlink.LinkSetUp(link); err != nil {
			return nil, fmt.Errorf("failed to set VLAN interface %s up: %w", name, err)
		}
	}
	
	// Add IP addresses if specified
	if len(config.Addresses) > 0 {
		for _, ipConfig := range config.Addresses {
			// Determine IP version (IPv4 = 32 bits, IPv6 = 128 bits)
			bits := 32
			if ipConfig.Address.To4() == nil {
				bits = 128
			}

			ipNet := &net.IPNet{
				IP:   ipConfig.Address,
				Mask: net.CIDRMask(ipConfig.Prefix, bits),
			}

			addr := &netlink.Addr{
				IPNet: ipNet,
			}

			if err := netlink.AddrAdd(link, addr); err != nil {
				klog.Warningf("Failed to add address %s to VLAN interface %s: %v",
					ipNet.String(), name, err)
			}
		}
	}
	
	// Configure egress QoS if specified
	if config.Egress.Enabled {
		klog.Infof("Configuring egress QoS for VLAN interface %s", name)

		if err := m.qosManager.ConfigureQoS(name, config.Egress); err != nil {
			klog.Warningf("Failed to configure egress QoS for VLAN interface %s: %v", name, err)
		}
	}

	// Note: Ingress QoS typically requires different mechanisms (e.g., IFB devices, police)
	// For now, we focus on egress QoS which is more commonly used
	if config.Ingress.Enabled {
		klog.Infof("Ingress QoS requested for VLAN interface %s (not yet fully implemented)", name)
	}

	// Set DSCP marking if specified
	if config.DSCP >= 0 && config.DSCP <= 63 {
		klog.Infof("Setting DSCP marking %d for VLAN interface %s", config.DSCP, name)

		if err := m.qosManager.SetDSCPMarking(name, config.DSCP); err != nil {
			klog.Warningf("Failed to set DSCP marking for VLAN interface %s: %v", name, err)
		}
	}
	
	// Create VLANInterface object
	actualMTU := config.MTU
	if actualMTU == 0 {
		// Get actual MTU from parent minus VLAN header size
		actualMTU = parentLink.Attrs().MTU - 4
	}
	
	vlanIf := &VLANInterface{
		Name:             name,
		Parent:           parent,
		VLANID:           vlanID,
		OperationalState: getInterfaceState(link),
		Config:           config,
		ActualMTU:        actualMTU,
		Statistics:       m.statsCollector.CollectStats(link),
	}
	
	// Save the interface
	m.interfaces[name] = vlanIf
	
	// Send event
	m.sendEvent(VLANEvent{
		Type:      VLANEventCreated,
		Interface: vlanIf,
		Message:   fmt.Sprintf("Created VLAN interface %s", name),
		Timestamp: getCurrentTimestamp(),
	})
	
	return vlanIf, nil
}

// DeleteVLAN removes a VLAN interface
func (m *VLANManagerImpl) DeleteVLAN(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	klog.Infof("Deleting VLAN interface %s", name)
	
	// Get the interface
	vlanIf, exists := m.interfaces[name]
	if !exists {
		return fmt.Errorf("VLAN interface %s does not exist", name)
	}
	
	// If the interface is pending, just remove it from our map
	if vlanIf.OperationalState == string(VLANStatePending) {
		delete(m.interfaces, name)
		
		// Send event
		m.sendEvent(VLANEvent{
			Type:      VLANEventDeleted,
			Interface: vlanIf,
			Message:   fmt.Sprintf("Deleted pending VLAN interface %s", name),
			Timestamp: getCurrentTimestamp(),
		})
		
		return nil
	}
	
	// Delete the interface from the system
	link, err := netlink.LinkByName(name)
	if err != nil {
		// Interface doesn't exist in the system, just remove from our map
		delete(m.interfaces, name)
		return nil
	}
	
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete VLAN interface %s: %w", name, err)
	}
	
	// Remove from our map
	delete(m.interfaces, name)
	
	// Send event
	m.sendEvent(VLANEvent{
		Type:      VLANEventDeleted,
		Interface: vlanIf,
		Message:   fmt.Sprintf("Deleted VLAN interface %s", name),
		Timestamp: getCurrentTimestamp(),
	})
	
	return nil
}

// GetVLAN retrieves information about a VLAN interface
func (m *VLANManagerImpl) GetVLAN(name string) (*VLANInterface, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Get the interface from our map
	vlanIf, exists := m.interfaces[name]
	if !exists {
		return nil, fmt.Errorf("VLAN interface %s does not exist", name)
	}
	
	// If the interface is pending, just return it
	if vlanIf.OperationalState == string(VLANStatePending) {
		return vlanIf, nil
	}
	
	// Get the interface from the system to update statistics
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get VLAN interface %s: %w", name, err)
	}
	
	// Update statistics
	vlanIf.Statistics = m.statsCollector.CollectStats(link)
	vlanIf.OperationalState = getInterfaceState(link)
	vlanIf.ActualMTU = link.Attrs().MTU
	
	return vlanIf, nil
}

// ListVLANs returns all configured VLAN interfaces
func (m *VLANManagerImpl) ListVLANs() ([]*VLANInterface, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Create a list of all interfaces in our map
	vlanIfs := make([]*VLANInterface, 0, len(m.interfaces))
	for _, vlanIf := range m.interfaces {
		vlanIfs = append(vlanIfs, vlanIf)
	}
	
	return vlanIfs, nil
}

// UpdateVLAN modifies a VLAN interface configuration
func (m *VLANManagerImpl) UpdateVLAN(name string, config VLANConfig) (*VLANInterface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	klog.Infof("Updating VLAN interface %s", name)
	
	// Get the interface from our map
	vlanIf, exists := m.interfaces[name]
	if !exists {
		return nil, fmt.Errorf("VLAN interface %s does not exist", name)
	}
	
	// If the interface is pending, just update the config
	if vlanIf.OperationalState == string(VLANStatePending) {
		vlanIf.Config = config
		
		// Send event
		m.sendEvent(VLANEvent{
			Type:      VLANEventUpdated,
			Interface: vlanIf,
			Message:   fmt.Sprintf("Updated pending VLAN interface %s", name),
			Timestamp: getCurrentTimestamp(),
		})
		
		return vlanIf, nil
	}
	
	// Get the interface from the system
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get VLAN interface %s: %w", name, err)
	}
	
	// Update MTU if changed
	if config.MTU > 0 && config.MTU != link.Attrs().MTU {
		if err := netlink.LinkSetMTU(link, config.MTU); err != nil {
			return nil, fmt.Errorf("failed to set MTU for VLAN interface %s: %w", name, err)
		}
	}
	
	// Update state if changed
	currentState := getInterfaceState(link)
	if (config.State == "up" && currentState != string(VLANStateUp)) ||
	   (config.State == "down" && currentState != string(VLANStateDown)) {
		if config.State == "up" {
			if err := netlink.LinkSetUp(link); err != nil {
				return nil, fmt.Errorf("failed to set VLAN interface %s up: %w", name, err)
			}
		} else {
			if err := netlink.LinkSetDown(link); err != nil {
				return nil, fmt.Errorf("failed to set VLAN interface %s down: %w", name, err)
			}
		}
	}
	
	// Update addresses if changed
	currentAddrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses for VLAN interface %s: %w", name, err)
	}
	
	// Remove addresses that are not in the new config
	for _, addr := range currentAddrs {
		found := false
		for _, ipConfig := range config.Addresses {
			if addr.IP.Equal(ipConfig.Address) {
				found = true
				break
			}
		}

		if !found {
			if err := netlink.AddrDel(link, &addr); err != nil {
				klog.Warningf("Failed to remove address %s from VLAN interface %s: %v",
					addr.String(), name, err)
			}
		}
	}
	
	// Add addresses that are not already configured
	for _, ipConfig := range config.Addresses {
		found := false
		for _, addr := range currentAddrs {
			if addr.IP.Equal(ipConfig.Address) {
				found = true
				break
			}
		}

		if !found {
			// Determine IP version (IPv4 = 32 bits, IPv6 = 128 bits)
			bits := 32
			if ipConfig.Address.To4() == nil {
				bits = 128
			}

			ipNet := &net.IPNet{
				IP:   ipConfig.Address,
				Mask: net.CIDRMask(ipConfig.Prefix, bits),
			}

			addr := &netlink.Addr{
				IPNet: ipNet,
			}

			if err := netlink.AddrAdd(link, addr); err != nil {
				klog.Warningf("Failed to add address %s to VLAN interface %s: %v",
					ipNet.String(), name, err)
			}
		}
	}

	// Save old config for comparison
	oldConfig := vlanIf.Config

	// Update QoS priority if changed
	if config.QoSPriority >= 0 && config.QoSPriority <= 7 &&
	   config.QoSPriority != oldConfig.QoSPriority {
		klog.Infof("Updating 802.1p QoS priority to %d for VLAN interface %s", config.QoSPriority, name)

		if err := m.qosManager.SetVLANPriority(name, config.QoSPriority); err != nil {
			klog.Warningf("Failed to update 802.1p priority for VLAN interface %s: %v", name, err)
		}
	}

	// Update egress QoS if changed
	if config.Egress.Enabled != oldConfig.Egress.Enabled {
		if config.Egress.Enabled {
			klog.Infof("Enabling egress QoS for VLAN interface %s", name)

			if err := m.qosManager.ConfigureQoS(name, config.Egress); err != nil {
				klog.Warningf("Failed to configure egress QoS for VLAN interface %s: %v", name, err)
			}
		} else {
			klog.Infof("Disabling egress QoS for VLAN interface %s", name)

			if err := m.qosManager.RemoveQoS(name); err != nil {
				klog.Warningf("Failed to remove QoS for VLAN interface %s: %v", name, err)
			}
		}
	} else if config.Egress.Enabled {
		// QoS is enabled, but configuration may have changed
		klog.Infof("Updating egress QoS configuration for VLAN interface %s", name)

		if err := m.qosManager.ConfigureQoS(name, config.Egress); err != nil {
			klog.Warningf("Failed to update egress QoS for VLAN interface %s: %v", name, err)
		}
	}

	// Update DSCP marking if changed
	if config.DSCP != oldConfig.DSCP && config.DSCP >= 0 && config.DSCP <= 63 {
		klog.Infof("Updating DSCP marking to %d for VLAN interface %s", config.DSCP, name)

		if err := m.qosManager.SetDSCPMarking(name, config.DSCP); err != nil {
			klog.Warningf("Failed to update DSCP marking for VLAN interface %s: %v", name, err)
		}
	}

	// Update the configuration in our map
	vlanIf.Config = config
	vlanIf.OperationalState = getInterfaceState(link)
	vlanIf.ActualMTU = link.Attrs().MTU
	vlanIf.Statistics = m.statsCollector.CollectStats(link)
	
	// Send event
	m.sendEvent(VLANEvent{
		Type:      VLANEventUpdated,
		Interface: vlanIf,
		Message:   fmt.Sprintf("Updated VLAN interface %s", name),
		Timestamp: getCurrentTimestamp(),
	})
	
	// Send QoS event if QoS was changed
	if (config.Egress.Enabled != oldConfig.Egress.Enabled) ||
	   (config.Ingress.Enabled != oldConfig.Ingress.Enabled) ||
	   (config.QoSPriority != oldConfig.QoSPriority) ||
	   (config.DSCP != oldConfig.DSCP) {
		m.sendEvent(VLANEvent{
			Type:      VLANEventQoSModified,
			Interface: vlanIf,
			Message:   fmt.Sprintf("QoS configuration updated for VLAN interface %s", name),
			Timestamp: getCurrentTimestamp(),
		})
	}
	
	return vlanIf, nil
}

// ConfigureTrunk configures a trunk interface with multiple VLANs
func (m *VLANManagerImpl) ConfigureTrunk(parent string, config TrunkConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	klog.Infof("Configuring trunk interface %s", parent)
	
	// Check if parent interface exists
	link, err := netlink.LinkByName(parent)
	if err != nil {
		return fmt.Errorf("parent interface %s not found: %w", parent, err)
	}
	
	// Validate config
	if config.NativeVLAN < 0 || config.NativeVLAN > 4094 {
		return fmt.Errorf("invalid native VLAN ID %d, must be between 0 and 4094", config.NativeVLAN)
	}
	
	for _, vlanID := range config.AllowedVLANs {
		if vlanID < 1 || vlanID > 4094 {
			return fmt.Errorf("invalid VLAN ID %d in allowed VLANs, must be between 1 and 4094", vlanID)
		}
	}
	
	// Set MTU if specified
	if config.MTU > 0 && config.MTU != link.Attrs().MTU {
		if err := netlink.LinkSetMTU(link, config.MTU); err != nil {
			return fmt.Errorf("failed to set MTU for trunk interface %s: %w", parent, err)
		}
	}
	
	// Set state if specified
	if config.State != "" {
		if config.State == "up" {
			if err := netlink.LinkSetUp(link); err != nil {
				return fmt.Errorf("failed to set trunk interface %s up: %w", parent, err)
			}
		} else if config.State == "down" {
			if err := netlink.LinkSetDown(link); err != nil {
				return fmt.Errorf("failed to set trunk interface %s down: %w", parent, err)
			}
		}
	}
	
	// Store the trunk configuration
	m.trunkConfigs[parent] = &config
	
	// Send event
	m.sendEvent(VLANEvent{
		Type:      VLANEventTrunkModified,
		Interface: nil,
		Message:   fmt.Sprintf("Configured trunk interface %s", parent),
		Timestamp: getCurrentTimestamp(),
	})
	
	return nil
}

// GetTrunkConfig retrieves trunk configuration for an interface
func (m *VLANManagerImpl) GetTrunkConfig(parent string) (*TrunkConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	config, exists := m.trunkConfigs[parent]
	if !exists {
		return nil, fmt.Errorf("no trunk configuration for interface %s", parent)
	}
	
	return config, nil
}

// AddVLANToTrunk adds a VLAN to a trunk interface
func (m *VLANManagerImpl) AddVLANToTrunk(parent string, vlanID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Check if trunk configuration exists
	config, exists := m.trunkConfigs[parent]
	if !exists {
		// Create a new trunk configuration
		config = &TrunkConfig{
			NativeVLAN:   0,
			AllowedVLANs: []int{vlanID},
			QinQ:         false,
			QinQEthertype: 0x8100,
			MTU:          0,
			State:        "",
		}
		m.trunkConfigs[parent] = config
	} else {
		// Check if VLAN is already in the list
		for _, id := range config.AllowedVLANs {
			if id == vlanID {
				return nil // VLAN already allowed, nothing to do
			}
		}
		
		// Add VLAN to allowed list
		config.AllowedVLANs = append(config.AllowedVLANs, vlanID)
	}
	
	// Send event
	m.sendEvent(VLANEvent{
		Type:      VLANEventTrunkModified,
		Interface: nil,
		Message:   fmt.Sprintf("Added VLAN %d to trunk interface %s", vlanID, parent),
		Timestamp: getCurrentTimestamp(),
	})
	
	return nil
}

// RemoveVLANFromTrunk removes a VLAN from a trunk interface
func (m *VLANManagerImpl) RemoveVLANFromTrunk(parent string, vlanID int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Check if trunk configuration exists
	config, exists := m.trunkConfigs[parent]
	if !exists {
		return fmt.Errorf("no trunk configuration for interface %s", parent)
	}
	
	// Remove VLAN from allowed list
	newAllowed := make([]int, 0, len(config.AllowedVLANs))
	for _, id := range config.AllowedVLANs {
		if id != vlanID {
			newAllowed = append(newAllowed, id)
		}
	}
	
	// If no change, return
	if len(newAllowed) == len(config.AllowedVLANs) {
		return nil
	}
	
	// Update allowed VLANs
	config.AllowedVLANs = newAllowed
	
	// Send event
	m.sendEvent(VLANEvent{
		Type:      VLANEventTrunkModified,
		Interface: nil,
		Message:   fmt.Sprintf("Removed VLAN %d from trunk interface %s", vlanID, parent),
		Timestamp: getCurrentTimestamp(),
	})
	
	return nil
}

// Subscribe registers a callback for VLAN events
func (m *VLANManagerImpl) Subscribe(handler VLANEventHandler) (subscriptionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	id := strconv.Itoa(m.nextSubID)
	m.nextSubID++
	
	m.subscriptions[id] = handler
	
	return id
}

// Unsubscribe removes a callback registered with Subscribe
func (m *VLANManagerImpl) Unsubscribe(subscriptionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	delete(m.subscriptions, subscriptionID)
}

// getInterfaceState returns the operational state of an interface
func getInterfaceState(link netlink.Link) string {
	if link.Attrs().Flags&net.FlagUp != 0 {
		return string(VLANStateUp)
	}
	return string(VLANStateDown)
}

// getInterfaceStats is kept for backward compatibility but now uses StatsCollector
func getInterfaceStats(link netlink.Link) VLANStats {
	collector := NewStatsCollector()
	return collector.CollectStats(link)
}

// getCurrentTimestamp returns the current Unix timestamp
func getCurrentTimestamp() int64 {
	return time.Now().Unix()
}
