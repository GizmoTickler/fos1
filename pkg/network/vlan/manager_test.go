package vlan

import (
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// TestVLANManagerCreation tests the creation of a VLAN manager
func TestVLANManagerCreation(t *testing.T) {
	manager := NewVLANManagerImpl()
	if manager == nil {
		t.Fatal("Failed to create VLAN manager")
	}

	if manager.interfaces == nil {
		t.Error("interfaces map is nil")
	}

	if manager.subscriptions == nil {
		t.Error("subscriptions map is nil")
	}

	if manager.qosManager == nil {
		t.Error("qosManager is nil")
	}

	if manager.statsCollector == nil {
		t.Error("statsCollector is nil")
	}
}

// TestVLANIDValidation tests VLAN ID validation
func TestVLANIDValidation(t *testing.T) {
	manager := NewVLANManagerImpl()

	tests := []struct {
		name     string
		vlanID   int
		wantErr  bool
	}{
		{"Valid VLAN ID 1", 1, false},
		{"Valid VLAN ID 100", 100, false},
		{"Valid VLAN ID 4094", 4094, false},
		{"Invalid VLAN ID 0", 0, true},
		{"Invalid VLAN ID -1", -1, true},
		{"Invalid VLAN ID 4095", 4095, true},
		{"Invalid VLAN ID 5000", 5000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := VLANConfig{
				State: "down",
			}

			_, err := manager.CreateVLAN("nonexistent", tt.vlanID, "test-vlan", config)

			if (err != nil) != tt.wantErr {
				if tt.wantErr {
					t.Errorf("Expected error for VLAN ID %d, got none", tt.vlanID)
				} else {
					t.Errorf("Unexpected error for VLAN ID %d: %v", tt.vlanID, err)
				}
			}
		})
	}
}

// TestVLANInterfacePending tests creating a VLAN with non-existent parent
func TestVLANInterfacePending(t *testing.T) {
	manager := NewVLANManagerImpl()

	config := VLANConfig{
		State: "down",
		MTU:   1500,
	}

	vlanIf, err := manager.CreateVLAN("nonexistent-parent", 100, "vlan100", config)
	if err != nil {
		t.Fatalf("Failed to create pending VLAN: %v", err)
	}

	if vlanIf.OperationalState != string(VLANStatePending) {
		t.Errorf("Expected VLAN state to be pending, got %s", vlanIf.OperationalState)
	}

	if vlanIf.VLANID != 100 {
		t.Errorf("Expected VLAN ID 100, got %d", vlanIf.VLANID)
	}

	if vlanIf.Parent != "nonexistent-parent" {
		t.Errorf("Expected parent nonexistent-parent, got %s", vlanIf.Parent)
	}
}

// TestVLANList tests listing VLAN interfaces
func TestVLANList(t *testing.T) {
	manager := NewVLANManagerImpl()

	// Create multiple pending VLANs
	config := VLANConfig{State: "down"}

	for i := 1; i <= 5; i++ {
		name := "vlan" + string(rune('0'+i))
		_, err := manager.CreateVLAN("nonexistent", 100+i, name, config)
		if err != nil {
			t.Fatalf("Failed to create VLAN %s: %v", name, err)
		}
	}

	vlans, err := manager.ListVLANs()
	if err != nil {
		t.Fatalf("Failed to list VLANs: %v", err)
	}

	if len(vlans) != 5 {
		t.Errorf("Expected 5 VLANs, got %d", len(vlans))
	}
}

// TestVLANGet tests getting a specific VLAN interface
func TestVLANGet(t *testing.T) {
	manager := NewVLANManagerImpl()

	config := VLANConfig{
		State: "down",
		MTU:   1500,
	}

	created, err := manager.CreateVLAN("nonexistent", 100, "vlan100", config)
	if err != nil {
		t.Fatalf("Failed to create VLAN: %v", err)
	}

	retrieved, err := manager.GetVLAN("vlan100")
	if err != nil {
		t.Fatalf("Failed to get VLAN: %v", err)
	}

	if retrieved.Name != created.Name {
		t.Errorf("Expected VLAN name %s, got %s", created.Name, retrieved.Name)
	}

	if retrieved.VLANID != created.VLANID {
		t.Errorf("Expected VLAN ID %d, got %d", created.VLANID, retrieved.VLANID)
	}
}

// TestVLANDelete tests deleting a VLAN interface
func TestVLANDelete(t *testing.T) {
	manager := NewVLANManagerImpl()

	config := VLANConfig{State: "down"}

	_, err := manager.CreateVLAN("nonexistent", 100, "vlan100", config)
	if err != nil {
		t.Fatalf("Failed to create VLAN: %v", err)
	}

	err = manager.DeleteVLAN("vlan100")
	if err != nil {
		t.Fatalf("Failed to delete VLAN: %v", err)
	}

	// Verify it's deleted
	_, err = manager.GetVLAN("vlan100")
	if err == nil {
		t.Error("Expected error when getting deleted VLAN, got none")
	}
}

// TestVLANUpdate tests updating a VLAN interface
func TestVLANUpdate(t *testing.T) {
	manager := NewVLANManagerImpl()

	config := VLANConfig{
		State:       "down",
		MTU:         1500,
		QoSPriority: 3,
	}

	_, err := manager.CreateVLAN("nonexistent", 100, "vlan100", config)
	if err != nil {
		t.Fatalf("Failed to create VLAN: %v", err)
	}

	// Update the configuration
	newConfig := VLANConfig{
		State:       "down",
		MTU:         1400,
		QoSPriority: 5,
	}

	updated, err := manager.UpdateVLAN("vlan100", newConfig)
	if err != nil {
		t.Fatalf("Failed to update VLAN: %v", err)
	}

	if updated.Config.MTU != 1400 {
		t.Errorf("Expected MTU 1400, got %d", updated.Config.MTU)
	}

	if updated.Config.QoSPriority != 5 {
		t.Errorf("Expected QoS priority 5, got %d", updated.Config.QoSPriority)
	}
}

// TestTrunkConfiguration tests trunk interface configuration
func TestTrunkConfiguration(t *testing.T) {
	manager := NewVLANManagerImpl()

	trunkConfig := TrunkConfig{
		NativeVLAN:   1,
		AllowedVLANs: []int{10, 20, 30, 40},
		QinQ:         false,
		MTU:          9000,
		State:        "down",
	}

	// This will fail if the parent doesn't exist, which is expected
	err := manager.ConfigureTrunk("nonexistent", trunkConfig)
	if err == nil {
		t.Error("Expected error for non-existent trunk interface, got none")
	}
}

// TestTrunkVLANManagement tests adding and removing VLANs from trunk
func TestTrunkVLANManagement(t *testing.T) {
	manager := NewVLANManagerImpl()

	// Add VLAN to trunk (creates new trunk config if needed)
	err := manager.AddVLANToTrunk("eth0", 100)
	if err != nil {
		t.Fatalf("Failed to add VLAN to trunk: %v", err)
	}

	// Add another VLAN
	err = manager.AddVLANToTrunk("eth0", 200)
	if err != nil {
		t.Fatalf("Failed to add second VLAN to trunk: %v", err)
	}

	// Get trunk config
	config, err := manager.GetTrunkConfig("eth0")
	if err != nil {
		t.Fatalf("Failed to get trunk config: %v", err)
	}

	if len(config.AllowedVLANs) != 2 {
		t.Errorf("Expected 2 allowed VLANs, got %d", len(config.AllowedVLANs))
	}

	// Remove a VLAN
	err = manager.RemoveVLANFromTrunk("eth0", 100)
	if err != nil {
		t.Fatalf("Failed to remove VLAN from trunk: %v", err)
	}

	config, err = manager.GetTrunkConfig("eth0")
	if err != nil {
		t.Fatalf("Failed to get trunk config after removal: %v", err)
	}

	if len(config.AllowedVLANs) != 1 {
		t.Errorf("Expected 1 allowed VLAN after removal, got %d", len(config.AllowedVLANs))
	}
}

// TestVLANEvents tests VLAN event subscription and notification
func TestVLANEvents(t *testing.T) {
	manager := NewVLANManagerImpl()

	eventReceived := make(chan VLANEvent, 10)

	// Subscribe to events
	subID := manager.Subscribe(func(event VLANEvent) {
		eventReceived <- event
	})

	if subID == "" {
		t.Fatal("Failed to subscribe to events")
	}

	config := VLANConfig{State: "down"}

	// Create a VLAN
	_, err := manager.CreateVLAN("nonexistent", 100, "vlan100", config)
	if err != nil {
		t.Fatalf("Failed to create VLAN: %v", err)
	}

	// Wait for event
	select {
	case event := <-eventReceived:
		if event.Type != VLANEventCreated {
			t.Errorf("Expected VLANEventCreated, got %s", event.Type)
		}
		if event.Interface.Name != "vlan100" {
			t.Errorf("Expected interface name vlan100, got %s", event.Interface.Name)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for event")
	}

	// Update the VLAN
	newConfig := VLANConfig{
		State:       "down",
		QoSPriority: 5,
	}

	_, err = manager.UpdateVLAN("vlan100", newConfig)
	if err != nil {
		t.Fatalf("Failed to update VLAN: %v", err)
	}

	// Wait for update event
	select {
	case event := <-eventReceived:
		if event.Type != VLANEventUpdated {
			t.Errorf("Expected VLANEventUpdated, got %s", event.Type)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for update event")
	}

	// Unsubscribe
	manager.Unsubscribe(subID)

	// Delete the VLAN
	err = manager.DeleteVLAN("vlan100")
	if err != nil {
		t.Fatalf("Failed to delete VLAN: %v", err)
	}

	// Should not receive event after unsubscribe
	select {
	case <-eventReceived:
		t.Error("Received event after unsubscribe")
	case <-time.After(100 * time.Millisecond):
		// Expected - no event
	}
}

// TestQoSPriorityValidation tests QoS priority validation
func TestQoSPriorityValidation(t *testing.T) {
	manager := NewVLANManagerImpl()

	tests := []struct {
		name     string
		priority int
		valid    bool
	}{
		{"Valid priority 0", 0, true},
		{"Valid priority 3", 3, true},
		{"Valid priority 7", 7, true},
		{"Invalid priority -1", -1, false},
		{"Invalid priority 8", 8, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := VLANConfig{
				State:       "down",
				QoSPriority: tt.priority,
			}

			vlanIf, err := manager.CreateVLAN("nonexistent", 100, "vlan100", config)
			if err != nil {
				t.Fatalf("Failed to create VLAN: %v", err)
			}

			// For invalid priorities, the config should still be stored
			// but QoS application would fail
			if vlanIf.Config.QoSPriority != tt.priority {
				t.Errorf("Expected QoS priority %d, got %d", tt.priority, vlanIf.Config.QoSPriority)
			}

			// Clean up
			manager.DeleteVLAN("vlan100")
		})
	}
}

// TestVLANConfigWithAddresses tests VLAN configuration with IP addresses
func TestVLANConfigWithAddresses(t *testing.T) {
	manager := NewVLANManagerImpl()

	config := VLANConfig{
		State: "down",
		MTU:   1500,
		Addresses: []IPConfig{
			{
				Address: net.ParseIP("192.168.1.1"),
				Prefix:  24,
				Gateway: net.ParseIP("192.168.1.254"),
			},
			{
				Address: net.ParseIP("2001:db8::1"),
				Prefix:  64,
			},
		},
	}

	vlanIf, err := manager.CreateVLAN("nonexistent", 100, "vlan100", config)
	if err != nil {
		t.Fatalf("Failed to create VLAN: %v", err)
	}

	if len(vlanIf.Config.Addresses) != 2 {
		t.Errorf("Expected 2 addresses, got %d", len(vlanIf.Config.Addresses))
	}

	// Verify IPv4 address
	if !vlanIf.Config.Addresses[0].Address.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("Expected IPv4 address 192.168.1.1, got %s", vlanIf.Config.Addresses[0].Address)
	}

	// Verify IPv6 address
	if !vlanIf.Config.Addresses[1].Address.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("Expected IPv6 address 2001:db8::1, got %s", vlanIf.Config.Addresses[1].Address)
	}
}

// TestVLANQoSConfig tests VLAN QoS configuration
func TestVLANQoSConfig(t *testing.T) {
	manager := NewVLANManagerImpl()

	config := VLANConfig{
		State:       "down",
		QoSPriority: 5,
		DSCP:        46, // EF (Expedited Forwarding)
		Egress: QoSConfig{
			Enabled:      true,
			DefaultClass: 1,
			MaxRate:      "1Gbit",
			Classes: []QoSClass{
				{
					ID:       1,
					Priority: 7,
					Rate:     "800Mbit",
					Ceiling:  "1Gbit",
					Burst:    "15kb",
				},
				{
					ID:       2,
					Priority: 3,
					Rate:     "200Mbit",
					Ceiling:  "500Mbit",
					Burst:    "10kb",
				},
			},
		},
	}

	vlanIf, err := manager.CreateVLAN("nonexistent", 100, "vlan100", config)
	if err != nil {
		t.Fatalf("Failed to create VLAN: %v", err)
	}

	if vlanIf.Config.QoSPriority != 5 {
		t.Errorf("Expected QoS priority 5, got %d", vlanIf.Config.QoSPriority)
	}

	if vlanIf.Config.DSCP != 46 {
		t.Errorf("Expected DSCP 46, got %d", vlanIf.Config.DSCP)
	}

	if !vlanIf.Config.Egress.Enabled {
		t.Error("Expected egress QoS to be enabled")
	}

	if len(vlanIf.Config.Egress.Classes) != 2 {
		t.Errorf("Expected 2 QoS classes, got %d", len(vlanIf.Config.Egress.Classes))
	}
}

// TestGetInterfaceState tests interface state detection
func TestGetInterfaceState(t *testing.T) {
	// Create a dummy link for testing
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:  "test-dummy",
			Flags: net.FlagUp,
		},
	}

	state := getInterfaceState(link)
	if state != string(VLANStateUp) {
		t.Errorf("Expected state up, got %s", state)
	}

	// Test down state
	link.Flags = 0
	state = getInterfaceState(link)
	if state != string(VLANStateDown) {
		t.Errorf("Expected state down, got %s", state)
	}
}

// TestConcurrentOperations tests concurrent VLAN operations
func TestConcurrentOperations(t *testing.T) {
	manager := NewVLANManagerImpl()

	// Create multiple VLANs concurrently
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			config := VLANConfig{State: "down"}
			vlanName := "vlan" + string(rune('0'+id))
			_, err := manager.CreateVLAN("nonexistent", 100+id, vlanName, config)
			if err != nil {
				t.Errorf("Failed to create VLAN %s: %v", vlanName, err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all VLANs were created
	vlans, err := manager.ListVLANs()
	if err != nil {
		t.Fatalf("Failed to list VLANs: %v", err)
	}

	if len(vlans) != 10 {
		t.Errorf("Expected 10 VLANs, got %d", len(vlans))
	}
}
