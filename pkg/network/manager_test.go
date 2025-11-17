package network

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netns"
)

// TestMain sets up network namespace for tests
func TestMain(m *testing.M) {
	// Only run tests if we have CAP_NET_ADMIN (root or in network namespace)
	if os.Getuid() != 0 {
		fmt.Println("Skipping network manager tests - requires root/CAP_NET_ADMIN")
		os.Exit(0)
	}

	os.Exit(m.Run())
}

// setupNetNS creates a new network namespace for isolated testing
func setupNetNS(t *testing.T) (netns.NsHandle, netns.NsHandle) {
	t.Helper()

	// Save current namespace
	origNS, err := netns.Get()
	if err != nil {
		t.Fatalf("Failed to get current namespace: %v", err)
	}

	// Create new namespace
	newNS, err := netns.New()
	if err != nil {
		origNS.Close()
		t.Fatalf("Failed to create new namespace: %v", err)
	}

	return origNS, newNS
}

// teardownNetNS cleans up network namespace
func teardownNetNS(t *testing.T, origNS, newNS netns.NsHandle) {
	t.Helper()

	// Switch back to original namespace
	if err := netns.Set(origNS); err != nil {
		t.Errorf("Failed to switch back to original namespace: %v", err)
	}

	// Close handles
	newNS.Close()
	origNS.Close()
}

func TestNetworkInterfaceManager_CreateInterface(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mgr, err := NewNetworkInterfaceManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create network interface manager: %v", err)
	}
	defer mgr.Stop()

	testCases := []struct {
		name          string
		ifName        string
		interfaceType string
		config        InterfaceConfig
		wantErr       bool
	}{
		{
			name:          "create dummy interface",
			ifName:        "test0",
			interfaceType: "dummy",
			config: InterfaceConfig{
				MTU:       1500,
				Addresses: []string{"192.168.1.1/24"},
				Enabled:   true,
			},
			wantErr: false,
		},
		{
			name:          "create bridge interface",
			ifName:        "br0",
			interfaceType: "bridge",
			config: InterfaceConfig{
				MTU:     1500,
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name:          "create duplicate interface should fail",
			ifName:        "test0",
			interfaceType: "dummy",
			config: InterfaceConfig{
				MTU:     1500,
				Enabled: false,
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			netIf, err := mgr.CreateInterface(tc.ifName, tc.interfaceType, tc.config)
			if (err != nil) != tc.wantErr {
				t.Errorf("CreateInterface() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr {
				// Verify interface was created
				if netIf.Name != tc.ifName {
					t.Errorf("Interface name = %s, want %s", netIf.Name, tc.ifName)
				}
				if netIf.Type != tc.interfaceType {
					t.Errorf("Interface type = %s, want %s", netIf.Type, tc.interfaceType)
				}

				// Verify operational state
				if tc.config.Enabled {
					if netIf.OperationalState != "up" {
						t.Errorf("Interface state = %s, want 'up'", netIf.OperationalState)
					}
				}

				// Cleanup
				if err := mgr.DeleteInterface(tc.ifName); err != nil {
					t.Errorf("Failed to delete interface: %v", err)
				}
			}
		})
	}
}

func TestNetworkInterfaceManager_CreateVLAN(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mgr, err := NewNetworkInterfaceManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create network interface manager: %v", err)
	}
	defer mgr.Stop()

	// Create parent interface
	parentName := "eth0"
	_, err = mgr.CreateInterface(parentName, "dummy", InterfaceConfig{
		MTU:     1500,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("Failed to create parent interface: %v", err)
	}
	defer mgr.DeleteInterface(parentName)

	testCases := []struct {
		name       string
		ifName     string
		config     InterfaceConfig
		vlanConfig VLANConfig
		wantErr    bool
	}{
		{
			name:   "create VLAN interface",
			ifName: "eth0.100",
			config: InterfaceConfig{
				MTU:       1496,
				Addresses: []string{"10.0.100.1/24"},
				Enabled:   true,
			},
			vlanConfig: VLANConfig{
				Parent:      parentName,
				VLANID:      100,
				QoSPriority: 0,
			},
			wantErr: false,
		},
		{
			name:   "create VLAN with invalid ID",
			ifName: "eth0.5000",
			config: InterfaceConfig{
				MTU:     1496,
				Enabled: false,
			},
			vlanConfig: VLANConfig{
				Parent: parentName,
				VLANID: 5000,
			},
			wantErr: true,
		},
		{
			name:   "create VLAN with non-existent parent",
			ifName: "eth1.100",
			config: InterfaceConfig{
				MTU:     1496,
				Enabled: false,
			},
			vlanConfig: VLANConfig{
				Parent: "eth1",
				VLANID: 100,
			},
			wantErr: false, // Should create pending VLAN
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vlanIf, err := mgr.CreateVLAN(tc.ifName, tc.config, tc.vlanConfig)
			if (err != nil) != tc.wantErr {
				t.Errorf("CreateVLAN() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr {
				// Verify VLAN interface was created
				if vlanIf.Name != tc.ifName {
					t.Errorf("VLAN name = %s, want %s", vlanIf.Name, tc.ifName)
				}
				if vlanIf.Type != "vlan" {
					t.Errorf("VLAN type = %s, want 'vlan'", vlanIf.Type)
				}
				if vlanIf.VLANConfig.VLANID != tc.vlanConfig.VLANID {
					t.Errorf("VLAN ID = %d, want %d", vlanIf.VLANConfig.VLANID, tc.vlanConfig.VLANID)
				}

				// Cleanup
				if err := mgr.DeleteInterface(tc.ifName); err != nil {
					t.Errorf("Failed to delete VLAN interface: %v", err)
				}
			}
		})
	}
}

func TestNetworkInterfaceManager_UpdateInterface(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mgr, err := NewNetworkInterfaceManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create network interface manager: %v", err)
	}
	defer mgr.Stop()

	// Create test interface
	ifName := "test0"
	_, err = mgr.CreateInterface(ifName, "dummy", InterfaceConfig{
		MTU:       1500,
		Addresses: []string{"192.168.1.1/24"},
		Enabled:   false,
	})
	if err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}
	defer mgr.DeleteInterface(ifName)

	// Update interface configuration
	newConfig := InterfaceConfig{
		MTU:       9000,
		Addresses: []string{"192.168.1.1/24", "192.168.2.1/24"},
		Enabled:   true,
	}

	updatedIf, err := mgr.UpdateInterface(ifName, newConfig)
	if err != nil {
		t.Errorf("UpdateInterface() error = %v", err)
	}

	// Verify updates
	if updatedIf.ActualMTU != 9000 {
		t.Errorf("Updated MTU = %d, want 9000", updatedIf.ActualMTU)
	}
	if !updatedIf.Config.Enabled {
		t.Error("Interface should be enabled after update")
	}
	if updatedIf.OperationalState != "up" {
		t.Errorf("Interface state = %s, want 'up'", updatedIf.OperationalState)
	}
}

func TestNetworkInterfaceManager_SetInterfaceState(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mgr, err := NewNetworkInterfaceManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create network interface manager: %v", err)
	}
	defer mgr.Stop()

	// Create test interface
	ifName := "test0"
	_, err = mgr.CreateInterface(ifName, "dummy", InterfaceConfig{
		MTU:     1500,
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}
	defer mgr.DeleteInterface(ifName)

	// Test bringing interface up
	t.Run("bring interface up", func(t *testing.T) {
		if err := mgr.SetInterfaceUp(ifName); err != nil {
			t.Errorf("SetInterfaceUp() error = %v", err)
		}

		// Verify state
		netIf, err := mgr.GetInterface(ifName)
		if err != nil {
			t.Errorf("GetInterface() error = %v", err)
		}
		if netIf.OperationalState != "up" {
			t.Errorf("Interface state = %s, want 'up'", netIf.OperationalState)
		}
		if !netIf.Config.Enabled {
			t.Error("Interface should be enabled")
		}
	})

	// Test bringing interface down
	t.Run("bring interface down", func(t *testing.T) {
		if err := mgr.SetInterfaceDown(ifName); err != nil {
			t.Errorf("SetInterfaceDown() error = %v", err)
		}

		// Verify state
		netIf, err := mgr.GetInterface(ifName)
		if err != nil {
			t.Errorf("GetInterface() error = %v", err)
		}
		if netIf.OperationalState != "down" {
			t.Errorf("Interface state = %s, want 'down'", netIf.OperationalState)
		}
		if netIf.Config.Enabled {
			t.Error("Interface should not be enabled")
		}
	})
}

func TestNetworkInterfaceManager_DeleteInterface(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mgr, err := NewNetworkInterfaceManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create network interface manager: %v", err)
	}
	defer mgr.Stop()

	// Create test interface
	ifName := "test0"
	_, err = mgr.CreateInterface(ifName, "dummy", InterfaceConfig{
		MTU:     1500,
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}

	// Verify interface exists
	_, err = mgr.GetInterface(ifName)
	if err != nil {
		t.Errorf("Interface should exist before deletion")
	}

	// Delete interface
	if err := mgr.DeleteInterface(ifName); err != nil {
		t.Errorf("DeleteInterface() error = %v", err)
	}

	// Verify interface no longer exists in manager
	_, err = mgr.GetInterface(ifName)
	if err == nil {
		t.Error("Interface should not exist after deletion")
	}

	// Verify interface no longer exists in kernel
	exists, err := mgr.kernelManager.InterfaceExists(ifName)
	if err != nil {
		t.Errorf("InterfaceExists() error = %v", err)
	}
	if exists {
		t.Error("Interface should not exist in kernel after deletion")
	}
}

func TestNetworkInterfaceManager_ListInterfaces(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mgr, err := NewNetworkInterfaceManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create network interface manager: %v", err)
	}
	defer mgr.Stop()

	// Create multiple interfaces
	interfaces := []string{"test0", "test1", "test2"}
	for _, ifName := range interfaces {
		_, err := mgr.CreateInterface(ifName, "dummy", InterfaceConfig{
			MTU:     1500,
			Enabled: false,
		})
		if err != nil {
			t.Fatalf("Failed to create interface %s: %v", ifName, err)
		}
		defer mgr.DeleteInterface(ifName)
	}

	// List interfaces
	list, err := mgr.ListInterfaces()
	if err != nil {
		t.Errorf("ListInterfaces() error = %v", err)
	}

	// Verify all interfaces are in the list
	if len(list) < len(interfaces) {
		t.Errorf("ListInterfaces() returned %d interfaces, want at least %d", len(list), len(interfaces))
	}

	for _, expectedIf := range interfaces {
		found := false
		for _, netIf := range list {
			if netIf.Name == expectedIf {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Interface %s not found in list", expectedIf)
		}
	}
}

func TestNetworkInterfaceManager_GetAllVLANInterfaces(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mgr, err := NewNetworkInterfaceManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create network interface manager: %v", err)
	}
	defer mgr.Stop()

	// Create parent interface
	parentName := "eth0"
	_, err = mgr.CreateInterface(parentName, "dummy", InterfaceConfig{
		MTU:     1500,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("Failed to create parent interface: %v", err)
	}
	defer mgr.DeleteInterface(parentName)

	// Create VLAN interfaces
	vlanIDs := []int{100, 200, 300}
	for _, vlanID := range vlanIDs {
		ifName := fmt.Sprintf("eth0.%d", vlanID)
		_, err := mgr.CreateVLAN(ifName, InterfaceConfig{
			MTU:     1496,
			Enabled: false,
		}, VLANConfig{
			Parent: parentName,
			VLANID: vlanID,
		})
		if err != nil {
			t.Fatalf("Failed to create VLAN %d: %v", vlanID, err)
		}
		defer mgr.DeleteInterface(ifName)
	}

	// Get all VLAN interfaces
	vlans, err := mgr.GetAllVLANInterfaces()
	if err != nil {
		t.Errorf("GetAllVLANInterfaces() error = %v", err)
	}

	// Verify count
	if len(vlans) != len(vlanIDs) {
		t.Errorf("GetAllVLANInterfaces() returned %d VLANs, want %d", len(vlans), len(vlanIDs))
	}

	// Verify all are VLAN type
	for _, vlan := range vlans {
		if vlan.Type != "vlan" {
			t.Errorf("Interface %s has type %s, want 'vlan'", vlan.Name, vlan.Type)
		}
	}
}
