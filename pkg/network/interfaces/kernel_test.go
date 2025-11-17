package interfaces

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// TestMain sets up network namespace for tests
func TestMain(m *testing.M) {
	// Only run tests if we have CAP_NET_ADMIN (root or in network namespace)
	if os.Getuid() != 0 {
		fmt.Println("Skipping kernel interface tests - requires root/CAP_NET_ADMIN")
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

func TestKernelInterfaceManager_CreateDummyInterface(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	testCases := []struct {
		name    string
		ifName  string
		mtu     int
		wantErr bool
	}{
		{
			name:    "create dummy interface with default MTU",
			ifName:  "dummy0",
			mtu:     1500,
			wantErr: false,
		},
		{
			name:    "create dummy interface with custom MTU",
			ifName:  "dummy1",
			mtu:     9000,
			wantErr: false,
		},
		{
			name:    "create duplicate interface should fail",
			ifName:  "dummy0",
			mtu:     1500,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := mgr.CreateDummyInterface(tc.ifName, tc.mtu)
			if (err != nil) != tc.wantErr {
				t.Errorf("CreateDummyInterface() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr {
				// Verify interface exists
				exists, err := mgr.InterfaceExists(tc.ifName)
				if err != nil {
					t.Errorf("Failed to check interface existence: %v", err)
				}
				if !exists {
					t.Errorf("Interface %s was not created", tc.ifName)
				}

				// Verify MTU
				actualMTU, err := mgr.GetInterfaceMTU(tc.ifName)
				if err != nil {
					t.Errorf("Failed to get interface MTU: %v", err)
				}
				if actualMTU != tc.mtu {
					t.Errorf("Interface MTU = %d, want %d", actualMTU, tc.mtu)
				}

				// Cleanup
				if err := mgr.DeleteInterface(tc.ifName); err != nil {
					t.Errorf("Failed to delete interface: %v", err)
				}
			}
		})
	}
}

func TestKernelInterfaceManager_CreateVLANInterface(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	// Create parent interface first
	if err := mgr.CreateDummyInterface("eth0", 1500); err != nil {
		t.Fatalf("Failed to create parent interface: %v", err)
	}
	defer mgr.DeleteInterface("eth0")

	testCases := []struct {
		name       string
		ifName     string
		parentName string
		vlanID     int
		mtu        int
		wantErr    bool
	}{
		{
			name:       "create VLAN interface",
			ifName:     "eth0.100",
			parentName: "eth0",
			vlanID:     100,
			mtu:        1496,
			wantErr:    false,
		},
		{
			name:       "create VLAN with invalid ID (too low)",
			ifName:     "eth0.0",
			parentName: "eth0",
			vlanID:     0,
			mtu:        1496,
			wantErr:    true,
		},
		{
			name:       "create VLAN with invalid ID (too high)",
			ifName:     "eth0.5000",
			parentName: "eth0",
			vlanID:     5000,
			mtu:        1496,
			wantErr:    true,
		},
		{
			name:       "create VLAN with non-existent parent",
			ifName:     "eth1.100",
			parentName: "eth1",
			vlanID:     100,
			mtu:        1496,
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := mgr.CreateVLANInterface(tc.ifName, tc.parentName, tc.vlanID, tc.mtu)
			if (err != nil) != tc.wantErr {
				t.Errorf("CreateVLANInterface() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr {
				// Verify interface exists
				exists, err := mgr.InterfaceExists(tc.ifName)
				if err != nil {
					t.Errorf("Failed to check interface existence: %v", err)
				}
				if !exists {
					t.Errorf("VLAN interface %s was not created", tc.ifName)
				}

				// Cleanup
				if err := mgr.DeleteInterface(tc.ifName); err != nil {
					t.Errorf("Failed to delete VLAN interface: %v", err)
				}
			}
		})
	}
}

func TestKernelInterfaceManager_SetInterfaceState(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	// Create test interface
	ifName := "test0"
	if err := mgr.CreateDummyInterface(ifName, 1500); err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}
	defer mgr.DeleteInterface(ifName)

	// Test bringing interface up
	t.Run("bring interface up", func(t *testing.T) {
		if err := mgr.SetInterfaceUp(ifName); err != nil {
			t.Errorf("SetInterfaceUp() error = %v", err)
		}

		// Verify state
		state, err := mgr.GetInterfaceState(ifName)
		if err != nil {
			t.Errorf("GetInterfaceState() error = %v", err)
		}
		if state != "up" && state != "no-carrier" {
			t.Errorf("Interface state = %s, want 'up' or 'no-carrier'", state)
		}
	})

	// Test bringing interface down
	t.Run("bring interface down", func(t *testing.T) {
		if err := mgr.SetInterfaceDown(ifName); err != nil {
			t.Errorf("SetInterfaceDown() error = %v", err)
		}

		// Verify state
		state, err := mgr.GetInterfaceState(ifName)
		if err != nil {
			t.Errorf("GetInterfaceState() error = %v", err)
		}
		if state != "down" {
			t.Errorf("Interface state = %s, want 'down'", state)
		}
	})
}

func TestKernelInterfaceManager_SetMTU(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	// Create test interface
	ifName := "test0"
	if err := mgr.CreateDummyInterface(ifName, 1500); err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}
	defer mgr.DeleteInterface(ifName)

	testCases := []struct {
		name    string
		mtu     int
		wantErr bool
	}{
		{
			name:    "set valid MTU 1500",
			mtu:     1500,
			wantErr: false,
		},
		{
			name:    "set valid MTU 9000",
			mtu:     9000,
			wantErr: false,
		},
		{
			name:    "set MTU below minimum",
			mtu:     67,
			wantErr: true,
		},
		{
			name:    "set MTU above maximum",
			mtu:     9001,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := mgr.SetMTU(ifName, tc.mtu)
			if (err != nil) != tc.wantErr {
				t.Errorf("SetMTU() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr {
				// Verify MTU was set
				actualMTU, err := mgr.GetInterfaceMTU(ifName)
				if err != nil {
					t.Errorf("GetInterfaceMTU() error = %v", err)
				}
				if actualMTU != tc.mtu {
					t.Errorf("MTU = %d, want %d", actualMTU, tc.mtu)
				}
			}
		})
	}
}

func TestKernelInterfaceManager_IPAddresses(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	// Create test interface
	ifName := "test0"
	if err := mgr.CreateDummyInterface(ifName, 1500); err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}
	defer mgr.DeleteInterface(ifName)

	testCases := []struct {
		name    string
		address string
		wantErr bool
	}{
		{
			name:    "add IPv4 address",
			address: "192.168.1.1/24",
			wantErr: false,
		},
		{
			name:    "add IPv6 address",
			address: "2001:db8::1/64",
			wantErr: false,
		},
		{
			name:    "add invalid address",
			address: "invalid",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := mgr.AddIPAddress(ifName, tc.address)
			if (err != nil) != tc.wantErr {
				t.Errorf("AddIPAddress() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr {
				// Verify address was added
				addrs, err := mgr.GetInterfaceAddresses(ifName)
				if err != nil {
					t.Errorf("GetInterfaceAddresses() error = %v", err)
				}

				found := false
				for _, addr := range addrs {
					if addr == tc.address {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Address %s not found in interface addresses", tc.address)
				}

				// Test deletion
				if err := mgr.DeleteIPAddress(ifName, tc.address); err != nil {
					t.Errorf("DeleteIPAddress() error = %v", err)
				}

				// Verify address was deleted
				addrs, err = mgr.GetInterfaceAddresses(ifName)
				if err != nil {
					t.Errorf("GetInterfaceAddresses() error = %v", err)
				}

				for _, addr := range addrs {
					if addr == tc.address {
						t.Errorf("Address %s still present after deletion", tc.address)
					}
				}
			}
		})
	}
}

func TestKernelInterfaceManager_SetMACAddress(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	// Create test interface
	ifName := "test0"
	if err := mgr.CreateDummyInterface(ifName, 1500); err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}
	defer mgr.DeleteInterface(ifName)

	testCases := []struct {
		name    string
		mac     string
		wantErr bool
	}{
		{
			name:    "set valid MAC address",
			mac:     "02:00:00:00:00:01",
			wantErr: false,
		},
		{
			name:    "set another valid MAC address",
			mac:     "02:00:00:00:00:02",
			wantErr: false,
		},
		{
			name:    "set invalid MAC address",
			mac:     "invalid",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Interface must be down to change MAC
			if err := mgr.SetInterfaceDown(ifName); err != nil {
				t.Fatalf("Failed to bring interface down: %v", err)
			}

			err := mgr.SetMACAddress(ifName, tc.mac)
			if (err != nil) != tc.wantErr {
				t.Errorf("SetMACAddress() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr {
				// Verify MAC was set
				actualMAC, err := mgr.GetInterfaceMACAddress(ifName)
				if err != nil {
					t.Errorf("GetInterfaceMACAddress() error = %v", err)
				}
				if actualMAC != tc.mac {
					t.Errorf("MAC address = %s, want %s", actualMAC, tc.mac)
				}
			}
		})
	}
}

func TestKernelInterfaceManager_DeleteInterface(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	// Create test interface
	ifName := "test0"
	if err := mgr.CreateDummyInterface(ifName, 1500); err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}

	// Verify interface exists
	exists, err := mgr.InterfaceExists(ifName)
	if err != nil {
		t.Errorf("InterfaceExists() error = %v", err)
	}
	if !exists {
		t.Error("Interface should exist before deletion")
	}

	// Delete interface
	if err := mgr.DeleteInterface(ifName); err != nil {
		t.Errorf("DeleteInterface() error = %v", err)
	}

	// Verify interface no longer exists
	exists, err = mgr.InterfaceExists(ifName)
	if err != nil {
		t.Errorf("InterfaceExists() error = %v", err)
	}
	if exists {
		t.Error("Interface should not exist after deletion")
	}

	// Try to delete non-existent interface
	if err := mgr.DeleteInterface("nonexistent"); err == nil {
		t.Error("DeleteInterface() should fail for non-existent interface")
	}
}

func TestKernelInterfaceManager_CreateBridgeInterface(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	bridgeName := "br0"
	if err := mgr.CreateBridgeInterface(bridgeName, 1500); err != nil {
		t.Errorf("CreateBridgeInterface() error = %v", err)
	}
	defer mgr.DeleteInterface(bridgeName)

	// Verify bridge exists
	link, err := netlink.LinkByName(bridgeName)
	if err != nil {
		t.Errorf("Failed to get bridge: %v", err)
	}

	if _, ok := link.(*netlink.Bridge); !ok {
		t.Errorf("Created interface is not a bridge")
	}
}

func TestKernelInterfaceManager_AddInterfaceToBridge(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	// Create bridge
	bridgeName := "br0"
	if err := mgr.CreateBridgeInterface(bridgeName, 1500); err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}
	defer mgr.DeleteInterface(bridgeName)

	// Create interface to add to bridge
	ifName := "test0"
	if err := mgr.CreateDummyInterface(ifName, 1500); err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}
	defer mgr.DeleteInterface(ifName)

	// Add interface to bridge
	if err := mgr.AddInterfaceToBridge(bridgeName, ifName); err != nil {
		t.Errorf("AddInterfaceToBridge() error = %v", err)
	}

	// Verify interface is in bridge
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		t.Errorf("Failed to get interface: %v", err)
	}

	if link.Attrs().MasterIndex == 0 {
		t.Error("Interface should have a master (bridge)")
	}

	// Remove interface from bridge
	if err := mgr.RemoveInterfaceFromBridge(ifName); err != nil {
		t.Errorf("RemoveInterfaceFromBridge() error = %v", err)
	}
}

func TestKernelInterfaceManager_LinkMonitoring(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start monitoring
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("Failed to start monitoring: %v", err)
	}
	defer mgr.Stop()

	// Create a channel to receive link updates
	updateReceived := make(chan bool, 1)

	// Register callback
	mgr.RegisterLinkUpdateCallback(func(update netlink.LinkUpdate) {
		select {
		case updateReceived <- true:
		default:
		}
	})

	// Create an interface which should trigger an update
	ifName := "test0"
	if err := mgr.CreateDummyInterface(ifName, 1500); err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}
	defer mgr.DeleteInterface(ifName)

	// Wait for update
	select {
	case <-updateReceived:
		// Success - update was received
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for link update callback")
	}
}

func TestKernelInterfaceManager_ListInterfaces(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	// Create some test interfaces
	interfaces := []string{"test0", "test1", "test2"}
	for _, ifName := range interfaces {
		if err := mgr.CreateDummyInterface(ifName, 1500); err != nil {
			t.Fatalf("Failed to create test interface %s: %v", ifName, err)
		}
		defer mgr.DeleteInterface(ifName)
	}

	// List interfaces
	links, err := mgr.ListInterfaces()
	if err != nil {
		t.Errorf("ListInterfaces() error = %v", err)
	}

	// Verify our interfaces are in the list
	for _, expectedIf := range interfaces {
		found := false
		for _, link := range links {
			if link.Attrs().Name == expectedIf {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Interface %s not found in list", expectedIf)
		}
	}
}

func TestKernelInterfaceManager_GetInterfaceStats(t *testing.T) {
	origNS, newNS := setupNetNS(t)
	defer teardownNetNS(t, origNS, newNS)

	mgr := NewKernelInterfaceManager()

	// Create test interface
	ifName := "test0"
	if err := mgr.CreateDummyInterface(ifName, 1500); err != nil {
		t.Fatalf("Failed to create test interface: %v", err)
	}
	defer mgr.DeleteInterface(ifName)

	// Get statistics
	stats, err := mgr.GetInterfaceStats(ifName)
	if err != nil {
		t.Errorf("GetInterfaceStats() error = %v", err)
	}

	if stats == nil {
		t.Error("Statistics should not be nil")
	}
}
