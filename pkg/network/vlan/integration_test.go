// +build integration

package vlan

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// Integration tests require root privileges and a test environment
// Run with: go test -tags=integration -v ./pkg/network/vlan/...
// Must be run as root: sudo -E go test -tags=integration -v ./pkg/network/vlan/...

func skipIfNotRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping integration test: requires root privileges")
	}
}

// TestIntegrationVLANCreate tests creating a real VLAN interface
func TestIntegrationVLANCreate(t *testing.T) {
	skipIfNotRoot(t)

	manager := NewVLANManagerImpl()

	// Create a dummy parent interface for testing
	parentName := "test-parent"
	parent := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: parentName,
		},
	}

	// Clean up any existing test interface
	if existing, _ := netlink.LinkByName(parentName); existing != nil {
		netlink.LinkDel(existing)
	}

	// Create parent interface
	if err := netlink.LinkAdd(parent); err != nil {
		t.Fatalf("Failed to create parent interface: %v", err)
	}
	defer func() {
		if link, _ := netlink.LinkByName(parentName); link != nil {
			netlink.LinkDel(link)
		}
	}()

	// Bring up parent interface
	parentLink, _ := netlink.LinkByName(parentName)
	if err := netlink.LinkSetUp(parentLink); err != nil {
		t.Fatalf("Failed to bring up parent interface: %v", err)
	}

	// Create VLAN interface
	vlanName := "test-vlan100"
	config := VLANConfig{
		State: "up",
		MTU:   1500,
		Addresses: []IPConfig{
			{
				Address: net.ParseIP("192.168.100.1"),
				Prefix:  24,
			},
		},
	}

	vlanIf, err := manager.CreateVLAN(parentName, 100, vlanName, config)
	if err != nil {
		t.Fatalf("Failed to create VLAN interface: %v", err)
	}
	defer manager.DeleteVLAN(vlanName)

	// Verify VLAN was created
	if vlanIf.VLANID != 100 {
		t.Errorf("Expected VLAN ID 100, got %d", vlanIf.VLANID)
	}

	// Verify interface exists in kernel
	link, err := netlink.LinkByName(vlanName)
	if err != nil {
		t.Fatalf("VLAN interface not found in kernel: %v", err)
	}

	vlan, ok := link.(*netlink.Vlan)
	if !ok {
		t.Fatal("Interface is not a VLAN")
	}

	if vlan.VlanId != 100 {
		t.Errorf("Expected VLAN ID 100 in kernel, got %d", vlan.VlanId)
	}

	// Verify IP address was assigned
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("Failed to list addresses: %v", err)
	}

	found := false
	for _, addr := range addrs {
		if addr.IP.Equal(net.ParseIP("192.168.100.1")) {
			found = true
			break
		}
	}

	if !found {
		t.Error("IP address 192.168.100.1 not assigned to VLAN interface")
	}

	t.Logf("Successfully created and verified VLAN interface %s", vlanName)
}

// TestIntegrationVLANQoS tests QoS configuration on a real VLAN interface
func TestIntegrationVLANQoS(t *testing.T) {
	skipIfNotRoot(t)

	manager := NewVLANManagerImpl()

	// Create parent interface
	parentName := "test-parent-qos"
	parent := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: parentName,
		},
	}

	if existing, _ := netlink.LinkByName(parentName); existing != nil {
		netlink.LinkDel(existing)
	}

	if err := netlink.LinkAdd(parent); err != nil {
		t.Fatalf("Failed to create parent interface: %v", err)
	}
	defer func() {
		if link, _ := netlink.LinkByName(parentName); link != nil {
			netlink.LinkDel(link)
		}
	}()

	parentLink, _ := netlink.LinkByName(parentName)
	netlink.LinkSetUp(parentLink)

	// Create VLAN with QoS
	vlanName := "test-vlan-qos"
	config := VLANConfig{
		State:       "up",
		QoSPriority: 5,
		Egress: QoSConfig{
			Enabled:      true,
			DefaultClass: 1,
			MaxRate:      "1Gbit",
			Classes: []QoSClass{
				{
					ID:       1,
					Priority: 7,
					Rate:     "500Mbit",
					Ceiling:  "1Gbit",
					Burst:    "15kb",
				},
			},
		},
	}

	vlanIf, err := manager.CreateVLAN(parentName, 200, vlanName, config)
	if err != nil {
		t.Fatalf("Failed to create VLAN with QoS: %v", err)
	}
	defer manager.DeleteVLAN(vlanName)

	// Give QoS configuration time to apply
	time.Sleep(100 * time.Millisecond)

	// Verify qdisc exists
	link, _ := netlink.LinkByName(vlanName)
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		t.Fatalf("Failed to list qdiscs: %v", err)
	}

	hasHTB := false
	for _, qd := range qdiscs {
		if _, ok := qd.(*netlink.Htb); ok {
			hasHTB = true
			break
		}
	}

	if !hasHTB {
		t.Error("HTB qdisc not found on VLAN interface")
	} else {
		t.Log("HTB QoS successfully configured on VLAN interface")
	}

	// Verify VLAN priority was set
	if vlanIf.Config.QoSPriority != 5 {
		t.Errorf("Expected QoS priority 5, got %d", vlanIf.Config.QoSPriority)
	}
}

// TestIntegrationVLANStatistics tests statistics collection from a real interface
func TestIntegrationVLANStatistics(t *testing.T) {
	skipIfNotRoot(t)

	manager := NewVLANManagerImpl()

	// Create parent interface
	parentName := "test-parent-stats"
	parent := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: parentName,
		},
	}

	if existing, _ := netlink.LinkByName(parentName); existing != nil {
		netlink.LinkDel(existing)
	}

	if err := netlink.LinkAdd(parent); err != nil {
		t.Fatalf("Failed to create parent interface: %v", err)
	}
	defer func() {
		if link, _ := netlink.LinkByName(parentName); link != nil {
			netlink.LinkDel(link)
		}
	}()

	parentLink, _ := netlink.LinkByName(parentName)
	netlink.LinkSetUp(parentLink)

	// Create VLAN
	vlanName := "test-vlan-stats"
	config := VLANConfig{
		State: "up",
	}

	_, err := manager.CreateVLAN(parentName, 300, vlanName, config)
	if err != nil {
		t.Fatalf("Failed to create VLAN: %v", err)
	}
	defer manager.DeleteVLAN(vlanName)

	// Get statistics
	vlanIf, err := manager.GetVLAN(vlanName)
	if err != nil {
		t.Fatalf("Failed to get VLAN: %v", err)
	}

	// Verify statistics structure
	if vlanIf.Statistics.LastUpdated == 0 {
		t.Error("Statistics LastUpdated should be set")
	}

	// Statistics should be zero for a newly created interface
	if vlanIf.Statistics.RxPackets != 0 {
		t.Logf("Note: RxPackets=%d (expected 0 for new interface)", vlanIf.Statistics.RxPackets)
	}

	t.Logf("Statistics collected: RX packets=%d, TX packets=%d, RX bytes=%d, TX bytes=%d",
		vlanIf.Statistics.RxPackets,
		vlanIf.Statistics.TxPackets,
		vlanIf.Statistics.RxBytes,
		vlanIf.Statistics.TxBytes)
}

// TestIntegrationVLANDSCP tests DSCP marking on a real interface
func TestIntegrationVLANDSCP(t *testing.T) {
	skipIfNotRoot(t)

	manager := NewVLANManagerImpl()

	// Create parent interface
	parentName := "test-parent-dscp"
	parent := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: parentName,
		},
	}

	if existing, _ := netlink.LinkByName(parentName); existing != nil {
		netlink.LinkDel(existing)
	}

	if err := netlink.LinkAdd(parent); err != nil {
		t.Fatalf("Failed to create parent interface: %v", err)
	}
	defer func() {
		if link, _ := netlink.LinkByName(parentName); link != nil {
			netlink.LinkDel(link)
		}
	}()

	parentLink, _ := netlink.LinkByName(parentName)
	netlink.LinkSetUp(parentLink)

	// Create VLAN with DSCP marking
	vlanName := "test-vlan-dscp"
	config := VLANConfig{
		State: "up",
		DSCP:  46, // EF (Expedited Forwarding)
	}

	vlanIf, err := manager.CreateVLAN(parentName, 400, vlanName, config)
	if err != nil {
		t.Fatalf("Failed to create VLAN with DSCP: %v", err)
	}
	defer manager.DeleteVLAN(vlanName)

	// Verify DSCP config was stored
	if vlanIf.Config.DSCP != 46 {
		t.Errorf("Expected DSCP 46, got %d", vlanIf.Config.DSCP)
	}

	t.Logf("Successfully configured DSCP marking %d on VLAN %s", config.DSCP, vlanName)
}

// TestIntegrationVLANTrunk tests trunk configuration
func TestIntegrationVLANTrunk(t *testing.T) {
	skipIfNotRoot(t)

	manager := NewVLANManagerImpl()

	// Create trunk interface
	trunkName := "test-trunk"
	trunk := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: trunkName,
		},
	}

	if existing, _ := netlink.LinkByName(trunkName); existing != nil {
		netlink.LinkDel(existing)
	}

	if err := netlink.LinkAdd(trunk); err != nil {
		t.Fatalf("Failed to create trunk interface: %v", err)
	}
	defer func() {
		if link, _ := netlink.LinkByName(trunkName); link != nil {
			netlink.LinkDel(link)
		}
	}()

	trunkLink, _ := netlink.LinkByName(trunkName)
	if err := netlink.LinkSetUp(trunkLink); err != nil {
		t.Fatalf("Failed to bring up trunk: %v", err)
	}

	// Configure trunk
	trunkConfig := TrunkConfig{
		NativeVLAN:   1,
		AllowedVLANs: []int{10, 20, 30},
		State:        "up",
	}

	if err := manager.ConfigureTrunk(trunkName, trunkConfig); err != nil {
		t.Fatalf("Failed to configure trunk: %v", err)
	}

	// Verify trunk config
	config, err := manager.GetTrunkConfig(trunkName)
	if err != nil {
		t.Fatalf("Failed to get trunk config: %v", err)
	}

	if config.NativeVLAN != 1 {
		t.Errorf("Expected native VLAN 1, got %d", config.NativeVLAN)
	}

	if len(config.AllowedVLANs) != 3 {
		t.Errorf("Expected 3 allowed VLANs, got %d", len(config.AllowedVLANs))
	}

	// Create VLANs on trunk
	for _, vlanID := range config.AllowedVLANs {
		vlanName := "trunk-vlan" + string(rune('0'+vlanID/10))
		vlanConfig := VLANConfig{State: "up"}

		_, err := manager.CreateVLAN(trunkName, vlanID, vlanName, vlanConfig)
		if err != nil {
			t.Errorf("Failed to create VLAN %d on trunk: %v", vlanID, err)
		} else {
			defer manager.DeleteVLAN(vlanName)
			t.Logf("Created VLAN %d on trunk %s", vlanID, trunkName)
		}
	}
}

// TestIntegrationVLANIngressQoS tests ingress QoS with IFB devices
func TestIntegrationVLANIngressQoS(t *testing.T) {
	skipIfNotRoot(t)

	manager := NewVLANManagerImpl()

	// Create parent interface
	parentName := "test-parent-ingress"
	parent := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: parentName,
		},
	}

	if existing, _ := netlink.LinkByName(parentName); existing != nil {
		netlink.LinkDel(existing)
	}

	if err := netlink.LinkAdd(parent); err != nil {
		t.Fatalf("Failed to create parent interface: %v", err)
	}
	defer func() {
		if link, _ := netlink.LinkByName(parentName); link != nil {
			netlink.LinkDel(link)
		}
	}()

	parentLink, _ := netlink.LinkByName(parentName)
	netlink.LinkSetUp(parentLink)

	// Create VLAN with ingress QoS
	vlanName := "test-vlan-ingress"
	config := VLANConfig{
		State: "up",
		Ingress: QoSConfig{
			Enabled:      true,
			DefaultClass: 1,
			MaxRate:      "500Mbit",
			Classes: []QoSClass{
				{
					ID:       1,
					Priority: 5,
					Rate:     "250Mbit",
					Ceiling:  "500Mbit",
					Burst:    "10kb",
				},
			},
		},
	}

	_, err := manager.CreateVLAN(parentName, 500, vlanName, config)
	if err != nil {
		t.Fatalf("Failed to create VLAN with ingress QoS: %v", err)
	}
	defer manager.DeleteVLAN(vlanName)

	// Give time for IFB setup
	time.Sleep(200 * time.Millisecond)

	// Check if IFB device was created
	ifbName := "ifb-" + vlanName
	if len(ifbName) > 15 {
		link, _ := netlink.LinkByName(vlanName)
		ifbName = "ifb" + string(rune('0'+link.Attrs().Index))
	}

	ifbLink, err := netlink.LinkByName(ifbName)
	if err != nil {
		t.Fatalf("IFB device %s not found: %v", ifbName, err)
	}

	// Verify IFB device is up
	if ifbLink.Attrs().Flags&net.FlagUp == 0 {
		t.Error("IFB device is not up")
	}

	// Verify ingress qdisc exists on main interface
	link, _ := netlink.LinkByName(vlanName)
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		t.Fatalf("Failed to list qdiscs: %v", err)
	}

	hasIngress := false
	for _, qd := range qdiscs {
		if _, ok := qd.(*netlink.Ingress); ok {
			hasIngress = true
			break
		}
	}

	if !hasIngress {
		t.Error("Ingress qdisc not found on VLAN interface")
	} else {
		t.Log("Ingress QoS successfully configured with IFB device")
	}

	// Verify HTB qdisc on IFB device
	ifbQdiscs, err := netlink.QdiscList(ifbLink)
	if err != nil {
		t.Fatalf("Failed to list IFB qdiscs: %v", err)
	}

	hasHTB := false
	for _, qd := range ifbQdiscs {
		if _, ok := qd.(*netlink.Htb); ok {
			hasHTB = true
			break
		}
	}

	if !hasHTB {
		t.Error("HTB qdisc not found on IFB device")
	} else {
		t.Log("HTB QoS configured on IFB device for ingress traffic shaping")
	}
}
