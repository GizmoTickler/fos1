// +build integration

package ipam

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func requireRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root privileges")
	}
}

func createDummyInterface(t *testing.T, name string) {
	// Clean up any existing interface with the same name
	link, _ := netlink.LinkByName(name)
	if link != nil {
		netlink.LinkDel(link)
	}

	// Create dummy interface
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  1500,
		},
	}

	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatalf("Failed to create dummy interface: %v", err)
	}

	// Bring the interface up
	if err := netlink.LinkSetUp(dummy); err != nil {
		t.Fatalf("Failed to bring interface up: %v", err)
	}
}

func deleteDummyInterface(t *testing.T, name string) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return // Interface doesn't exist
	}

	if err := netlink.LinkDel(link); err != nil {
		t.Logf("Warning: Failed to delete interface %s: %v", name, err)
	}
}

func TestIntegration_AddDeleteIPv4Address(t *testing.T) {
	requireRoot(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	ifaceName := "ipam-test0"
	createDummyInterface(t, ifaceName)
	defer deleteDummyInterface(t, ifaceName)

	// Add IPv4 address
	address := "192.168.100.10/24"
	flags := AddressFlags{
		Permanent: true,
	}

	if err := mgr.AddAddress(ifaceName, address, flags); err != nil {
		t.Fatalf("Failed to add IPv4 address: %v", err)
	}

	// Verify address was added
	time.Sleep(100 * time.Millisecond) // Give time for kernel to process

	ipAddr, err := mgr.GetAddress(ifaceName, address)
	if err != nil {
		t.Fatalf("Failed to get IPv4 address: %v", err)
	}

	if ipAddr.Address != address {
		t.Errorf("Expected address %s, got %s", address, ipAddr.Address)
	}

	if !ipAddr.IsIPv4() {
		t.Error("Address should be IPv4")
	}

	// Delete the address
	if err := mgr.DeleteAddress(ifaceName, address); err != nil {
		t.Fatalf("Failed to delete IPv4 address: %v", err)
	}

	// Verify address was deleted
	time.Sleep(100 * time.Millisecond)

	_, err = mgr.GetAddress(ifaceName, address)
	if err == nil {
		t.Error("Address should have been deleted")
	}
}

func TestIntegration_AddDeleteIPv6Address(t *testing.T) {
	requireRoot(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	ifaceName := "ipam-test1"
	createDummyInterface(t, ifaceName)
	defer deleteDummyInterface(t, ifaceName)

	// Add IPv6 address
	address := "2001:db8::10/64"
	flags := AddressFlags{
		Permanent: true,
	}

	if err := mgr.AddAddress(ifaceName, address, flags); err != nil {
		t.Fatalf("Failed to add IPv6 address: %v", err)
	}

	// Wait for DAD to complete
	time.Sleep(2 * time.Second)

	// Verify address was added
	ipAddr, err := mgr.GetAddress(ifaceName, address)
	if err != nil {
		t.Fatalf("Failed to get IPv6 address: %v", err)
	}

	if ipAddr.Address != address {
		t.Errorf("Expected address %s, got %s", address, ipAddr.Address)
	}

	if !ipAddr.IsIPv6() {
		t.Error("Address should be IPv6")
	}

	// Delete the address
	if err := mgr.DeleteAddress(ifaceName, address); err != nil {
		t.Fatalf("Failed to delete IPv6 address: %v", err)
	}

	// Verify address was deleted
	time.Sleep(100 * time.Millisecond)

	_, err = mgr.GetAddress(ifaceName, address)
	if err == nil {
		t.Error("Address should have been deleted")
	}
}

func TestIntegration_ListAddresses(t *testing.T) {
	requireRoot(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	ifaceName := "ipam-test2"
	createDummyInterface(t, ifaceName)
	defer deleteDummyInterface(t, ifaceName)

	// Add multiple addresses
	addresses := []struct {
		addr   string
		family AddressFamily
	}{
		{"192.168.100.20/24", FamilyIPv4},
		{"192.168.100.21/24", FamilyIPv4},
		{"2001:db8::20/64", FamilyIPv6},
	}

	for _, a := range addresses {
		flags := AddressFlags{Permanent: true}
		if err := mgr.AddAddress(ifaceName, a.addr, flags); err != nil {
			t.Fatalf("Failed to add address %s: %v", a.addr, err)
		}
	}

	time.Sleep(100 * time.Millisecond)

	// List all addresses
	allAddrs, err := mgr.ListAddresses(ifaceName, FamilyAll)
	if err != nil {
		t.Fatalf("Failed to list addresses: %v", err)
	}

	// Should have at least our 3 addresses (may have link-local too)
	if len(allAddrs) < 3 {
		t.Errorf("Expected at least 3 addresses, got %d", len(allAddrs))
	}

	// List IPv4 addresses
	ipv4Addrs, err := mgr.ListAddresses(ifaceName, FamilyIPv4)
	if err != nil {
		t.Fatalf("Failed to list IPv4 addresses: %v", err)
	}

	if len(ipv4Addrs) != 2 {
		t.Errorf("Expected 2 IPv4 addresses, got %d", len(ipv4Addrs))
	}

	// List IPv6 addresses
	ipv6Addrs, err := mgr.ListAddresses(ifaceName, FamilyIPv6)
	if err != nil {
		t.Fatalf("Failed to list IPv6 addresses: %v", err)
	}

	// Should have at least 1 (may have link-local)
	if len(ipv6Addrs) < 1 {
		t.Errorf("Expected at least 1 IPv6 address, got %d", len(ipv6Addrs))
	}

	// Clean up
	for _, a := range addresses {
		mgr.DeleteAddress(ifaceName, a.addr)
	}
}

func TestIntegration_AllocateReleaseAddress(t *testing.T) {
	requireRoot(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	ifaceName := "ipam-test3"
	createDummyInterface(t, ifaceName)
	defer deleteDummyInterface(t, ifaceName)

	// Add a subnet
	subnet := &Subnet{
		CIDR:        "192.168.200.0/24",
		Description: "Test allocation subnet",
	}

	if err := mgr.AddSubnet(subnet); err != nil {
		t.Fatalf("Failed to add subnet: %v", err)
	}

	// Allocate an address
	req := AllocationRequest{
		Interface: ifaceName,
		Subnet:    subnet.CIDR,
		Family:    FamilyIPv4,
		Permanent: true,
	}

	ipAddr, err := mgr.AllocateAddress(req)
	if err != nil {
		t.Fatalf("Failed to allocate address: %v", err)
	}

	t.Logf("Allocated address: %s", ipAddr.Address)

	// Verify address was added to kernel
	time.Sleep(100 * time.Millisecond)

	kernelAddr, err := mgr.GetAddress(ifaceName, ipAddr.Address)
	if err != nil {
		t.Fatalf("Failed to get allocated address from kernel: %v", err)
	}

	if kernelAddr.Address != ipAddr.Address {
		t.Errorf("Expected address %s, got %s", ipAddr.Address, kernelAddr.Address)
	}

	// Verify allocation is tracked in subnet
	if _, exists := subnet.Allocations[ipAddr.IP.String()]; !exists {
		t.Error("Allocation should be tracked in subnet")
	}

	// Release the address
	if err := mgr.ReleaseAddress(ifaceName, ipAddr.Address); err != nil {
		t.Fatalf("Failed to release address: %v", err)
	}

	// Verify address was removed from kernel
	time.Sleep(100 * time.Millisecond)

	_, err = mgr.GetAddress(ifaceName, ipAddr.Address)
	if err == nil {
		t.Error("Address should have been removed from kernel")
	}

	// Verify allocation was removed from subnet
	if _, exists := subnet.Allocations[ipAddr.IP.String()]; exists {
		t.Error("Allocation should have been removed from subnet")
	}
}

func TestIntegration_AllocatePreferredIP(t *testing.T) {
	requireRoot(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	ifaceName := "ipam-test4"
	createDummyInterface(t, ifaceName)
	defer deleteDummyInterface(t, ifaceName)

	// Add a subnet
	subnet := &Subnet{
		CIDR: "192.168.201.0/24",
	}

	if err := mgr.AddSubnet(subnet); err != nil {
		t.Fatalf("Failed to add subnet: %v", err)
	}

	// Allocate with preferred IP
	preferredIP := net.ParseIP("192.168.201.42")
	req := AllocationRequest{
		Interface:   ifaceName,
		Subnet:      subnet.CIDR,
		Family:      FamilyIPv4,
		PreferredIP: preferredIP,
		Permanent:   true,
	}

	ipAddr, err := mgr.AllocateAddress(req)
	if err != nil {
		t.Fatalf("Failed to allocate preferred address: %v", err)
	}

	if !ipAddr.IP.Equal(preferredIP) {
		t.Errorf("Expected IP %s, got %s", preferredIP.String(), ipAddr.IP.String())
	}

	// Try to allocate the same IP again (should fail)
	req2 := AllocationRequest{
		Interface:   ifaceName,
		Subnet:      subnet.CIDR,
		Family:      FamilyIPv4,
		PreferredIP: preferredIP,
		Permanent:   true,
	}

	_, err = mgr.AllocateAddress(req2)
	if err == nil {
		t.Error("Should not be able to allocate already allocated IP")
	}

	// Clean up
	mgr.ReleaseAddress(ifaceName, ipAddr.Address)
}

func TestIntegration_MultipleAllocations(t *testing.T) {
	requireRoot(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	ifaceName := "ipam-test5"
	createDummyInterface(t, ifaceName)
	defer deleteDummyInterface(t, ifaceName)

	// Add a small subnet
	subnet := &Subnet{
		CIDR: "192.168.202.0/29", // 8 addresses total, 6 usable
	}

	if err := mgr.AddSubnet(subnet); err != nil {
		t.Fatalf("Failed to add subnet: %v", err)
	}

	// Allocate multiple addresses
	allocated := make([]*IPAddress, 0)
	for i := 0; i < 5; i++ {
		req := AllocationRequest{
			Interface: ifaceName,
			Subnet:    subnet.CIDR,
			Family:    FamilyIPv4,
			Permanent: true,
		}

		ipAddr, err := mgr.AllocateAddress(req)
		if err != nil {
			t.Fatalf("Failed to allocate address %d: %v", i, err)
		}

		t.Logf("Allocated %d: %s", i, ipAddr.Address)
		allocated = append(allocated, ipAddr)
	}

	// Verify all allocations are unique
	seen := make(map[string]bool)
	for _, addr := range allocated {
		if seen[addr.Address] {
			t.Errorf("Duplicate allocation: %s", addr.Address)
		}
		seen[addr.Address] = true
	}

	// Clean up
	for _, addr := range allocated {
		if err := mgr.ReleaseAddress(ifaceName, addr.Address); err != nil {
			t.Logf("Warning: Failed to release %s: %v", addr.Address, err)
		}
	}
}

func TestIntegration_SyncAddresses(t *testing.T) {
	requireRoot(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	ifaceName := "ipam-test6"
	createDummyInterface(t, ifaceName)
	defer deleteDummyInterface(t, ifaceName)

	// Add addresses directly via netlink (bypassing manager)
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		t.Fatalf("Failed to get link: %v", err)
	}

	addr1, _ := netlink.ParseAddr("192.168.210.10/24")
	addr2, _ := netlink.ParseAddr("192.168.210.11/24")

	netlink.AddrAdd(link, addr1)
	netlink.AddrAdd(link, addr2)

	time.Sleep(100 * time.Millisecond)

	// Sync addresses
	if err := mgr.SyncAddresses(ifaceName); err != nil {
		t.Fatalf("Failed to sync addresses: %v", err)
	}

	// Verify addresses are in our tracking
	mgr.mu.RLock()
	addrs := mgr.addresses[ifaceName]
	mgr.mu.RUnlock()

	// Should have at least 2 addresses
	if len(addrs) < 2 {
		t.Errorf("Expected at least 2 addresses after sync, got %d", len(addrs))
	}

	// Clean up
	netlink.AddrDel(link, addr1)
	netlink.AddrDel(link, addr2)
}

func TestIntegration_FlushAddresses(t *testing.T) {
	requireRoot(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	ifaceName := "ipam-test7"
	createDummyInterface(t, ifaceName)
	defer deleteDummyInterface(t, ifaceName)

	// Add multiple addresses
	addresses := []string{
		"192.168.220.10/24",
		"192.168.220.11/24",
		"192.168.220.12/24",
	}

	flags := AddressFlags{Permanent: true}
	for _, addr := range addresses {
		mgr.AddAddress(ifaceName, addr, flags)
	}

	time.Sleep(100 * time.Millisecond)

	// Flush all IPv4 addresses
	if err := mgr.kernelMgr.FlushAddresses(ifaceName, FamilyIPv4); err != nil {
		t.Fatalf("Failed to flush addresses: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify addresses were flushed
	ipv4Addrs, err := mgr.ListAddresses(ifaceName, FamilyIPv4)
	if err != nil {
		t.Fatalf("Failed to list addresses: %v", err)
	}

	if len(ipv4Addrs) > 0 {
		t.Errorf("Expected 0 IPv4 addresses after flush, got %d", len(ipv4Addrs))
	}
}

func TestIntegration_DAD(t *testing.T) {
	requireRoot(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	ifaceName := "ipam-test8"
	createDummyInterface(t, ifaceName)
	defer deleteDummyInterface(t, ifaceName)

	// Add an IPv6 address
	address := "2001:db8::100/64"
	flags := AddressFlags{
		Permanent: true,
	}

	if err := mgr.AddAddress(ifaceName, address, flags); err != nil {
		t.Fatalf("Failed to add IPv6 address: %v", err)
	}

	// Wait for DAD to complete
	if err := mgr.kernelMgr.WaitForDAD(ifaceName, address, 10*time.Second); err != nil {
		t.Fatalf("DAD failed or timed out: %v", err)
	}

	// Verify address is no longer tentative
	ipAddr, err := mgr.GetAddress(ifaceName, address)
	if err != nil {
		t.Fatalf("Failed to get address: %v", err)
	}

	if ipAddr.IsTentative() {
		t.Error("Address should not be tentative after DAD")
	}

	if ipAddr.IsDuplicate() {
		t.Error("Address should not be duplicate")
	}

	// Clean up
	mgr.DeleteAddress(ifaceName, address)
}
