package ipam

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	if mgr == nil {
		t.Fatal("Manager is nil")
	}

	if mgr.kernelMgr == nil {
		t.Fatal("Kernel manager is nil")
	}

	if mgr.subnets == nil {
		t.Fatal("Subnets map is nil")
	}

	if mgr.addresses == nil {
		t.Fatal("Addresses map is nil")
	}
}

func TestAddSubnet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	tests := []struct {
		name    string
		subnet  *Subnet
		wantErr bool
	}{
		{
			name: "valid IPv4 subnet",
			subnet: &Subnet{
				CIDR:        "192.168.1.0/24",
				Description: "Test subnet",
			},
			wantErr: false,
		},
		{
			name: "valid IPv6 subnet",
			subnet: &Subnet{
				CIDR:        "2001:db8::/64",
				Description: "Test IPv6 subnet",
			},
			wantErr: false,
		},
		{
			name: "invalid CIDR",
			subnet: &Subnet{
				CIDR: "invalid",
			},
			wantErr: true,
		},
		{
			name:    "empty CIDR",
			subnet:  &Subnet{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.AddSubnet(tt.subnet)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddSubnet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify subnet was added
				subnet, err := mgr.GetSubnet(tt.subnet.CIDR)
				if err != nil {
					t.Errorf("Failed to get subnet: %v", err)
					return
				}

				if subnet.Network == nil {
					t.Error("Subnet network is nil")
				}

				if subnet.Allocations == nil {
					t.Error("Subnet allocations map is nil")
				}

				if subnet.Reserved == nil {
					t.Error("Subnet reserved map is nil")
				}

				// Check if IPv4 has reserved addresses
				if subnet.IsIPv4() {
					if len(subnet.Reserved) < 2 {
						t.Error("IPv4 subnet should have at least 2 reserved addresses (network and broadcast)")
					}
				}
			}
		})
	}
}

func TestRemoveSubnet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	// Add a subnet
	subnet := &Subnet{
		CIDR: "192.168.1.0/24",
	}
	if err := mgr.AddSubnet(subnet); err != nil {
		t.Fatalf("Failed to add subnet: %v", err)
	}

	// Remove the subnet
	if err := mgr.RemoveSubnet(subnet.CIDR); err != nil {
		t.Errorf("Failed to remove subnet: %v", err)
	}

	// Verify subnet was removed
	_, err = mgr.GetSubnet(subnet.CIDR)
	if err == nil {
		t.Error("Subnet should not exist after removal")
	}
}

func TestRemoveSubnetWithAllocations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	// Add a subnet
	subnet := &Subnet{
		CIDR: "192.168.1.0/24",
	}
	if err := mgr.AddSubnet(subnet); err != nil {
		t.Fatalf("Failed to add subnet: %v", err)
	}

	// Add an allocation manually
	subnet.Allocations["192.168.1.10"] = &IPAddress{
		Address: "192.168.1.10/24",
	}

	// Try to remove the subnet (should fail)
	if err := mgr.RemoveSubnet(subnet.CIDR); err == nil {
		t.Error("Should not be able to remove subnet with active allocations")
	}
}

func TestListSubnets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	// Add multiple subnets
	subnets := []*Subnet{
		{CIDR: "192.168.1.0/24"},
		{CIDR: "192.168.2.0/24"},
		{CIDR: "10.0.0.0/16"},
	}

	for _, subnet := range subnets {
		if err := mgr.AddSubnet(subnet); err != nil {
			t.Fatalf("Failed to add subnet %s: %v", subnet.CIDR, err)
		}
	}

	// List subnets
	listed := mgr.ListSubnets()
	if len(listed) != len(subnets) {
		t.Errorf("Expected %d subnets, got %d", len(subnets), len(listed))
	}
}

func TestReserveIP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	// Add a subnet
	subnet := &Subnet{
		CIDR: "192.168.1.0/24",
	}
	if err := mgr.AddSubnet(subnet); err != nil {
		t.Fatalf("Failed to add subnet: %v", err)
	}

	// Reserve an IP
	ip := net.ParseIP("192.168.1.100")
	if err := mgr.ReserveIP(subnet.CIDR, ip); err != nil {
		t.Errorf("Failed to reserve IP: %v", err)
	}

	// Verify IP is reserved
	if !subnet.Reserved[ip.String()] {
		t.Error("IP should be reserved")
	}
}

func TestUnreserveIP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	// Add a subnet
	subnet := &Subnet{
		CIDR: "192.168.1.0/24",
	}
	if err := mgr.AddSubnet(subnet); err != nil {
		t.Fatalf("Failed to add subnet: %v", err)
	}

	// Reserve an IP
	ip := net.ParseIP("192.168.1.100")
	if err := mgr.ReserveIP(subnet.CIDR, ip); err != nil {
		t.Fatalf("Failed to reserve IP: %v", err)
	}

	// Unreserve the IP
	if err := mgr.UnreserveIP(subnet.CIDR, ip); err != nil {
		t.Errorf("Failed to unreserve IP: %v", err)
	}

	// Verify IP is no longer reserved
	if subnet.Reserved[ip.String()] {
		t.Error("IP should not be reserved")
	}
}

func TestSubnetMethods(t *testing.T) {
	// Test IPv4 subnet
	ipv4Subnet := &Subnet{
		CIDR: "192.168.1.0/24",
	}
	_, network, _ := net.ParseCIDR(ipv4Subnet.CIDR)
	ipv4Subnet.Network = network
	ipv4Subnet.Family = FamilyIPv4

	if !ipv4Subnet.IsIPv4() {
		t.Error("Subnet should be IPv4")
	}

	if ipv4Subnet.IsIPv6() {
		t.Error("Subnet should not be IPv6")
	}

	// Test IPv6 subnet
	ipv6Subnet := &Subnet{
		CIDR: "2001:db8::/64",
	}
	_, network, _ = net.ParseCIDR(ipv6Subnet.CIDR)
	ipv6Subnet.Network = network
	ipv6Subnet.Family = FamilyIPv6

	if ipv6Subnet.IsIPv4() {
		t.Error("Subnet should not be IPv4")
	}

	if !ipv6Subnet.IsIPv6() {
		t.Error("Subnet should be IPv6")
	}

	// Test Contains
	ip := net.ParseIP("192.168.1.50")
	if !ipv4Subnet.Contains(ip) {
		t.Error("Subnet should contain IP 192.168.1.50")
	}

	ip = net.ParseIP("192.168.2.50")
	if ipv4Subnet.Contains(ip) {
		t.Error("Subnet should not contain IP 192.168.2.50")
	}
}

func TestIPAddressMethods(t *testing.T) {
	// Test IPv4 address
	ipv4Addr := &IPAddress{
		Family: FamilyIPv4,
		State:  StateValid,
	}

	if !ipv4Addr.IsIPv4() {
		t.Error("Address should be IPv4")
	}

	if ipv4Addr.IsIPv6() {
		t.Error("Address should not be IPv6")
	}

	if !ipv4Addr.IsValid() {
		t.Error("Address should be valid")
	}

	// Test tentative address
	tentativeAddr := &IPAddress{
		State: StateTentative,
	}

	if !tentativeAddr.IsTentative() {
		t.Error("Address should be tentative")
	}

	// Test duplicate address
	duplicateAddr := &IPAddress{
		State: StateDuplicate,
	}

	if !duplicateAddr.IsDuplicate() {
		t.Error("Address should be duplicate")
	}

	// Test prefix length
	_, network, _ := net.ParseCIDR("192.168.1.10/24")
	addr := &IPAddress{
		Network: network,
	}

	if addr.PrefixLength() != 24 {
		t.Errorf("Expected prefix length 24, got %d", addr.PrefixLength())
	}
}

func TestAddressFamilyString(t *testing.T) {
	tests := []struct {
		family   AddressFamily
		expected string
	}{
		{FamilyIPv4, "IPv4"},
		{FamilyIPv6, "IPv6"},
		{FamilyAll, "All"},
		{AddressFamily(99), "Unknown"},
	}

	for _, tt := range tests {
		if tt.family.String() != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, tt.family.String())
		}
	}
}

func TestAddressScopeString(t *testing.T) {
	tests := []struct {
		scope    AddressScope
		expected string
	}{
		{ScopeGlobal, "global"},
		{ScopeSite, "site"},
		{ScopeLink, "link"},
		{ScopeHost, "host"},
		{AddressScope(99), "unknown"},
	}

	for _, tt := range tests {
		if tt.scope.String() != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, tt.scope.String())
		}
	}
}

func TestAddressUpdateTypeString(t *testing.T) {
	tests := []struct {
		updateType AddressUpdateType
		expected   string
	}{
		{AddressAdded, "added"},
		{AddressDeleted, "deleted"},
		{AddressUpdated, "updated"},
		{AddressUpdateType(99), "unknown"},
	}

	for _, tt := range tests {
		if tt.updateType.String() != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, tt.updateType.String())
		}
	}
}

func TestIncrementIP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"IPv4 simple", "192.168.1.1", "192.168.1.2"},
		{"IPv4 rollover", "192.168.1.255", "192.168.2.0"},
		{"IPv6 simple", "2001:db8::1", "2001:db8::2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP %s", tt.ip)
			}

			// Make a copy
			ipCopy := make(net.IP, len(ip))
			copy(ipCopy, ip)

			mgr.incrementIP(ipCopy)

			expected := net.ParseIP(tt.expected)
			if expected == nil {
				t.Fatalf("Failed to parse expected IP %s", tt.expected)
			}

			if !ipCopy.Equal(expected) {
				t.Errorf("Expected %s, got %s", expected.String(), ipCopy.String())
			}
		})
	}
}

func TestCalculateSubnetRange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	tests := []struct {
		name      string
		cidr      string
		wantStart string
		wantEnd   string
	}{
		{
			name:      "IPv4 /24",
			cidr:      "192.168.1.0/24",
			wantStart: "192.168.1.1",
			wantEnd:   "192.168.1.254",
		},
		{
			name:      "IPv4 /30",
			cidr:      "10.0.0.0/30",
			wantStart: "10.0.0.1",
			wantEnd:   "10.0.0.2",
		},
		{
			name:      "IPv6 /64",
			cidr:      "2001:db8::/64",
			wantStart: "2001:db8::1",
			wantEnd:   "2001:db8::ffff:ffff:ffff:ffff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, network, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("Failed to parse CIDR %s: %v", tt.cidr, err)
			}

			start, end := mgr.calculateSubnetRange(network)

			expectedStart := net.ParseIP(tt.wantStart)
			if !start.Equal(expectedStart) {
				t.Errorf("Start IP: expected %s, got %s", expectedStart.String(), start.String())
			}

			expectedEnd := net.ParseIP(tt.wantEnd)
			if !end.Equal(expectedEnd) {
				t.Errorf("End IP: expected %s, got %s", expectedEnd.String(), end.String())
			}
		})
	}
}

func TestSubnetSize(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want uint64
	}{
		{"IPv4 /24", "192.168.1.0/24", 256},
		{"IPv4 /30", "10.0.0.0/30", 4},
		{"IPv4 /32", "192.168.1.1/32", 1},
		{"IPv6 /128", "2001:db8::1/128", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, network, err := net.ParseCIDR(tt.cidr)
			if err != nil {
				t.Fatalf("Failed to parse CIDR %s: %v", tt.cidr, err)
			}

			subnet := &Subnet{
				CIDR:    tt.cidr,
				Network: network,
			}

			if network.IP.To4() != nil {
				subnet.Family = FamilyIPv4
			} else {
				subnet.Family = FamilyIPv6
			}

			size := subnet.Size()
			if size != tt.want {
				t.Errorf("Expected size %d, got %d", tt.want, size)
			}
		})
	}
}

func TestSubnetAvailable(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/30") // 4 addresses total

	subnet := &Subnet{
		CIDR:        "192.168.1.0/30",
		Network:     network,
		Family:      FamilyIPv4,
		Allocations: make(map[string]*IPAddress),
		Reserved:    make(map[string]bool),
	}

	// Initially should have 4 addresses
	if subnet.Size() != 4 {
		t.Errorf("Expected size 4, got %d", subnet.Size())
	}

	// Reserve 2 addresses
	subnet.Reserved["192.168.1.0"] = true
	subnet.Reserved["192.168.1.1"] = true

	// Available should be 2
	available := subnet.Available()
	if available != 2 {
		t.Errorf("Expected 2 available addresses, got %d", available)
	}

	// Allocate 1 address
	subnet.Allocations["192.168.1.2"] = &IPAddress{}

	// Available should be 1
	available = subnet.Available()
	if available != 1 {
		t.Errorf("Expected 1 available address, got %d", available)
	}
}

func TestHandleAddressUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr, err := NewManager(ctx)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Stop()

	// Create a test address update
	_, network, _ := net.ParseCIDR("192.168.1.10/24")
	addr := &IPAddress{
		Interface: "eth0",
		Address:   "192.168.1.10/24",
		IP:        net.ParseIP("192.168.1.10"),
		Network:   network,
		Family:    FamilyIPv4,
	}

	update := AddressUpdate{
		Interface: "eth0",
		Address:   addr,
		Type:      AddressAdded,
		Timestamp: time.Now(),
	}

	// Handle the update
	mgr.handleAddressUpdate(update)

	// Verify the address was added to our tracking
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	if _, exists := mgr.addresses["eth0"]; !exists {
		t.Error("Interface should be tracked")
	}

	if _, exists := mgr.addresses["eth0"]["192.168.1.10/24"]; !exists {
		t.Error("Address should be tracked")
	}
}
