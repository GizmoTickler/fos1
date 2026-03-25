package policy

import (
	"testing"

	"github.com/GizmoTickler/fos1/pkg/security/firewall"
)

func TestCreateZone(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	err := zm.CreateZone("lan", []string{"eth0", "eth1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := zm.GetZone("lan")
	if err != nil {
		t.Fatalf("unexpected error getting zone: %v", err)
	}
	if state.Name != "lan" {
		t.Errorf("expected zone name lan, got %s", state.Name)
	}
	if len(state.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(state.Interfaces))
	}
	if state.Interfaces[0] != "eth0" || state.Interfaces[1] != "eth1" {
		t.Errorf("expected interfaces [eth0 eth1], got %v", state.Interfaces)
	}
	if state.ChainRef.Table != defaultFilterTable {
		t.Errorf("expected table %s, got %s", defaultFilterTable, state.ChainRef.Table)
	}
	if state.ChainRef.Chain != "zone-lan" {
		t.Errorf("expected chain zone-lan, got %s", state.ChainRef.Chain)
	}
}

func TestCreateZone_Duplicate(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	if err := zm.CreateZone("wan", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err := zm.CreateZone("wan", nil)
	if err == nil {
		t.Fatal("expected error for duplicate zone")
	}
}

func TestCreateZone_EmptyName(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	err := zm.CreateZone("", nil)
	if err == nil {
		t.Fatal("expected error for empty zone name")
	}
}

func TestDeleteZone(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	if err := zm.CreateZone("dmz", []string{"eth2"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := zm.DeleteZone("dmz"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := zm.GetZone("dmz")
	if err == nil {
		t.Fatal("expected error getting deleted zone")
	}
}

func TestDeleteZone_NotExist(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	err := zm.DeleteZone("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent zone")
	}
}

func TestAddInterfaceToZone(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	if err := zm.CreateZone("lan", []string{"eth0"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := zm.AddInterfaceToZone("lan", "eth2"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, _ := zm.GetZone("lan")
	if len(state.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(state.Interfaces))
	}
	if state.Interfaces[1] != "eth2" {
		t.Errorf("expected eth2, got %s", state.Interfaces[1])
	}
}

func TestAddInterfaceToZone_Duplicate(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	if err := zm.CreateZone("lan", []string{"eth0"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := zm.AddInterfaceToZone("lan", "eth0")
	if err == nil {
		t.Fatal("expected error for duplicate interface")
	}
}

func TestAddInterfaceToZone_NoZone(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	err := zm.AddInterfaceToZone("nonexistent", "eth0")
	if err == nil {
		t.Fatal("expected error for non-existent zone")
	}
}

func TestRemoveInterfaceFromZone(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	if err := zm.CreateZone("lan", []string{"eth0", "eth1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := zm.RemoveInterfaceFromZone("lan", "eth0"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, _ := zm.GetZone("lan")
	if len(state.Interfaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(state.Interfaces))
	}
	if state.Interfaces[0] != "eth1" {
		t.Errorf("expected eth1, got %s", state.Interfaces[0])
	}
}

func TestRemoveInterfaceFromZone_NotFound(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	if err := zm.CreateZone("lan", []string{"eth0"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := zm.RemoveInterfaceFromZone("lan", "eth99")
	if err == nil {
		t.Fatal("expected error for non-existent interface")
	}
}

func TestRemoveInterfaceFromZone_EmptyName(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	if err := zm.CreateZone("lan", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := zm.RemoveInterfaceFromZone("lan", "")
	if err == nil {
		t.Fatal("expected error for empty interface name")
	}
}

func TestListZones(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	zones := zm.ListZones()
	if len(zones) != 0 {
		t.Fatalf("expected 0 zones, got %d", len(zones))
	}

	_ = zm.CreateZone("lan", []string{"eth0"})
	_ = zm.CreateZone("wan", []string{"eth1"})
	_ = zm.CreateZone("dmz", []string{"eth2"})

	zones = zm.ListZones()
	if len(zones) != 3 {
		t.Fatalf("expected 3 zones, got %d", len(zones))
	}

	// Verify all zones are present.
	names := map[string]bool{}
	for _, z := range zones {
		names[z.Name] = true
	}
	for _, expected := range []string{"lan", "wan", "dmz"} {
		if !names[expected] {
			t.Errorf("expected zone %q in list", expected)
		}
	}
}

func TestGetZone_ReturnsCopy(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	_ = zm.CreateZone("lan", []string{"eth0"})

	state1, _ := zm.GetZone("lan")
	state1.Interfaces = append(state1.Interfaces, "modified")

	state2, _ := zm.GetZone("lan")
	if len(state2.Interfaces) != 1 {
		t.Errorf("expected 1 interface (copy should be independent), got %d", len(state2.Interfaces))
	}
}

func TestDeleteChain_CalledOnDeleteZone(t *testing.T) {
	mock := newMockFirewallManager()
	zm := NewZoneManager(mock)

	_ = zm.CreateZone("test", nil)

	// Verify the chain ref was set.
	state, _ := zm.GetZone("test")
	expectedChain := firewall.ChainRef{Table: defaultFilterTable, Chain: "zone-test"}
	if state.ChainRef != expectedChain {
		t.Errorf("expected chain ref %+v, got %+v", expectedChain, state.ChainRef)
	}

	if err := zm.DeleteZone("test"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
