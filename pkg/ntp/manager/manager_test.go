package manager

import (
	"testing"

	"github.com/GizmoTickler/fos1/pkg/ntp"
)

func TestManager_GetConfig_NoConfigApplied(t *testing.T) {
	// Create a manager with nil currentConfig (the zero-value state)
	m := &Manager{}

	_, err := m.GetConfig()
	if err == nil {
		t.Fatal("GetConfig() should return error when no config has been applied")
	}
	if err.Error() != "no NTP service configuration has been applied yet" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestManager_GetConfig_ReturnsLastApplied(t *testing.T) {
	cfg := &ntp.NTPService{
		Name:    "applied-ntp",
		Enabled: true,
		Sources: ntp.Sources{
			Pools: []ntp.PoolSource{
				{Name: "pool.ntp.org", Servers: 4, IBurst: true},
			},
		},
	}

	m := &Manager{
		currentConfig: cfg,
	}

	got, err := m.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if got.Name != "applied-ntp" {
		t.Errorf("Name = %q, want %q", got.Name, "applied-ntp")
	}
	if !got.Enabled {
		t.Error("Enabled should be true")
	}
	if len(got.Sources.Pools) != 1 {
		t.Errorf("Pools len = %d, want 1", len(got.Sources.Pools))
	}
}

func TestDHCPIntegration_GetNTPServerAddresses(t *testing.T) {
	cfg := &ntp.NTPService{
		Name:    "test-ntp",
		Enabled: true,
		Server: ntp.ServerConfig{
			Local: ntp.LocalClockConfig{Enabled: true, Stratum: 10},
		},
		VLANConfig: []ntp.VLANConfig{
			{VLANRef: "vlan-10", Enabled: true, IPv4Address: "192.168.10.1", IPv6Address: "fd00:10::1"},
			{VLANRef: "vlan-20", Enabled: true, IPv4Address: "192.168.20.1"},
			{VLANRef: "vlan-30", Enabled: false, IPv4Address: "192.168.30.1"},
		},
		Sources: ntp.Sources{}, // No external sources for this test
	}

	m := &Manager{currentConfig: cfg}
	d := &DHCPIntegration{ntpManager: m}

	servers, err := d.getNTPServerAddresses(cfg)
	if err != nil {
		t.Fatalf("getNTPServerAddresses() error = %v", err)
	}

	// Should include IPs from enabled VLANs only
	// vlan-10: 192.168.10.1 and fd00:10::1
	// vlan-20: 192.168.20.1
	// vlan-30: disabled, should be excluded
	expected := []string{"192.168.10.1", "fd00:10::1", "192.168.20.1"}
	if len(servers) != len(expected) {
		t.Fatalf("servers = %v, want %v", servers, expected)
	}
	for i, s := range servers {
		if s != expected[i] {
			t.Errorf("servers[%d] = %q, want %q", i, s, expected[i])
		}
	}
}

func TestDHCPIntegration_GetNTPServerAddresses_NoLocalClock(t *testing.T) {
	cfg := &ntp.NTPService{
		Name:    "test-ntp",
		Enabled: true,
		Server: ntp.ServerConfig{
			Local: ntp.LocalClockConfig{Enabled: false},
		},
		VLANConfig: []ntp.VLANConfig{
			{VLANRef: "vlan-10", Enabled: true, IPv4Address: "192.168.10.1"},
		},
		Sources: ntp.Sources{},
	}

	d := &DHCPIntegration{ntpManager: &Manager{currentConfig: cfg}}

	servers, err := d.getNTPServerAddresses(cfg)
	if err != nil {
		t.Fatalf("getNTPServerAddresses() error = %v", err)
	}

	// With local clock disabled, no VLAN addresses should be included
	if len(servers) != 0 {
		t.Errorf("servers = %v, want empty (local clock disabled)", servers)
	}
}
