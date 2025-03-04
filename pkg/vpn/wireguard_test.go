package vpn

import (
	"strings"
	"testing"
)

func TestWireGuardService_AddInterface(t *testing.T) {
	service := NewWireGuardService()
	
	t.Run("ValidConfig", func(t *testing.T) {
		config := &WireGuardConfig{
			InterfaceName: "wg0",
			PrivateKey:    "private-key",
			Address:       "10.10.10.1/24",
		}
		
		err := service.AddInterface(config)
		if err != nil {
			t.Fatalf("Failed to add valid interface: %v", err)
		}
		
		if len(service.configs) != 1 {
			t.Fatalf("Expected 1 config, got %d", len(service.configs))
		}
		
		if service.configs["wg0"] != config {
			t.Fatalf("Config not stored correctly")
		}
	})
	
	t.Run("NilConfig", func(t *testing.T) {
		err := service.AddInterface(nil)
		if err == nil {
			t.Fatalf("Expected error for nil config")
		}
	})
	
	t.Run("MissingInterfaceName", func(t *testing.T) {
		config := &WireGuardConfig{
			PrivateKey: "private-key",
			Address:    "10.10.10.1/24",
		}
		
		err := service.AddInterface(config)
		if err == nil {
			t.Fatalf("Expected error for missing interface name")
		}
	})
	
	t.Run("MissingPrivateKey", func(t *testing.T) {
		config := &WireGuardConfig{
			InterfaceName: "wg0",
			Address:       "10.10.10.1/24",
		}
		
		err := service.AddInterface(config)
		if err == nil {
			t.Fatalf("Expected error for missing private key")
		}
	})
	
	t.Run("MissingAddress", func(t *testing.T) {
		config := &WireGuardConfig{
			InterfaceName: "wg0",
			PrivateKey:    "private-key",
		}
		
		err := service.AddInterface(config)
		if err == nil {
			t.Fatalf("Expected error for missing address")
		}
	})
}

func TestWireGuardService_GenerateConfig(t *testing.T) {
	service := NewWireGuardService()
	
	config := &WireGuardConfig{
		InterfaceName: "wg0",
		PrivateKey:    "private-key",
		ListenPort:    51820,
		Address:       "10.10.10.1/24",
		PostUp: []string{
			"iptables -A FORWARD -i %i -j ACCEPT",
			"iptables -A FORWARD -o %i -j ACCEPT",
		},
		PostDown: []string{
			"iptables -D FORWARD -i %i -j ACCEPT",
			"iptables -D FORWARD -o %i -j ACCEPT",
		},
		Peers: []WireGuardPeer{
			{
				PublicKey:           "peer1-public-key",
				PresharedKey:        "psk1",
				Endpoint:            "192.168.1.100:51820",
				AllowedIPs:          []string{"10.10.10.2/32"},
				PersistentKeepalive: 25,
			},
			{
				PublicKey:  "peer2-public-key",
				AllowedIPs: []string{"10.10.10.3/32", "10.10.10.4/32"},
			},
		},
	}
	
	service.AddInterface(config)
	
	configString, err := service.GenerateConfig("wg0")
	if err != nil {
		t.Fatalf("Failed to generate config: %v", err)
	}
	
	// Check for expected content
	expectedStrings := []string{
		"[Interface]",
		"PrivateKey = private-key",
		"Address = 10.10.10.1/24",
		"ListenPort = 51820",
		"PostUp = iptables -A FORWARD -i %i -j ACCEPT",
		"PostUp = iptables -A FORWARD -o %i -j ACCEPT",
		"PostDown = iptables -D FORWARD -i %i -j ACCEPT",
		"PostDown = iptables -D FORWARD -o %i -j ACCEPT",
		"[Peer]",
		"PublicKey = peer1-public-key",
		"PresharedKey = psk1",
		"Endpoint = 192.168.1.100:51820",
		"AllowedIPs = 10.10.10.2/32",
		"PersistentKeepalive = 25",
		"PublicKey = peer2-public-key",
		"AllowedIPs = 10.10.10.3/32, 10.10.10.4/32",
	}
	
	for _, expected := range expectedStrings {
		if !strings.Contains(configString, expected) {
			t.Errorf("Generated config missing expected string: %s", expected)
		}
	}
	
	// Test non-existent interface
	_, err = service.GenerateConfig("nonexistent")
	if err == nil {
		t.Fatalf("Expected error for non-existent interface")
	}
}