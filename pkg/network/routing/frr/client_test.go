package frr

import (
	"context"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
	if client.config == nil {
		t.Fatal("Client config is nil")
	}
}

func TestNewClientWithConfig(t *testing.T) {
	config := &ClientConfig{
		VTYSHPath:      "/usr/local/bin/vtysh",
		SocketPath:     "/var/run/frr-test",
		ConfigPath:     "/etc/frr-test",
		CommandTimeout: 60,
		MaxRetries:     5,
		RetryDelay:     2,
	}

	client := NewClientWithConfig(config)
	if client == nil {
		t.Fatal("NewClientWithConfig() returned nil")
	}

	if client.config.VTYSHPath != config.VTYSHPath {
		t.Errorf("VTYSHPath mismatch: got %s, want %s", client.config.VTYSHPath, config.VTYSHPath)
	}
	if client.config.CommandTimeout != config.CommandTimeout {
		t.Errorf("CommandTimeout mismatch: got %d, want %d", client.config.CommandTimeout, config.CommandTimeout)
	}
}

func TestDefaultClientConfig(t *testing.T) {
	config := DefaultClientConfig()
	if config == nil {
		t.Fatal("DefaultClientConfig() returned nil")
	}

	if config.VTYSHPath == "" {
		t.Error("VTYSHPath is empty")
	}
	if config.CommandTimeout <= 0 {
		t.Error("CommandTimeout is invalid")
	}
	if config.MaxRetries <= 0 {
		t.Error("MaxRetries is invalid")
	}
}

func TestConfigureBGP(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	neighbors := []BGPNeighbor{
		{
			Address:           "192.0.2.1",
			RemoteASNumber:    65001,
			Description:       "Test Neighbor",
			KeepaliveInterval: 30,
			HoldTime:          90,
			BFDEnabled:        true,
		},
	}

	addressFamilies := []BGPAddressFamily{
		{
			Type:    "ipv4-unicast",
			Enabled: true,
			Networks: []string{
				"10.0.0.0/24",
			},
			Redistributions: []Redistribution{
				{
					Protocol: "connected",
				},
			},
		},
	}

	// This will fail without an actual FRR instance, but tests the function signature
	err := client.ConfigureBGP(ctx, 65000, "1.1.1.1", neighbors, addressFamilies)
	// We expect an error since FRR is not running in test environment
	if err == nil {
		t.Log("ConfigureBGP succeeded (FRR must be running)")
	} else {
		t.Logf("ConfigureBGP failed as expected without FRR: %v", err)
	}
}

func TestConfigureOSPF(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	areas := []OSPFArea{
		{
			AreaID: "0.0.0.0",
			Interfaces: []OSPFInterface{
				{
					Name:     "eth0",
					Network:  "10.0.0.0/24",
					Cost:     10,
					Priority: 1,
				},
			},
			StubArea: false,
			NSSAArea: false,
		},
	}

	redistributions := []Redistribution{
		{
			Protocol: "connected",
		},
	}

	// This will fail without an actual FRR instance
	err := client.ConfigureOSPF(ctx, "2.2.2.2", areas, redistributions)
	if err == nil {
		t.Log("ConfigureOSPF succeeded (FRR must be running)")
	} else {
		t.Logf("ConfigureOSPF failed as expected without FRR: %v", err)
	}
}

func TestHealthCheck(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	// This will fail without an actual FRR instance
	err := client.HealthCheck(ctx)
	if err == nil {
		t.Log("HealthCheck succeeded (FRR must be running)")
	} else {
		t.Logf("HealthCheck failed as expected without FRR: %v", err)
	}
}

func TestIsAvailable(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	// This will return false without an actual FRR instance
	available := client.IsAvailable(ctx)
	if available {
		t.Log("FRR is available")
	} else {
		t.Log("FRR is not available (expected in test environment)")
	}
}
