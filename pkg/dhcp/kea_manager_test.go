package dhcp

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GizmoTickler/fos1/pkg/dhcp/kea"
	"github.com/GizmoTickler/fos1/pkg/dhcp/types"
)

// fakeKeaClient implements KeaClientInterface for testing.
type fakeKeaClient struct {
	configSetCalls   []any
	configSetErr     error
	configGetResult  any
	configGetErr     error
	configReloadErr  error
	executeCalls     []keaExecCall
	executeResponses []kea.KeaResponse
	executeErr       error
	running          bool
}

type keaExecCall struct {
	Command string
	Args    any
}

func (f *fakeKeaClient) Execute(ctx context.Context, command string, args any) ([]kea.KeaResponse, error) {
	f.executeCalls = append(f.executeCalls, keaExecCall{Command: command, Args: args})
	if f.executeErr != nil {
		return nil, f.executeErr
	}
	return f.executeResponses, nil
}

func (f *fakeKeaClient) ConfigGet(ctx context.Context) (any, error) {
	return f.configGetResult, f.configGetErr
}

func (f *fakeKeaClient) ConfigSet(ctx context.Context, config any) error {
	f.configSetCalls = append(f.configSetCalls, config)
	return f.configSetErr
}

func (f *fakeKeaClient) ConfigReload(ctx context.Context) error {
	return f.configReloadErr
}

func (f *fakeKeaClient) IsRunning() bool {
	return f.running
}

// --- Config generation tests ---

func TestBuildKeaDHCPv4Config_ValidInput(t *testing.T) {
	service := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:      "vlan100",
			LeaseTime:    3600,
			MaxLeaseTime: 7200,
			Range:        types.AddressRange{Start: "192.168.1.10", End: "192.168.1.200"},
			Domain:       "home.arpa",
		},
	}

	config, err := BuildKeaDHCPv4Config(service, "192.168.1.0/24", "192.168.1.1")
	require.NoError(t, err)
	require.NotNil(t, config)
	require.NotNil(t, config.Dhcp4)

	assert.Equal(t, 3600, config.Dhcp4.ValidLifetime)
	assert.Equal(t, 7200, config.Dhcp4.MaxValidLifetime)
	assert.Equal(t, []string{"eth-vlan100"}, config.Dhcp4.Interfaces)
	require.Len(t, config.Dhcp4.Subnet4, 1)
	assert.Equal(t, "192.168.1.0/24", config.Dhcp4.Subnet4[0].Subnet)
	assert.Equal(t, "192.168.1.10-192.168.1.200", config.Dhcp4.Subnet4[0].Pools[0].Pool)

	// Verify the JSON serialization produces valid Kea JSON.
	jsonBytes, err := json.Marshal(config)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(jsonBytes, &parsed))

	dhcp4, ok := parsed["Dhcp4"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, dhcp4, "valid-lifetime")
	assert.Contains(t, dhcp4, "subnet4")
}

func TestBuildKeaDHCPv4Config_IncludesRouterAndDomainOptions(t *testing.T) {
	service := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:   "vlan100",
			LeaseTime: 3600,
			Range:     types.AddressRange{Start: "192.168.1.10", End: "192.168.1.200"},
			Domain:    "home.arpa",
		},
	}

	config, err := BuildKeaDHCPv4Config(service, "192.168.1.0/24", "192.168.1.1")
	require.NoError(t, err)

	opts := config.Dhcp4.Subnet4[0].OptionData
	require.Len(t, opts, 2) // Router + Domain Name

	assert.Equal(t, 3, opts[0].Code)  // Router
	assert.Equal(t, "192.168.1.1", opts[0].Data)
	assert.Equal(t, 15, opts[1].Code) // Domain Name
	assert.Equal(t, "home.arpa", opts[1].Data)
}

func TestBuildKeaDHCPv4Config_WithReservations(t *testing.T) {
	service := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:   "vlan100",
			LeaseTime: 3600,
			Range:     types.AddressRange{Start: "192.168.1.10", End: "192.168.1.200"},
			Reservations: []types.DHCPv4Reservation{
				{Hostname: "server1", MACAddress: "aa:bb:cc:dd:ee:ff", IPAddress: "192.168.1.5"},
				{Hostname: "server2", ClientID: "01:11:22:33:44:55:66", IPAddress: "192.168.1.6"},
			},
		},
	}

	config, err := BuildKeaDHCPv4Config(service, "192.168.1.0/24", "192.168.1.1")
	require.NoError(t, err)

	reservations := config.Dhcp4.Subnet4[0].Reservations
	require.Len(t, reservations, 2)
	assert.Equal(t, "server1", reservations[0].Hostname)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", reservations[0].HwAddress)
	assert.Equal(t, "192.168.1.5", reservations[0].IPAddress)
	assert.Equal(t, "server2", reservations[1].Hostname)
	assert.Equal(t, "01:11:22:33:44:55:66", reservations[1].ClientID)
}

func TestBuildKeaDHCPv4Config_WithDNSHook(t *testing.T) {
	service := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:   "vlan100",
			LeaseTime: 3600,
			Range:     types.AddressRange{Start: "192.168.1.10", End: "192.168.1.200"},
			Domain:    "home.arpa",
			DNSIntegration: types.DNSIntegration{
				Enabled:        true,
				ForwardUpdates: true,
				ReverseUpdates: true,
				TTL:            300,
			},
		},
	}

	config, err := BuildKeaDHCPv4Config(service, "192.168.1.0/24", "192.168.1.1")
	require.NoError(t, err)

	require.Len(t, config.Dhcp4.HookLibraries, 1)
	assert.Contains(t, config.Dhcp4.HookLibraries[0].Library, "libdhcp_ddns.so")
	params := config.Dhcp4.HookLibraries[0].Parameters
	assert.Equal(t, true, params["enable-updates"])
	assert.Equal(t, "home.arpa", params["qualifying-suffix"])
}

func TestBuildKeaDHCPv4Config_MissingSubnet(t *testing.T) {
	service := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:   "vlan100",
			LeaseTime: 3600,
			Range:     types.AddressRange{Start: "192.168.1.10", End: "192.168.1.200"},
		},
	}

	_, err := BuildKeaDHCPv4Config(service, "", "192.168.1.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subnet is required")
}

func TestBuildKeaDHCPv4Config_MissingRange(t *testing.T) {
	service := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:   "vlan100",
			LeaseTime: 3600,
			Range:     types.AddressRange{Start: "", End: ""},
		},
	}

	_, err := BuildKeaDHCPv4Config(service, "192.168.1.0/24", "192.168.1.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "address range")
}

func TestBuildKeaDHCPv6Config_ValidInput(t *testing.T) {
	service := &types.DHCPv6Service{
		Spec: types.DHCPv6ServiceSpec{
			VLANRef:      "vlan100",
			LeaseTime:    3600,
			MaxLeaseTime: 7200,
			Range:        types.AddressRange{Start: "2001:db8::10", End: "2001:db8::ff"},
			Domain:       "home.arpa",
		},
	}

	config, err := BuildKeaDHCPv6Config(service, "2001:db8::/64", "2001:db8::1")
	require.NoError(t, err)
	require.NotNil(t, config)
	require.NotNil(t, config.Dhcp6)

	assert.Equal(t, 3600, config.Dhcp6.ValidLifetime)
	require.Len(t, config.Dhcp6.Subnet6, 1)
	assert.Equal(t, "2001:db8::/64", config.Dhcp6.Subnet6[0].Subnet)
}

func TestBuildKeaDHCPv4Config_ProducesValidKeaJSON(t *testing.T) {
	service := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:      "vlan100",
			LeaseTime:    3600,
			MaxLeaseTime: 7200,
			Range:        types.AddressRange{Start: "192.168.1.10", End: "192.168.1.200"},
			Domain:       "home.arpa",
			Options: []types.DHCPOption{
				{Code: 6, Value: "8.8.8.8"},
			},
			Reservations: []types.DHCPv4Reservation{
				{Hostname: "printer", MACAddress: "00:11:22:33:44:55", IPAddress: "192.168.1.5"},
			},
			DNSIntegration: types.DNSIntegration{
				Enabled:        true,
				ForwardUpdates: true,
				ReverseUpdates: false,
				TTL:            600,
			},
		},
	}

	config, err := BuildKeaDHCPv4Config(service, "192.168.1.0/24", "192.168.1.1")
	require.NoError(t, err)

	// Marshal to JSON and parse back to verify structure.
	jsonBytes, err := json.MarshalIndent(config, "", "  ")
	require.NoError(t, err)

	var roundTripped types.KeaConfig
	require.NoError(t, json.Unmarshal(jsonBytes, &roundTripped))

	require.NotNil(t, roundTripped.Dhcp4)
	assert.Equal(t, config.Dhcp4.ValidLifetime, roundTripped.Dhcp4.ValidLifetime)
	assert.Equal(t, config.Dhcp4.Subnet4[0].Subnet, roundTripped.Dhcp4.Subnet4[0].Subnet)
	assert.Equal(t, config.Dhcp4.Subnet4[0].Pools[0].Pool, roundTripped.Dhcp4.Subnet4[0].Pools[0].Pool)
}

// --- KeaManager integration tests ---

func TestPushDHCPv4Config_Success(t *testing.T) {
	client := &fakeKeaClient{
		running:         true,
		configGetResult: map[string]any{"Dhcp4": map[string]any{}},
	}
	mgr := NewKeaManager(client, nil)

	service := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:   "vlan100",
			LeaseTime: 3600,
			Range:     types.AddressRange{Start: "192.168.1.10", End: "192.168.1.200"},
			Domain:    "home.arpa",
		},
	}

	err := mgr.PushDHCPv4Config(context.Background(), service, "192.168.1.0/24", "192.168.1.1")
	require.NoError(t, err)

	// Verify ConfigSet was called with a valid config.
	require.Len(t, client.configSetCalls, 1)
	cfg, ok := client.configSetCalls[0].(*types.KeaConfig)
	require.True(t, ok)
	require.NotNil(t, cfg.Dhcp4)
	assert.Equal(t, "192.168.1.0/24", cfg.Dhcp4.Subnet4[0].Subnet)
}

func TestPushDHCPv4Config_ConfigSetError(t *testing.T) {
	client := &fakeKeaClient{
		running:      true,
		configSetErr: fmt.Errorf("config-set: result=1: invalid configuration"),
	}
	mgr := NewKeaManager(client, nil)

	service := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:   "vlan100",
			LeaseTime: 3600,
			Range:     types.AddressRange{Start: "192.168.1.10", End: "192.168.1.200"},
		},
	}

	err := mgr.PushDHCPv4Config(context.Background(), service, "192.168.1.0/24", "192.168.1.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config-set")
}

func TestPushDHCPv4Config_VerificationError(t *testing.T) {
	client := &fakeKeaClient{
		running:     true,
		configGetErr: fmt.Errorf("config-get: timeout"),
	}
	mgr := NewKeaManager(client, nil)

	service := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:   "vlan100",
			LeaseTime: 3600,
			Range:     types.AddressRange{Start: "192.168.1.10", End: "192.168.1.200"},
		},
	}

	err := mgr.PushDHCPv4Config(context.Background(), service, "192.168.1.0/24", "192.168.1.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config-get verification")
}

func TestPushDHCPv6Config_Success(t *testing.T) {
	client := &fakeKeaClient{
		running:         true,
		configGetResult: map[string]any{"Dhcp6": map[string]any{}},
	}
	mgr := NewKeaManager(nil, client)

	service := &types.DHCPv6Service{
		Spec: types.DHCPv6ServiceSpec{
			VLANRef:   "vlan100",
			LeaseTime: 3600,
			Range:     types.AddressRange{Start: "2001:db8::10", End: "2001:db8::ff"},
			Domain:    "home.arpa",
		},
	}

	err := mgr.PushDHCPv6Config(context.Background(), service, "2001:db8::/64", "2001:db8::1")
	require.NoError(t, err)

	require.Len(t, client.configSetCalls, 1)
	cfg, ok := client.configSetCalls[0].(*types.KeaConfig)
	require.True(t, ok)
	require.NotNil(t, cfg.Dhcp6)
	assert.Equal(t, "2001:db8::/64", cfg.Dhcp6.Subnet6[0].Subnet)
}

func TestPushDHCPv6Config_ConfigSetError(t *testing.T) {
	client := &fakeKeaClient{
		running:      true,
		configSetErr: fmt.Errorf("config-set: result=1: bad config"),
	}
	mgr := NewKeaManager(nil, client)

	service := &types.DHCPv6Service{
		Spec: types.DHCPv6ServiceSpec{
			VLANRef:   "vlan100",
			LeaseTime: 3600,
			Range:     types.AddressRange{Start: "2001:db8::10", End: "2001:db8::ff"},
		},
	}

	err := mgr.PushDHCPv6Config(context.Background(), service, "2001:db8::/64", "2001:db8::1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config-set")
}

func TestReloadDHCPv4(t *testing.T) {
	client := &fakeKeaClient{running: true}
	mgr := NewKeaManager(client, nil)

	err := mgr.ReloadDHCPv4(context.Background())
	assert.NoError(t, err)
}

func TestReloadDHCPv4_Error(t *testing.T) {
	client := &fakeKeaClient{
		running:         true,
		configReloadErr: fmt.Errorf("config-reload: result=1: file not found"),
	}
	mgr := NewKeaManager(client, nil)

	err := mgr.ReloadDHCPv4(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config-reload")
}

func TestIsDHCPv4Running(t *testing.T) {
	client := &fakeKeaClient{running: true}
	mgr := NewKeaManager(client, nil)
	assert.True(t, mgr.IsDHCPv4Running())

	client.running = false
	assert.False(t, mgr.IsDHCPv4Running())
}
