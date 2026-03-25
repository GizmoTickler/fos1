//go:build linux

package wireguard

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/GizmoTickler/fos1/pkg/vpn"
)

// ---------------------------------------------------------------------------
// Mock wgctrl client
// ---------------------------------------------------------------------------

type mockWgctrlClient struct {
	devices       map[string]*wgtypes.Device
	configuredCfg *wgtypes.Config
	configuredDev string
	configureErr  error
	deviceErr     error
}

func newMockWgctrlClient() *mockWgctrlClient {
	return &mockWgctrlClient{
		devices: make(map[string]*wgtypes.Device),
	}
}

func (m *mockWgctrlClient) Device(name string) (*wgtypes.Device, error) {
	if m.deviceErr != nil {
		return nil, m.deviceErr
	}
	dev, ok := m.devices[name]
	if !ok {
		return nil, &devNotFoundErr{name: name}
	}
	return dev, nil
}

func (m *mockWgctrlClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	m.configuredDev = name
	m.configuredCfg = &cfg
	return m.configureErr
}

func (m *mockWgctrlClient) Close() error {
	return nil
}

type devNotFoundErr struct{ name string }

func (e *devNotFoundErr) Error() string { return "device not found: " + e.name }

// ---------------------------------------------------------------------------
// Tests: type conversion (buildWgConfig)
// ---------------------------------------------------------------------------

func TestBuildWgConfig_PrivateKey(t *testing.T) {
	keyB64 := makeTestKeyBase64(1)

	cfg, err := buildWgConfig(vpn.InterfaceConfig{
		PrivateKey: keyB64,
		ListenPort: 51820,
	})
	require.NoError(t, err)

	assert.NotNil(t, cfg.PrivateKey)
	assert.Equal(t, keyB64, cfg.PrivateKey.String())
	assert.NotNil(t, cfg.ListenPort)
	assert.Equal(t, 51820, *cfg.ListenPort)
}

func TestBuildWgConfig_EmptyPrivateKey(t *testing.T) {
	cfg, err := buildWgConfig(vpn.InterfaceConfig{})
	require.NoError(t, err)
	assert.Nil(t, cfg.PrivateKey)
	assert.Nil(t, cfg.ListenPort)
}

func TestBuildWgConfig_InvalidPrivateKey(t *testing.T) {
	_, err := buildWgConfig(vpn.InterfaceConfig{
		PrivateKey: "not-a-valid-key",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse private key")
}

func TestBuildWgConfig_FirewallMark(t *testing.T) {
	cfg, err := buildWgConfig(vpn.InterfaceConfig{
		Firewall: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, cfg.FirewallMark)
	assert.Equal(t, 1, *cfg.FirewallMark)
}

// ---------------------------------------------------------------------------
// Tests: type conversion (buildPeerConfig)
// ---------------------------------------------------------------------------

func TestBuildPeerConfig_Full(t *testing.T) {
	pubKeyB64 := makeTestKeyBase64(2)
	pskB64 := makeTestKeyBase64(3)

	pc, err := buildPeerConfig(vpn.PeerConfig{
		PublicKey:           pubKeyB64,
		PresharedKey:        pskB64,
		Endpoint:            "10.0.0.1:51820",
		PersistentKeepalive: 25,
		AllowedIPs:          []string{"10.0.0.0/24", "fd00::/64"},
	}, false)
	require.NoError(t, err)

	assert.Equal(t, pubKeyB64, pc.PublicKey.String())
	assert.False(t, pc.Remove)
	assert.True(t, pc.ReplaceAllowedIPs)

	assert.NotNil(t, pc.PresharedKey)
	assert.Equal(t, pskB64, pc.PresharedKey.String())

	assert.NotNil(t, pc.Endpoint)
	assert.Equal(t, "10.0.0.1", pc.Endpoint.IP.String())
	assert.Equal(t, 51820, pc.Endpoint.Port)

	assert.NotNil(t, pc.PersistentKeepaliveInterval)
	assert.Equal(t, 25*time.Second, *pc.PersistentKeepaliveInterval)

	require.Len(t, pc.AllowedIPs, 2)
	assert.Equal(t, "10.0.0.0/24", pc.AllowedIPs[0].String())
	assert.Equal(t, "fd00::/64", pc.AllowedIPs[1].String())
}

func TestBuildPeerConfig_Remove(t *testing.T) {
	pubKeyB64 := makeTestKeyBase64(4)

	pc, err := buildPeerConfig(vpn.PeerConfig{
		PublicKey: pubKeyB64,
	}, true)
	require.NoError(t, err)
	assert.True(t, pc.Remove)
}

func TestBuildPeerConfig_BareIP(t *testing.T) {
	pubKeyB64 := makeTestKeyBase64(5)

	pc, err := buildPeerConfig(vpn.PeerConfig{
		PublicKey:   pubKeyB64,
		AllowedIPs:  []string{"10.0.0.1", "fd00::1"},
	}, false)
	require.NoError(t, err)

	require.Len(t, pc.AllowedIPs, 2)
	assert.Equal(t, "10.0.0.1/32", pc.AllowedIPs[0].String())
	assert.Equal(t, "fd00::1/128", pc.AllowedIPs[1].String())
}

func TestBuildPeerConfig_InvalidPublicKey(t *testing.T) {
	_, err := buildPeerConfig(vpn.PeerConfig{
		PublicKey: "bad",
	}, false)
	assert.Error(t, err)
}

func TestBuildPeerConfig_InvalidEndpoint(t *testing.T) {
	pubKeyB64 := makeTestKeyBase64(6)

	_, err := buildPeerConfig(vpn.PeerConfig{
		PublicKey: pubKeyB64,
		Endpoint:  "not-a-valid-endpoint",
	}, false)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Tests: DeviceToStatus
// ---------------------------------------------------------------------------

func TestDeviceToStatus(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-10 * time.Second)

	dev := &wgtypes.Device{
		Name:      "wg0",
		PublicKey: makeTestKey(10),
		Peers: []wgtypes.Peer{
			{
				PublicKey:          makeTestKey(11),
				Endpoint:          &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 51820},
				LastHandshakeTime: earlier,
				ReceiveBytes:      1000,
				TransmitBytes:     2000,
			},
			{
				PublicKey:          makeTestKey(12),
				Endpoint:          &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 51821},
				LastHandshakeTime: now,
				ReceiveBytes:      3000,
				TransmitBytes:     4000,
			},
		},
	}

	status := DeviceToStatus(dev)

	assert.Equal(t, "Running", status.Phase)
	assert.Equal(t, makeTestKey(10).String(), status.PublicKey)
	assert.Equal(t, 2, status.ConnectedPeers)
	assert.Equal(t, now, status.LastHandshake)
	assert.Equal(t, int64(4000), status.TransferRx)
	assert.Equal(t, int64(6000), status.TransferTx)

	require.Len(t, status.Conditions, 2)
	assert.Equal(t, "Peer", status.Conditions[0].Type)
	assert.Equal(t, makeTestKey(11).String(), status.Conditions[0].Reason)
	assert.Contains(t, status.Conditions[0].Message, "1.2.3.4:51820")
}

func TestDeviceToStatus_NoPeers(t *testing.T) {
	dev := &wgtypes.Device{
		Name:      "wg0",
		PublicKey: makeTestKey(20),
	}

	status := DeviceToStatus(dev)
	assert.Equal(t, 0, status.ConnectedPeers)
	assert.Empty(t, status.Conditions)
	assert.True(t, status.LastHandshake.IsZero())
}

// ---------------------------------------------------------------------------
// Tests: PeerToPeerStatus
// ---------------------------------------------------------------------------

func TestPeerToPeerStatus_Connected(t *testing.T) {
	recentHandshake := time.Now().Add(-10 * time.Second)

	p := &wgtypes.Peer{
		PublicKey:          makeTestKey(30),
		Endpoint:          &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 51820},
		LastHandshakeTime: recentHandshake,
		ReceiveBytes:      500,
		TransmitBytes:     600,
	}

	ps := PeerToPeerStatus(p)

	assert.Equal(t, makeTestKey(30).String(), ps.PublicKey)
	assert.Equal(t, "10.0.0.1:51820", ps.Endpoint)
	assert.Equal(t, recentHandshake, ps.LastHandshake)
	assert.Equal(t, int64(500), ps.TransferRx)
	assert.Equal(t, int64(600), ps.TransferTx)
	assert.True(t, ps.Connected)
}

func TestPeerToPeerStatus_Disconnected(t *testing.T) {
	oldHandshake := time.Now().Add(-5 * time.Minute)

	p := &wgtypes.Peer{
		PublicKey:          makeTestKey(31),
		LastHandshakeTime: oldHandshake,
	}

	ps := PeerToPeerStatus(p)
	assert.False(t, ps.Connected)
	assert.Equal(t, "", ps.Endpoint)
}

func TestPeerToPeerStatus_NeverHandshake(t *testing.T) {
	p := &wgtypes.Peer{
		PublicKey: makeTestKey(32),
	}

	ps := PeerToPeerStatus(p)
	assert.False(t, ps.Connected)
}

// ---------------------------------------------------------------------------
// Tests: NetlinkClient with mock (AddPeer, RemovePeer, GetInterfaceStatus,
// GetPeerStatus, ListPeers)
// ---------------------------------------------------------------------------

func TestNetlinkClient_AddPeer(t *testing.T) {
	mock := newMockWgctrlClient()
	client := &NetlinkClient{wg: mock}

	pubKeyB64 := makeTestKeyBase64(40)

	err := client.AddPeer("wg0", vpn.PeerConfig{
		PublicKey:           pubKeyB64,
		Endpoint:            "10.0.0.1:51820",
		PersistentKeepalive: 25,
		AllowedIPs:          []string{"10.0.0.0/24"},
	})
	require.NoError(t, err)

	assert.Equal(t, "wg0", mock.configuredDev)
	require.NotNil(t, mock.configuredCfg)
	require.Len(t, mock.configuredCfg.Peers, 1)
	assert.Equal(t, pubKeyB64, mock.configuredCfg.Peers[0].PublicKey.String())
	assert.False(t, mock.configuredCfg.Peers[0].Remove)
}

func TestNetlinkClient_RemovePeer(t *testing.T) {
	mock := newMockWgctrlClient()
	client := &NetlinkClient{wg: mock}

	pubKeyB64 := makeTestKeyBase64(41)

	err := client.RemovePeer("wg0", pubKeyB64)
	require.NoError(t, err)

	require.NotNil(t, mock.configuredCfg)
	require.Len(t, mock.configuredCfg.Peers, 1)
	assert.True(t, mock.configuredCfg.Peers[0].Remove)
}

func TestNetlinkClient_GetInterfaceStatus(t *testing.T) {
	mock := newMockWgctrlClient()
	mock.devices["wg0"] = &wgtypes.Device{
		Name:      "wg0",
		PublicKey: makeTestKey(42),
		Peers: []wgtypes.Peer{
			{
				PublicKey:          makeTestKey(43),
				Endpoint:          &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 51820},
				LastHandshakeTime: time.Now(),
				ReceiveBytes:      100,
				TransmitBytes:     200,
			},
		},
	}

	client := &NetlinkClient{wg: mock}
	status, err := client.GetInterfaceStatus("wg0")
	require.NoError(t, err)

	assert.Equal(t, "Running", status.Phase)
	assert.Equal(t, 1, status.ConnectedPeers)
	assert.Equal(t, makeTestKey(42).String(), status.PublicKey)
}

func TestNetlinkClient_GetInterfaceStatus_NotFound(t *testing.T) {
	mock := newMockWgctrlClient()
	client := &NetlinkClient{wg: mock}

	_, err := client.GetInterfaceStatus("wg99")
	assert.Error(t, err)
}

func TestNetlinkClient_GetPeerStatus(t *testing.T) {
	peerKey := makeTestKey(50)
	mock := newMockWgctrlClient()
	mock.devices["wg0"] = &wgtypes.Device{
		Name: "wg0",
		Peers: []wgtypes.Peer{
			{
				PublicKey:          peerKey,
				Endpoint:          &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 51820},
				LastHandshakeTime: time.Now().Add(-5 * time.Second),
				ReceiveBytes:      1000,
				TransmitBytes:     2000,
			},
		},
	}

	client := &NetlinkClient{wg: mock}
	ps, err := client.GetPeerStatus("wg0", peerKey.String())
	require.NoError(t, err)

	assert.Equal(t, peerKey.String(), ps.PublicKey)
	assert.True(t, ps.Connected)
	assert.Equal(t, "1.2.3.4:51820", ps.Endpoint)
}

func TestNetlinkClient_GetPeerStatus_NotFound(t *testing.T) {
	otherKey := makeTestKey(51)
	searchKey := makeTestKey(52)

	mock := newMockWgctrlClient()
	mock.devices["wg0"] = &wgtypes.Device{
		Name: "wg0",
		Peers: []wgtypes.Peer{
			{PublicKey: otherKey},
		},
	}

	client := &NetlinkClient{wg: mock}
	_, err := client.GetPeerStatus("wg0", searchKey.String())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestNetlinkClient_ListPeers(t *testing.T) {
	mock := newMockWgctrlClient()
	mock.devices["wg0"] = &wgtypes.Device{
		Name: "wg0",
		Peers: []wgtypes.Peer{
			{
				PublicKey:          makeTestKey(60),
				Endpoint:          &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 51820},
				LastHandshakeTime: time.Now(),
				ReceiveBytes:      100,
				TransmitBytes:     200,
			},
			{
				PublicKey:          makeTestKey(61),
				Endpoint:          &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 51821},
				LastHandshakeTime: time.Now().Add(-10 * time.Minute),
				ReceiveBytes:      300,
				TransmitBytes:     400,
			},
		},
	}

	client := &NetlinkClient{wg: mock}
	peers, err := client.ListPeers("wg0")
	require.NoError(t, err)

	require.Len(t, peers, 2)
	assert.Equal(t, makeTestKey(60).String(), peers[0].PublicKey)
	assert.True(t, peers[0].Connected)
	assert.Equal(t, makeTestKey(61).String(), peers[1].PublicKey)
	assert.False(t, peers[1].Connected)
}

func TestNetlinkClient_ListPeers_DeviceNotFound(t *testing.T) {
	mock := newMockWgctrlClient()
	client := &NetlinkClient{wg: mock}

	_, err := client.ListPeers("wg99")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Tests: helper utilities
// ---------------------------------------------------------------------------

func TestAllowedIPsToStrings(t *testing.T) {
	_, net1, _ := net.ParseCIDR("10.0.0.0/24")
	_, net2, _ := net.ParseCIDR("fd00::/64")

	result := AllowedIPsToStrings([]net.IPNet{*net1, *net2})
	assert.Equal(t, []string{"10.0.0.0/24", "fd00::/64"}, result)
}

func TestAllowedIPsToStrings_Empty(t *testing.T) {
	result := AllowedIPsToStrings(nil)
	assert.Empty(t, result)
}

func TestMakeTestKey_Deterministic(t *testing.T) {
	k1 := makeTestKey(1)
	k2 := makeTestKey(1)
	k3 := makeTestKey(2)

	assert.Equal(t, k1, k2)
	assert.NotEqual(t, k1, k3)
}

func TestMakeTestKeyBase64_Roundtrip(t *testing.T) {
	b64 := makeTestKeyBase64(7)
	key, err := wgtypes.ParseKey(b64)
	require.NoError(t, err)
	assert.Equal(t, makeTestKey(7), key)
}
