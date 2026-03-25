//go:build linux

package wireguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/vpn"
)

// WgctrlClient is an interface wrapping the subset of wgctrl.Client methods
// we use, enabling test mocks.
type WgctrlClient interface {
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Close() error
}

// NetlinkClient implements vpn.WireGuardClient using netlink for link
// management and wgctrl for WireGuard-specific configuration.
type NetlinkClient struct {
	wg WgctrlClient
}

// NetlinkClientConfig holds configuration for the NetlinkClient.
type NetlinkClientConfig struct {
	// WgctrlClient allows injecting a custom wgctrl client (useful for testing).
	// If nil, a real wgctrl.Client is created.
	WgctrlClient WgctrlClient
}

// NewNetlinkClient creates a new NetlinkClient.
func NewNetlinkClient(config *NetlinkClientConfig) (*NetlinkClient, error) {
	if config == nil {
		config = &NetlinkClientConfig{}
	}

	var wg WgctrlClient
	if config.WgctrlClient != nil {
		wg = config.WgctrlClient
	} else {
		c, err := wgctrl.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create wgctrl client: %w", err)
		}
		wg = c
	}

	return &NetlinkClient{wg: wg}, nil
}

// Close releases resources held by the underlying wgctrl client.
func (c *NetlinkClient) Close() error {
	return c.wg.Close()
}

// CreateInterface creates a WireGuard interface via netlink and configures it
// with wgctrl.
func (c *NetlinkClient) CreateInterface(name string, config vpn.InterfaceConfig) error {
	// Create the WireGuard link via netlink.
	la := netlink.NewLinkAttrs()
	la.Name = name
	if config.MTU > 0 {
		la.MTU = config.MTU
	}

	wgLink := &netlink.Wireguard{LinkAttrs: la}
	if err := netlink.LinkAdd(wgLink); err != nil {
		// If it already exists, continue to configure it.
		if !os.IsExist(err) {
			return fmt.Errorf("netlink: failed to add wireguard link %s: %w", name, err)
		}
		klog.V(2).Infof("Interface %s already exists, reconfiguring", name)
	}

	// Build wgtypes.Config from project types.
	wgCfg, err := buildWgConfig(config)
	if err != nil {
		return fmt.Errorf("failed to build wgctrl config: %w", err)
	}

	if err := c.wg.ConfigureDevice(name, wgCfg); err != nil {
		return fmt.Errorf("wgctrl: failed to configure device %s: %w", name, err)
	}

	// Assign IP addresses.
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("netlink: failed to find link %s: %w", name, err)
	}

	for _, addrStr := range config.Addresses {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			return fmt.Errorf("netlink: failed to parse address %s: %w", addrStr, err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil && !os.IsExist(err) {
			return fmt.Errorf("netlink: failed to add address %s to %s: %w", addrStr, name, err)
		}
	}

	// Bring the interface up.
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("netlink: failed to bring up %s: %w", name, err)
	}

	klog.Infof("Created WireGuard interface %s via netlink/wgctrl", name)
	return nil
}

// DeleteInterface removes a WireGuard interface via netlink.
func (c *NetlinkClient) DeleteInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		// Interface does not exist; treat as success.
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("netlink: failed to find link %s: %w", name, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("netlink: failed to delete link %s: %w", name, err)
	}

	klog.Infof("Deleted WireGuard interface %s via netlink", name)
	return nil
}

// AddPeer adds or updates a peer on a WireGuard interface using wgctrl.
func (c *NetlinkClient) AddPeer(interfaceName string, peer vpn.PeerConfig) error {
	peerCfg, err := buildPeerConfig(peer, false)
	if err != nil {
		return fmt.Errorf("failed to build peer config: %w", err)
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}

	if err := c.wg.ConfigureDevice(interfaceName, cfg); err != nil {
		return fmt.Errorf("wgctrl: failed to add peer to %s: %w", interfaceName, err)
	}

	klog.Infof("Added peer %s to interface %s via wgctrl", peer.PublicKey, interfaceName)
	return nil
}

// RemovePeer removes a peer from a WireGuard interface using wgctrl.
func (c *NetlinkClient) RemovePeer(interfaceName, publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: key,
				Remove:   true,
			},
		},
	}

	if err := c.wg.ConfigureDevice(interfaceName, cfg); err != nil {
		return fmt.Errorf("wgctrl: failed to remove peer from %s: %w", interfaceName, err)
	}

	klog.Infof("Removed peer %s from interface %s via wgctrl", publicKey, interfaceName)
	return nil
}

// GetInterfaceStatus retrieves the status of a WireGuard interface from wgctrl
// and converts it to the project's vpn.Status type.
func (c *NetlinkClient) GetInterfaceStatus(name string) (*vpn.Status, error) {
	dev, err := c.wg.Device(name)
	if err != nil {
		return nil, fmt.Errorf("wgctrl: failed to get device %s: %w", name, err)
	}

	return DeviceToStatus(dev), nil
}

// GetPeerStatus retrieves the status of a specific peer on a WireGuard
// interface.
func (c *NetlinkClient) GetPeerStatus(interfaceName, publicKey string) (*vpn.PeerStatus, error) {
	dev, err := c.wg.Device(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("wgctrl: failed to get device %s: %w", interfaceName, err)
	}

	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	for _, p := range dev.Peers {
		if p.PublicKey == key {
			return PeerToPeerStatus(&p), nil
		}
	}

	return nil, fmt.Errorf("peer %s not found on interface %s", publicKey, interfaceName)
}

// ListPeers returns the list of peers configured on a WireGuard interface.
func (c *NetlinkClient) ListPeers(interfaceName string) ([]vpn.PeerStatus, error) {
	dev, err := c.wg.Device(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("wgctrl: failed to get device %s: %w", interfaceName, err)
	}

	peers := make([]vpn.PeerStatus, 0, len(dev.Peers))
	for i := range dev.Peers {
		peers = append(peers, *PeerToPeerStatus(&dev.Peers[i]))
	}

	return peers, nil
}

// ---------------------------------------------------------------------------
// Type conversion helpers (exported for testing)
// ---------------------------------------------------------------------------

// DeviceToStatus converts a wgtypes.Device to the project's vpn.Status.
func DeviceToStatus(dev *wgtypes.Device) *vpn.Status {
	status := &vpn.Status{
		Phase:          "Running",
		PublicKey:      dev.PublicKey.String(),
		ConnectedPeers: len(dev.Peers),
		Conditions:     make([]vpn.Condition, 0, len(dev.Peers)),
	}

	var latestHandshake time.Time
	var totalRx, totalTx int64

	for _, p := range dev.Peers {
		endpoint := ""
		if p.Endpoint != nil {
			endpoint = p.Endpoint.String()
		}

		condition := vpn.Condition{
			Type:               "Peer",
			Status:             "True",
			Reason:             p.PublicKey.String(),
			Message:            fmt.Sprintf("Endpoint: %s", endpoint),
			LastTransitionTime: p.LastHandshakeTime,
		}
		status.Conditions = append(status.Conditions, condition)

		if p.LastHandshakeTime.After(latestHandshake) {
			latestHandshake = p.LastHandshakeTime
		}

		totalRx += p.ReceiveBytes
		totalTx += p.TransmitBytes
	}

	status.LastHandshake = latestHandshake
	status.TransferRx = totalRx
	status.TransferTx = totalTx

	return status
}

// PeerToPeerStatus converts a wgtypes.Peer to the project's vpn.PeerStatus.
func PeerToPeerStatus(p *wgtypes.Peer) *vpn.PeerStatus {
	ps := &vpn.PeerStatus{
		PublicKey:     p.PublicKey.String(),
		LastHandshake: p.LastHandshakeTime,
		TransferRx:    p.ReceiveBytes,
		TransferTx:    p.TransmitBytes,
		Connected:     !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < 150*time.Second,
	}

	if p.Endpoint != nil {
		ps.Endpoint = p.Endpoint.String()
	}

	return ps
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// buildWgConfig translates a vpn.InterfaceConfig to a wgtypes.Config for use
// with wgctrl.ConfigureDevice.
func buildWgConfig(config vpn.InterfaceConfig) (wgtypes.Config, error) {
	cfg := wgtypes.Config{}

	if config.PrivateKey != "" {
		key, err := wgtypes.ParseKey(config.PrivateKey)
		if err != nil {
			return cfg, fmt.Errorf("failed to parse private key: %w", err)
		}
		cfg.PrivateKey = &key
	}

	if config.ListenPort > 0 {
		cfg.ListenPort = &config.ListenPort
	}

	if config.Firewall {
		fwMark := 1
		cfg.FirewallMark = &fwMark
	}

	return cfg, nil
}

// buildPeerConfig translates a vpn.PeerConfig to a wgtypes.PeerConfig.
func buildPeerConfig(peer vpn.PeerConfig, remove bool) (wgtypes.PeerConfig, error) {
	pubKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("failed to parse public key: %w", err)
	}

	pc := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		Remove:            remove,
		ReplaceAllowedIPs: true,
	}

	if peer.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(peer.PresharedKey)
		if err != nil {
			return pc, fmt.Errorf("failed to parse preshared key: %w", err)
		}
		pc.PresharedKey = &psk
	}

	if peer.Endpoint != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", peer.Endpoint)
		if err != nil {
			return pc, fmt.Errorf("failed to resolve endpoint %s: %w", peer.Endpoint, err)
		}
		pc.Endpoint = udpAddr
	}

	if peer.PersistentKeepalive > 0 {
		d := time.Duration(peer.PersistentKeepalive) * time.Second
		pc.PersistentKeepaliveInterval = &d
	}

	for _, ipStr := range peer.AllowedIPs {
		// Ensure CIDR notation.
		if !strings.Contains(ipStr, "/") {
			if strings.Contains(ipStr, ":") {
				ipStr += "/128"
			} else {
				ipStr += "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return pc, fmt.Errorf("failed to parse allowed IP %s: %w", ipStr, err)
		}
		pc.AllowedIPs = append(pc.AllowedIPs, *ipNet)
	}

	return pc, nil
}

// GenerateBase64Key generates a base64-encoded WireGuard key (for testing or
// key generation utilities).
func GenerateBase64Key() (string, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}
	return key.String(), nil
}

// AllowedIPsToStrings converts a slice of net.IPNet to string representations.
func AllowedIPsToStrings(nets []net.IPNet) []string {
	result := make([]string, 0, len(nets))
	for _, n := range nets {
		result = append(result, n.String())
	}
	return result
}

// Ensure NetlinkClient implements vpn.WireGuardClient at compile time.
var _ vpn.WireGuardClient = (*NetlinkClient)(nil)

// mustParseKey is a test-only helper; panics on error. Exported so tests in
// this package can use it.
func mustParseKey(s string) wgtypes.Key {
	k, err := wgtypes.ParseKey(s)
	if err != nil {
		panic(fmt.Sprintf("mustParseKey: %v", err))
	}
	return k
}

// makeTestKey creates a deterministic wgtypes.Key from an integer seed.
// Useful for building test fixtures without calling the real crypto RNG.
func makeTestKey(seed byte) wgtypes.Key {
	var raw [wgtypes.KeyLen]byte
	for i := range raw {
		raw[i] = seed
	}
	return wgtypes.Key(raw)
}

// makeTestKeyBase64 returns the base64 representation of makeTestKey(seed).
func makeTestKeyBase64(seed byte) string {
	k := makeTestKey(seed)
	return base64.StdEncoding.EncodeToString(k[:])
}

// parsePort is a small helper that parses a port string from a host:port.
func parsePort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(portStr)
	return port
}
