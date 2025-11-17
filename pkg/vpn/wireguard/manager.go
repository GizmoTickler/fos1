package wireguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/vpn"
)

// Manager implements the vpn.WireGuardManager interface
type Manager struct {
	configDir    string
	client       vpn.WireGuardClient
	vpns         map[string]*vpn.WireGuardVPN
	mutex        sync.RWMutex
}

// Config holds manager configuration
type Config struct {
	ConfigDir    string
	WGBinary     string
}

// NewManager creates a new WireGuard manager
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		config = &Config{
			ConfigDir: "/etc/wireguard",
			WGBinary:  "wg",
		}
	}

	// Ensure the config directory exists
	if err := os.MkdirAll(config.ConfigDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create the client
	client, err := NewClient(&ClientConfig{
		WGBinary: config.WGBinary,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard client: %w", err)
	}

	return &Manager{
		configDir: config.ConfigDir,
		client:    client,
		vpns:      make(map[string]*vpn.WireGuardVPN),
	}, nil
}

// CreateVPN creates a new WireGuard VPN
func (m *Manager) CreateVPN(vpn *vpn.WireGuardVPN) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if vpn == nil {
		return fmt.Errorf("VPN configuration is nil")
	}

	if vpn.Name == "" {
		return fmt.Errorf("VPN name is required")
	}

	// Check if the VPN already exists
	if _, exists := m.vpns[vpn.Name]; exists {
		return fmt.Errorf("VPN %s already exists", vpn.Name)
	}

	// Create the interface
	if err := m.client.CreateInterface(vpn.Interface.Name, vpn.Interface); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Add peers
	for _, peer := range vpn.Peers {
		if err := m.client.AddPeer(vpn.Interface.Name, peer); err != nil {
			klog.Errorf("Failed to add peer %s to interface %s: %v", peer.PublicKey, vpn.Interface.Name, err)
			// Continue with other peers
		}
	}

	// Save the configuration
	if err := m.saveConfig(vpn); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	// Store the VPN in memory
	m.vpns[vpn.Name] = vpn

	klog.Infof("Created WireGuard VPN %s", vpn.Name)
	return nil
}

// UpdateVPN updates an existing WireGuard VPN
func (m *Manager) UpdateVPN(vpn *vpn.WireGuardVPN) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if vpn == nil {
		return fmt.Errorf("VPN configuration is nil")
	}

	if vpn.Name == "" {
		return fmt.Errorf("VPN name is required")
	}

	// Check if the VPN exists
	existingVPN, exists := m.vpns[vpn.Name]
	if !exists {
		return fmt.Errorf("VPN %s does not exist", vpn.Name)
	}

	// If the interface name has changed, we need to recreate the interface
	if existingVPN.Interface.Name != vpn.Interface.Name {
		// Delete the old interface
		if err := m.client.DeleteInterface(existingVPN.Interface.Name); err != nil {
			return fmt.Errorf("failed to delete old interface: %w", err)
		}

		// Create the new interface
		if err := m.client.CreateInterface(vpn.Interface.Name, vpn.Interface); err != nil {
			return fmt.Errorf("failed to create new interface: %w", err)
		}
	} else {
		// Update the interface
		if err := m.client.CreateInterface(vpn.Interface.Name, vpn.Interface); err != nil {
			return fmt.Errorf("failed to update interface: %w", err)
		}
	}

	// Get the current peers
	status, err := m.client.GetInterfaceStatus(vpn.Interface.Name)
	if err != nil {
		return fmt.Errorf("failed to get interface status: %w", err)
	}

	// Track existing peers
	existingPeers := make(map[string]bool)
	for _, condition := range status.Conditions {
		if condition.Type == "Peer" {
			existingPeers[condition.Reason] = true
		}
	}

	// Add or update peers
	for _, peer := range vpn.Peers {
		if err := m.client.AddPeer(vpn.Interface.Name, peer); err != nil {
			klog.Errorf("Failed to add/update peer %s to interface %s: %v", peer.PublicKey, vpn.Interface.Name, err)
			// Continue with other peers
		}
		delete(existingPeers, peer.PublicKey)
	}

	// Remove peers that no longer exist
	for publicKey := range existingPeers {
		if err := m.client.RemovePeer(vpn.Interface.Name, publicKey); err != nil {
			klog.Errorf("Failed to remove peer %s from interface %s: %v", publicKey, vpn.Interface.Name, err)
			// Continue with other peers
		}
	}

	// Save the configuration
	if err := m.saveConfig(vpn); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	// Update the VPN in memory
	m.vpns[vpn.Name] = vpn

	klog.Infof("Updated WireGuard VPN %s", vpn.Name)
	return nil
}

// DeleteVPN deletes a WireGuard VPN
func (m *Manager) DeleteVPN(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if name == "" {
		return fmt.Errorf("VPN name is required")
	}

	// Check if the VPN exists
	vpn, exists := m.vpns[name]
	if !exists {
		return fmt.Errorf("VPN %s does not exist", name)
	}

	// Delete the interface
	if err := m.client.DeleteInterface(vpn.Interface.Name); err != nil {
		return fmt.Errorf("failed to delete interface: %w", err)
	}

	// Delete the configuration file
	configFile := filepath.Join(m.configDir, vpn.Interface.Name+".conf")
	if err := os.Remove(configFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete configuration file: %w", err)
	}

	// Remove the VPN from memory
	delete(m.vpns, name)

	klog.Infof("Deleted WireGuard VPN %s", name)
	return nil
}

// GetVPNStatus gets the status of a WireGuard VPN
func (m *Manager) GetVPNStatus(name string) (*vpn.Status, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if name == "" {
		return nil, fmt.Errorf("VPN name is required")
	}

	// Check if the VPN exists
	vpn, exists := m.vpns[name]
	if !exists {
		return nil, fmt.Errorf("VPN %s does not exist", name)
	}

	// Get the interface status
	status, err := m.client.GetInterfaceStatus(vpn.Interface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface status: %w", err)
	}

	return status, nil
}

// GetPeerStatus gets the status of a WireGuard peer
func (m *Manager) GetPeerStatus(vpnName, peerPublicKey string) (*vpn.PeerStatus, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if vpnName == "" {
		return nil, fmt.Errorf("VPN name is required")
	}

	if peerPublicKey == "" {
		return nil, fmt.Errorf("peer public key is required")
	}

	// Check if the VPN exists
	vpn, exists := m.vpns[vpnName]
	if !exists {
		return nil, fmt.Errorf("VPN %s does not exist", vpnName)
	}

	// Get the peer status
	status, err := m.client.GetPeerStatus(vpn.Interface.Name, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer status: %w", err)
	}

	return status, nil
}

// RotateKeys rotates the keys for a WireGuard VPN
func (m *Manager) RotateKeys(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if name == "" {
		return fmt.Errorf("VPN name is required")
	}

	// Check if the VPN exists
	vpn, exists := m.vpns[name]
	if !exists {
		return fmt.Errorf("VPN %s does not exist", name)
	}

	// Generate a new private key
	privateKey, err := generatePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Update the VPN configuration
	vpn.Interface.PrivateKey = privateKey

	// Update the interface
	if err := m.client.CreateInterface(vpn.Interface.Name, vpn.Interface); err != nil {
		return fmt.Errorf("failed to update interface: %w", err)
	}

	// Save the configuration
	if err := m.saveConfig(vpn); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	klog.Infof("Rotated keys for WireGuard VPN %s", name)
	return nil
}

// saveConfig saves the WireGuard configuration to a file
func (m *Manager) saveConfig(vpn *vpn.WireGuardVPN) error {
	configFile := filepath.Join(m.configDir, vpn.Interface.Name+".conf")

	// Create the configuration
	var config strings.Builder

	// Interface section
	config.WriteString("[Interface]\n")
	config.WriteString(fmt.Sprintf("PrivateKey = %s\n", vpn.Interface.PrivateKey))
	config.WriteString(fmt.Sprintf("ListenPort = %d\n", vpn.Interface.ListenPort))

	for _, address := range vpn.Interface.Addresses {
		config.WriteString(fmt.Sprintf("Address = %s\n", address))
	}

	if vpn.Interface.MTU > 0 {
		config.WriteString(fmt.Sprintf("MTU = %d\n", vpn.Interface.MTU))
	}

	if vpn.Interface.Table > 0 {
		config.WriteString(fmt.Sprintf("Table = %d\n", vpn.Interface.Table))
	}

	for _, dns := range vpn.Interface.DNS {
		config.WriteString(fmt.Sprintf("DNS = %s\n", dns))
	}

	for _, cmd := range vpn.Interface.PreUp {
		config.WriteString(fmt.Sprintf("PreUp = %s\n", cmd))
	}

	for _, cmd := range vpn.Interface.PostUp {
		config.WriteString(fmt.Sprintf("PostUp = %s\n", cmd))
	}

	for _, cmd := range vpn.Interface.PreDown {
		config.WriteString(fmt.Sprintf("PreDown = %s\n", cmd))
	}

	for _, cmd := range vpn.Interface.PostDown {
		config.WriteString(fmt.Sprintf("PostDown = %s\n", cmd))
	}

	// Peer sections
	for _, peer := range vpn.Peers {
		config.WriteString("\n[Peer]\n")
		config.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))

		if peer.PresharedKey != "" {
			config.WriteString(fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey))
		}

		if peer.Endpoint != "" {
			config.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}

		if peer.PersistentKeepalive > 0 {
			config.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.PersistentKeepalive))
		}

		for _, ip := range peer.AllowedIPs {
			config.WriteString(fmt.Sprintf("AllowedIPs = %s\n", ip))
		}
	}

	// Write the configuration to the file
	if err := os.WriteFile(configFile, []byte(config.String()), 0600); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	return nil
}

// generatePrivateKey generates a new WireGuard private key
func generatePrivateKey() (string, error) {
	cmd := exec.Command("wg", "genkey")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}
