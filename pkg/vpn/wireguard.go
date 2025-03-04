// Package vpn provides VPN functionality for the router/firewall system
package vpn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// WireGuardConfig defines the configuration for a WireGuard tunnel
type WireGuardConfig struct {
	// Interface configuration
	InterfaceName string
	PrivateKey    string
	ListenPort    int
	Address       string
	
	// Peers configuration
	Peers []WireGuardPeer
	
	// Post up/down scripts
	PostUp   []string
	PostDown []string
}

// WireGuardPeer represents a WireGuard peer configuration
type WireGuardPeer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

// WireGuardService manages WireGuard VPN tunnels
type WireGuardService struct {
	configs map[string]*WireGuardConfig
}

// NewWireGuardService creates a new instance of the WireGuard service
func NewWireGuardService() *WireGuardService {
	return &WireGuardService{
		configs: make(map[string]*WireGuardConfig),
	}
}

// AddInterface adds a new WireGuard interface configuration
func (w *WireGuardService) AddInterface(config *WireGuardConfig) error {
	if config == nil {
		return errors.New("config cannot be nil")
	}
	
	if config.InterfaceName == "" {
		return errors.New("interface name is required")
	}
	
	if config.PrivateKey == "" {
		return errors.New("private key is required")
	}
	
	if config.Address == "" {
		return errors.New("address is required")
	}
	
	w.configs[config.InterfaceName] = config
	return nil
}

// Start initializes and configures all WireGuard interfaces
func (w *WireGuardService) Start(ctx context.Context) error {
	for name, config := range w.configs {
		if err := w.createInterface(name); err != nil {
			return fmt.Errorf("failed to create interface %s: %w", name, err)
		}
		
		if err := w.configureInterface(config); err != nil {
			return fmt.Errorf("failed to configure interface %s: %w", name, err)
		}
	}
	
	return nil
}

// Stop terminates all WireGuard interfaces
func (w *WireGuardService) Stop(ctx context.Context) error {
	for name, config := range w.configs {
		if err := w.executePostDownCommands(config); err != nil {
			return fmt.Errorf("failed to execute post-down commands for %s: %w", name, err)
		}
		
		if err := w.deleteInterface(name); err != nil {
			return fmt.Errorf("failed to delete interface %s: %w", name, err)
		}
	}
	
	return nil
}

// GenerateConfig generates a WireGuard configuration file for the given interface
func (w *WireGuardService) GenerateConfig(name string) (string, error) {
	config, ok := w.configs[name]
	if !ok {
		return "", fmt.Errorf("interface %s not found", name)
	}
	
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", config.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", config.Address))
	
	if config.ListenPort > 0 {
		sb.WriteString(fmt.Sprintf("ListenPort = %d\n", config.ListenPort))
	}
	
	for _, cmd := range config.PostUp {
		sb.WriteString(fmt.Sprintf("PostUp = %s\n", cmd))
	}
	
	for _, cmd := range config.PostDown {
		sb.WriteString(fmt.Sprintf("PostDown = %s\n", cmd))
	}
	
	sb.WriteString("\n")
	
	for _, peer := range config.Peers {
		sb.WriteString("[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
		
		if peer.PresharedKey != "" {
			sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey))
		}
		
		if peer.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}
		
		if len(peer.AllowedIPs) > 0 {
			sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", ")))
		}
		
		if peer.PersistentKeepalive > 0 {
			sb.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.PersistentKeepalive))
		}
		
		sb.WriteString("\n")
	}
	
	return sb.String(), nil
}

// createInterface creates a new WireGuard interface
func (w *WireGuardService) createInterface(name string) error {
	cmd := exec.Command("ip", "link", "add", name, "type", "wireguard")
	return cmd.Run()
}

// deleteInterface removes a WireGuard interface
func (w *WireGuardService) deleteInterface(name string) error {
	cmd := exec.Command("ip", "link", "del", name)
	return cmd.Run()
}

// configureInterface applies configuration to a WireGuard interface
func (w *WireGuardService) configureInterface(config *WireGuardConfig) error {
	// Write private key to temporary file
	privateKeyFile, err := os.CreateTemp("", "wg-key-")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(privateKeyFile.Name())
	
	if _, err := privateKeyFile.WriteString(config.PrivateKey); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	privateKeyFile.Close()
	
	// Set private key
	cmd := exec.Command("wg", "set", config.InterfaceName, "private-key", privateKeyFile.Name())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set private key: %w", err)
	}
	
	// Set listen port if specified
	if config.ListenPort > 0 {
		cmd = exec.Command("wg", "set", config.InterfaceName, "listen-port", fmt.Sprintf("%d", config.ListenPort))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set listen port: %w", err)
		}
	}
	
	// Set interface address
	cmd = exec.Command("ip", "address", "add", "dev", config.InterfaceName, config.Address)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set address: %w", err)
	}
	
	// Set interface up
	cmd = exec.Command("ip", "link", "set", "up", "dev", config.InterfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set interface up: %w", err)
	}
	
	// Add peers
	for _, peer := range config.Peers {
		args := []string{"set", config.InterfaceName, "peer", peer.PublicKey}
		
		if peer.PresharedKey != "" {
			// Write preshared key to temporary file
			presharedKeyFile, err := os.CreateTemp("", "wg-psk-")
			if err != nil {
				return fmt.Errorf("failed to create temp file: %w", err)
			}
			defer os.Remove(presharedKeyFile.Name())
			
			if _, err := presharedKeyFile.WriteString(peer.PresharedKey); err != nil {
				return fmt.Errorf("failed to write preshared key: %w", err)
			}
			presharedKeyFile.Close()
			
			args = append(args, "preshared-key", presharedKeyFile.Name())
		}
		
		if peer.Endpoint != "" {
			args = append(args, "endpoint", peer.Endpoint)
		}
		
		if len(peer.AllowedIPs) > 0 {
			args = append(args, "allowed-ips", strings.Join(peer.AllowedIPs, ","))
		}
		
		if peer.PersistentKeepalive > 0 {
			args = append(args, "persistent-keepalive", fmt.Sprintf("%d", peer.PersistentKeepalive))
		}
		
		cmd = exec.Command("wg", args...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to configure peer: %w", err)
		}
	}
	
	// Execute post-up commands
	if err := w.executePostUpCommands(config); err != nil {
		return fmt.Errorf("failed to execute post-up commands: %w", err)
	}
	
	return nil
}

// executePostUpCommands runs the post-up commands for an interface
func (w *WireGuardService) executePostUpCommands(config *WireGuardConfig) error {
	for _, cmdStr := range config.PostUp {
		parts := strings.Split(cmdStr, " ")
		cmd := exec.Command(parts[0], parts[1:]...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute post-up command '%s': %w", cmdStr, err)
		}
	}
	return nil
}

// executePostDownCommands runs the post-down commands for an interface
func (w *WireGuardService) executePostDownCommands(config *WireGuardConfig) error {
	for _, cmdStr := range config.PostDown {
		parts := strings.Split(cmdStr, " ")
		cmd := exec.Command(parts[0], parts[1:]...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute post-down command '%s': %w", cmdStr, err)
		}
	}
	return nil
}

// GenerateKeys generates a new WireGuard key pair
func GenerateKeys() (privateKey, publicKey string, err error) {
	// Generate private key
	privateKeyCmd := exec.Command("wg", "genkey")
	privateKeyBytes, err := privateKeyCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}
	privateKey = strings.TrimSpace(string(privateKeyBytes))
	
	// Derive public key
	publicKeyCmd := exec.Command("wg", "pubkey")
	publicKeyCmd.Stdin = strings.NewReader(privateKey)
	publicKeyBytes, err := publicKeyCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate public key: %w", err)
	}
	publicKey = strings.TrimSpace(string(publicKeyBytes))
	
	return privateKey, publicKey, nil
}

// GeneratePresharedKey generates a new WireGuard preshared key
func GeneratePresharedKey() (string, error) {
	cmd := exec.Command("wg", "genpsk")
	pskBytes, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate preshared key: %w", err)
	}
	return strings.TrimSpace(string(pskBytes)), nil
}