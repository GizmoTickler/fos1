package wireguard

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/vpn"
)

// Client implements the vpn.WireGuardClient interface
type Client struct {
	wgBinary string
}

// ClientConfig holds client configuration
type ClientConfig struct {
	WGBinary string
}

// NewClient creates a new WireGuard client
func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil {
		config = &ClientConfig{
			WGBinary: "wg",
		}
	}

	// Check if the WireGuard binary exists
	if _, err := exec.LookPath(config.WGBinary); err != nil {
		return nil, fmt.Errorf("WireGuard binary not found: %w", err)
	}

	return &Client{
		wgBinary: config.WGBinary,
	}, nil
}

// CreateInterface creates a WireGuard interface
func (c *Client) CreateInterface(name string, config vpn.InterfaceConfig) error {
	// Check if the interface already exists
	if c.interfaceExists(name) {
		// Interface exists, update it
		return c.updateInterface(name, config)
	}

	// Create the interface
	cmd := exec.Command("ip", "link", "add", name, "type", "wireguard")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Configure the interface
	if err := c.configureInterface(name, config); err != nil {
		// Clean up on failure
		c.DeleteInterface(name)
		return fmt.Errorf("failed to configure interface: %w", err)
	}

	klog.Infof("Created WireGuard interface %s", name)
	return nil
}

// DeleteInterface deletes a WireGuard interface
func (c *Client) DeleteInterface(name string) error {
	// Check if the interface exists
	if !c.interfaceExists(name) {
		return nil
	}

	// Delete the interface
	cmd := exec.Command("ip", "link", "del", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete interface: %w", err)
	}

	klog.Infof("Deleted WireGuard interface %s", name)
	return nil
}

// AddPeer adds a peer to a WireGuard interface
func (c *Client) AddPeer(interfaceName string, peer vpn.PeerConfig) error {
	// Check if the interface exists
	if !c.interfaceExists(interfaceName) {
		return fmt.Errorf("interface %s does not exist", interfaceName)
	}

	// Build the command
	args := []string{"set", interfaceName, "peer", peer.PublicKey}

	if peer.PresharedKey != "" {
		args = append(args, "preshared-key", peer.PresharedKey)
	}

	if peer.Endpoint != "" {
		args = append(args, "endpoint", peer.Endpoint)
	}

	if peer.PersistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(peer.PersistentKeepalive))
	}

	if len(peer.AllowedIPs) > 0 {
		args = append(args, "allowed-ips", strings.Join(peer.AllowedIPs, ","))
	}

	// Execute the command
	cmd := exec.Command(c.wgBinary, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}

	klog.Infof("Added peer %s to interface %s", peer.PublicKey, interfaceName)
	return nil
}

// RemovePeer removes a peer from a WireGuard interface
func (c *Client) RemovePeer(interfaceName, publicKey string) error {
	// Check if the interface exists
	if !c.interfaceExists(interfaceName) {
		return fmt.Errorf("interface %s does not exist", interfaceName)
	}

	// Execute the command
	cmd := exec.Command(c.wgBinary, "set", interfaceName, "peer", publicKey, "remove")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}

	klog.Infof("Removed peer %s from interface %s", publicKey, interfaceName)
	return nil
}

// GetInterfaceStatus gets the status of a WireGuard interface
func (c *Client) GetInterfaceStatus(name string) (*vpn.Status, error) {
	// Check if the interface exists
	if !c.interfaceExists(name) {
		return nil, fmt.Errorf("interface %s does not exist", name)
	}

	// Get the interface status
	cmd := exec.Command(c.wgBinary, "show", name)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface status: %w", err)
	}

	// Parse the output
	status := &vpn.Status{
		Phase:          "Running",
		ConnectedPeers: 0,
		Conditions:     []vpn.Condition{},
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if i == 0 && strings.HasPrefix(line, "interface:") {
			// Interface line
			parts := strings.Fields(line)
			if len(parts) >= 4 && parts[2] == "public" && parts[3] == "key:" {
				status.PublicKey = parts[4]
			}
		} else if strings.HasPrefix(line, "peer:") {
			// Peer line
			status.ConnectedPeers++
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				publicKey := parts[1]
				condition := vpn.Condition{
					Type:               "Peer",
					Status:             "True",
					Reason:             publicKey,
					Message:            "Peer is configured",
					LastTransitionTime: time.Now(),
				}
				status.Conditions = append(status.Conditions, condition)
			}
		} else if strings.HasPrefix(line, "  endpoint:") {
			// Endpoint line
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				// Update the last condition
				if len(status.Conditions) > 0 {
					status.Conditions[len(status.Conditions)-1].Message = fmt.Sprintf("Endpoint: %s", parts[1])
				}
			}
		} else if strings.HasPrefix(line, "  latest handshake:") {
			// Handshake line
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				// Parse the handshake time
				handshakeTime, err := parseHandshakeTime(strings.Join(parts[3:], " "))
				if err == nil {
					status.LastHandshake = handshakeTime
					// Update the last condition
					if len(status.Conditions) > 0 {
						status.Conditions[len(status.Conditions)-1].LastTransitionTime = handshakeTime
					}
				}
			}
		} else if strings.HasPrefix(line, "  transfer:") {
			// Transfer line
			parts := strings.Fields(line)
			if len(parts) >= 5 && parts[1] == "received" && parts[3] == "sent" {
				// Parse the transfer amounts
				rx, err := parseTransferAmount(parts[2])
				if err == nil {
					status.TransferRx = rx
				}

				tx, err := parseTransferAmount(parts[4])
				if err == nil {
					status.TransferTx = tx
				}
			}
		}
	}

	return status, nil
}

// GetPeerStatus gets the status of a WireGuard peer
func (c *Client) GetPeerStatus(interfaceName, publicKey string) (*vpn.PeerStatus, error) {
	// Check if the interface exists
	if !c.interfaceExists(interfaceName) {
		return nil, fmt.Errorf("interface %s does not exist", interfaceName)
	}

	// Get the peer status
	cmd := exec.Command(c.wgBinary, "show", interfaceName, "peer", publicKey)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get peer status: %w", err)
	}

	// Parse the output
	status := &vpn.PeerStatus{
		PublicKey: publicKey,
		Connected: false,
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "endpoint:") {
			// Endpoint line
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				status.Endpoint = parts[1]
			}
		} else if strings.HasPrefix(line, "latest handshake:") {
			// Handshake line
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				// Parse the handshake time
				handshakeTime, err := parseHandshakeTime(strings.Join(parts[3:], " "))
				if err == nil {
					status.LastHandshake = handshakeTime
					// Check if the handshake is recent (within 2.5 minutes)
					if time.Since(handshakeTime) < 150*time.Second {
						status.Connected = true
					}
				}
			}
		} else if strings.HasPrefix(line, "transfer:") {
			// Transfer line
			parts := strings.Fields(line)
			if len(parts) >= 5 && parts[1] == "received" && parts[3] == "sent" {
				// Parse the transfer amounts
				rx, err := parseTransferAmount(parts[2])
				if err == nil {
					status.TransferRx = rx
				}

				tx, err := parseTransferAmount(parts[4])
				if err == nil {
					status.TransferTx = tx
				}
			}
		}
	}

	return status, nil
}

// interfaceExists checks if a WireGuard interface exists
func (c *Client) interfaceExists(name string) bool {
	cmd := exec.Command("ip", "link", "show", name)
	return cmd.Run() == nil
}

// configureInterface configures a WireGuard interface
func (c *Client) configureInterface(name string, config vpn.InterfaceConfig) error {
	// Set the private key
	cmd := exec.Command(c.wgBinary, "set", name, "private-key", "/dev/stdin")
	cmd.Stdin = strings.NewReader(config.PrivateKey)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set private key: %w", err)
	}

	// Set the listen port
	if config.ListenPort > 0 {
		cmd = exec.Command(c.wgBinary, "set", name, "listen-port", strconv.Itoa(config.ListenPort))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set listen port: %w", err)
		}
	}

	// Set the MTU
	if config.MTU > 0 {
		cmd = exec.Command("ip", "link", "set", name, "mtu", strconv.Itoa(config.MTU))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	// Set the addresses
	for _, address := range config.Addresses {
		cmd = exec.Command("ip", "addr", "add", address, "dev", name)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set address: %w", err)
		}
	}

	// Bring the interface up
	cmd = exec.Command("ip", "link", "set", name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Run post-up commands
	for _, command := range config.PostUp {
		cmd = exec.Command("sh", "-c", strings.Replace(command, "%i", name, -1))
		if err := cmd.Run(); err != nil {
			klog.Warningf("Failed to run post-up command: %v", err)
		}
	}

	return nil
}

// updateInterface updates a WireGuard interface
func (c *Client) updateInterface(name string, config vpn.InterfaceConfig) error {
	// Set the private key
	cmd := exec.Command(c.wgBinary, "set", name, "private-key", "/dev/stdin")
	cmd.Stdin = strings.NewReader(config.PrivateKey)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set private key: %w", err)
	}

	// Set the listen port
	if config.ListenPort > 0 {
		cmd = exec.Command(c.wgBinary, "set", name, "listen-port", strconv.Itoa(config.ListenPort))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set listen port: %w", err)
		}
	}

	// Set the MTU
	if config.MTU > 0 {
		cmd = exec.Command("ip", "link", "set", name, "mtu", strconv.Itoa(config.MTU))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	// Get current addresses
	cmd = exec.Command("ip", "addr", "show", name)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get current addresses: %w", err)
	}

	// Parse current addresses
	currentAddresses := make(map[string]bool)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") || strings.HasPrefix(line, "inet6 ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentAddresses[parts[1]] = true
			}
		}
	}

	// Add new addresses
	for _, address := range config.Addresses {
		if !currentAddresses[address] {
			cmd = exec.Command("ip", "addr", "add", address, "dev", name)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to add address: %w", err)
			}
		}
		delete(currentAddresses, address)
	}

	// Remove old addresses
	for address := range currentAddresses {
		cmd = exec.Command("ip", "addr", "del", address, "dev", name)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to remove address: %w", err)
		}
	}

	// Run post-up commands
	for _, command := range config.PostUp {
		cmd = exec.Command("sh", "-c", strings.Replace(command, "%i", name, -1))
		if err := cmd.Run(); err != nil {
			klog.Warningf("Failed to run post-up command: %v", err)
		}
	}

	return nil
}

// parseHandshakeTime parses a handshake time string
func parseHandshakeTime(timeStr string) (time.Time, error) {
	// Try to parse the time string
	// Format: "5 seconds ago" or "2 minutes ago" or "1 hour ago" or "2 days ago"
	parts := strings.Fields(timeStr)
	if len(parts) < 3 || parts[len(parts)-1] != "ago" {
		return time.Time{}, fmt.Errorf("invalid time format: %s", timeStr)
	}

	// Parse the number
	number, err := strconv.Atoi(parts[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid number: %s", parts[0])
	}

	// Parse the unit
	unit := parts[1]
	var duration time.Duration
	switch unit {
	case "second", "seconds":
		duration = time.Duration(number) * time.Second
	case "minute", "minutes":
		duration = time.Duration(number) * time.Minute
	case "hour", "hours":
		duration = time.Duration(number) * time.Hour
	case "day", "days":
		duration = time.Duration(number) * 24 * time.Hour
	default:
		return time.Time{}, fmt.Errorf("invalid time unit: %s", unit)
	}

	// Calculate the time
	return time.Now().Add(-duration), nil
}

// parseTransferAmount parses a transfer amount string
func parseTransferAmount(amountStr string) (int64, error) {
	// Format: "123.45 KiB" or "1.23 MiB" or "2.34 GiB"
	parts := strings.Fields(amountStr)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid amount format: %s", amountStr)
	}

	// Parse the number
	number, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", parts[0])
	}

	// Parse the unit
	unit := parts[1]
	var multiplier int64
	switch unit {
	case "B":
		multiplier = 1
	case "KiB":
		multiplier = 1024
	case "MiB":
		multiplier = 1024 * 1024
	case "GiB":
		multiplier = 1024 * 1024 * 1024
	case "TiB":
		multiplier = 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("invalid unit: %s", unit)
	}

	// Calculate the amount
	return int64(number * float64(multiplier)), nil
}
