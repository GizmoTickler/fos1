package interfaces

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// VLANManager handles VLAN interface operations
type VLANManager struct {
	// Dependencies could be injected here
}

// NewVLANManager creates a new VLAN manager
func NewVLANManager() *VLANManager {
	return &VLANManager{}
}

// CreateVLAN creates a new VLAN interface
func (m *VLANManager) CreateVLAN(parent string, vlanID int, name string) error {
	if vlanID < 1 || vlanID > 4094 {
		return fmt.Errorf("invalid VLAN ID: %d", vlanID)
	}

	// Check if parent interface exists
	if err := m.checkInterfaceExists(parent); err != nil {
		return fmt.Errorf("parent interface check failed: %w", err)
	}

	// Create the VLAN interface
	cmd := exec.Command("ip", "link", "add", "link", parent, name, "type", "vlan", "id", strconv.Itoa(vlanID))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create VLAN interface: %w", err)
	}

	return nil
}

// DeleteVLAN removes a VLAN interface
func (m *VLANManager) DeleteVLAN(name string) error {
	// Check if interface exists
	if err := m.checkInterfaceExists(name); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Delete the interface
	cmd := exec.Command("ip", "link", "delete", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete VLAN interface: %w", err)
	}

	return nil
}

// SetVLANUp brings a VLAN interface up
func (m *VLANManager) SetVLANUp(name string) error {
	// Check if interface exists
	if err := m.checkInterfaceExists(name); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Bring the interface up
	cmd := exec.Command("ip", "link", "set", "dev", name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// SetVLANDown brings a VLAN interface down
func (m *VLANManager) SetVLANDown(name string) error {
	// Check if interface exists
	if err := m.checkInterfaceExists(name); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Bring the interface down
	cmd := exec.Command("ip", "link", "set", "dev", name, "down")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}

	return nil
}

// AddIPAddress adds an IP address to a VLAN interface
func (m *VLANManager) AddIPAddress(name, address string) error {
	// Check if interface exists
	if err := m.checkInterfaceExists(name); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Add the IP address
	cmd := exec.Command("ip", "addr", "add", address, "dev", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add IP address: %w", err)
	}

	return nil
}

// RemoveIPAddress removes an IP address from a VLAN interface
func (m *VLANManager) RemoveIPAddress(name, address string) error {
	// Check if interface exists
	if err := m.checkInterfaceExists(name); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Remove the IP address
	cmd := exec.Command("ip", "addr", "del", address, "dev", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove IP address: %w", err)
	}

	return nil
}

// SetMTU sets the MTU for a VLAN interface
func (m *VLANManager) SetMTU(name string, mtu int) error {
	// Check if interface exists
	if err := m.checkInterfaceExists(name); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Set the MTU
	cmd := exec.Command("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	return nil
}

// GetVLANInfo gets information about a VLAN interface
func (m *VLANManager) GetVLANInfo(name string) (map[string]string, error) {
	// Check if interface exists
	if err := m.checkInterfaceExists(name); err != nil {
		return nil, fmt.Errorf("interface check failed: %w", err)
	}

	// Get the interface information
	cmd := exec.Command("ip", "-d", "link", "show", name)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface info: %w", err)
	}

	// Parse the output (this is a simplified example)
	info := make(map[string]string)
	info["name"] = name
	info["output"] = string(output)

	return info, nil
}

// ListVLANs lists all VLAN interfaces
func (m *VLANManager) ListVLANs() ([]string, error) {
	// List all interfaces with VLAN info
	cmd := exec.Command("grep", "-l", "VLAN", "/sys/class/net/*/uevent")
	output, err := cmd.Output()
	if err != nil {
		// If no VLANs exist, grep might return non-zero exit code
		return []string{}, nil
	}

	// Parse the output to get the interface names
	// This is a simplified example; in a real implementation you would parse the output
	var vlans []string
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		
		// Extract interface name from path like "/sys/class/net/vlan10/uevent"
		parts := strings.Split(line, "/")
		if len(parts) >= 5 {
			vlans = append(vlans, parts[4])
		}
	}

	return vlans, nil
}

// checkInterfaceExists checks if an interface exists
func (m *VLANManager) checkInterfaceExists(name string) error {
	cmd := exec.Command("ip", "link", "show", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("interface %s does not exist", name)
	}
	return nil
}