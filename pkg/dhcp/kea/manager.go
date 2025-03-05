package kea

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"k8s.io/klog/v2"

	"github.com/fos/pkg/dhcp/types"
)

// Manager handles configuration and control of Kea DHCP servers
type Manager struct {
	configDir       string
	keaCommandBase  string
	configLock      sync.Mutex
	dhcpv4Config    *DHCPv4Config
	dhcpv6Config    *DHCPv6Config
}

// NewManager creates a new Kea manager
func NewManager(configDir, keaCommandBase string) *Manager {
	return &Manager{
		configDir:      configDir,
		keaCommandBase: keaCommandBase,
		dhcpv4Config:   NewDHCPv4Config(),
		dhcpv6Config:   NewDHCPv6Config(),
	}
}

// UpdateDHCPv4Subnet updates or adds a subnet in the DHCPv4 configuration
func (m *Manager) UpdateDHCPv4Subnet(vlanID int, subnet *types.DHCPv4SubnetConfig) error {
	m.configLock.Lock()
	defer m.configLock.Unlock()

	// Convert the internal subnet config to Kea's format
	keaSubnet := m.convertToKeaDHCPv4Subnet(vlanID, subnet)

	// Find if this subnet already exists
	found := false
	for i, s := range m.dhcpv4Config.Dhcp4.Subnet4 {
		if s.ID == vlanID {
			// Replace existing subnet
			m.dhcpv4Config.Dhcp4.Subnet4[i] = keaSubnet
			found = true
			break
		}
	}

	if !found {
		// Add new subnet
		m.dhcpv4Config.Dhcp4.Subnet4 = append(m.dhcpv4Config.Dhcp4.Subnet4, keaSubnet)
	}

	// Write the updated configuration to disk
	return m.writeConfig(fmt.Sprintf("dhcp4-%d.conf", vlanID), m.dhcpv4Config)
}

// UpdateDHCPv6Subnet updates or adds a subnet in the DHCPv6 configuration
func (m *Manager) UpdateDHCPv6Subnet(vlanID int, subnet *types.DHCPv6SubnetConfig) error {
	m.configLock.Lock()
	defer m.configLock.Unlock()

	// Convert the internal subnet config to Kea's format
	keaSubnet := m.convertToKeaDHCPv6Subnet(vlanID, subnet)

	// Find if this subnet already exists
	found := false
	for i, s := range m.dhcpv6Config.Dhcp6.Subnet6 {
		if s.ID == vlanID {
			// Replace existing subnet
			m.dhcpv6Config.Dhcp6.Subnet6[i] = keaSubnet
			found = true
			break
		}
	}

	if !found {
		// Add new subnet
		m.dhcpv6Config.Dhcp6.Subnet6 = append(m.dhcpv6Config.Dhcp6.Subnet6, keaSubnet)
	}

	// Write the updated configuration to disk
	return m.writeConfig(fmt.Sprintf("dhcp6-%d.conf", vlanID), m.dhcpv6Config)
}

// RestartDHCPv4Service restarts the Kea DHCPv4 service for a specific VLAN
func (m *Manager) RestartDHCPv4Service(vlanID int) error {
	// In a real implementation, this would signal Kea to reload its configuration
	// For now, we'll just log a message indicating the service would be restarted
	klog.Infof("Would restart Kea DHCPv4 service for VLAN %d", vlanID)
	return nil
}

// RestartDHCPv6Service restarts the Kea DHCPv6 service for a specific VLAN
func (m *Manager) RestartDHCPv6Service(vlanID int) error {
	// In a real implementation, this would signal Kea to reload its configuration
	// For now, we'll just log a message indicating the service would be restarted
	klog.Infof("Would restart Kea DHCPv6 service for VLAN %d", vlanID)
	return nil
}

// writeConfig writes a configuration object to a file
func (m *Manager) writeConfig(filename string, config interface{}) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %v", err)
	}

	path := filepath.Join(m.configDir, filename)
	err = ioutil.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write configuration file %s: %v", path, err)
	}

	klog.Infof("Wrote Kea configuration to %s", path)
	return nil
}

// convertToKeaDHCPv4Subnet converts an internal subnet config to Kea's format
func (m *Manager) convertToKeaDHCPv4Subnet(vlanID int, subnet *types.DHCPv4SubnetConfig) DHCPv4Subnet {
	keaSubnet := DHCPv4Subnet{
		ID:     vlanID,
		Subnet: subnet.Subnet,
		Pools:  make([]DHCPPool, 0, len(subnet.Pools)),
	}

	// Add pools
	for _, pool := range subnet.Pools {
		keaSubnet.Pools = append(keaSubnet.Pools, DHCPPool{
			Pool: fmt.Sprintf("%s - %s", pool.Start, pool.End),
		})
	}

	// Add options
	keaSubnet.OptionData = make([]DHCPOption, 0, len(subnet.Options))
	for _, option := range subnet.Options {
		keaSubnet.OptionData = append(keaSubnet.OptionData, DHCPOption{
			Name: option.Name,
			Data: option.Data,
		})
	}

	// Add reservations
	keaSubnet.Reservations = make([]DHCPv4Reservation, 0, len(subnet.Reservations))
	for _, res := range subnet.Reservations {
		keaRes := DHCPv4Reservation{
			IPAddress: res.IPAddress,
			Hostname:  res.Hostname,
		}
		if res.HWAddress != "" {
			keaRes.HWAddress = res.HWAddress
		}
		if res.ClientID != "" {
			keaRes.ClientID = res.ClientID
		}
		keaSubnet.Reservations = append(keaSubnet.Reservations, keaRes)
	}

	return keaSubnet
}

// convertToKeaDHCPv6Subnet converts an internal subnet config to Kea's format
func (m *Manager) convertToKeaDHCPv6Subnet(vlanID int, subnet *types.DHCPv6SubnetConfig) DHCPv6Subnet {
	keaSubnet := DHCPv6Subnet{
		ID:     vlanID,
		Subnet: subnet.Subnet,
		Pools:  make([]DHCPPool, 0, len(subnet.Pools)),
	}

	// Add pools
	for _, pool := range subnet.Pools {
		keaSubnet.Pools = append(keaSubnet.Pools, DHCPPool{
			Pool: fmt.Sprintf("%s - %s", pool.Start, pool.End),
		})
	}

	// Add options
	keaSubnet.OptionData = make([]DHCPOption, 0, len(subnet.Options))
	for _, option := range subnet.Options {
		keaSubnet.OptionData = append(keaSubnet.OptionData, DHCPOption{
			Name: option.Name,
			Data: option.Data,
		})
	}

	// Add reservations
	keaSubnet.Reservations = make([]DHCPv6Reservation, 0, len(subnet.Reservations))
	for _, res := range subnet.Reservations {
		keaRes := DHCPv6Reservation{
			IPAddresses: []string{res.IPAddress},
			Hostname:    res.Hostname,
		}
		if res.DUID != "" {
			keaRes.DUID = res.DUID
		}
		if res.HWAddress != "" {
			keaRes.HWAddress = res.HWAddress
		}
		keaSubnet.Reservations = append(keaSubnet.Reservations, keaRes)
	}

	return keaSubnet
}