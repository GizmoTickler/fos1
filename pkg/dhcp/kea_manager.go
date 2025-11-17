package dhcp

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/GizmoTickler/fos1/pkg/dhcp/types"
	"k8s.io/klog/v2"
)

// KeaManager handles the management of Kea DHCP server instances
type KeaManager struct {
	configDir  string
	keaCommand string
	instances  map[string]*KeaInstance
	mutex      sync.RWMutex
}

// KeaInstance represents a running instance of Kea DHCP server
type KeaInstance struct {
	vlanID     string
	configPath string
	running    bool
}

// NewKeaManager creates a new Kea manager
func NewKeaManager(configDir, keaCommand string) (*KeaManager, error) {
	// Create the config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	return &KeaManager{
		configDir:  configDir,
		keaCommand: keaCommand,
		instances:  make(map[string]*KeaInstance),
	}, nil
}

// UpdateConfig updates the Kea configuration file for a specific VLAN
func (m *KeaManager) UpdateConfig(vlanID string, config *KeaConfig) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Create the Kea configuration file
	configPath := filepath.Join(m.configDir, fmt.Sprintf("kea-%s.conf", vlanID))
	
	// Marshal the configuration to JSON
	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	// Write the configuration to the file
	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}

	// Create or update the instance
	instance, exists := m.instances[vlanID]
	if !exists {
		instance = &KeaInstance{
			vlanID:     vlanID,
			configPath: configPath,
			running:    false,
		}
		m.instances[vlanID] = instance
	} else {
		instance.configPath = configPath
	}

	klog.Infof("Updated Kea configuration for VLAN %s", vlanID)
	return nil
}

// DeleteConfig deletes the Kea configuration for a specific VLAN
func (m *KeaManager) DeleteConfig(vlanID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Stop the instance if it's running
	instance, exists := m.instances[vlanID]
	if exists && instance.running {
		if err := m.stopInstance(instance); err != nil {
			return fmt.Errorf("failed to stop instance: %w", err)
		}
	}

	// Remove the configuration file
	configPath := filepath.Join(m.configDir, fmt.Sprintf("kea-%s.conf", vlanID))
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete configuration file: %w", err)
	}

	// Remove the instance
	delete(m.instances, vlanID)

	klog.Infof("Deleted Kea configuration for VLAN %s", vlanID)
	return nil
}

// StartService starts the Kea service for a specific VLAN
func (m *KeaManager) StartService(vlanID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if the instance exists
	instance, exists := m.instances[vlanID]
	if !exists {
		return fmt.Errorf("no configuration exists for VLAN %s", vlanID)
	}

	// Start the instance
	if err := m.startInstance(instance); err != nil {
		return fmt.Errorf("failed to start instance: %w", err)
	}

	klog.Infof("Started Kea service for VLAN %s", vlanID)
	return nil
}

// RestartService restarts the Kea service for a specific VLAN
func (m *KeaManager) RestartService(vlanID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if the instance exists
	instance, exists := m.instances[vlanID]
	if !exists {
		return fmt.Errorf("no configuration exists for VLAN %s", vlanID)
	}

	// Restart the instance
	if instance.running {
		if err := m.stopInstance(instance); err != nil {
			return fmt.Errorf("failed to stop instance: %w", err)
		}
	}

	if err := m.startInstance(instance); err != nil {
		return fmt.Errorf("failed to start instance: %w", err)
	}

	klog.Infof("Restarted Kea service for VLAN %s", vlanID)
	return nil
}

// StopService stops the Kea service for a specific VLAN
func (m *KeaManager) StopService(vlanID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if the instance exists
	instance, exists := m.instances[vlanID]
	if !exists {
		return fmt.Errorf("no configuration exists for VLAN %s", vlanID)
	}

	// Stop the instance
	if !instance.running {
		klog.Infof("Kea service for VLAN %s is not running", vlanID)
		return nil
	}

	if err := m.stopInstance(instance); err != nil {
		return fmt.Errorf("failed to stop instance: %w", err)
	}

	klog.Infof("Stopped Kea service for VLAN %s", vlanID)
	return nil
}

// startInstance starts a Kea instance
func (m *KeaManager) startInstance(instance *KeaInstance) error {
	if instance.running {
		klog.Infof("Kea service for VLAN %s is already running", instance.vlanID)
		return nil
	}

	// In a real implementation, this would start a Kea process
	// For now, just log that it would be started
	klog.Infof("Would start Kea service with command: %s -c %s", m.keaCommand, instance.configPath)

	// In a real implementation, you would use something like:
	/*
	cmd := exec.Command(m.keaCommand, "-c", instance.configPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Kea process: %w", err)
	}
	*/

	instance.running = true
	return nil
}

// stopInstance stops a Kea instance
func (m *KeaManager) stopInstance(instance *KeaInstance) error {
	if !instance.running {
		klog.Infof("Kea service for VLAN %s is not running", instance.vlanID)
		return nil
	}

	// In a real implementation, this would stop a Kea process
	// For now, just log that it would be stopped
	klog.Infof("Would stop Kea service for VLAN %s", instance.vlanID)

	// In a real implementation, you would use something like:
	/*
	cmd := exec.Command("pkill", "-f", fmt.Sprintf("%s -c %s", m.keaCommand, instance.configPath))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to stop Kea process: %w", err)
	}
	*/

	instance.running = false
	return nil
}

// GetLeases gets the current DHCP leases for a specific VLAN
func (m *KeaManager) GetLeases(vlanID string) ([]types.Lease, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Check if the instance exists
	instance, exists := m.instances[vlanID]
	if !exists {
		return nil, fmt.Errorf("no configuration exists for VLAN %s", vlanID)
	}

	// In a real implementation, this would query the Kea API for leases
	// For now, just return an empty list
	klog.Infof("Would get leases for VLAN %s", vlanID)

	// In a real implementation, you would use the Kea API to get leases
	// This would involve making a JSON-RPC call to the Kea control socket

	return []Lease{}, nil
}

// ConfigureFromDHCPv4 creates a Kea configuration from a DHCPv4Service
func (m *KeaManager) ConfigureFromDHCPv4(service *types.DHCPv4Service, subnet, gateway string) (*KeaConfig, error) {
	// Create a new Kea configuration
	config := &KeaConfig{
		Dhcp4: &Kea4Config{
			Interfaces: []string{fmt.Sprintf("eth-%s", service.Spec.VLANRef)},
			ControlSocket: KeaControlSocket{
				SocketType: "unix",
				SocketName: fmt.Sprintf("/tmp/kea-%s.sock", service.Spec.VLANRef),
			},
			LeaseDatabase: KeaDatabase{
				Type: "memfile",
				Name: fmt.Sprintf("/var/lib/kea/dhcp4-%s.leases", service.Spec.VLANRef),
			},
			ValidLifetime:    service.Spec.LeaseTime,
			MaxValidLifetime: service.Spec.MaxLeaseTime,
			Subnet4: []KeaSubnet4{
				{
					Subnet: subnet,
					Pools: []KeaPool{
						{
							Pool: fmt.Sprintf("%s-%s", service.Spec.Range.Start, service.Spec.Range.End),
						},
					},
					ReservationMode: "all",
					OptionData: []KeaOptionData{
						{
							Code: 3, // Router option
							Data: gateway,
						},
					},
				},
			},
			Loggers: []KeaLogger{
				{
					Name: "kea-dhcp4",
					OutputOptions: []KeaOutputOption{
						{
							Output: "/var/log/kea-dhcp4.log",
						},
					},
					Severity:   "INFO",
					DebugLevel: 0,
				},
			},
		},
	}

	// Add domain name if provided
	if service.Spec.Domain != "" {
		config.Dhcp4.Subnet4[0].OptionData = append(config.Dhcp4.Subnet4[0].OptionData, KeaOptionData{
			Code: 15, // Domain Name option
			Data: service.Spec.Domain,
		})
	}

	// Add additional options
	for _, option := range service.Spec.Options {
		config.Dhcp4.Subnet4[0].OptionData = append(config.Dhcp4.Subnet4[0].OptionData, KeaOptionData{
			Code: option.Code,
			Data: option.Value,
		})
	}

	// Add reservations
	for _, reservation := range service.Spec.Reservations {
		keaReservation := KeaReservation4{
			Hostname:  reservation.Hostname,
			IPAddress: reservation.IPAddress,
		}

		if reservation.MACAddress != "" {
			keaReservation.HwAddress = reservation.MACAddress
		} else if reservation.ClientID != "" {
			keaReservation.ClientID = reservation.ClientID
		}

		config.Dhcp4.Subnet4[0].Reservations = append(config.Dhcp4.Subnet4[0].Reservations, keaReservation)
	}

	// Add DNS update hook if DNS integration is enabled
	if service.Spec.DNSIntegration.Enabled {
		config.Dhcp4.HookLibraries = []KeaHookLibrary{
			{
				Library: "/usr/lib/kea/hooks/libdhcp_ddns.so",
				Parameters: map[string]interface{}{
					"enable-updates": true,
					"qualifying-suffix": service.Spec.Domain,
					"forward-updates": service.Spec.DNSIntegration.ForwardUpdates,
					"reverse-updates": service.Spec.DNSIntegration.ReverseUpdates,
					"ttl": service.Spec.DNSIntegration.TTL,
				},
			},
		}
	}

	return config, nil
}

// ConfigureFromDHCPv6 creates a Kea configuration from a DHCPv6Service
func (m *KeaManager) ConfigureFromDHCPv6(service *types.DHCPv6Service, subnet, gateway string) (*KeaConfig, error) {
	// Create a new Kea configuration
	config := &KeaConfig{
		Dhcp6: &Kea6Config{
			Interfaces: []string{fmt.Sprintf("eth-%s", service.Spec.VLANRef)},
			ControlSocket: KeaControlSocket{
				SocketType: "unix",
				SocketName: fmt.Sprintf("/tmp/kea6-%s.sock", service.Spec.VLANRef),
			},
			LeaseDatabase: KeaDatabase{
				Type: "memfile",
				Name: fmt.Sprintf("/var/lib/kea/dhcp6-%s.leases", service.Spec.VLANRef),
			},
			ValidLifetime:    service.Spec.LeaseTime,
			MaxValidLifetime: service.Spec.MaxLeaseTime,
			Subnet6: []KeaSubnet6{
				{
					Subnet: subnet,
					Pools: []KeaPool{
						{
							Pool: fmt.Sprintf("%s-%s", service.Spec.Range.Start, service.Spec.Range.End),
						},
					},
					ReservationMode: "all",
				},
			},
			Loggers: []KeaLogger{
				{
					Name: "kea-dhcp6",
					OutputOptions: []KeaOutputOption{
						{
							Output: "/var/log/kea-dhcp6.log",
						},
					},
					Severity:   "INFO",
					DebugLevel: 0,
				},
			},
		},
	}

	// Add domain name if provided
	if service.Spec.Domain != "" {
		config.Dhcp6.Subnet6[0].OptionData = append(config.Dhcp6.Subnet6[0].OptionData, KeaOptionData{
			Code: 39, // FQDN option
			Data: service.Spec.Domain,
		})
	}

	// Add additional options
	for _, option := range service.Spec.Options {
		config.Dhcp6.Subnet6[0].OptionData = append(config.Dhcp6.Subnet6[0].OptionData, KeaOptionData{
			Code: option.Code,
			Data: option.Value,
		})
	}

	// Add reservations
	for _, reservation := range service.Spec.Reservations {
		keaReservation := KeaReservation6{
			Hostname:    reservation.Hostname,
			IPAddresses: []string{reservation.IPAddress},
		}

		if reservation.DUID != "" {
			keaReservation.DUID = reservation.DUID
		} else if reservation.HWAddress != "" {
			keaReservation.HwAddress = reservation.HWAddress
		}

		config.Dhcp6.Subnet6[0].Reservations = append(config.Dhcp6.Subnet6[0].Reservations, keaReservation)
	}

	// Add DNS update hook if DNS integration is enabled
	if service.Spec.DNSIntegration.Enabled {
		config.Dhcp6.HookLibraries = []KeaHookLibrary{
			{
				Library: "/usr/lib/kea/hooks/libdhcp_ddns.so",
				Parameters: map[string]interface{}{
					"enable-updates": true,
					"qualifying-suffix": service.Spec.Domain,
					"forward-updates": service.Spec.DNSIntegration.ForwardUpdates,
					"reverse-updates": service.Spec.DNSIntegration.ReverseUpdates,
					"ttl": service.Spec.DNSIntegration.TTL,
				},
			},
		}
	}

	return config, nil
}
