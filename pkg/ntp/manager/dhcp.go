package manager

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/dhcp/types"
	"github.com/varuntirumala1/fos1/pkg/ntp"
)

// DHCPIntegration handles the integration between NTP and DHCP
type DHCPIntegration struct {
	ntpManager *Manager
	mutex      sync.Mutex
	running    bool
	stopCh     chan struct{}
}

// NewDHCPIntegration creates a new DHCP integration instance
func NewDHCPIntegration(ntpManager *Manager) (*DHCPIntegration, error) {
	if ntpManager == nil {
		return nil, errors.New("NTP manager is required")
	}

	return &DHCPIntegration{
		ntpManager: ntpManager,
		stopCh:     make(chan struct{}),
	}, nil
}

// Start starts the DHCP integration
func (d *DHCPIntegration) Start() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.running {
		return nil
	}

	klog.Info("Starting NTP-DHCP integration")
	d.running = true

	// In a real implementation, this would listen for events from the DHCP system
	// and update NTP time sources in DHCP options when the NTP server status changes.
	return nil
}

// Stop stops the DHCP integration
func (d *DHCPIntegration) Stop() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if !d.running {
		return nil
	}

	klog.Info("Stopping NTP-DHCP integration")
	close(d.stopCh)
	d.running = false
	return nil
}

// UpdateDHCPOptions updates DHCP options with NTP server information
func (d *DHCPIntegration) UpdateDHCPOptions() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if !d.running {
		return errors.New("DHCP integration is not running")
	}

	// Get NTP server status
	status, err := d.ntpManager.Status()
	if err != nil {
		return fmt.Errorf("failed to get NTP status: %w", err)
	}

	// Only update if NTP is synchronized
	if !status.Synchronized {
		klog.Warning("NTP is not synchronized, skipping DHCP option update")
		return nil
	}

	klog.Info("Updating DHCP options with NTP server information")

	// Get the NTP service configuration
	ntpConfig, err := d.ntpManager.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get NTP configuration: %w", err)
	}

	// Get the list of IP addresses for NTP servers
	ntpServers, err := d.getNTPServerAddresses(ntpConfig)
	if err != nil {
		return fmt.Errorf("failed to get NTP server addresses: %w", err)
	}

	if len(ntpServers) == 0 {
		klog.Warning("No NTP server addresses available, skipping DHCP option update")
		return nil
	}

	// Update DHCPv4 option 42 (NTP servers)
	if err := d.updateDHCPv4Option(ntpServers); err != nil {
		return fmt.Errorf("failed to update DHCPv4 option: %w", err)
	}

	// Update DHCPv6 option 56 (NTP servers)
	if err := d.updateDHCPv6Option(ntpServers); err != nil {
		return fmt.Errorf("failed to update DHCPv6 option: %w", err)
	}

	klog.Infof("Successfully updated DHCP options with %d NTP servers", len(ntpServers))
	return nil
}

// getNTPServerAddresses returns a list of IP addresses for NTP servers
func (d *DHCPIntegration) getNTPServerAddresses(ntpConfig *ntp.NTPService) ([]string, error) {
	var servers []string

	// Add the local NTP server if it's enabled and synchronized
	if ntpConfig.Enabled && ntpConfig.Server.Local.Enabled {
		// Get the IP addresses for each VLAN where NTP is enabled
		for _, vlanConfig := range ntpConfig.VLANConfig {
			if vlanConfig.Enabled {
				// In a real implementation, this would get the IP address of the NTP server on this VLAN
				// For now, we'll use a placeholder IP address
				servers = append(servers, fmt.Sprintf("192.168.%d.1", len(servers)+1))
			}
		}
	}

	// Add external NTP servers if configured
	for _, server := range ntpConfig.Sources.Servers {
		// Check if the address is an IP address
		if net.ParseIP(server.Address) != nil {
			servers = append(servers, server.Address)
		} else {
			// Resolve the hostname to IP addresses
			ips, err := net.LookupIP(server.Address)
			if err != nil {
				klog.Warningf("Failed to resolve NTP server %s: %v", server.Address, err)
				continue
			}

			// Add the resolved IP addresses
			for _, ip := range ips {
				servers = append(servers, ip.String())
			}
		}
	}

	// Add pool servers if configured
	for _, pool := range ntpConfig.Sources.Pools {
		// Resolve the pool hostname to IP addresses
		ips, err := net.LookupIP(pool.Name)
		if err != nil {
			klog.Warningf("Failed to resolve NTP pool %s: %v", pool.Name, err)
			continue
		}

		// Add the resolved IP addresses (up to the configured number of servers)
		for i, ip := range ips {
			if i >= pool.Servers {
				break
			}
			servers = append(servers, ip.String())
		}
	}

	return servers, nil
}

// updateDHCPv4Option updates the DHCPv4 option 42 (NTP servers)
func (d *DHCPIntegration) updateDHCPv4Option(ntpServers []string) error {
	// In a real implementation, this would update the DHCPv4 option 42 in the DHCP server configuration
	// For now, we'll just log the servers
	klog.Infof("Would update DHCPv4 option 42 with NTP servers: %v", ntpServers)

	// Filter for IPv4 addresses only
	var ipv4Servers []string
	for _, server := range ntpServers {
		ip := net.ParseIP(server)
		if ip != nil && ip.To4() != nil {
			ipv4Servers = append(ipv4Servers, server)
		}
	}

	// Create the DHCPv4 option
	option := types.DHCPOption{
		Code: 42, // NTP servers
		Name: "ntp-servers",
		Value: strings.Join(ipv4Servers, ","),
	}

	// In a real implementation, this would update the option in all DHCPv4 services
	klog.Infof("Created DHCPv4 option 42 with value: %s", option.Value)

	return nil
}

// updateDHCPv6Option updates the DHCPv6 option 56 (NTP servers)
func (d *DHCPIntegration) updateDHCPv6Option(ntpServers []string) error {
	// In a real implementation, this would update the DHCPv6 option 56 in the DHCP server configuration
	// For now, we'll just log the servers
	klog.Infof("Would update DHCPv6 option 56 with NTP servers: %v", ntpServers)

	// Filter for IPv6 addresses only
	var ipv6Servers []string
	for _, server := range ntpServers {
		ip := net.ParseIP(server)
		if ip != nil && ip.To4() == nil {
			ipv6Servers = append(ipv6Servers, server)
		}
	}

	// Create the DHCPv6 option
	option := types.DHCPOption{
		Code: 56, // NTP servers
		Name: "ntp-servers",
		Value: strings.Join(ipv6Servers, ","),
	}

	// In a real implementation, this would update the option in all DHCPv6 services
	klog.Infof("Created DHCPv6 option 56 with value: %s", option.Value)

	return nil
}