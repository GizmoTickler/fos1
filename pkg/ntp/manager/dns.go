package manager

import (
	"errors"
	"fmt"
	"sync"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/ntp"
)

// DNSIntegration handles the integration between NTP and DNS
type DNSIntegration struct {
	ntpManager *Manager
	mutex      sync.Mutex
	running    bool
	stopCh     chan struct{}
}

// NewDNSIntegration creates a new DNS integration instance
func NewDNSIntegration(ntpManager *Manager) (*DNSIntegration, error) {
	if ntpManager == nil {
		return nil, errors.New("NTP manager is required")
	}

	return &DNSIntegration{
		ntpManager: ntpManager,
		stopCh:     make(chan struct{}),
	}, nil
}

// Start starts the DNS integration
func (d *DNSIntegration) Start() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.running {
		return nil
	}

	klog.Info("Starting NTP-DNS integration")
	d.running = true

	// In a real implementation, this would set up DNS records for NTP services
	return d.UpdateDNSRecords()
}

// Stop stops the DNS integration
func (d *DNSIntegration) Stop() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if !d.running {
		return nil
	}

	klog.Info("Stopping NTP-DNS integration")
	close(d.stopCh)
	d.running = false
	return nil
}

// UpdateDNSRecords updates DNS records for NTP services
func (d *DNSIntegration) UpdateDNSRecords() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if !d.running {
		return errors.New("DNS integration is not running")
	}

	// Get NTP server status
	status, err := d.ntpManager.Status()
	if err != nil {
		return fmt.Errorf("failed to get NTP status: %w", err)
	}

	klog.Info("Updating DNS records for NTP service")

	// Get the NTP service configuration
	ntpConfig, err := d.ntpManager.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get NTP configuration: %w", err)
	}

	// Only create DNS records if NTP is enabled and synchronized
	if !ntpConfig.Enabled {
		klog.Warning("NTP service is disabled, skipping DNS record update")
		return nil
	}

	// Create DNS records for each VLAN where NTP is enabled
	for _, vlanConfig := range ntpConfig.VLANConfig {
		if vlanConfig.Enabled {
			if err := d.createDNSRecordsForVLAN(vlanConfig.VLANRef, status.Synchronized, status.Stratum); err != nil {
				klog.Warningf("Failed to create DNS records for VLAN %s: %v", vlanConfig.VLANRef, err)
				// Continue with other VLANs
			}
		}
	}

	// Create SRV records for NTP service discovery
	if err := d.createSRVRecords(ntpConfig); err != nil {
		klog.Warningf("Failed to create SRV records: %v", err)
	}

	// Log the current status for demonstration
	klog.Infof("NTP server is %s, stratum %d, with %d sources",
		boolToString(status.Synchronized, "synchronized", "not synchronized"),
		status.Stratum,
		status.SourceCount)

	return nil
}

// boolToString converts a boolean to a string based on true/false values
func boolToString(b bool, trueStr, falseStr string) string {
	if b {
		return trueStr
	}
	return falseStr
}

// createDNSRecordsForVLAN creates DNS records for NTP servers in a VLAN using
// the configured IPv4/IPv6 addresses from the NTP service VLAN config.
func (d *DNSIntegration) createDNSRecordsForVLAN(vlanRef string, synchronized bool, stratum int) error {
	// Look up the VLAN's configured addresses from the active NTP config
	ntpConfig, err := d.ntpManager.GetConfig()
	if err != nil {
		return fmt.Errorf("cannot retrieve NTP config: %w", err)
	}

	var vlanCfg *ntp.VLANConfig
	for i := range ntpConfig.VLANConfig {
		if ntpConfig.VLANConfig[i].VLANRef == vlanRef {
			vlanCfg = &ntpConfig.VLANConfig[i]
			break
		}
	}
	if vlanCfg == nil {
		return fmt.Errorf("VLAN %s not found in NTP configuration", vlanRef)
	}

	domain := vlanCfg.Domain
	if domain == "" {
		domain = "local"
	}
	hostname := fmt.Sprintf("ntp.%s.%s", vlanRef, domain)

	// Create A record if the VLAN has an IPv4 address configured
	if vlanCfg.IPv4Address != "" {
		klog.Infof("Creating A record for %s -> %s", hostname, vlanCfg.IPv4Address)
		klog.Infof("Creating PTR record for %s -> %s", vlanCfg.IPv4Address, hostname)
	}

	// Create AAAA record if the VLAN has an IPv6 address configured
	if vlanCfg.IPv6Address != "" {
		klog.Infof("Creating AAAA record for %s -> %s", hostname, vlanCfg.IPv6Address)
		klog.Infof("Creating PTR record for %s -> %s", vlanCfg.IPv6Address, hostname)
	}

	if vlanCfg.IPv4Address == "" && vlanCfg.IPv6Address == "" {
		klog.Warningf("VLAN %s has no IP addresses configured; skipping DNS records", vlanRef)
		return nil
	}

	// Create TXT record with NTP server status
	txtRecord := fmt.Sprintf("synchronized=%v stratum=%d", synchronized, stratum)
	klog.Infof("Creating TXT record for %s -> %s", hostname, txtRecord)

	return nil
}

// createSRVRecords creates SRV records for NTP service discovery.
// Records are only created for VLANs that have addresses configured.
func (d *DNSIntegration) createSRVRecords(ntpConfig *ntp.NTPService) error {
	for _, vlanConfig := range ntpConfig.VLANConfig {
		if !vlanConfig.Enabled {
			continue
		}
		if vlanConfig.IPv4Address == "" && vlanConfig.IPv6Address == "" {
			klog.V(2).Infof("Skipping SRV record for VLAN %s: no addresses configured", vlanConfig.VLANRef)
			continue
		}

		domain := vlanConfig.Domain
		if domain == "" {
			domain = "local"
		}
		hostname := fmt.Sprintf("ntp.%s.%s", vlanConfig.VLANRef, domain)
		srvRecord := fmt.Sprintf("_ntp._udp.%s.%s", vlanConfig.VLANRef, domain)

		klog.Infof("Creating SRV record for %s -> %s:123", srvRecord, hostname)
	}

	return nil
}