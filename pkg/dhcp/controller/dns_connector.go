package controller

import (
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"github.com/fos/pkg/dhcp/types"
	"github.com/fos/pkg/dns/manager"
)

// DNSConnector manages the connection between DHCP and DNS
type DNSConnector struct {
	dnsManager *manager.Manager
}

// NewDNSConnector creates a new DNS connector
func NewDNSConnector(dnsManager *manager.Manager) *DNSConnector {
	return &DNSConnector{
		dnsManager: dnsManager,
	}
}

// UpdateLease updates DNS records for a DHCP lease
func (c *DNSConnector) UpdateLease(lease *types.Lease) error {
	if lease.Hostname == "" {
		// No hostname, no DNS record
		klog.V(4).Infof("No hostname for lease %s, skipping DNS update", lease.IP)
		return nil
	}

	// Determine the domain from the VLAN
	// In a real implementation, this would look up the domain based on the VLAN reference
	// For now, we'll use a placeholder domain suffix
	domain := "local"
	if lease.Domain != "" {
		domain = lease.Domain
	}

	// Create the DNS record
	hostname := fmt.Sprintf("%s.%s", lease.Hostname, domain)
	ttl := uint32(3600) // Default TTL
	if lease.TTL > 0 {
		ttl = lease.TTL
	}

	// Create forward record
	err := c.dnsManager.AddRecord(hostname, "A", lease.IP, ttl)
	if err != nil {
		return fmt.Errorf("failed to add forward DNS record for %s: %v", hostname, err)
	}

	// Create reverse record
	err = c.dnsManager.AddReverseRecord(lease.IP, hostname, ttl)
	if err != nil {
		klog.Warningf("Failed to add reverse DNS record for %s: %v", hostname, err)
		// We don't want to fail the entire operation if just the reverse record fails
	}

	klog.Infof("Added DNS records for lease %s (%s)", lease.IP, hostname)
	return nil
}

// RemoveLease removes DNS records for an expired DHCP lease
func (c *DNSConnector) RemoveLease(lease *types.Lease) error {
	if lease.Hostname == "" {
		// No hostname, no DNS record to remove
		klog.V(4).Infof("No hostname for lease %s, skipping DNS removal", lease.IP)
		return nil
	}

	// Determine the domain from the VLAN
	// In a real implementation, this would look up the domain based on the VLAN reference
	// For now, we'll use a placeholder domain suffix
	domain := "local"
	if lease.Domain != "" {
		domain = lease.Domain
	}

	// Build the hostname
	hostname := fmt.Sprintf("%s.%s", lease.Hostname, domain)

	// Remove forward record
	err := c.dnsManager.RemoveRecord(hostname, "A", lease.IP)
	if err != nil {
		return fmt.Errorf("failed to remove forward DNS record for %s: %v", hostname, err)
	}

	// Remove reverse record
	err = c.dnsManager.RemoveReverseRecord(lease.IP)
	if err != nil {
		klog.Warningf("Failed to remove reverse DNS record for %s: %v", hostname, err)
		// We don't want to fail the entire operation if just the reverse record fails
	}

	klog.Infof("Removed DNS records for lease %s (%s)", lease.IP, hostname)
	return nil
}

// ScheduleLeaseRemoval schedules a lease to be removed when it expires
func (c *DNSConnector) ScheduleLeaseRemoval(lease *types.Lease) {
	// Calculate when the lease will expire
	expirationTime := lease.ExpiresAt

	// Calculate how long until the lease expires
	waitTime := time.Until(expirationTime)
	if waitTime <= 0 {
		// Lease is already expired, remove it immediately
		go func() {
			err := c.RemoveLease(lease)
			if err != nil {
				klog.Errorf("Failed to remove expired lease %s: %v", lease.IP, err)
			}
		}()
		return
	}

	// Schedule removal at expiration time
	go func() {
		klog.V(4).Infof("Scheduling DNS record removal for lease %s in %v", lease.IP, waitTime)
		time.Sleep(waitTime)
		err := c.RemoveLease(lease)
		if err != nil {
			klog.Errorf("Failed to remove expired lease %s: %v", lease.IP, err)
		}
	}()
}