package controller

import (
	"fmt"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/dhcp/types"
)

// DNSManager captures the DNS operations the DHCP connector depends on.
type DNSManager interface {
	AddRecord(name, recordType, value string, ttl uint32) error
	RemoveRecord(name, recordType, value string) error
	AddReverseRecord(ip, target string, ttl uint32) error
	RemoveReverseRecord(ip string) error
}

// DNSConnector manages the connection between DHCP and DNS.
// It generates FQDNs from the lease hostname and the domain suffix
// configured on the DHCP CRD spec (via Lease.Domain).
type DNSConnector struct {
	dnsManager DNSManager
}

// NewDNSConnector creates a new DNS connector.
func NewDNSConnector(dnsManager DNSManager) *DNSConnector {
	return &DNSConnector{
		dnsManager: dnsManager,
	}
}

// resolveDomain returns the domain suffix for a lease. The domain is sourced
// from the DHCP CRD spec and carried on the Lease struct. If the lease has no
// domain set, this returns an error because we require an explicit domain
// rather than falling back to a placeholder.
func resolveDomain(lease *types.Lease) (string, error) {
	if lease.Domain != "" {
		return lease.Domain, nil
	}
	// Derive a minimal domain from the VLAN reference when available.
	if lease.VLANRef != "" {
		return fmt.Sprintf("%s.local", lease.VLANRef), nil
	}
	return "", fmt.Errorf("lease %s has no domain suffix configured; set domain in the DHCP CRD spec", lease.IP)
}

// UpdateLease updates DNS records for a DHCP lease.
func (c *DNSConnector) UpdateLease(lease *types.Lease) error {
	if lease.Hostname == "" {
		klog.V(4).Infof("No hostname for lease %s, skipping DNS update", lease.IP)
		return nil
	}

	domain, err := resolveDomain(lease)
	if err != nil {
		return err
	}

	// Build an FQDN from the hostname and domain suffix.
	hostname := fmt.Sprintf("%s.%s", lease.Hostname, domain)
	ttl := uint32(3600)
	if lease.TTL > 0 {
		ttl = lease.TTL
	}

	// Create forward A record.
	if err := c.dnsManager.AddRecord(hostname, "A", lease.IP, ttl); err != nil {
		return fmt.Errorf("failed to add forward DNS record for %s: %v", hostname, err)
	}

	// Create reverse PTR record.
	if err := c.dnsManager.AddReverseRecord(lease.IP, hostname, ttl); err != nil {
		klog.Warningf("Failed to add reverse DNS record for %s: %v", hostname, err)
		// Non-fatal: forward record succeeded.
	}

	klog.Infof("Added DNS records for lease %s (%s)", lease.IP, hostname)
	return nil
}

// RemoveLease removes DNS records for an expired DHCP lease.
func (c *DNSConnector) RemoveLease(lease *types.Lease) error {
	if lease.Hostname == "" {
		klog.V(4).Infof("No hostname for lease %s, skipping DNS removal", lease.IP)
		return nil
	}

	domain, err := resolveDomain(lease)
	if err != nil {
		return err
	}

	hostname := fmt.Sprintf("%s.%s", lease.Hostname, domain)

	if err := c.dnsManager.RemoveRecord(hostname, "A", lease.IP); err != nil {
		return fmt.Errorf("failed to remove forward DNS record for %s: %v", hostname, err)
	}

	if err := c.dnsManager.RemoveReverseRecord(lease.IP); err != nil {
		klog.Warningf("Failed to remove reverse DNS record for %s: %v", hostname, err)
	}

	klog.Infof("Removed DNS records for lease %s (%s)", lease.IP, hostname)
	return nil
}

// ScheduleLeaseRemoval schedules a lease to be removed when it expires.
func (c *DNSConnector) ScheduleLeaseRemoval(lease *types.Lease) {
	expirationTime := lease.ExpiresAt
	waitTime := time.Until(expirationTime)

	if waitTime <= 0 {
		go func() {
			if err := c.RemoveLease(lease); err != nil {
				klog.Errorf("Failed to remove expired lease %s: %v", lease.IP, err)
			}
		}()
		return
	}

	go func() {
		klog.V(4).Infof("Scheduling DNS record removal for lease %s in %v", lease.IP, waitTime)
		time.Sleep(waitTime)
		if err := c.RemoveLease(lease); err != nil {
			klog.Errorf("Failed to remove expired lease %s: %v", lease.IP, err)
		}
	}()
}
