package manager

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/GizmoTickler/fos1/pkg/dns/adguard"
	"github.com/GizmoTickler/fos1/pkg/dns/coredns"
	"github.com/GizmoTickler/fos1/pkg/dns/mdns"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Manager coordinates all DNS services
type Manager struct {
	// Component controllers
	coreDNSController  *coredns.Controller
	adGuardController  *adguard.Controller
	mDNSController     *mdns.Controller

	// Integration
	dhcpIntegration    *DHCPIntegration
	metricsCollector   *MetricsCollector

	// API and status
	apiServer         *APIServer

	// Control
	k8sClient         kubernetes.Interface
	informers         []cache.SharedInformer
	ctx               context.Context
	cancel            context.CancelFunc
	mutex             sync.RWMutex
}

// Config holds DNS Manager configuration
type Config struct {
	EnableDHCPIntegration bool
	MetricsEnabled        bool
	APIEnabled            bool
	ResyncPeriod          time.Duration
}

// NewManager creates a new DNS Manager
func NewManager(
	client kubernetes.Interface,
	coreController *coredns.Controller,
	adGuardController *adguard.Controller,
	mDNSController *mdns.Controller,
	config *Config) (*Manager, error) {

	if client == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}

	if config == nil {
		config = &Config{
			EnableDHCPIntegration: true,
			MetricsEnabled:        true,
			APIEnabled:            true,
			ResyncPeriod:          time.Minute * 30,
		}
	}

	// Create context for management
	ctx, cancel := context.WithCancel(context.Background())

	// Create main manager
	manager := &Manager{
		coreDNSController: coreController,
		adGuardController: adGuardController,
		mDNSController:    mDNSController,
		k8sClient:         client,
		ctx:               ctx,
		cancel:            cancel,
		informers:         make([]cache.SharedInformer, 0),
	}

	// Initialize DHCP integration if enabled
	if config.EnableDHCPIntegration {
		dhcpIntegration, err := NewDHCPIntegration(manager)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to initialize DHCP integration: %w", err)
		}
		manager.dhcpIntegration = dhcpIntegration
	}

	// Initialize metrics collector if enabled
	if config.MetricsEnabled {
		metricsCollector, err := NewMetricsCollector(manager)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to initialize metrics collector: %w", err)
		}
		manager.metricsCollector = metricsCollector
	}

	// Initialize API server if enabled
	if config.APIEnabled {
		apiServer, err := NewAPIServer(manager)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to initialize API server: %w", err)
		}
		manager.apiServer = apiServer
	}

	return manager, nil
}

// Start starts the DNS Manager
func (m *Manager) Start() error {
	log.Println("Starting DNS Manager")

	// Start individual controllers if not already started
	if err := m.startControllers(); err != nil {
		return fmt.Errorf("failed to start controllers: %w", err)
	}

	// Set up informers
	if err := m.setupInformers(); err != nil {
		return fmt.Errorf("failed to set up informers: %w", err)
	}

	// Start DHCP integration if configured
	if m.dhcpIntegration != nil {
		if err := m.dhcpIntegration.Start(); err != nil {
			return fmt.Errorf("failed to start DHCP integration: %w", err)
		}
	}

	// Start metrics collector if configured
	if m.metricsCollector != nil {
		if err := m.metricsCollector.Start(); err != nil {
			return fmt.Errorf("failed to start metrics collector: %w", err)
		}
	}

	// Start API server if configured
	if m.apiServer != nil {
		if err := m.apiServer.Start(); err != nil {
			return fmt.Errorf("failed to start API server: %w", err)
		}
	}

	// Start informers
	for _, informer := range m.informers {
		go informer.Run(m.ctx.Done())
	}

	log.Println("DNS Manager started successfully")
	return nil
}

// Stop stops the DNS Manager
func (m *Manager) Stop() {
	log.Println("Stopping DNS Manager")

	// Cancel context to stop all components
	m.cancel()

	// Stop API server if running
	if m.apiServer != nil {
		if err := m.apiServer.Stop(); err != nil {
			log.Printf("Error stopping API server: %v", err)
		}
	}

	// Stop metrics collector if running
	if m.metricsCollector != nil {
		if err := m.metricsCollector.Stop(); err != nil {
			log.Printf("Error stopping metrics collector: %v", err)
		}
	}

	// Stop individual controllers
	m.stopControllers()

	log.Println("DNS Manager stopped")
}

// startControllers starts the individual DNS controllers
func (m *Manager) startControllers() error {
	if m.coreDNSController != nil {
		if err := m.coreDNSController.Start(); err != nil {
			return fmt.Errorf("failed to start CoreDNS controller: %w", err)
		}
	}

	if m.adGuardController != nil {
		if err := m.adGuardController.Start(); err != nil {
			return fmt.Errorf("failed to start AdGuard controller: %w", err)
		}
	}

	if m.mDNSController != nil {
		if err := m.mDNSController.Start(); err != nil {
			return fmt.Errorf("failed to start mDNS controller: %w", err)
		}
	}

	return nil
}

// stopControllers stops the individual DNS controllers
func (m *Manager) stopControllers() {
	if m.coreDNSController != nil {
		if err := m.coreDNSController.Stop(); err != nil {
			log.Printf("Error stopping CoreDNS controller: %v", err)
		}
	}

	if m.adGuardController != nil {
		if err := m.adGuardController.Stop(); err != nil {
			log.Printf("Error stopping AdGuard controller: %v", err)
		}
	}

	if m.mDNSController != nil {
		if err := m.mDNSController.Stop(); err != nil {
			log.Printf("Error stopping mDNS controller: %v", err)
		}
	}
}

// setupInformers sets up Kubernetes informers for custom resources
func (m *Manager) setupInformers() error {
	// In a real implementation, would use client-go's SharedInformerFactory
	// and create informers for all DNS-related CRDs
	
	// This is a simplified placeholder
	log.Println("Setting up CRD informers")
	
	return nil
}

// UpdateDNSZone handles DNS zone updates
func (m *Manager) UpdateDNSZone(zone *DNSZone) error {
	if m.coreDNSController == nil {
		return fmt.Errorf("CoreDNS controller not initialized")
	}

	log.Printf("Updating DNS zone: %s", zone.Name)
	return m.coreDNSController.UpdateZone(zone)
}

// UpdatePTRZone handles PTR zone updates
func (m *Manager) UpdatePTRZone(zone *PTRZone) error {
	if m.coreDNSController == nil {
		return fmt.Errorf("CoreDNS controller not initialized")
	}

	log.Printf("Updating PTR zone: %s", zone.Name)
	return m.coreDNSController.UpdatePTRZone(zone)
}

// UpdateDNSFilters updates DNS filtering rules
func (m *Manager) UpdateDNSFilters(filters *DNSFilterList) error {
	if m.adGuardController == nil {
		return fmt.Errorf("AdGuard controller not initialized")
	}

	log.Printf("Updating DNS filters: %s", filters.Name)
	return m.adGuardController.UpdateFilters(filters)
}

// UpdateDNSClient updates DNS client configuration
func (m *Manager) UpdateDNSClient(client *DNSClient) error {
	if m.adGuardController == nil {
		return fmt.Errorf("AdGuard controller not initialized")
	}

	log.Printf("Updating DNS client: %s", client.Name)
	return m.adGuardController.UpdateClient(client)
}

// UpdateMDNSReflection updates mDNS reflection rules
func (m *Manager) UpdateMDNSReflection(reflection *MDNSReflection) error {
	if m.mDNSController == nil {
		return fmt.Errorf("mDNS controller not initialized")
	}

	log.Printf("Updating mDNS reflection: %s", reflection.Name)
	return m.mDNSController.UpdateReflection(reflection)
}

// UpdateDynamicDNSConfig updates dynamic DNS configuration
func (m *Manager) UpdateDynamicDNSConfig(config *DynamicDNSConfig) error {
	if m.dhcpIntegration == nil {
		return fmt.Errorf("DHCP integration not initialized")
	}

	log.Printf("Updating dynamic DNS config: %s", config.Name)
	return m.dhcpIntegration.UpdateConfig(config)
}

// Sync forces a synchronization of all DNS services
func (m *Manager) Sync() error {
	log.Println("Syncing all DNS services")
	
	// Sync CoreDNS
	if m.coreDNSController != nil {
		if err := m.coreDNSController.Sync(); err != nil {
			return fmt.Errorf("failed to sync CoreDNS: %w", err)
		}
	}
	
	// Sync AdGuard
	if m.adGuardController != nil {
		if err := m.adGuardController.Sync(); err != nil {
			return fmt.Errorf("failed to sync AdGuard: %w", err)
		}
	}
	
	// Sync mDNS
	if m.mDNSController != nil {
		if err := m.mDNSController.Sync(); err != nil {
			return fmt.Errorf("failed to sync mDNS: %w", err)
		}
	}
	
	return nil
}

// Status returns the status of all DNS services
func (m *Manager) Status() (*DNSStatus, error) {
	status := &DNSStatus{
		CoreDNS: &CoreDNSStatus{},
		AdGuard: &AdGuardStatus{},
		MDNS:    &MDNSStatus{},
	}
	
	// Get CoreDNS status
	if m.coreDNSController != nil {
		coreStatus, err := m.coreDNSController.Status()
		if err != nil {
			return nil, fmt.Errorf("failed to get CoreDNS status: %w", err)
		}
		status.CoreDNS = coreStatus
	}
	
	// Get AdGuard status
	if m.adGuardController != nil {
		adGuardStatus, err := m.adGuardController.Status()
		if err != nil {
			return nil, fmt.Errorf("failed to get AdGuard status: %w", err)
		}
		status.AdGuard = adGuardStatus
	}
	
	// Get mDNS status
	if m.mDNSController != nil {
		mdnsStatus, err := m.mDNSController.Status()
		if err != nil {
			return nil, fmt.Errorf("failed to get mDNS status: %w", err)
		}
		status.MDNS = mdnsStatus
	}
	
	return status, nil
}

// AddRecord adds a DNS record to the appropriate zone
func (m *Manager) AddRecord(name, recordType, value string, ttl uint32) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Determine the zone for this record
	zone, err := m.findZoneForRecord(name)
	if err != nil {
		return fmt.Errorf("failed to find zone for record %s: %w", name, err)
	}
	
	// Create the record
	record := &DNSRecord{
		Name:    name,
		Type:    recordType,
		Value:   value,
		TTL:     int32(ttl),
		Dynamic: true,
	}
	
	// Add to CoreDNS
	if m.coreDNSController != nil {
		if err := m.coreDNSController.AddRecord(zone.Domain, record); err != nil {
			return fmt.Errorf("failed to add record to CoreDNS: %w", err)
		}
	}
	
	// Update zone in-memory cache
	for i, existingRecord := range zone.Records {
		if existingRecord.Name == record.Name && existingRecord.Type == record.Type {
			// Replace existing record
			zone.Records[i] = record
			return nil
		}
	}
	
	// Add new record
	zone.Records = append(zone.Records, record)
	return nil
}

// RemoveRecord removes a DNS record from the appropriate zone
func (m *Manager) RemoveRecord(name, recordType, value string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Determine the zone for this record
	zone, err := m.findZoneForRecord(name)
	if err != nil {
		return fmt.Errorf("failed to find zone for record %s: %w", name, err)
	}
	
	// Remove from CoreDNS
	if m.coreDNSController != nil {
		if err := m.coreDNSController.RemoveRecord(zone.Domain, name, recordType, value); err != nil {
			return fmt.Errorf("failed to remove record from CoreDNS: %w", err)
		}
	}
	
	// Update zone in-memory cache
	for i, record := range zone.Records {
		if record.Name == name && record.Type == recordType && record.Value == value {
			// Remove the record
			zone.Records = append(zone.Records[:i], zone.Records[i+1:]...)
			break
		}
	}
	
	return nil
}

// AddReverseRecord adds a reverse (PTR) DNS record
func (m *Manager) AddReverseRecord(ip, target string, ttl uint32) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Convert IP to reverse lookup format
	reverseIP, zone, err := m.convertToReverseLookup(ip)
	if err != nil {
		return fmt.Errorf("failed to convert IP %s to reverse lookup: %w", ip, err)
	}
	
	// Create the PTR record
	record := &DNSRecord{
		Name:    reverseIP,
		Type:    "PTR",
		Value:   target,
		TTL:     int32(ttl),
		Dynamic: true,
	}
	
	// Add to CoreDNS
	if m.coreDNSController != nil {
		if err := m.coreDNSController.AddPTRRecord(zone, record); err != nil {
			return fmt.Errorf("failed to add PTR record to CoreDNS: %w", err)
		}
	}
	
	return nil
}

// RemoveReverseRecord removes a reverse (PTR) DNS record
func (m *Manager) RemoveReverseRecord(ip string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Convert IP to reverse lookup format
	reverseIP, zone, err := m.convertToReverseLookup(ip)
	if err != nil {
		return fmt.Errorf("failed to convert IP %s to reverse lookup: %w", ip, err)
	}
	
	// Remove from CoreDNS
	if m.coreDNSController != nil {
		if err := m.coreDNSController.RemovePTRRecord(zone, reverseIP); err != nil {
			return fmt.Errorf("failed to remove PTR record from CoreDNS: %w", err)
		}
	}
	
	return nil
}

// findZoneForRecord finds the DNS zone for a given record name
func (m *Manager) findZoneForRecord(name string) (*DNSZone, error) {
	// Implementation depends on how zones are stored
	// For now, we'll use a placeholder implementation that just returns a default zone
	defaultZone := &DNSZone{
		Name:   "default",
		Domain: "local",
		TTL:    3600,
		Records: []*DNSRecord{},
	}
	
	return defaultZone, nil
}

// convertToReverseLookup converts an IP address to reverse lookup format
func (m *Manager) convertToReverseLookup(ip string) (string, string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", "", fmt.Errorf("invalid IP address: %s", ip)
	}
	
	if parsedIP.To4() != nil {
		// IPv4 address
		octs := strings.Split(ip, ".")
		reversedOcts := []string{octs[3], octs[2], octs[1], octs[0]}
		reverseIP := strings.Join(reversedOcts, ".")
		return reverseIP, "in-addr.arpa", nil
	} else {
		// IPv6 address
		return reverseIPv6(parsedIP), "ip6.arpa", nil
	}
}