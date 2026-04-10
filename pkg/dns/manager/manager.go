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

type coreDNSController interface {
	Start() error
	Stop() error
	Sync() error
	Status() (*coredns.CoreDNSStatus, error)
	AddRecord(zoneName string, record *coredns.DNSRecord) error
	RemoveRecord(zoneName, name, recordType, value string) error
	AddPTRRecord(zoneName string, record *coredns.DNSRecord) error
	RemovePTRRecord(zoneName, name string) error
	UpdateZone(zone *coredns.Zone) error
	UpdatePTRZone(ptrZone *coredns.PTRZone) error
	GetZone(name string) *coredns.Zone
	ListZones() []string
}

type adGuardController interface {
	Start() error
	Stop() error
	Sync() error
	Status() (*adguard.AdGuardStatus, error)
	UpdateFilterList(name, url string, enabled bool) error
	RemoveFilterList(name string) error
	UpdateClientRule(clientID, clientName string, addresses []string, enabled bool, blockLists, allowLists []string) error
	RemoveClientRule(clientID string) error
}

type mdnsController interface {
	Start() error
	Stop() error
	Sync() error
	Status() (*mdns.MDNSStatus, error)
	UpdateReflectionRule(name string, sourceVLANs, destinationVLANs []int, serviceTypes []string, enabled bool) error
	RemoveReflectionRule(name string) error
	EnableReflection(enabled bool) error
}

// Manager coordinates all DNS services
type Manager struct {
	// Component controllers
	coreDNSController coreDNSController
	adGuardController adGuardController
	mDNSController    mdnsController

	// Zone cache for record lookup
	zones map[string]*DNSZone

	// Integration
	dhcpIntegration  *DHCPIntegration
	metricsCollector *MetricsCollector

	// API and status
	apiServer *APIServer

	// Control
	k8sClient kubernetes.Interface
	informers []cache.SharedInformer
	ctx       context.Context
	cancel    context.CancelFunc
	mutex     sync.RWMutex
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
	coreController coreDNSController,
	adGuardController adGuardController,
	mDNSController mdnsController,
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
		zones:             make(map[string]*DNSZone),
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

// UpdateDNSZone handles DNS zone updates by converting the manager zone
// representation to a CoreDNS zone and delegating to the CoreDNS controller,
// which writes the zone file to disk and triggers a reload.
func (m *Manager) UpdateDNSZone(zone *DNSZone) error {
	if m.coreDNSController == nil {
		return fmt.Errorf("CoreDNS controller not initialized")
	}
	if zone == nil {
		return fmt.Errorf("zone is nil")
	}

	log.Printf("Updating DNS zone: %s", zone.Name)

	// Convert manager zone to CoreDNS zone
	coreZone := &coredns.Zone{
		Name:    zone.Name,
		Domain:  zone.Domain,
		Records: make([]*coredns.DNSRecord, 0, len(zone.Records)),
	}

	if zone.SOA != nil {
		coreZone.SOA = &coredns.SOARecord{
			MName:   zone.SOA.MName,
			RName:   zone.SOA.RName,
			Serial:  zone.SOA.Serial,
			Refresh: zone.SOA.Refresh,
			Retry:   zone.SOA.Retry,
			Expire:  zone.SOA.Expire,
			Minimum: zone.SOA.Minimum,
		}
	}

	for _, rec := range zone.Records {
		coreZone.Records = append(coreZone.Records, &coredns.DNSRecord{
			Name:    rec.Name,
			Type:    rec.Type,
			Value:   rec.Value,
			TTL:     rec.TTL,
			Dynamic: rec.Dynamic,
		})
	}

	if err := m.coreDNSController.UpdateZone(coreZone); err != nil {
		return fmt.Errorf("failed to update zone %s via CoreDNS controller: %w", zone.Domain, err)
	}

	// Cache the zone locally for lookup
	m.mutex.Lock()
	m.zones[zone.Domain] = zone
	m.mutex.Unlock()

	return nil
}

// UpdatePTRZone handles PTR zone updates by converting the manager PTR zone
// representation to a CoreDNS PTR zone and delegating to the CoreDNS controller,
// which writes the reverse zone file to disk and triggers a reload.
func (m *Manager) UpdatePTRZone(zone *PTRZone) error {
	if m.coreDNSController == nil {
		return fmt.Errorf("CoreDNS controller not initialized")
	}
	if zone == nil {
		return fmt.Errorf("PTR zone is nil")
	}

	log.Printf("Updating PTR zone: %s", zone.Name)

	// Convert manager PTR zone to CoreDNS PTR zone
	corePTRZone := &coredns.PTRZone{
		Name:    zone.Name,
		Network: zone.Network,
		Records: make([]*coredns.DNSRecord, 0, len(zone.Records)),
	}

	if zone.SOA != nil {
		corePTRZone.SOA = &coredns.SOARecord{
			MName:   zone.SOA.MName,
			RName:   zone.SOA.RName,
			Serial:  zone.SOA.Serial,
			Refresh: zone.SOA.Refresh,
			Retry:   zone.SOA.Retry,
			Expire:  zone.SOA.Expire,
			Minimum: zone.SOA.Minimum,
		}
	}

	for _, rec := range zone.Records {
		corePTRZone.Records = append(corePTRZone.Records, &coredns.DNSRecord{
			Name:    rec.Name,
			Type:    rec.Type,
			Value:   rec.Value,
			TTL:     rec.TTL,
			Dynamic: rec.Dynamic,
		})
	}

	if err := m.coreDNSController.UpdatePTRZone(corePTRZone); err != nil {
		return fmt.Errorf("failed to update PTR zone %s via CoreDNS controller: %w", zone.Name, err)
	}

	return nil
}

// UpdateDNSFilters updates DNS filtering rules by syncing each custom filter
// list to the AdGuard controller, which persists the configuration and applies it.
func (m *Manager) UpdateDNSFilters(filters *DNSFilterList) error {
	if m.adGuardController == nil {
		return fmt.Errorf("AdGuard controller not initialized")
	}
	if filters == nil {
		return fmt.Errorf("filters is nil")
	}

	log.Printf("Updating DNS filters: %s", filters.Name)

	// Sync each custom filter list to AdGuard
	for _, customList := range filters.CustomLists {
		if err := m.adGuardController.UpdateFilterList(customList.Name, customList.URL, customList.Enabled); err != nil {
			return fmt.Errorf("failed to update filter list %s via AdGuard controller: %w", customList.Name, err)
		}
	}

	return nil
}

// UpdateDNSClient updates DNS client configuration by converting the manager
// client representation to AdGuard controller parameters and delegating the update.
func (m *Manager) UpdateDNSClient(client *DNSClient) error {
	if m.adGuardController == nil {
		return fmt.Errorf("AdGuard controller not initialized")
	}
	if client == nil {
		return fmt.Errorf("client is nil")
	}

	log.Printf("Updating DNS client: %s", client.Name)

	// Extract client addresses from identifiers
	addresses := make([]string, 0, len(client.Identifiers))
	for _, id := range client.Identifiers {
		addresses = append(addresses, id.Value)
	}

	if err := m.adGuardController.UpdateClientRule(
		client.Name,
		client.Description,
		addresses,
		client.Filtering.Enabled,
		client.Filtering.BlockLists,
		client.Filtering.Exceptions,
	); err != nil {
		return fmt.Errorf("failed to update client %s via AdGuard controller: %w", client.Name, err)
	}

	return nil
}

// UpdateMDNSReflection updates mDNS reflection rules by syncing each rule
// to the mDNS controller and updating the global reflection enabled state.
func (m *Manager) UpdateMDNSReflection(reflection *MDNSReflection) error {
	if m.mDNSController == nil {
		return fmt.Errorf("mDNS controller not initialized")
	}
	if reflection == nil {
		return fmt.Errorf("reflection is nil")
	}

	log.Printf("Updating mDNS reflection: %s", reflection.Name)

	// Update global reflection state
	if err := m.mDNSController.EnableReflection(reflection.Enabled); err != nil {
		return fmt.Errorf("failed to set reflection enabled state: %w", err)
	}

	// Sync each reflection rule
	for _, rule := range reflection.ReflectionRules {
		if err := m.mDNSController.UpdateReflectionRule(
			rule.Name,
			rule.SourceVLANs,
			rule.DestinationVLANs,
			rule.ServiceTypes,
			reflection.Enabled,
		); err != nil {
			return fmt.Errorf("failed to update reflection rule %s via mDNS controller: %w", rule.Name, err)
		}
	}

	return nil
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
		status.CoreDNS = &CoreDNSStatus{
			Running:       coreStatus.Running,
			Zones:         coreStatus.Zones,
			RecordsServed: coreStatus.RecordsServed,
			QueryRate:     coreStatus.QueryRate,
			CacheHitRate:  coreStatus.CacheHitRate,
			ErrorRate:     coreStatus.ErrorRate,
			LastError:     coreStatus.LastError,
			LastErrorTime: coreStatus.LastErrorTime,
		}
	}

	// Get AdGuard status
	if m.adGuardController != nil {
		adGuardStatus, err := m.adGuardController.Status()
		if err != nil {
			return nil, fmt.Errorf("failed to get AdGuard status: %w", err)
		}
		status.AdGuard = &AdGuardStatus{
			Running:           adGuardStatus.Running,
			FilteringEnabled:  adGuardStatus.FilteringEnabled,
			BlockedQueries:    adGuardStatus.BlockedQueries,
			TotalQueries:      adGuardStatus.TotalQueries,
			BlockRate:         adGuardStatus.BlockRate,
			AvgProcessingTime: adGuardStatus.AvgProcessingTime,
			LastError:         adGuardStatus.LastError,
			LastErrorTime:     adGuardStatus.LastErrorTime,
		}
	}

	// Get mDNS status
	if m.mDNSController != nil {
		mdnsStatus, err := m.mDNSController.Status()
		if err != nil {
			return nil, fmt.Errorf("failed to get mDNS status: %w", err)
		}
		status.MDNS = &MDNSStatus{
			Running:           mdnsStatus.Running,
			ReflectionEnabled: mdnsStatus.ReflectionEnabled,
			ReflectionRules:   mdnsStatus.ReflectionRules,
			ServicesReflected: mdnsStatus.ServicesReflected,
			LastError:         mdnsStatus.LastError,
			LastErrorTime:     mdnsStatus.LastErrorTime,
		}
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
		coreRecord := &coredns.DNSRecord{
			Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL, Dynamic: record.Dynamic,
		}
		if err := m.coreDNSController.AddRecord(zone.Domain, coreRecord); err != nil {
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
		coreRecord := &coredns.DNSRecord{
			Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL, Dynamic: record.Dynamic,
		}
		if err := m.coreDNSController.AddPTRRecord(zone, coreRecord); err != nil {
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

// findZoneForRecord finds the DNS zone for a given record name by checking the
// local zone cache and the CoreDNS controller's zone list for the longest
// matching domain suffix.
// The caller must already hold m.mutex (read or write).
func (m *Manager) findZoneForRecord(name string) (*DNSZone, error) {
	// Collect all known zone names from cache and CoreDNS controller
	zoneNames := make(map[string]bool)
	for domain := range m.zones {
		zoneNames[domain] = true
	}

	if m.coreDNSController != nil {
		for _, zn := range m.coreDNSController.ListZones() {
			zoneNames[zn] = true
		}
	}

	// Find the longest matching zone suffix for the record name
	var bestMatch string
	normalizedName := strings.TrimSuffix(name, ".")

	for domain := range zoneNames {
		normalizedDomain := strings.TrimSuffix(domain, ".")
		if normalizedName == normalizedDomain || strings.HasSuffix(normalizedName, "."+normalizedDomain) {
			if len(normalizedDomain) > len(bestMatch) {
				bestMatch = normalizedDomain
			}
		}
	}

	if bestMatch != "" {
		// Check local cache first
		if zone, ok := m.zones[bestMatch]; ok {
			return zone, nil
		}

		// Fall back to CoreDNS controller state
		if m.coreDNSController != nil {
			coreZone := m.coreDNSController.GetZone(bestMatch)
			if coreZone != nil {
				// Convert to manager zone
				zone := &DNSZone{
					Name:    coreZone.Name,
					Domain:  coreZone.Domain,
					Records: make([]*DNSRecord, 0, len(coreZone.Records)),
				}
				for _, rec := range coreZone.Records {
					zone.Records = append(zone.Records, &DNSRecord{
						Name:    rec.Name,
						Type:    rec.Type,
						Value:   rec.Value,
						TTL:     rec.TTL,
						Dynamic: rec.Dynamic,
					})
				}
				return zone, nil
			}
		}
	}

	// No matching zone found; return a default zone so individual record
	// operations can still proceed (the CoreDNS controller auto-creates
	// zones on first record addition).
	return &DNSZone{
		Name:    "local",
		Domain:  "local",
		TTL:     3600,
		Records: []*DNSRecord{},
	}, nil
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
