package coredns

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Controller manages CoreDNS configuration and operations
type Controller struct {
	// Configuration
	configPath string
	zonesPath  string
	
	// Runtime state
	zones         map[string]*Zone
	ptrZones      map[string]*PTRZone
	mutex         sync.RWMutex
	lastReload    time.Time
	lastError     string
	lastErrorTime time.Time
}

// Zone represents a DNS zone managed by CoreDNS
type Zone struct {
	Name      string
	Domain    string
	Records   []*DNSRecord
	SOA       *SOARecord
	Updated   time.Time
	ConfigGen int64
}

// PTRZone represents a reverse DNS zone managed by CoreDNS
type PTRZone struct {
	Name      string
	Network   string
	Records   []*DNSRecord
	SOA       *SOARecord
	Updated   time.Time
	ConfigGen int64
}

// DNSRecord represents a DNS record
type DNSRecord struct {
	Name    string
	Type    string
	Value   string
	TTL     int32
	Dynamic bool
}

// SOARecord represents a Start of Authority record
type SOARecord struct {
	MName   string
	RName   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

// NewController creates a new CoreDNS controller
func NewController(configPath, zonesPath string) (*Controller, error) {
	if configPath == "" {
		return nil, fmt.Errorf("CoreDNS config path is required")
	}
	
	if zonesPath == "" {
		// Default to config path if not specified
		zonesPath = configPath
	}
	
	return &Controller{
		configPath: configPath,
		zonesPath:  zonesPath,
		zones:      make(map[string]*Zone),
		ptrZones:   make(map[string]*PTRZone),
	}, nil
}

// Start starts the CoreDNS controller
func (c *Controller) Start() error {
	// Load existing configuration
	if err := c.loadConfiguration(); err != nil {
		return fmt.Errorf("failed to load CoreDNS configuration: %w", err)
	}
	
	// Apply configuration to CoreDNS
	if err := c.applyConfiguration(); err != nil {
		return fmt.Errorf("failed to apply CoreDNS configuration: %w", err)
	}
	
	return nil
}

// Stop stops the CoreDNS controller
func (c *Controller) Stop() error {
	// Save any pending changes
	if err := c.saveConfiguration(); err != nil {
		return fmt.Errorf("failed to save CoreDNS configuration during shutdown: %w", err)
	}
	
	return nil
}

// AddRecord adds a DNS record to a zone
func (c *Controller) AddRecord(zoneName string, record *DNSRecord) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Find the zone
	zone, ok := c.zones[zoneName]
	if !ok {
		// Zone doesn't exist, create it
		zone = &Zone{
			Name:    zoneName,
			Domain:  zoneName,
			Records: make([]*DNSRecord, 0),
			SOA:     defaultSOA(zoneName),
		}
		c.zones[zoneName] = zone
	}
	
	// Check if record already exists
	for i, existingRecord := range zone.Records {
		if existingRecord.Name == record.Name && existingRecord.Type == record.Type {
			// Replace existing record
			zone.Records[i] = record
			zone.Updated = time.Now()
			return c.saveConfiguration()
		}
	}
	
	// Add new record
	zone.Records = append(zone.Records, record)
	zone.Updated = time.Now()
	
	// Save configuration
	return c.saveConfiguration()
}

// RemoveRecord removes a DNS record from a zone
func (c *Controller) RemoveRecord(zoneName, name, recordType, value string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Find the zone
	zone, ok := c.zones[zoneName]
	if !ok {
		return fmt.Errorf("zone %s not found", zoneName)
	}
	
	// Find and remove the record
	for i, record := range zone.Records {
		if record.Name == name && record.Type == recordType && (value == "" || record.Value == value) {
			// Remove the record
			zone.Records = append(zone.Records[:i], zone.Records[i+1:]...)
			zone.Updated = time.Now()
			return c.saveConfiguration()
		}
	}
	
	return fmt.Errorf("record not found: %s %s", name, recordType)
}

// AddPTRRecord adds a PTR record to a reverse zone
func (c *Controller) AddPTRRecord(zoneName string, record *DNSRecord) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Find the zone
	zone, ok := c.ptrZones[zoneName]
	if !ok {
		// Zone doesn't exist, create it
		zone = &PTRZone{
			Name:    zoneName,
			Network: zoneName,
			Records: make([]*DNSRecord, 0),
			SOA:     defaultSOA(zoneName),
		}
		c.ptrZones[zoneName] = zone
	}
	
	// Check if record already exists
	for i, existingRecord := range zone.Records {
		if existingRecord.Name == record.Name && existingRecord.Type == record.Type {
			// Replace existing record
			zone.Records[i] = record
			zone.Updated = time.Now()
			return c.saveConfiguration()
		}
	}
	
	// Add new record
	zone.Records = append(zone.Records, record)
	zone.Updated = time.Now()
	
	// Save configuration
	return c.saveConfiguration()
}

// RemovePTRRecord removes a PTR record from a reverse zone
func (c *Controller) RemovePTRRecord(zoneName, name string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Find the zone
	zone, ok := c.ptrZones[zoneName]
	if !ok {
		return fmt.Errorf("PTR zone %s not found", zoneName)
	}
	
	// Find and remove the record
	for i, record := range zone.Records {
		if record.Name == name && record.Type == "PTR" {
			// Remove the record
			zone.Records = append(zone.Records[:i], zone.Records[i+1:]...)
			zone.Updated = time.Now()
			return c.saveConfiguration()
		}
	}
	
	return fmt.Errorf("PTR record not found: %s", name)
}

// Sync forces a synchronization of all CoreDNS zones
func (c *Controller) Sync() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Apply configuration to CoreDNS
	if err := c.applyConfiguration(); err != nil {
		c.lastError = err.Error()
		c.lastErrorTime = time.Now()
		return fmt.Errorf("failed to apply CoreDNS configuration: %w", err)
	}
	
	c.lastReload = time.Now()
	return nil
}

// Status returns the status of CoreDNS
func (c *Controller) Status() (*CoreDNSStatus, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	status := &CoreDNSStatus{
		Running:     true, // Assume CoreDNS is running
		Zones:       len(c.zones) + len(c.ptrZones),
		RecordsServed: c.countRecords(),
		QueryRate:    0, // Would need metrics integration to get actual rates
		CacheHitRate: 0,
		ErrorRate:    0,
		LastError:    c.lastError,
		LastErrorTime: c.lastErrorTime,
	}
	
	return status, nil
}

// CoreDNSStatus represents the status of CoreDNS
type CoreDNSStatus struct {
	Running        bool
	Zones          int
	RecordsServed  int
	QueryRate      float64
	CacheHitRate   float64
	ErrorRate      float64
	LastError      string
	LastErrorTime  time.Time
}

// Helper functions

// loadConfiguration loads the CoreDNS configuration from disk.
// It scans the zones directory for zone files (db.*) and parses each one.
// If no zone files exist, it initializes default zones.
func (c *Controller) loadConfiguration() error {
	c.zones = make(map[string]*Zone)
	c.ptrZones = make(map[string]*PTRZone)

	// Try to read existing zone files from the zones directory
	entries, err := os.ReadDir(c.zonesPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist yet; initialize defaults
			return c.initDefaults()
		}
		return fmt.Errorf("failed to read zones directory %s: %w", c.zonesPath, err)
	}

	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isZoneFile(name) {
			continue
		}

		// Derive zone name from filename: db.example.com -> example.com
		zoneName := strings.TrimPrefix(name, "db.")
		path := filepath.Join(c.zonesPath, name)

		zone, parseErr := ParseZoneFile(path, zoneName)
		if parseErr != nil {
			// Log but continue loading other zones
			c.lastError = fmt.Sprintf("failed to parse zone file %s: %v", path, parseErr)
			c.lastErrorTime = time.Now()
			continue
		}

		// Reverse zones go into ptrZones
		if strings.HasSuffix(zoneName, ".arpa") || strings.HasSuffix(zoneName, ".arpa.") {
			c.ptrZones[zoneName] = &PTRZone{
				Name:      zone.Name,
				Network:   zone.Domain,
				Records:   zone.Records,
				SOA:       zone.SOA,
				Updated:   zone.Updated,
				ConfigGen: zone.ConfigGen,
			}
		} else {
			c.zones[zoneName] = zone
		}
		loaded++
	}

	// If no zones were loaded, initialize defaults
	if loaded == 0 {
		return c.initDefaults()
	}

	return nil
}

// initDefaults creates default zones when no zone files exist on disk.
func (c *Controller) initDefaults() error {
	c.zones["local"] = &Zone{
		Name:    "local",
		Domain:  "local",
		Records: make([]*DNSRecord, 0),
		SOA:     defaultSOA("local"),
	}

	c.ptrZones["in-addr.arpa"] = &PTRZone{
		Name:    "in-addr.arpa",
		Network: "in-addr.arpa",
		Records: make([]*DNSRecord, 0),
		SOA:     defaultSOA("in-addr.arpa"),
	}

	c.ptrZones["ip6.arpa"] = &PTRZone{
		Name:    "ip6.arpa",
		Network: "ip6.arpa",
		Records: make([]*DNSRecord, 0),
		SOA:     defaultSOA("ip6.arpa"),
	}

	return nil
}

// saveConfiguration saves the CoreDNS configuration to disk.
// It writes each forward and reverse zone as an RFC 1035 zone file,
// incrementing the SOA serial on each save.
func (c *Controller) saveConfiguration() error {
	// Ensure the zones directory exists
	if err := os.MkdirAll(c.zonesPath, 0755); err != nil {
		return fmt.Errorf("failed to create zones directory %s: %w", c.zonesPath, err)
	}

	// Write forward zones
	for _, zone := range c.zones {
		IncrementSerial(zone)
		zone.ConfigGen++
		path := filepath.Join(c.zonesPath, zoneFileName(zone.Domain))
		if err := WriteZoneFile(zone, path); err != nil {
			return fmt.Errorf("failed to write zone file for %s: %w", zone.Domain, err)
		}
	}

	// Write reverse zones (convert PTRZone to Zone for writing)
	for _, ptrZone := range c.ptrZones {
		tmpZone := &Zone{
			Name:      ptrZone.Name,
			Domain:    ptrZone.Network,
			Records:   ptrZone.Records,
			SOA:       ptrZone.SOA,
			Updated:   ptrZone.Updated,
			ConfigGen: ptrZone.ConfigGen,
		}
		IncrementSerial(tmpZone)
		ptrZone.ConfigGen++
		ptrZone.SOA = tmpZone.SOA
		path := filepath.Join(c.zonesPath, zoneFileName(ptrZone.Network))
		if err := WriteZoneFile(tmpZone, path); err != nil {
			return fmt.Errorf("failed to write PTR zone file for %s: %w", ptrZone.Network, err)
		}
	}

	return nil
}

// applyConfiguration applies the current configuration to CoreDNS.
// It saves all zone files and triggers a CoreDNS reload via file modification times.
func (c *Controller) applyConfiguration() error {
	if err := c.saveConfiguration(); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	if err := ReloadZones(c.zonesPath); err != nil {
		// ReloadZones may fail if the directory is empty or has no zone files yet.
		// This is not fatal during initial startup.
		c.lastError = fmt.Sprintf("reload warning: %v", err)
		c.lastErrorTime = time.Now()
	}

	c.lastReload = time.Now()
	return nil
}

// GetZone returns a zone by name, or nil if not found.
func (c *Controller) GetZone(name string) *Zone {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.zones[name]
}

// GetPTRZone returns a PTR zone by name, or nil if not found.
func (c *Controller) GetPTRZone(name string) *PTRZone {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.ptrZones[name]
}

// ListZones returns the names of all forward zones.
func (c *Controller) ListZones() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	names := make([]string, 0, len(c.zones))
	for name := range c.zones {
		names = append(names, name)
	}
	return names
}

// UpdateZone replaces or creates a forward zone with the given records and SOA,
// writes the zone file to disk, and triggers a CoreDNS reload.
func (c *Controller) UpdateZone(zone *Zone) error {
	if zone == nil {
		return fmt.Errorf("zone is nil")
	}
	if zone.Domain == "" {
		return fmt.Errorf("zone domain is required")
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Ensure SOA is set
	if zone.SOA == nil {
		zone.SOA = defaultSOA(zone.Domain)
	}
	zone.Updated = time.Now()

	c.zones[zone.Domain] = zone

	return c.applyConfiguration()
}

// UpdatePTRZone replaces or creates a reverse zone with the given records and SOA,
// writes the zone file to disk, and triggers a CoreDNS reload.
func (c *Controller) UpdatePTRZone(ptrZone *PTRZone) error {
	if ptrZone == nil {
		return fmt.Errorf("PTR zone is nil")
	}
	if ptrZone.Name == "" {
		return fmt.Errorf("PTR zone name is required")
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Ensure SOA is set
	if ptrZone.SOA == nil {
		ptrZone.SOA = defaultSOA(ptrZone.Name)
	}
	ptrZone.Updated = time.Now()

	c.ptrZones[ptrZone.Name] = ptrZone

	return c.applyConfiguration()
}

// countRecords counts the total number of records across all zones
func (c *Controller) countRecords() int {
	count := 0
	
	for _, zone := range c.zones {
		count += len(zone.Records)
	}
	
	for _, zone := range c.ptrZones {
		count += len(zone.Records)
	}
	
	return count
}

// defaultSOA creates a default SOA record for a zone
func defaultSOA(domain string) *SOARecord {
	return &SOARecord{
		MName:   fmt.Sprintf("ns1.%s.", domain),
		RName:   fmt.Sprintf("admin.%s.", domain),
		Serial:  uint32(time.Now().Unix()),
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: 3600,
	}
}
