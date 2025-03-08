package coredns

import (
	"fmt"
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

// loadConfiguration loads the CoreDNS configuration from disk
func (c *Controller) loadConfiguration() error {
	// In a real implementation, this would parse CoreDNS configuration files
	// For now, just initialize with empty data
	c.zones = make(map[string]*Zone)
	c.ptrZones = make(map[string]*PTRZone)
	
	// Add default local zone
	c.zones["local"] = &Zone{
		Name:    "local",
		Domain:  "local",
		Records: make([]*DNSRecord, 0),
		SOA:     defaultSOA("local"),
	}
	
	// Add default reverse zones
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

// saveConfiguration saves the CoreDNS configuration to disk
func (c *Controller) saveConfiguration() error {
	// In a real implementation, this would write to CoreDNS configuration files
	// and possibly reload CoreDNS
	
	// For now, just simulate a save
	for _, zone := range c.zones {
		zone.ConfigGen++
	}
	
	for _, zone := range c.ptrZones {
		zone.ConfigGen++
	}
	
	return nil
}

// applyConfiguration applies the current configuration to CoreDNS
func (c *Controller) applyConfiguration() error {
	// In a real implementation, this would reload CoreDNS or use its API
	// For now, just simulate an apply
	c.lastReload = time.Now()
	return nil
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
