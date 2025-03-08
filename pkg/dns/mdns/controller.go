package mdns

import (
	"fmt"
	"sync"
	"time"
)

// Controller manages mDNS reflection
type Controller struct {
	// Configuration
	configPath      string
	reflectionRules map[string]*ReflectionRule
	serviceTypes    map[string]*ServiceType
	
	// Runtime state
	reflectionEnabled bool
	servicesReflected int64
	mutex            sync.RWMutex
	lastReload       time.Time
	lastError        string
	lastErrorTime    time.Time
}

// ReflectionRule defines a rule for mDNS reflection
type ReflectionRule struct {
	Name             string
	SourceVLANs      []int
	DestinationVLANs []int
	ServiceTypes     []string
	Enabled          bool
	LastUpdated      time.Time
}

// ServiceType defines a mDNS service type
type ServiceType struct {
	Name        string
	Description string
	Type        string // Service type in format _service._protocol.local.
	DefaultPorts []int
}

// NewController creates a new mDNS controller
func NewController(configPath string) (*Controller, error) {
	if configPath == "" {
		return nil, fmt.Errorf("mDNS config path is required")
	}
	
	return &Controller{
		configPath:        configPath,
		reflectionRules:   make(map[string]*ReflectionRule),
		serviceTypes:      make(map[string]*ServiceType),
		reflectionEnabled: false,
	}, nil
}

// Start starts the mDNS controller
func (c *Controller) Start() error {
	// Load existing configuration
	if err := c.loadConfiguration(); err != nil {
		return fmt.Errorf("failed to load mDNS configuration: %w", err)
	}
	
	// Apply configuration to mDNS
	if err := c.applyConfiguration(); err != nil {
		return fmt.Errorf("failed to apply mDNS configuration: %w", err)
	}
	
	return nil
}

// Stop stops the mDNS controller
func (c *Controller) Stop() error {
	// Save any pending changes
	if err := c.saveConfiguration(); err != nil {
		return fmt.Errorf("failed to save mDNS configuration during shutdown: %w", err)
	}
	
	// Disable reflection
	c.reflectionEnabled = false
	
	return nil
}

// UpdateReflectionRule updates or adds a mDNS reflection rule
func (c *Controller) UpdateReflectionRule(name string, sourceVLANs, destinationVLANs []int, serviceTypes []string, enabled bool) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Check if reflection rule already exists
	rule, exists := c.reflectionRules[name]
	if exists {
		rule.SourceVLANs = sourceVLANs
		rule.DestinationVLANs = destinationVLANs
		rule.ServiceTypes = serviceTypes
		rule.Enabled = enabled
		rule.LastUpdated = time.Now()
	} else {
		// Create new reflection rule
		rule = &ReflectionRule{
			Name:             name,
			SourceVLANs:      sourceVLANs,
			DestinationVLANs: destinationVLANs,
			ServiceTypes:     serviceTypes,
			Enabled:          enabled,
			LastUpdated:      time.Now(),
		}
		c.reflectionRules[name] = rule
	}
	
	// Update reflection status
	c.updateReflectionStatus()
	
	// Save configuration
	return c.saveConfiguration()
}

// RemoveReflectionRule removes a mDNS reflection rule
func (c *Controller) RemoveReflectionRule(name string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Check if reflection rule exists
	if _, exists := c.reflectionRules[name]; !exists {
		return fmt.Errorf("reflection rule %s not found", name)
	}
	
	// Remove reflection rule
	delete(c.reflectionRules, name)
	
	// Update reflection status
	c.updateReflectionStatus()
	
	// Save configuration
	return c.saveConfiguration()
}

// EnableReflection enables or disables mDNS reflection globally
func (c *Controller) EnableReflection(enabled bool) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Update reflection status
	c.reflectionEnabled = enabled
	
	// Save configuration
	return c.saveConfiguration()
}

// AddServiceType adds or updates a supported mDNS service type
func (c *Controller) AddServiceType(name, description, serviceType string, defaultPorts []int) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Create or update service type
	c.serviceTypes[name] = &ServiceType{
		Name:        name,
		Description: description,
		Type:        serviceType,
		DefaultPorts: defaultPorts,
	}
	
	// Save configuration
	return c.saveConfiguration()
}

// RemoveServiceType removes a supported mDNS service type
func (c *Controller) RemoveServiceType(name string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Check if service type exists
	if _, exists := c.serviceTypes[name]; !exists {
		return fmt.Errorf("service type %s not found", name)
	}
	
	// Remove service type
	delete(c.serviceTypes, name)
	
	// Save configuration
	return c.saveConfiguration()
}

// Sync forces a synchronization of mDNS reflection
func (c *Controller) Sync() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Apply configuration to mDNS
	if err := c.applyConfiguration(); err != nil {
		c.lastError = err.Error()
		c.lastErrorTime = time.Now()
		return fmt.Errorf("failed to apply mDNS configuration: %w", err)
	}
	
	c.lastReload = time.Now()
	return nil
}

// Status returns the status of mDNS reflection
func (c *Controller) Status() (*MDNSStatus, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	status := &MDNSStatus{
		Running:           true, // Assume mDNS reflection is running
		ReflectionEnabled: c.reflectionEnabled,
		ReflectionRules:   len(c.reflectionRules),
		ServicesReflected: c.servicesReflected,
		LastError:         c.lastError,
		LastErrorTime:     c.lastErrorTime,
	}
	
	return status, nil
}

// MDNSStatus represents the status of mDNS reflection
type MDNSStatus struct {
	Running           bool
	ReflectionEnabled bool
	ReflectionRules   int
	ServicesReflected int64
	LastError         string
	LastErrorTime     time.Time
}

// Helper functions

// loadConfiguration loads the mDNS configuration from disk
func (c *Controller) loadConfiguration() error {
	// In a real implementation, this would parse mDNS configuration files
	// For now, just initialize with empty data
	c.reflectionRules = make(map[string]*ReflectionRule)
	c.serviceTypes = make(map[string]*ServiceType)
	
	// Add some default service types
	c.serviceTypes["airplay"] = &ServiceType{
		Name:        "AirPlay",
		Description: "Apple AirPlay",
		Type:        "_airplay._tcp.local.",
		DefaultPorts: []int{7000},
	}
	
	c.serviceTypes["homekit"] = &ServiceType{
		Name:        "HomeKit",
		Description: "Apple HomeKit",
		Type:        "_hap._tcp.local.",
		DefaultPorts: []int{8080},
	}
	
	c.serviceTypes["chromecast"] = &ServiceType{
		Name:        "Chromecast",
		Description: "Google Chromecast",
		Type:        "_googlecast._tcp.local.",
		DefaultPorts: []int{8009},
	}
	
	return nil
}

// saveConfiguration saves the mDNS configuration to disk
func (c *Controller) saveConfiguration() error {
	// In a real implementation, this would write to mDNS configuration files
	// For now, just simulate a save
	return nil
}

// applyConfiguration applies the current configuration to mDNS
func (c *Controller) applyConfiguration() error {
	// In a real implementation, this would reload mDNS or use its API
	// For now, just simulate an apply
	c.lastReload = time.Now()
	return nil
}

// updateReflectionStatus updates the reflection status based on the rules
func (c *Controller) updateReflectionStatus() {
	// Check if any rules are enabled
	for _, rule := range c.reflectionRules {
		if rule.Enabled {
			c.reflectionEnabled = true
			return
		}
	}
	
	// No enabled rules
	c.reflectionEnabled = false
}
