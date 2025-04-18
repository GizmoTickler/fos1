package manager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/ntp"
	"github.com/varuntirumala1/fos1/pkg/ntp/chrony"
	"github.com/varuntirumala1/fos1/pkg/ntp/metrics"
)

// Manager coordinates all NTP services
type Manager struct {
	// Component controllers
	chronyManager    *chrony.Manager
	configGenerator  *chrony.ConfigGenerator
	exporterManager  *metrics.Exporter

	// Integration
	dhcpIntegration  *DHCPIntegration
	dnsIntegration   *DNSIntegration

	// API and status
	apiServer       *APIServer

	// Control
	k8sClient       kubernetes.Interface
	ctx             context.Context
	cancel          context.CancelFunc
	mutex           sync.RWMutex
}

// Config holds NTP Manager configuration
type Config struct {
	EnableDHCPIntegration bool
	EnableDNSIntegration  bool
	MetricsEnabled        bool
	APIEnabled            bool
	ChronyConfigPath      string
	ChronyKeysPath        string
	ChronyCommand         string
	MetricsPort           int
	MetricsInterval       time.Duration
}

// NewManager creates a new NTP Manager
func NewManager(
	client kubernetes.Interface,
	config *Config) (*Manager, error) {

	if client == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}

	if config == nil {
		config = &Config{
			EnableDHCPIntegration: true,
			EnableDNSIntegration:  true,
			MetricsEnabled:        true,
			APIEnabled:            true,
			ChronyConfigPath:      "/etc/chrony/chrony.conf",
			ChronyKeysPath:        "/etc/chrony/chrony.keys",
			ChronyCommand:         "chronyc",
			MetricsPort:           9559,
			MetricsInterval:       15 * time.Second,
		}
	}

	// Create context for management
	ctx, cancel := context.WithCancel(context.Background())

	// Create Chrony manager
	chronyManager := chrony.NewManager(
		config.ChronyConfigPath,
		config.ChronyKeysPath,
		config.ChronyCommand,
	)

	// Create config generator
	configGenerator := chrony.NewConfigGenerator()

	// Create main manager
	manager := &Manager{
		chronyManager:   chronyManager,
		configGenerator: configGenerator,
		k8sClient:       client,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Initialize metrics exporter if enabled
	if config.MetricsEnabled {
		exporterConfig := &metrics.Config{
			Port:          config.MetricsPort,
			Interval:      config.MetricsInterval,
			ChronyManager: chronyManager,
		}

		exporter, err := metrics.NewExporter(exporterConfig)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to initialize metrics exporter: %w", err)
		}
		manager.exporterManager = exporter
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

	// Initialize DNS integration if enabled
	if config.EnableDNSIntegration {
		dnsIntegration, err := NewDNSIntegration(manager)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to initialize DNS integration: %w", err)
		}
		manager.dnsIntegration = dnsIntegration
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

// Start starts the NTP Manager
func (m *Manager) Start() error {
	klog.Info("Starting NTP Manager")

	// Start metrics exporter if configured
	if m.exporterManager != nil {
		if err := m.exporterManager.Start(); err != nil {
			return fmt.Errorf("failed to start metrics exporter: %w", err)
		}
	}

	// Start DHCP integration if configured
	if m.dhcpIntegration != nil {
		if err := m.dhcpIntegration.Start(); err != nil {
			return fmt.Errorf("failed to start DHCP integration: %w", err)
		}
	}

	// Start DNS integration if configured
	if m.dnsIntegration != nil {
		if err := m.dnsIntegration.Start(); err != nil {
			return fmt.Errorf("failed to start DNS integration: %w", err)
		}
	}

	// Start API server if configured
	if m.apiServer != nil {
		if err := m.apiServer.Start(); err != nil {
			return fmt.Errorf("failed to start API server: %w", err)
		}
	}

	klog.Info("NTP Manager started successfully")
	return nil
}

// Stop stops the NTP Manager
func (m *Manager) Stop() {
	klog.Info("Stopping NTP Manager")

	// Cancel context to stop all components
	m.cancel()

	// Stop API server if running
	if m.apiServer != nil {
		if err := m.apiServer.Stop(); err != nil {
			klog.Errorf("Error stopping API server: %v", err)
		}
	}

	// Stop DNS integration if running
	if m.dnsIntegration != nil {
		if err := m.dnsIntegration.Stop(); err != nil {
			klog.Errorf("Error stopping DNS integration: %v", err)
		}
	}

	// Stop DHCP integration if running
	if m.dhcpIntegration != nil {
		if err := m.dhcpIntegration.Stop(); err != nil {
			klog.Errorf("Error stopping DHCP integration: %v", err)
		}
	}

	// Stop metrics exporter if running
	if m.exporterManager != nil {
		if err := m.exporterManager.Stop(); err != nil {
			klog.Errorf("Error stopping metrics exporter: %v", err)
		}
	}

	klog.Info("NTP Manager stopped")
}

// UpdateNTPService updates the NTP service configuration
func (m *Manager) UpdateNTPService(service *ntp.NTPService) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	klog.Infof("Updating NTP service configuration: %s", service.Name)

	// Generate Chrony configuration
	config, err := m.configGenerator.Generate(service)
	if err != nil {
		return fmt.Errorf("failed to generate configuration: %w", err)
	}

	// Update Chrony configuration
	if err := m.chronyManager.UpdateConfig(config); err != nil {
		return fmt.Errorf("failed to update Chrony configuration: %w", err)
	}

	// Update authentication keys if enabled
	if service.Security.Authentication.Enabled && len(service.Security.Authentication.Keys) > 0 {
		if err := m.chronyManager.UpdateKeys(service.Security.Authentication.Keys); err != nil {
			return fmt.Errorf("failed to update authentication keys: %w", err)
		}
	}

	// Restart Chrony service
	if err := m.chronyManager.RestartService(); err != nil {
		return fmt.Errorf("failed to restart Chrony service: %w", err)
	}

	klog.Infof("NTP service configuration updated successfully")
	return nil
}

// Status returns the status of the NTP service
func (m *Manager) Status() (*ntp.Status, error) {
	status, err := m.chronyManager.CheckStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get NTP status: %w", err)
	}
	return &status, nil
}

// UpdateFirewallRules updates firewall rules for NTP access
func (m *Manager) UpdateFirewallRules(service *ntp.NTPService) error {
	klog.Info("Updating firewall rules for NTP service")

	// In a real implementation, this would update the firewall rules
	// based on the VLAN configuration in the NTP service.
	// For now, we'll just log a message.

	for _, vlan := range service.VLANConfig {
		if vlan.Enabled {
			klog.Infof("Would update firewall rules for VLAN %s", vlan.VLANRef)
		}
	}

	return nil
}

// GetConfig returns the current NTP service configuration
func (m *Manager) GetConfig() (*ntp.NTPService, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// In a real implementation, this would retrieve the current configuration
	// from the Kubernetes API or from a local cache.
	// For now, we'll return a placeholder configuration.

	// Create a placeholder configuration
	config := &ntp.NTPService{
		Name:    "default",
		Enabled: true,
		Sources: ntp.Sources{
			Pools: []ntp.PoolSource{
				{
					Name:    "pool.ntp.org",
					Servers: 4,
					IBurst:  true,
				},
			},
			Servers: []ntp.ServerSource{
				{
					Address: "time.cloudflare.com",
					IBurst:  true,
					Prefer:  true,
				},
			},
		},
		Server: ntp.ServerConfig{
			Stratum: 10,
			Local: ntp.LocalClockConfig{
				Enabled: true,
				Stratum: 10,
			},
		},
		VLANConfig: []ntp.VLANConfig{
			{
				VLANRef: "management",
				Enabled: true,
			},
			{
				VLANRef: "trusted",
				Enabled: true,
			},
			{
				VLANRef: "guest",
				Enabled: true,
				ClientsOnly: true,
			},
		},
		Security: ntp.SecurityConfig{
			Authentication: ntp.AuthenticationConfig{
				Enabled: false,
			},
			RateLimit: ntp.RateLimitConfig{
				Enabled: true,
			},
		},
		Monitoring: ntp.MonitoringConfig{
			Enabled: true,
		},
	}

	return config, nil
}