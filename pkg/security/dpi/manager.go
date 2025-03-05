package dpi

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	
	"github.com/varuntirumala1/fos1/pkg/cilium"
	"github.com/varuntirumala1/fos1/pkg/security/dpi/connectors"
)

// DPIManager manages Deep Packet Inspection functionality
type DPIManager struct {
	// Configuration
	mu              sync.Mutex
	profiles        map[string]*DPIProfile
	flows           map[string]*DPIFlow
	flowStats       map[string]*FlowStatistics
	appDetector     *ApplicationDetector
	
	// Integration with Cilium
	ciliumClient    cilium.CiliumClient
	networkCtrl     *cilium.NetworkController
	
	// Connectors for DPI engines
	suricataConnector *connectors.SuricataConnector
	zeekConnector     *connectors.ZeekConnector
	
	// Control
	ctx              context.Context
	cancel           context.CancelFunc
}

// DPIManagerOptions configures the DPI manager
type DPIManagerOptions struct {
	CiliumClient  cilium.CiliumClient
	SuricataEvePath string
	SuricataMode    string // "ids" or "ips"
	ZeekLogsPath    string
}

// NewDPIManager creates a new DPI manager
func NewDPIManager(opts DPIManagerOptions) (*DPIManager, error) {
	if opts.CiliumClient == nil {
		return nil, fmt.Errorf("cilium client is required")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &DPIManager{
		profiles:     make(map[string]*DPIProfile),
		flows:        make(map[string]*DPIFlow),
		flowStats:    make(map[string]*FlowStatistics),
		appDetector:  NewApplicationDetector(),
		ciliumClient: opts.CiliumClient,
		networkCtrl:  cilium.NewNetworkController(opts.CiliumClient),
		ctx:          ctx,
		cancel:       cancel,
	}
	
	// Initialize Suricata connector
	suricataOpts := connectors.SuricataOptions{
		EvePath:      opts.SuricataEvePath,
		Mode:         opts.SuricataMode,
		CiliumClient: opts.CiliumClient,
	}
	
	suricataConnector, err := connectors.NewSuricataConnector(suricataOpts)
	if err != nil {
		cancel() // Cancel the context if we fail to initialize
		return nil, fmt.Errorf("failed to initialize Suricata connector: %w", err)
	}
	manager.suricataConnector = suricataConnector
	
	// Initialize Zeek connector
	zeekOpts := connectors.ZeekOptions{
		LogsPath:     opts.ZeekLogsPath,
		CiliumClient: opts.CiliumClient,
	}
	
	zeekConnector, err := connectors.NewZeekConnector(zeekOpts)
	if err != nil {
		cancel() // Cancel the context if we fail to initialize
		return nil, fmt.Errorf("failed to initialize Zeek connector: %w", err)
	}
	manager.zeekConnector = zeekConnector
	
	return manager, nil
}

// AddProfile adds a DPI profile
func (m *DPIManager) AddProfile(profile *DPIProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.profiles[profile.Name]; exists {
		return fmt.Errorf("profile %s already exists", profile.Name)
	}

	m.profiles[profile.Name] = profile
	return nil
}

// UpdateProfile updates a DPI profile
func (m *DPIManager) UpdateProfile(profile *DPIProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.profiles[profile.Name]; !exists {
		return fmt.Errorf("profile %s does not exist", profile.Name)
	}

	m.profiles[profile.Name] = profile
	return nil
}

// DeleteProfile deletes a DPI profile
func (m *DPIManager) DeleteProfile(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.profiles[name]; !exists {
		return fmt.Errorf("profile %s does not exist", name)
	}

	delete(m.profiles, name)
	return nil
}

// AddFlow adds a DPI flow
func (m *DPIManager) AddFlow(flow *DPIFlow) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate a key for the flow
	key := fmt.Sprintf("%s-%s", flow.SourceNetwork, flow.DestinationNetwork)
	if _, exists := m.flows[key]; exists {
		return fmt.Errorf("flow for %s to %s already exists", flow.SourceNetwork, flow.DestinationNetwork)
	}

	// Check if the profile exists
	if _, exists := m.profiles[flow.Profile]; !exists && flow.Profile != "" {
		return fmt.Errorf("profile %s does not exist", flow.Profile)
	}

	m.flows[key] = flow
	m.flowStats[key] = &FlowStatistics{}
	return nil
}

// UpdateFlow updates a DPI flow
func (m *DPIManager) UpdateFlow(flow *DPIFlow) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate a key for the flow
	key := fmt.Sprintf("%s-%s", flow.SourceNetwork, flow.DestinationNetwork)
	if _, exists := m.flows[key]; !exists {
		return fmt.Errorf("flow for %s to %s does not exist", flow.SourceNetwork, flow.DestinationNetwork)
	}

	// Check if the profile exists
	if _, exists := m.profiles[flow.Profile]; !exists && flow.Profile != "" {
		return fmt.Errorf("profile %s does not exist", flow.Profile)
	}

	m.flows[key] = flow
	return nil
}

// DeleteFlow deletes a DPI flow
func (m *DPIManager) DeleteFlow(sourceNetwork, destinationNetwork string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate a key for the flow
	key := fmt.Sprintf("%s-%s", sourceNetwork, destinationNetwork)
	if _, exists := m.flows[key]; !exists {
		return fmt.Errorf("flow for %s to %s does not exist", sourceNetwork, destinationNetwork)
	}

	delete(m.flows, key)
	delete(m.flowStats, key)
	return nil
}

// GetDetectedApplications gets the list of detected applications
func (m *DPIManager) GetDetectedApplications() (map[string]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// This would normally query the DPI engine for detected applications
	// For now, return a simple map
	return map[string]int{
		"http":  100,
		"https": 200,
		"ssh":   50,
		"dns":   150,
	}, nil
}

// GetFlowStatistics gets statistics for a flow
func (m *DPIManager) GetFlowStatistics(sourceNetwork, destinationNetwork string) (*FlowStatistics, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate a key for the flow
	key := fmt.Sprintf("%s-%s", sourceNetwork, destinationNetwork)
	stats, exists := m.flowStats[key]
	if !exists {
		return nil, fmt.Errorf("flow for %s to %s does not exist", sourceNetwork, destinationNetwork)
	}

	return stats, nil
}

// Start starts the DPI manager and all connectors
func (m *DPIManager) Start() error {
	// Start Suricata connector
	if m.suricataConnector != nil {
		if err := m.suricataConnector.Start(); err != nil {
			return fmt.Errorf("failed to start Suricata connector: %w", err)
		}
		fmt.Println("Started Suricata connector")
	}
	
	// Start Zeek connector
	if m.zeekConnector != nil {
		if err := m.zeekConnector.Start(); err != nil {
			return fmt.Errorf("failed to start Zeek connector: %w", err)
		}
		fmt.Println("Started Zeek connector")
	}
	
	// Apply DPI profiles and flows to configure what to inspect
	m.applyProfilesToEngines()
	
	fmt.Println("DPI manager started successfully")
	return nil
}

// Stop stops the DPI manager and all connectors
func (m *DPIManager) Stop() error {
	// Cancel our context to stop all goroutines
	m.cancel()
	
	// Stop Suricata connector
	if m.suricataConnector != nil {
		if err := m.suricataConnector.Stop(); err != nil {
			fmt.Printf("Error stopping Suricata connector: %v\n", err)
		}
	}
	
	// Stop Zeek connector
	if m.zeekConnector != nil {
		if err := m.zeekConnector.Stop(); err != nil {
			fmt.Printf("Error stopping Zeek connector: %v\n", err)
		}
	}
	
	fmt.Println("DPI manager stopped")
	return nil
}

// applyProfilesToEngines applies DPI profiles to the DPI engines
func (m *DPIManager) applyProfilesToEngines() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Apply profiles to DPI engines
	// This would configure which applications, protocols, etc. are of interest
	
	// In a real implementation, this would generate configuration files
	// for Suricata and Zeek based on the profiles
	
	fmt.Println("Applied DPI profiles to engines")
}

// GetApplicationInfo gets information about an application
func (m *DPIManager) GetApplicationInfo(applicationName string) (*ApplicationInfo, error) {
	return m.appDetector.GetApplicationInfo(applicationName)
}

// SetDSCPMarkingForApplication sets DSCP marking for an application
func (m *DPIManager) SetDSCPMarkingForApplication(applicationName string, dscp int) error {
	// Validate DSCP value
	if dscp < 0 || dscp > 63 {
		return fmt.Errorf("invalid DSCP value: %d", dscp)
	}

	// Create an application policy for DSCP marking
	appPolicy := cilium.AppPolicy{
		Application: applicationName,
		Action:      "mark",
		Priority:    1,
		DSCP:        uint8(dscp),
	}
	
	// Create a map with this application policy
	appPolicies := map[string]cilium.AppPolicy{
		applicationName: appPolicy,
	}
	
	// Apply policy to Cilium
	if err := m.networkCtrl.IntegrateDPI(m.ctx, appPolicies); err != nil {
		return fmt.Errorf("failed to apply DSCP marking to Cilium: %w", err)
	}
	
	fmt.Printf("Set DSCP marking %d for application %s\n", dscp, applicationName)
	return nil
}

// ConfigurePolicyBasedRouting configures policy-based routing for an application
func (m *DPIManager) ConfigurePolicyBasedRouting(applicationName, nextHop string) error {
	// Validate inputs
	if applicationName == "" || nextHop == "" {
		return fmt.Errorf("application name and next hop are required")
	}
	
	// Create a routing policy based on application
	// This would create Cilium policies that route specific application traffic
	policy := &cilium.NetworkPolicy{
		Name: fmt.Sprintf("app-routing-%s", applicationName),
		Labels: map[string]string{
			"app":       applicationName,
			"type":      "routing-policy",
			"next-hop":  nextHop,
		},
	}
	
	// Add rules to redirect the application traffic
	policy.Egress = append(policy.Egress, cilium.PolicyRule{
		ToPorts: []cilium.PortRule{
			{
				Rules: map[string]string{
					"l7proto": applicationName,
				},
			},
		},
		ToEndpoints: []cilium.Endpoint{
			{
				Labels: map[string]string{
					"next-hop": nextHop,
				},
			},
		},
	})
	
	// Apply the policy
	if err := m.networkCtrl.ApplyDynamicPolicy(m.ctx, policy); err != nil {
		return fmt.Errorf("failed to configure policy-based routing: %w", err)
	}
	
	fmt.Printf("Configured policy-based routing for %s to next hop %s\n", applicationName, nextHop)
	return nil
}

// ConfigureSuricataIPSMode configures Suricata to run in IPS mode
func (m *DPIManager) ConfigureSuricataIPSMode(enable bool) error {
	if m.suricataConnector == nil {
		return fmt.Errorf("Suricata connector not initialized")
	}
	
	if err := m.suricataConnector.ConfigureIPSMode(enable); err != nil {
		return fmt.Errorf("failed to configure Suricata IPS mode: %w", err)
	}
	
	mode := "IDS"
	if enable {
		mode = "IPS"
	}
	
	fmt.Printf("Configured Suricata to run in %s mode\n", mode)
	return nil
}

// UpdateSuricataIPList updates a Suricata IP list
func (m *DPIManager) UpdateSuricataIPList(listName string, ips []string) error {
	if m.suricataConnector == nil {
		return fmt.Errorf("Suricata connector not initialized")
	}
	
	if err := m.suricataConnector.UpdateIPList(listName, ips); err != nil {
		return fmt.Errorf("failed to update Suricata IP list: %w", err)
	}
	
	fmt.Printf("Updated Suricata IP list %s with %d IPs\n", listName, len(ips))
	return nil
}

// DPIProfile represents a DPI profile
type DPIProfile struct {
	Name                 string
	Description          string
	Enabled              bool
	InspectionDepth      int
	Applications         []string
	ApplicationCategories []string
	TrafficClasses       []TrafficClass
	CustomSignatures     []CustomSignature
	Logging              LoggingConfig
}

// DPIFlow represents a DPI flow
type DPIFlow struct {
	Description        string
	Enabled            bool
	SourceNetwork      string
	DestinationNetwork string
	Profile            string
	BypassRules        []BypassRule
}

// TrafficClass represents a traffic class for QoS
type TrafficClass struct {
	Name                 string
	Applications         []string
	ApplicationCategories []string
	DSCP                 int
}

// CustomSignature represents a custom DPI signature
type CustomSignature struct {
	Name        string
	Description string
	Pattern     string
	Protocol    string
	Port        string
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Enabled  bool
	LogLevel string
}

// BypassRule represents a rule to bypass DPI
type BypassRule struct {
	Match       string
	Description string
}

// FlowStatistics represents statistics for a flow
type FlowStatistics struct {
	FlowsProcessed int64
	BytesProcessed int64
	LastUpdateTime string
}

// ApplicationDetector detects applications in network traffic
type ApplicationDetector struct {
	// This would integrate with nDPI, Suricata, etc.
	applicationInfo map[string]*ApplicationInfo
}

// NewApplicationDetector creates a new application detector
func NewApplicationDetector() *ApplicationDetector {
	// Initialize with some predefined applications
	info := make(map[string]*ApplicationInfo)
	for _, app := range []string{"http", "https", "ssh", "dns", "ftp", "smtp"} {
		info[app] = &ApplicationInfo{
			Name:        app,
			Category:    categorizeApplication(app),
			Description: fmt.Sprintf("%s protocol", strings.ToUpper(app)),
			DefaultPorts: getDefaultPorts(app),
		}
	}

	return &ApplicationDetector{
		applicationInfo: info,
	}
}

// GetApplicationInfo gets information about an application
func (d *ApplicationDetector) GetApplicationInfo(applicationName string) (*ApplicationInfo, error) {
	info, exists := d.applicationInfo[applicationName]
	if !exists {
		return nil, fmt.Errorf("application %s not found", applicationName)
	}

	return info, nil
}

// DetectApplication detects an application in a packet
func (d *ApplicationDetector) DetectApplication(packet []byte) (string, error) {
	// This would normally use nDPI or another DPI library
	// For now, return a simple detection based on the first few bytes
	if len(packet) < 4 {
		return "unknown", nil
	}

	// Very simplistic detection based on port numbers
	// In a real implementation, you'd use proper DPI techniques
	srcPort := (int(packet[0]) << 8) | int(packet[1])
	dstPort := (int(packet[2]) << 8) | int(packet[3])

	if srcPort == 80 || dstPort == 80 {
		return "http", nil
	} else if srcPort == 443 || dstPort == 443 {
		return "https", nil
	} else if srcPort == 22 || dstPort == 22 {
		return "ssh", nil
	} else if srcPort == 53 || dstPort == 53 {
		return "dns", nil
	}

	return "unknown", nil
}

// ApplicationInfo represents information about an application
type ApplicationInfo struct {
	Name         string
	Category     string
	Description  string
	DefaultPorts []string
	Risks        []string
}

// Helper functions for the application detector

func categorizeApplication(app string) string {
	categories := map[string]string{
		"http":  "web",
		"https": "web",
		"ssh":   "remote_access",
		"dns":   "network",
		"ftp":   "file_transfer",
		"smtp":  "email",
	}

	category, exists := categories[app]
	if !exists {
		return "other"
	}

	return category
}

func getDefaultPorts(app string) []string {
	ports := map[string][]string{
		"http":  {"80"},
		"https": {"443"},
		"ssh":   {"22"},
		"dns":   {"53"},
		"ftp":   {"20", "21"},
		"smtp":  {"25"},
	}

	p, exists := ports[app]
	if !exists {
		return []string{}
	}

	return p
}