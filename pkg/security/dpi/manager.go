package dpi

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

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

	// Zeek connector
	zeekConnector   *connectors.ZeekConnector

	// Event processing
	eventChan        chan DPIEvent
	eventHandlers    []func(DPIEvent)

	// Control
	ctx              context.Context
	cancel           context.CancelFunc
}

// DPIManagerOptions configures the DPI manager
type DPIManagerOptions struct {
	CiliumClient     cilium.CiliumClient
	ZeekLogsPath     string
	ZeekPolicyPath   string
	KubernetesMode   bool   // Whether running in Kubernetes
	Namespace        string // Kubernetes namespace
}

// NewDPIManager creates a new DPI manager
func NewDPIManager(opts DPIManagerOptions) (*DPIManager, error) {
	if opts.CiliumClient == nil {
		return nil, fmt.Errorf("cilium client is required")
	}

	// Set default namespace if running in Kubernetes mode
	if opts.KubernetesMode && opts.Namespace == "" {
		// Try to get namespace from environment
		if ns := os.Getenv("KUBERNETES_NAMESPACE"); ns != "" {
			opts.Namespace = ns
		} else {
			// Default to "default" namespace
			opts.Namespace = "default"
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &DPIManager{
		profiles:     make(map[string]*DPIProfile),
		flows:        make(map[string]*DPIFlow),
		flowStats:    make(map[string]*FlowStatistics),
		appDetector:  NewApplicationDetector(),
		ciliumClient: opts.CiliumClient,
		networkCtrl:  cilium.NewNetworkController(opts.CiliumClient),
		eventChan:    make(chan DPIEvent, 1000),
		eventHandlers: make([]func(DPIEvent), 0),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Initialize Zeek connector
	zeekOpts := connectors.ZeekOptions{
		LogsPath:       opts.ZeekLogsPath,
		PolicyPath:     opts.ZeekPolicyPath,
		CiliumClient:   opts.CiliumClient,
		KubernetesMode: opts.KubernetesMode,
		Namespace:      opts.Namespace,
	}

	zeekConnector, err := connectors.NewZeekConnector(zeekOpts)
	if err != nil {
		cancel() // Cancel the context if we fail to initialize
		return nil, fmt.Errorf("failed to initialize Zeek connector: %w", err)
	}
	manager.zeekConnector = zeekConnector

	// Start event processing
	go manager.processEvents()

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

// Start starts the DPI manager and Zeek connector
func (m *DPIManager) Start() error {
	// Start Zeek connector
	if m.zeekConnector != nil {
		if err := m.zeekConnector.Start(); err != nil {
			return fmt.Errorf("failed to start Zeek connector: %w", err)
		}
		fmt.Println("Started Zeek connector")

		// Register for events
		events, err := m.zeekConnector.GetEvents(m.ctx)
		if err != nil {
			return fmt.Errorf("failed to get Zeek events: %w", err)
		}

		// Forward events to our event channel
		go m.forwardEvents(events, "zeek")
	}

	// Apply DPI profiles and flows to configure what to inspect
	m.applyProfilesToEngines()

	fmt.Println("DPI manager started successfully")
	return nil
}

// Stop stops the DPI manager and Zeek connector
func (m *DPIManager) Stop() error {
	// Cancel our context to stop all goroutines
	m.cancel()

	// Stop Zeek connector
	if m.zeekConnector != nil {
		if err := m.zeekConnector.Stop(); err != nil {
			fmt.Printf("Error stopping Zeek connector: %v\n", err)
		}
	}

	fmt.Println("DPI manager stopped")
	return nil
}

// applyProfilesToEngines applies DPI profiles to Zeek
func (m *DPIManager) applyProfilesToEngines() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Configure Zeek
	if m.zeekConnector != nil {
		// Generate Zeek configuration from profiles
		fmt.Println("Applying profiles to Zeek")

		// Create configuration for Zeek
		config := map[string]interface{}{
			"applications": getApplicationsFromProfiles(m.profiles),
		}

		// Apply configuration
		if err := m.zeekConnector.Configure(config); err != nil {
			fmt.Printf("Error configuring Zeek: %v\n", err)
		}
	}

	fmt.Println("Applied DPI profiles to Zeek")
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

// GetDetectedProtocols gets the list of protocols detected by Zeek
func (m *DPIManager) GetDetectedProtocols() (map[string]int, error) {
	if m.zeekConnector == nil {
		return nil, fmt.Errorf("Zeek connector not initialized")
	}

	return m.zeekConnector.ExtractProtocols()
}

// GetProtocolStats gets statistics for a specific protocol
func (m *DPIManager) GetProtocolStats(protocol string) (map[string]interface{}, error) {
	if m.zeekConnector == nil {
		return nil, fmt.Errorf("Zeek connector not initialized")
	}

	return m.zeekConnector.GetProtocolStats(protocol)
}

// GetZeekStatus gets the status of the Zeek engine
func (m *DPIManager) GetZeekStatus() (ZeekStatus, error) {
	if m.zeekConnector == nil {
		return ZeekStatus{}, fmt.Errorf("Zeek connector not initialized")
	}

	return m.zeekConnector.Status()
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

// processEvents processes events from all DPI engines
func (m *DPIManager) processEvents() {
	for {
		select {
		case <-m.ctx.Done():
			return // Context canceled, exit

		case event := <-m.eventChan:
			// Process the event
			m.handleEvent(event)
		}
	}
}

// forwardEvents forwards events from a DPI engine to the main event channel
func (m *DPIManager) forwardEvents(events <-chan DPIEvent, source string) {
	for {
		select {
		case <-m.ctx.Done():
			return // Context canceled, exit

		case event, ok := <-events:
			if !ok {
				// Channel closed
				fmt.Printf("Event channel for %s closed\n", source)
				return
			}

			// Add source information
			if event.RawData == nil {
				event.RawData = make(map[string]interface{})
			}
			event.RawData["source"] = source

			// Forward to main event channel
			select {
			case m.eventChan <- event:
				// Successfully sent
			default:
				// Channel full, log and continue
				fmt.Println("Event channel full, dropping event")
			}
		}
	}
}

// handleEvent handles a DPI event
func (m *DPIManager) handleEvent(event DPIEvent) {
	// Update flow statistics
	if event.SourceIP != "" && event.DestIP != "" {
		m.updateFlowStats(event)
	}

	// Handle based on event type
	switch event.EventType {
	case "flow":
		// Process flow event
		m.handleFlowEvent(event)

	case "alert":
		// Process alert event
		m.handleAlertEvent(event)

	case "notice":
		// Process notice event
		m.handleNoticeEvent(event)
	}

	// Call all registered event handlers
	for _, handler := range m.eventHandlers {
		handler(event)
	}
}

// updateFlowStats updates flow statistics based on an event
func (m *DPIManager) updateFlowStats(event DPIEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find matching flow
	for key, stats := range m.flowStats {
		// In a real implementation, would check if the event matches the flow
		// For now, just update all flow stats
		stats.FlowsProcessed++

		// Update bytes processed if available
		if bytes, ok := event.RawData["bytes"]; ok {
			if bytesInt, ok := bytes.(int64); ok {
				stats.BytesProcessed += bytesInt
			}
		}

		// Update last update time
		stats.LastUpdateTime = event.Timestamp.Format(time.RFC3339)

		// Update the stats in the map
		m.flowStats[key] = stats
	}
}

// handleFlowEvent handles a flow event
func (m *DPIManager) handleFlowEvent(event DPIEvent) {
	// Process flow event
	// In a real implementation, would update application statistics,
	// trigger policy updates, etc.

	// For now, just log the event
	fmt.Printf("Flow event: %s application from %s:%d to %s:%d\n",
		event.Application, event.SourceIP, event.SourcePort, event.DestIP, event.DestPort)
}

// handleAlertEvent handles an alert event
func (m *DPIManager) handleAlertEvent(event DPIEvent) {
	// Process alert event
	// In a real implementation, would trigger policy updates,
	// send notifications, etc.

	// For now, just log the event
	fmt.Printf("Alert event: %s (severity %d) - %s\n",
		event.Signature, event.Severity, event.Description)

	// For high-severity alerts, create a blocking policy
	if event.Severity >= 3 {
		m.createBlockingPolicy(event)
	}
}

// handleNoticeEvent handles a notice event
func (m *DPIManager) handleNoticeEvent(event DPIEvent) {
	// Process notice event
	// In a real implementation, would log, send notifications, etc.

	// For now, just log the event
	fmt.Printf("Notice event: %s - %s\n", event.Signature, event.Description)
}

// createBlockingPolicy creates a blocking policy for an event
func (m *DPIManager) createBlockingPolicy(event DPIEvent) {
	// Create a policy to block traffic related to the event
	policy := &cilium.NetworkPolicy{
		Name: fmt.Sprintf("dpi-block-%s-%s", event.EventType, normalizeString(event.Signature)),
		Labels: map[string]string{
			"app":       "dpi",
			"event":     event.EventType,
			"signature": normalizeString(event.Signature),
			"severity":  fmt.Sprintf("%d", event.Severity),
		},
	}

	// Add rules based on the event
	if event.SourceIP != "" {
		policy.Ingress = append(policy.Ingress, cilium.PolicyRule{
			FromCIDRs: []string{event.SourceIP + "/32"},
			Denied:   true,
		})
	}

	if event.DestIP != "" {
		policy.Egress = append(policy.Egress, cilium.PolicyRule{
			ToCIDRs: []string{event.DestIP + "/32"},
			Denied:  true,
		})
	}

	// Apply the policy
	if err := m.networkCtrl.ApplyDynamicPolicy(m.ctx, policy); err != nil {
		fmt.Printf("Failed to apply blocking policy: %v\n", err)
	} else {
		fmt.Printf("Applied blocking policy for %s\n", event.Signature)
	}
}

// RegisterEventHandler registers a handler for DPI events
func (m *DPIManager) RegisterEventHandler(handler func(DPIEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.eventHandlers = append(m.eventHandlers, handler)
}

// getApplicationsFromProfiles extracts all applications from profiles
func getApplicationsFromProfiles(profiles map[string]*DPIProfile) []string {
	apps := make(map[string]bool)

	for _, profile := range profiles {
		if profile.Enabled {
			for _, app := range profile.Applications {
				apps[app] = true
			}
		}
	}

	// Convert to slice
	result := make([]string, 0, len(apps))
	for app := range apps {
		result = append(result, app)
	}

	return result
}

// normalizeString normalizes a string for use in policy names
func normalizeString(s string) string {
	// Replace spaces and special characters with hyphens
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")

	// Convert to lowercase
	s = strings.ToLower(s)

	return s
}