package dpi

import (
	"context"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/security/dpi/common"
)

// MockCiliumClient is a mock implementation of the CiliumClient interface
type MockCiliumClient struct {
	ConfigureDPIIntegrationCalled bool
	ApplyNetworkPolicyCalled      bool
	LastConfig                    *cilium.CiliumDPIIntegrationConfig
	LastPolicy                    *cilium.CiliumPolicy
}

// ConfigureDPIIntegration is a mock implementation
func (m *MockCiliumClient) ConfigureDPIIntegration(ctx context.Context, config *cilium.CiliumDPIIntegrationConfig) error {
	m.ConfigureDPIIntegrationCalled = true
	m.LastConfig = config
	return nil
}

// ApplyNetworkPolicy is a mock implementation
func (m *MockCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *cilium.CiliumPolicy) error {
	m.ApplyNetworkPolicyCalled = true
	m.LastPolicy = policy
	return nil
}

// CreateNAT is a mock implementation
func (m *MockCiliumClient) CreateNAT(ctx context.Context, config *cilium.CiliumNATConfig) error {
	return nil
}

// RemoveNAT is a mock implementation
func (m *MockCiliumClient) RemoveNAT(ctx context.Context, config *cilium.CiliumNATConfig) error {
	return nil
}

// CreateNAT64 is a mock implementation
func (m *MockCiliumClient) CreateNAT64(ctx context.Context, config *cilium.NAT64Config) error {
	return nil
}

// RemoveNAT64 is a mock implementation
func (m *MockCiliumClient) RemoveNAT64(ctx context.Context, config *cilium.NAT64Config) error {
	return nil
}

// CreatePortForward is a mock implementation
func (m *MockCiliumClient) CreatePortForward(ctx context.Context, config *cilium.PortForwardConfig) error {
	return nil
}

// RemovePortForward is a mock implementation
func (m *MockCiliumClient) RemovePortForward(ctx context.Context, config *cilium.PortForwardConfig) error {
	return nil
}

// ConfigureVLANRouting is a mock implementation
func (m *MockCiliumClient) ConfigureVLANRouting(ctx context.Context, config *cilium.CiliumVLANRoutingConfig) error {
	return nil
}

// DeleteNetworkPolicy is a mock implementation
func (m *MockCiliumClient) DeleteNetworkPolicy(ctx context.Context, policyName string) error {
	return nil
}

// TestDPIManager_AddProfile tests the AddProfile method
func TestDPIManager_AddProfile(t *testing.T) {
	// Create a mock Cilium client
	mockClient := &MockCiliumClient{}

	// Create a DPI manager
	manager, err := NewDPIManager(DPIManagerOptions{
		CiliumClient: mockClient,
	})
	if err != nil {
		t.Fatalf("Failed to create DPI manager: %v", err)
	}

	// Create a test profile
	profile := &DPIProfile{
		Name:        "test-profile",
		Description: "Test profile",
		Enabled:     true,
		InspectionDepth: 5,
		Applications: []string{
			"http",
			"https",
		},
		ApplicationCategories: []string{
			"web",
		},
	}

	// Add the profile
	err = manager.AddProfile(profile)
	if err != nil {
		t.Fatalf("Failed to add profile: %v", err)
	}

	// Verify the profile was added
	if len(manager.profiles) != 1 {
		t.Errorf("Expected 1 profile, got %d", len(manager.profiles))
	}

	// Verify the profile is correct
	addedProfile, exists := manager.profiles["test-profile"]
	if !exists {
		t.Errorf("Profile 'test-profile' not found")
	}
	if addedProfile.Name != "test-profile" {
		t.Errorf("Expected profile name 'test-profile', got '%s'", addedProfile.Name)
	}
	if addedProfile.Description != "Test profile" {
		t.Errorf("Expected profile description 'Test profile', got '%s'", addedProfile.Description)
	}
	if !addedProfile.Enabled {
		t.Errorf("Expected profile to be enabled")
	}
	if addedProfile.InspectionDepth != 5 {
		t.Errorf("Expected inspection depth 5, got %d", addedProfile.InspectionDepth)
	}
	if len(addedProfile.Applications) != 2 {
		t.Errorf("Expected 2 applications, got %d", len(addedProfile.Applications))
	}
	if len(addedProfile.ApplicationCategories) != 1 {
		t.Errorf("Expected 1 application category, got %d", len(addedProfile.ApplicationCategories))
	}
}

// TestDPIManager_HandleEvent tests the event handling functionality
func TestDPIManager_HandleEvent(t *testing.T) {
	// Create a mock Cilium client
	mockClient := &MockCiliumClient{}

	// Create a DPI manager
	manager, err := NewDPIManager(DPIManagerOptions{
		CiliumClient: mockClient,
	})
	if err != nil {
		t.Fatalf("Failed to create DPI manager: %v", err)
	}

	// Create a test flow
	flow := &DPIFlow{
		Description:        "Test flow",
		Enabled:            true,
		SourceNetwork:      "192.168.1.0/24",
		DestinationNetwork: "10.0.0.0/8",
		Profile:            "",
	}

	// Add the flow
	err = manager.AddFlow(flow)
	if err != nil {
		t.Fatalf("Failed to add flow: %v", err)
	}

	// Create a test event
	event := common.DPIEvent{
		Timestamp:   time.Now(),
		SourceIP:    "192.168.1.10",
		DestIP:      "10.0.0.10",
		SourcePort:  12345,
		DestPort:    80,
		Protocol:    "TCP",
		Application: "http",
		Category:    "web",
		EventType:   "flow",
		Severity:    0,
		Description: "HTTP flow",
		SessionID:   "test-session",
		RawData: map[string]interface{}{
			"bytes":   int64(1024),
			"packets": int64(10),
		},
	}

	// Create a channel to receive events
	eventReceived := make(chan bool, 1)

	// Register an event handler
	manager.RegisterEventHandler(func(e common.DPIEvent) {
		// Verify the event is correct
		if e.Application != "http" {
			t.Errorf("Expected application 'http', got '%s'", e.Application)
		}
		if e.SourceIP != "192.168.1.10" {
			t.Errorf("Expected source IP '192.168.1.10', got '%s'", e.SourceIP)
		}
		if e.DestIP != "10.0.0.10" {
			t.Errorf("Expected destination IP '10.0.0.10', got '%s'", e.DestIP)
		}

		// Signal that the event was received
		eventReceived <- true
	})

	// Send the event
	manager.eventChan <- event

	// Wait for the event to be processed
	select {
	case <-eventReceived:
		// Event was received and processed
	case <-time.After(1 * time.Second):
		t.Errorf("Timeout waiting for event to be processed")
	}

	// Verify flow statistics were updated
	stats, err := manager.GetFlowStatistics("192.168.1.0/24", "10.0.0.0/8")
	if err != nil {
		t.Fatalf("Failed to get flow statistics: %v", err)
	}
	if stats.FlowsProcessed != 1 {
		t.Errorf("Expected 1 flow processed, got %d", stats.FlowsProcessed)
	}
	if stats.BytesProcessed != 1024 {
		t.Errorf("Expected 1024 bytes processed, got %d", stats.BytesProcessed)
	}
}

// TestDPIManager_HandleAlertEvent tests the alert event handling functionality
func TestDPIManager_HandleAlertEvent(t *testing.T) {
	// Create a mock Cilium client
	mockClient := &MockCiliumClient{}

	// Create a DPI manager
	manager, err := NewDPIManager(DPIManagerOptions{
		CiliumClient: mockClient,
	})
	if err != nil {
		t.Fatalf("Failed to create DPI manager: %v", err)
	}

	// Create a test alert event
	event := common.DPIEvent{
		Timestamp:   time.Now(),
		SourceIP:    "192.168.1.10",
		DestIP:      "10.0.0.10",
		SourcePort:  12345,
		DestPort:    80,
		Protocol:    "TCP",
		Application: "http",
		Category:    "web",
		EventType:   "alert",
		Severity:    3, // High severity
		Description: "Malicious traffic detected",
		Signature:   "ET MALWARE Known Malicious User-Agent",
		SessionID:   "test-session",
		RawData:     map[string]interface{}{},
	}

	// Send the event
	manager.handleAlertEvent(event)

	// Verify a blocking policy was created via the policy pipeline
	if !mockClient.ApplyNetworkPolicyCalled {
		t.Errorf("Expected ApplyNetworkPolicy to be called")
	}
	if mockClient.LastPolicy == nil {
		t.Errorf("Expected LastPolicy to be set")
	} else {
		// The policy pipeline labels use fos1.io/ prefixed keys
		if mockClient.LastPolicy.Labels["fos1.io/auto-generated"] != "true" {
			t.Errorf("Expected policy label 'fos1.io/auto-generated' to be 'true', got '%s'", mockClient.LastPolicy.Labels["fos1.io/auto-generated"])
		}
		if mockClient.LastPolicy.Labels["fos1.io/source-ip"] != "192.168.1.10" {
			t.Errorf("Expected policy label 'fos1.io/source-ip' to be '192.168.1.10', got '%s'", mockClient.LastPolicy.Labels["fos1.io/source-ip"])
		}
		if mockClient.LastPolicy.Labels["fos1.io/action"] != "block" {
			t.Errorf("Expected policy label 'fos1.io/action' to be 'block', got '%s'", mockClient.LastPolicy.Labels["fos1.io/action"])
		}

		// Verify CIDR-based deny rule exists
		if len(mockClient.LastPolicy.Rules) == 0 {
			t.Errorf("Expected at least one rule in the policy")
		} else {
			rule := mockClient.LastPolicy.Rules[0]
			if !rule.Denied {
				t.Error("Expected deny rule for high-severity alert")
			}
			if len(rule.FromCIDR) == 0 || rule.FromCIDR[0] != "192.168.1.10/32" {
				t.Errorf("Expected FromCIDR '192.168.1.10/32', got %v", rule.FromCIDR)
			}
		}
	}
}

// TestDPIManager_GetDetectedProtocols tests the GetDetectedProtocols method
func TestDPIManager_GetDetectedProtocols(t *testing.T) {
	// Create a mock Cilium client
	mockClient := &MockCiliumClient{}

	// Create a DPI manager with a mock Zeek connector
	manager, err := NewDPIManager(DPIManagerOptions{
		CiliumClient: mockClient,
		ZeekLogsPath: "/tmp/zeek-logs",
	})
	if err != nil {
		t.Fatalf("Failed to create DPI manager: %v", err)
	}

	// We can't easily test the actual Zeek connector without a real Zeek instance
	// So we'll just verify that the method returns an error
	_, err = manager.GetDetectedProtocols()
	if err == nil {
		// We expect an error since the Zeek connector isn't properly initialized
		t.Errorf("Expected error from GetDetectedProtocols, got nil")
	} else {
		// We got an error as expected
		t.Logf("Got expected error from GetDetectedProtocols: %v", err)
	}
}

// TestDPIManager_HandleDNSFlow tests the DNS flow handling
func TestDPIManager_HandleDNSFlow(t *testing.T) {
	// Create a mock Cilium client
	mockClient := &MockCiliumClient{}

	// Create a DPI manager
	manager, err := NewDPIManager(DPIManagerOptions{
		CiliumClient: mockClient,
	})
	if err != nil {
		t.Fatalf("Failed to create DPI manager: %v", err)
	}

	// Create a test DNS event
	event := common.DPIEvent{
		Timestamp:   time.Now(),
		SourceIP:    "192.168.1.10",
		DestIP:      "8.8.8.8",
		SourcePort:  12345,
		DestPort:    53,
		Protocol:    "UDP",
		Application: "dns",
		Category:    "network_service",
		EventType:   "dns",
		Severity:    0,
		Description: "DNS query for example.com",
		SessionID:   "test-session",
		RawData: map[string]interface{}{
			"query":  "example.com",
			"qtype":  "A",
			"rcode":  "NOERROR",
			"answers": "93.184.216.34",
		},
	}

	// Test the DNS flow handler
	manager.handleDNSFlow(event)

	// Create a test DNS over TLS event
	dotEvent := common.DPIEvent{
		Timestamp:   time.Now(),
		SourceIP:    "192.168.1.10",
		DestIP:      "1.1.1.1",
		SourcePort:  12345,
		DestPort:    853,
		Protocol:    "TCP",
		Application: "dns-over-tls",
		Category:    "network_service",
		EventType:   "dns",
		Severity:    0,
		Description: "DNS over TLS query",
		SessionID:   "test-session-dot",
		RawData: map[string]interface{}{
			"query":  "example.org",
			"qtype":  "A",
		},
	}

	// Test the DNS over TLS flow handler
	manager.handleDNSFlow(dotEvent)
}

// TestDPIManager_HandleMQTTFlow tests the MQTT flow handling
func TestDPIManager_HandleMQTTFlow(t *testing.T) {
	// Create a mock Cilium client
	mockClient := &MockCiliumClient{}

	// Create a DPI manager
	manager, err := NewDPIManager(DPIManagerOptions{
		CiliumClient: mockClient,
	})
	if err != nil {
		t.Fatalf("Failed to create DPI manager: %v", err)
	}

	// Create a test MQTT event
	event := common.DPIEvent{
		Timestamp:   time.Now(),
		SourceIP:    "192.168.1.10",
		DestIP:      "192.168.1.100",
		SourcePort:  12345,
		DestPort:    1883,
		Protocol:    "TCP",
		Application: "mqtt",
		Category:    "iot",
		EventType:   "mqtt",
		Severity:    0,
		Description: "MQTT connection",
		SessionID:   "test-session-mqtt",
		RawData: map[string]interface{}{
			"topic":     "sensors/temperature",
			"qos":       float64(1),
			"client_id": "device-123",
		},
	}

	// Test the MQTT flow handler
	manager.handleMQTTFlow(event)

	// Create a test MQTT over TLS event
	mqttTLSEvent := common.DPIEvent{
		Timestamp:   time.Now(),
		SourceIP:    "192.168.1.10",
		DestIP:      "192.168.1.100",
		SourcePort:  12345,
		DestPort:    8883,
		Protocol:    "TCP",
		Application: "mqtt",
		Category:    "iot",
		EventType:   "mqtt",
		Severity:    0,
		Description: "MQTT over TLS connection",
		SessionID:   "test-session-mqtt-tls",
		RawData: map[string]interface{}{
			"topic":     "sensors/humidity",
			"qos":       float64(2),
			"client_id": "device-456",
		},
	}

	// Test the MQTT over TLS flow handler
	manager.handleMQTTFlow(mqttTLSEvent)
}

// TestDPIManager_GetZeekStatus tests the GetZeekStatus method
func TestDPIManager_GetZeekStatus(t *testing.T) {
	// Create a mock Cilium client
	mockClient := &MockCiliumClient{}

	// Create a DPI manager with a mock Zeek connector
	manager, err := NewDPIManager(DPIManagerOptions{
		CiliumClient: mockClient,
		ZeekLogsPath: "/tmp/zeek-logs",
	})
	if err != nil {
		t.Fatalf("Failed to create DPI manager: %v", err)
	}

	// We can't easily test the actual Zeek connector without a real Zeek instance
	// So we'll just verify that the method returns an error
	_, err = manager.GetZeekStatus()
	if err == nil {
		// We expect an error since the Zeek connector isn't properly initialized
		t.Errorf("Expected error from GetZeekStatus, got nil")
	} else {
		// We got an error as expected
		t.Logf("Got expected error from GetZeekStatus: %v", err)
	}
}
