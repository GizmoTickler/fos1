package dpi

import (
	"context"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// MockCiliumClient is a mock implementation of the CiliumClient interface
type MockCiliumClient struct {
	ConfigureDPIIntegrationCalled bool
	ApplyNetworkPolicyCalled      bool
	LastConfig                    *cilium.DPIIntegrationConfig
	LastPolicy                    *cilium.NetworkPolicy
}

// ConfigureDPIIntegration is a mock implementation
func (m *MockCiliumClient) ConfigureDPIIntegration(ctx context.Context, config *cilium.DPIIntegrationConfig) error {
	m.ConfigureDPIIntegrationCalled = true
	m.LastConfig = config
	return nil
}

// ApplyNetworkPolicy is a mock implementation
func (m *MockCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *cilium.NetworkPolicy) error {
	m.ApplyNetworkPolicyCalled = true
	m.LastPolicy = policy
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
	event := DPIEvent{
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
	manager.RegisterEventHandler(func(e DPIEvent) {
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
	event := DPIEvent{
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

	// Verify a blocking policy was created
	if !mockClient.ApplyNetworkPolicyCalled {
		t.Errorf("Expected ApplyNetworkPolicy to be called")
	}
	if mockClient.LastPolicy == nil {
		t.Errorf("Expected LastPolicy to be set")
	} else {
		// Verify the policy is correct
		if mockClient.LastPolicy.Labels["app"] != "dpi" {
			t.Errorf("Expected policy label 'app' to be 'dpi', got '%s'", mockClient.LastPolicy.Labels["app"])
		}
		if mockClient.LastPolicy.Labels["event"] != "alert" {
			t.Errorf("Expected policy label 'event' to be 'alert', got '%s'", mockClient.LastPolicy.Labels["event"])
		}
		if mockClient.LastPolicy.Labels["severity"] != "3" {
			t.Errorf("Expected policy label 'severity' to be '3', got '%s'", mockClient.LastPolicy.Labels["severity"])
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
	// So we'll just verify that the method doesn't panic
	_, err = manager.GetDetectedProtocols()
	if err == nil {
		// We expect an error since the Zeek connector isn't properly initialized
		t.Errorf("Expected error from GetDetectedProtocols, got nil")
	}
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
	// So we'll just verify that the method doesn't panic
	_, err = manager.GetZeekStatus()
	if err == nil {
		// We expect an error since the Zeek connector isn't properly initialized
		t.Errorf("Expected error from GetZeekStatus, got nil")
	}
}
