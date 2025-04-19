package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/varuntirumala1/fos1/pkg/cilium"
	"github.com/varuntirumala1/fos1/pkg/security/dpi"
)

// SimpleCiliumClient is a simple implementation of the CiliumClient interface
type SimpleCiliumClient struct{}

// ConfigureDPIIntegration is a simple implementation
func (s *SimpleCiliumClient) ConfigureDPIIntegration(ctx context.Context, config *cilium.DPIIntegrationConfig) error {
	log.Printf("Configuring DPI integration: %+v", config)
	return nil
}

// ApplyNetworkPolicy is a simple implementation
func (s *SimpleCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *cilium.NetworkPolicy) error {
	log.Printf("Applying network policy: %s", policy.Name)
	return nil
}

func main() {
	// Parse command-line flags
	zeekLogsPath := flag.String("zeek-logs", "/usr/local/zeek/logs/current", "Path to Zeek logs directory")
	zeekPolicyPath := flag.String("zeek-policy", "/usr/local/zeek/share/zeek/policy", "Path to Zeek policy directory")
	flag.Parse()

	// Create a simple Cilium client
	ciliumClient := &SimpleCiliumClient{}

	// Create DPI manager options
	opts := dpi.DPIManagerOptions{
		CiliumClient:   ciliumClient,
		ZeekLogsPath:   *zeekLogsPath,
		ZeekPolicyPath: *zeekPolicyPath,
	}

	// Create DPI manager
	manager, err := dpi.NewDPIManager(opts)
	if err != nil {
		log.Fatalf("Failed to create DPI manager: %v", err)
	}

	// Register event handler
	manager.RegisterEventHandler(func(event dpi.DPIEvent) {
		log.Printf("Event: %s - %s", event.EventType, event.Description)
	})

	// Create a sample profile
	profile := &dpi.DPIProfile{
		Name:        "default-profile",
		Description: "Default DPI profile",
		Enabled:     true,
		InspectionDepth: 5,
		Applications: []string{
			"http",
			"https",
			"ssh",
			"dns",
			"ftp",
		},
		ApplicationCategories: []string{
			"web",
			"email",
			"file-transfer",
		},
		TrafficClasses: []dpi.TrafficClass{
			{
				Name: "web-traffic",
				Applications: []string{
					"http",
					"https",
				},
				DSCP: 0,
			},
			{
				Name: "high-priority",
				Applications: []string{
					"ssh",
				},
				DSCP: 46,
			},
		},
	}

	// Add the profile
	if err := manager.AddProfile(profile); err != nil {
		log.Printf("Warning: Failed to add profile: %v", err)
	} else {
		log.Println("Added default DPI profile")
	}

	// Create a sample flow
	flow := &dpi.DPIFlow{
		Description:        "Default flow",
		Enabled:            true,
		SourceNetwork:      "0.0.0.0/0",
		DestinationNetwork: "0.0.0.0/0",
		Profile:            "default-profile",
	}

	// Add the flow
	if err := manager.AddFlow(flow); err != nil {
		log.Printf("Warning: Failed to add flow: %v", err)
	} else {
		log.Println("Added default DPI flow")
	}

	// Start the DPI manager
	if err := manager.Start(); err != nil {
		log.Fatalf("Failed to start DPI manager: %v", err)
	}

	// Simulate some events for testing
	go simulateEvents(manager)

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Stop the DPI manager
	if err := manager.Stop(); err != nil {
		log.Printf("Error stopping DPI manager: %v", err)
	}

	log.Println("DPI test exited")
}

// simulateEvents simulates DPI events for testing
func simulateEvents(manager *dpi.DPIManager) {
	// Wait a moment for everything to start
	time.Sleep(2 * time.Second)

	log.Println("Simulating DPI events...")

	// Simulate a flow event
	flowEvent := dpi.DPIEvent{
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
		SessionID:   "sim-session-1",
		RawData: map[string]interface{}{
			"bytes":   int64(1024),
			"packets": int64(10),
		},
	}
	manager.eventChan <- flowEvent
	log.Println("Sent flow event")

	// Wait a moment
	time.Sleep(2 * time.Second)

	// Simulate an alert event
	alertEvent := dpi.DPIEvent{
		Timestamp:   time.Now(),
		SourceIP:    "192.168.1.20",
		DestIP:      "10.0.0.20",
		SourcePort:  23456,
		DestPort:    443,
		Protocol:    "TCP",
		Application: "https",
		Category:    "web",
		EventType:   "alert",
		Severity:    3,
		Description: "Malicious traffic detected",
		Signature:   "ET MALWARE Known Malicious User-Agent",
		SessionID:   "sim-session-2",
		RawData:     map[string]interface{}{},
	}
	manager.eventChan <- alertEvent
	log.Println("Sent alert event")

	// Wait a moment
	time.Sleep(2 * time.Second)

	// Simulate a notice event
	noticeEvent := dpi.DPIEvent{
		Timestamp:   time.Now(),
		SourceIP:    "192.168.1.30",
		DestIP:      "10.0.0.30",
		SourcePort:  34567,
		DestPort:    22,
		Protocol:    "TCP",
		Application: "ssh",
		Category:    "remote_access",
		EventType:   "notice",
		Severity:    1,
		Description: "Unusual SSH connection",
		Signature:   "SSH::Password_Guessing",
		SessionID:   "sim-session-3",
		RawData:     map[string]interface{}{},
	}
	manager.eventChan <- noticeEvent
	log.Println("Sent notice event")

	// Simulate periodic events
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Simulate a random event
			event := dpi.DPIEvent{
				Timestamp:   time.Now(),
				SourceIP:    fmt.Sprintf("192.168.1.%d", time.Now().Second()%254+1),
				DestIP:      fmt.Sprintf("10.0.0.%d", time.Now().Second()%254+1),
				SourcePort:  12345 + time.Now().Second(),
				DestPort:    80,
				Protocol:    "TCP",
				Application: "http",
				Category:    "web",
				EventType:   "flow",
				Severity:    0,
				Description: "Simulated HTTP flow",
				SessionID:   fmt.Sprintf("sim-session-%d", time.Now().Unix()),
				RawData: map[string]interface{}{
					"bytes":   int64(1024 * (time.Now().Second() % 10 + 1)),
					"packets": int64(10 * (time.Now().Second() % 10 + 1)),
				},
			}
			manager.eventChan <- event
			log.Println("Sent periodic flow event")
		}
	}
}
