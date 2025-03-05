package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/varuntirumala1/fos1/pkg/cilium"
	"github.com/varuntirumala1/fos1/pkg/security/dpi"
)

func main() {
	// Parse command line flags
	ciliumAPI := flag.String("cilium-api", "http://localhost:9234", "Cilium API endpoint")
	suricataEvePath := flag.String("suricata-eve", "/var/log/suricata/eve.json", "Path to Suricata eve.json")
	suricataMode := flag.String("suricata-mode", "ids", "Suricata mode: 'ids' or 'ips'")
	zeekLogsPath := flag.String("zeek-logs", "/usr/local/zeek/logs/current", "Path to Zeek logs directory")
	enableIPS := flag.Bool("enable-ips", false, "Enable IPS mode (Suricata)")
	flag.Parse()

	// Check if Suricata mode is valid
	if *suricataMode != "ids" && *suricataMode != "ips" {
		log.Fatalf("Invalid Suricata mode: %s (must be 'ids' or 'ips')", *suricataMode)
	}

	// Create Cilium client
	ciliumClient := cilium.NewDefaultCiliumClient(*ciliumAPI, "")

	// Create DPI manager
	dpiOpts := dpi.DPIManagerOptions{
		CiliumClient:     ciliumClient,
		SuricataEvePath:  *suricataEvePath,
		SuricataMode:     *suricataMode,
		ZeekLogsPath:     *zeekLogsPath,
	}

	dpiManager, err := dpi.NewDPIManager(dpiOpts)
	if err != nil {
		log.Fatalf("Failed to create DPI manager: %v", err)
	}

	// Set Suricata to IPS mode if requested
	if *enableIPS {
		if err := dpiManager.ConfigureSuricataIPSMode(true); err != nil {
			log.Fatalf("Failed to enable IPS mode: %v", err)
		}
		log.Println("Enabled Suricata IPS mode")
	}

	// Start DPI manager
	if err := dpiManager.Start(); err != nil {
		log.Fatalf("Failed to start DPI manager: %v", err)
	}
	log.Println("DPI manager started")

	// Define a sample profile (in real usage, this would be from a configuration)
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
	}

	// Add the profile
	if err := dpiManager.AddProfile(profile); err != nil {
		log.Printf("Warning: Failed to add profile: %v", err)
	} else {
		log.Println("Added default DPI profile")
	}

	// Create a blocklist for malicious IPs
	maliciousIPs := []string{
		"192.0.2.1",   // Example IP (TEST-NET-1)
		"198.51.100.1", // Example IP (TEST-NET-2)
		"203.0.113.1", // Example IP (TEST-NET-3)
	}

	// Update Suricata IP list
	if err := dpiManager.UpdateSuricataIPList("malicious-ips", maliciousIPs); err != nil {
		log.Printf("Warning: Failed to update Suricata IP list: %v", err)
	} else {
		log.Println("Updated malicious IPs blocklist")
	}

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for termination signal
	sig := <-sigChan
	fmt.Printf("Received signal %v, shutting down...\n", sig)

	// Stop DPI manager
	if err := dpiManager.Stop(); err != nil {
		log.Fatalf("Error stopping DPI manager: %v", err)
	}
	log.Println("DPI manager stopped, exiting")
}