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
)

func main() {
	// Parse command line flags
	apiEndpoint := flag.String("api-endpoint", "http://localhost:9234", "Cilium API endpoint")
	k8sContext := flag.String("k8s-context", "", "Kubernetes context to use")
	flag.Parse()

	// Create Cilium client
	client := cilium.NewDefaultCiliumClient(*apiEndpoint, *k8sContext)
	controller := cilium.NewNetworkController(client)

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signalCh
		log.Printf("Received signal %v, shutting down", sig)
		cancel()
	}()

	// Example: Configure NAT for a source network
	sourceNetwork := "192.168.1.0/24"
	outInterface := "eth0"
	if err := controller.ConfigureNAT(ctx, sourceNetwork, outInterface, false); err != nil {
		log.Fatalf("Failed to configure NAT: %v", err)
	}
	log.Printf("Configured NAT for %s via %s", sourceNetwork, outInterface)

	// Example: Configure NAT66 for an IPv6 network
	sourceNetworkV6 := "2001:db8::/64"
	if err := controller.ConfigureNAT(ctx, sourceNetworkV6, outInterface, true); err != nil {
		log.Fatalf("Failed to configure NAT66: %v", err)
	}
	log.Printf("Configured NAT66 for %s via %s", sourceNetworkV6, outInterface)

	// Example: Configure inter-VLAN routing
	vlans := []uint16{10, 20, 30}
	if err := controller.ConfigureInterVLANRouting(ctx, vlans, false); err != nil {
		log.Fatalf("Failed to configure inter-VLAN routing: %v", err)
	}
	log.Printf("Configured routing between VLANs: %v", vlans)

	// Example: Add specific VLAN policy
	fromVLAN := uint16(10)
	toVLAN := uint16(20)
	rules := []cilium.VLANRule{
		{
			Protocol: "tcp",
			Port:     80,
			Allow:    true,
		},
		{
			Protocol: "tcp",
			Port:     443,
			Allow:    true,
		},
	}
	if err := controller.AddVLANPolicy(ctx, fromVLAN, toVLAN, false, rules); err != nil {
		log.Fatalf("Failed to add VLAN policy: %v", err)
	}
	log.Printf("Added policy for VLAN %d to VLAN %d", fromVLAN, toVLAN)

	// Example: Set up DPI integration
	appPolicies := map[string]cilium.AppPolicy{
		"http": {
			Application: "http",
			Action:      "allow",
			Priority:    1,
			DSCP:        0,
		},
		"ssh": {
			Application: "ssh",
			Action:      "allow",
			Priority:    2,
			DSCP:        0,
		},
	}
	if err := controller.IntegrateDPI(ctx, appPolicies); err != nil {
		log.Fatalf("Failed to integrate DPI: %v", err)
	}
	log.Printf("Integrated DPI with policies for applications")

	// Run indefinitely until signal received
	log.Println("Cilium controller running, press Ctrl+C to stop")
	<-ctx.Done()
	log.Println("Shutting down...")
	time.Sleep(1 * time.Second) // Allow time for cleanup
	log.Println("Cilium controller stopped")
}