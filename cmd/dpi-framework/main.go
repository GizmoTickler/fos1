package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/varuntirumala1/fos1/pkg/cilium"
	"github.com/varuntirumala1/fos1/pkg/kubernetes"
	"github.com/varuntirumala1/fos1/pkg/security/dpi"
	"gopkg.in/yaml.v2"
)

// Config represents the application configuration
type Config struct {
	Kubernetes struct {
		Enabled   bool   `yaml:"enabled"`
		Namespace string `yaml:"namespace"`
	} `yaml:"kubernetes"`

	Zeek struct {
		LogsPath   string `yaml:"logsPath"`
		PolicyPath string `yaml:"policyPath"`
	} `yaml:"zeek"`

	Profiles []dpi.DPIProfile `yaml:"profiles"`
	Flows    []dpi.DPIFlow    `yaml:"flows"`
}

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "/etc/dpi-framework/config.yaml", "Path to configuration file")
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig file (if running outside of cluster)")
	kubeMode := flag.Bool("kubernetes", false, "Run in Kubernetes mode")
	zeekLogsPath := flag.String("zeek-logs", "", "Path to Zeek logs directory")
	zeekPolicyPath := flag.String("zeek-policy", "", "Path to Zeek policy directory")
	flag.Parse()

	// Load configuration
	config, err := loadConfig(*configPath)
	if err != nil {
		// If config file doesn't exist, create a default config
		if os.IsNotExist(err) {
			config = &Config{}
			config.Kubernetes.Enabled = *kubeMode

			// Set default values from command line flags
			if *zeekLogsPath != "" {
				config.Zeek.LogsPath = *zeekLogsPath
			}
			if *zeekPolicyPath != "" {
				config.Zeek.PolicyPath = *zeekPolicyPath
			}
		} else {
			log.Printf("Warning: Failed to load configuration: %v", err)
		}
	}

	// Command line flags override config file
	if *kubeMode {
		config.Kubernetes.Enabled = true
	}
	if *zeekLogsPath != "" {
		config.Zeek.LogsPath = *zeekLogsPath
	}
	if *zeekPolicyPath != "" {
		config.Zeek.PolicyPath = *zeekPolicyPath
	}

	// Create Cilium client
	var ciliumClient cilium.CiliumClient
	if config.Kubernetes.Enabled {
		// Initialize Kubernetes client
		k8sClient, err := kubernetes.NewClient(*kubeconfig)
		if err != nil {
			log.Fatalf("Failed to create Kubernetes client: %v", err)
		}

		// Create Kubernetes-based Cilium client
		ciliumClient = cilium.NewKubernetesCiliumClient(k8sClient)
	} else {
		// Create direct Cilium client
		ciliumClient = &cilium.DirectCiliumClient{}
	}

	// Create DPI manager options
	opts := dpi.DPIManagerOptions{
		CiliumClient:   ciliumClient,
		ZeekLogsPath:   config.Zeek.LogsPath,
		ZeekPolicyPath: config.Zeek.PolicyPath,
		KubernetesMode: config.Kubernetes.Enabled,
		Namespace:      config.Kubernetes.Namespace,
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

	// Add profiles from configuration
	for _, profile := range config.Profiles {
		if err := manager.AddProfile(&profile); err != nil {
			log.Printf("Warning: Failed to add profile %s: %v", profile.Name, err)
		} else {
			log.Printf("Added DPI profile: %s", profile.Name)
		}
	}

	// Add default profile if none specified
	if len(config.Profiles) == 0 {
		defaultProfile := &dpi.DPIProfile{
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

		if err := manager.AddProfile(defaultProfile); err != nil {
			log.Printf("Warning: Failed to add default profile: %v", err)
		} else {
			log.Println("Added default DPI profile")
		}
	}

	// Add flows from configuration
	for _, flow := range config.Flows {
		if err := manager.AddFlow(&flow); err != nil {
			log.Printf("Warning: Failed to add flow %s: %v", flow.Description, err)
		} else {
			log.Printf("Added DPI flow: %s", flow.Description)
		}
	}

	// Add default flow if none specified
	if len(config.Flows) == 0 {
		defaultFlow := &dpi.DPIFlow{
			Description:        "Default flow",
			Enabled:            true,
			SourceNetwork:      "0.0.0.0/0",
			DestinationNetwork: "0.0.0.0/0",
			Profile:            "default-profile",
		}

		if err := manager.AddFlow(defaultFlow); err != nil {
			log.Printf("Warning: Failed to add default flow: %v", err)
		} else {
			log.Println("Added default DPI flow")
		}
	}

	// Start the DPI manager
	if err := manager.Start(); err != nil {
		log.Fatalf("Failed to start DPI manager: %v", err)
	}

	// Start Kubernetes controller for policy management if in Kubernetes mode
	if config.Kubernetes.Enabled {
		k8sClient, _ := kubernetes.NewClient(*kubeconfig)
		controller := kubernetes.NewPolicyController(k8sClient, manager)
		go controller.Run(context.Background())

		// Start metrics server for Prometheus
		go kubernetes.StartMetricsServer(":8080", manager)
	} else {
		// Simulate some events for testing in non-Kubernetes mode
		go simulateEvents(manager)
	}

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("Received signal %v, shutting down", sig)

	// Stop the DPI manager
	if err := manager.Stop(); err != nil {
		log.Printf("Error stopping DPI manager: %v", err)
	}

	log.Println("DPI framework exited")
}

// loadConfig loads the application configuration from a YAML file
func loadConfig(path string) (*Config, error) {
	// Read configuration file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	// Set default values if not specified
	if config.Zeek.LogsPath == "" {
		if config.Kubernetes.Enabled {
			config.Zeek.LogsPath = "/zeek-logs/current"
		} else {
			config.Zeek.LogsPath = "/usr/local/zeek/logs/current"
		}
	}

	if config.Zeek.PolicyPath == "" {
		if config.Kubernetes.Enabled {
			config.Zeek.PolicyPath = "/zeek-policy"
		} else {
			config.Zeek.PolicyPath = "/usr/local/zeek/share/zeek/policy"
		}
	}

	// Ensure paths are absolute
	if !filepath.IsAbs(config.Zeek.LogsPath) {
		config.Zeek.LogsPath = filepath.Join("/", config.Zeek.LogsPath)
	}

	if !filepath.IsAbs(config.Zeek.PolicyPath) {
		config.Zeek.PolicyPath = filepath.Join("/", config.Zeek.PolicyPath)
	}

	return &config, nil
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

	// Simulate periodic events
	ticker := time.NewTicker(30 * time.Second)
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
