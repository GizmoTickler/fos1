package connectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/your-org/fos1/pkg/cilium"
)

// NProbeOptions configures the nProbe connector
type NProbeOptions struct {
	// Path to the nProbe executable
	NProbeExecPath string
	
	// Interface to capture traffic from
	Interface string
	
	// Port for nProbe to listen on (for JSON export)
	ZMQPort int
	
	// Host for ZMQ connection (default: 127.0.0.1)
	ZMQHost string
	
	// Sampling rate (1 = no sampling)
	SamplingRate int
	
	// Additional nProbe parameters
	ExtraParams []string
	
	// Cilium client for policy updates
	CiliumClient cilium.CiliumClient
}

// NProbeConnector interfaces with nProbe for DPI capabilities
type NProbeConnector struct {
	// Configuration
	opts           NProbeOptions
	ciliumClient   cilium.CiliumClient
	
	// Process management
	cmd            *exec.Cmd
	cmdLock        sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
	
	// Data processing
	flowChan       chan NProbeFlow
	appStats       map[string]AppStats
	statsLock      sync.RWMutex
	
	// Configuration
	flowTimeout    time.Duration
	appDefinitions map[string]AppDefinition
}

// NProbeFlow represents a flow detected by nProbe
type NProbeFlow struct {
	SrcIP        string    `json:"IPV4_SRC_ADDR"`
	DstIP        string    `json:"IPV4_DST_ADDR"`
	SrcPort      int       `json:"L4_SRC_PORT"`
	DstPort      int       `json:"L4_DST_PORT"`
	Protocol     int       `json:"PROTOCOL"`
	Application  string    `json:"NDPI_PROTOCOL"`
	Category     string    `json:"NDPI_CATEGORY"`
	L7Proto      string    `json:"L7_PROTO"`
	HTTPHost     string    `json:"HTTP_HOST"`
	HTTPUrl      string    `json:"HTTP_URL"`
	HTTPUserAgent string   `json:"HTTP_USER_AGENT"`
	SSLServerName string   `json:"TLS_SNI"`
	Bytes        int64     `json:"IN_BYTES"`
	Packets      int64     `json:"IN_PKTS"`
	FlowDuration int64     `json:"FLOW_DURATION_MILLISECONDS"`
	Timestamp    time.Time `json:"TIMESTAMP"`
	TcpFlags     int       `json:"TCP_FLAGS"`
	DnsQuery     string    `json:"DNS_QUERY"`
	DnsQueryType string    `json:"DNS_QUERY_TYPE"`
	DnsRespCode  string    `json:"DNS_RESPONSE_CODE"`
}

// AppStats contains statistics for an application
type AppStats struct {
	Flows        int64
	Bytes        int64
	Packets      int64
	Hosts        map[string]bool
	LastSeen     time.Time
	Categories   map[string]int64
}

// AppDefinition contains metadata about an application
type AppDefinition struct {
	Name         string
	Category     string
	Description  string
	DefaultPorts []string
	Risks        []string
	References   []string
}

// NewNProbeConnector creates a new nProbe connector
func NewNProbeConnector(opts NProbeOptions) (*NProbeConnector, error) {
	if opts.NProbeExecPath == "" {
		return nil, fmt.Errorf("nProbe executable path is required")
	}

	if opts.Interface == "" {
		return nil, fmt.Errorf("capture interface is required")
	}

	if opts.ZMQPort == 0 {
		opts.ZMQPort = 5556 // Default ZMQ port
	}

	if opts.ZMQHost == "" {
		opts.ZMQHost = "127.0.0.1" // Default to localhost
	}

	if opts.SamplingRate <= 0 {
		opts.SamplingRate = 1 // Default to no sampling
	}

	ctx, cancel := context.WithCancel(context.Background())

	connector := &NProbeConnector{
		opts:          opts,
		ciliumClient:  opts.CiliumClient,
		ctx:           ctx,
		cancel:        cancel,
		flowChan:      make(chan NProbeFlow, 1000),
		appStats:      make(map[string]AppStats),
		flowTimeout:   30 * time.Second,
		appDefinitions: loadAppDefinitions(),
	}

	return connector, nil
}

// Start starts the nProbe process and begins processing flows
func (n *NProbeConnector) Start() error {
	n.cmdLock.Lock()
	defer n.cmdLock.Unlock()

	if n.cmd != nil {
		return fmt.Errorf("nProbe connector is already running")
	}

	// Build the nProbe command with all necessary parameters
	cmdArgs := []string{
		"--interface", n.opts.Interface,
		"--zmq", fmt.Sprintf("tcp://%s:%d", n.opts.ZMQHost, n.opts.ZMQPort),
		"--ndpi-protocols", "/etc/nprobe/ndpi.txt",
		"--flow-version", "10",
		"--json-labels",
	}

	// Add sampling if configured
	if n.opts.SamplingRate > 1 {
		cmdArgs = append(cmdArgs, "--flow-sample", fmt.Sprintf("%d", n.opts.SamplingRate))
	}

	// Add any extra parameters
	cmdArgs = append(cmdArgs, n.opts.ExtraParams...)

	log.Printf("Starting nProbe with: %s %s", n.opts.NProbeExecPath, strings.Join(cmdArgs, " "))
	n.cmd = exec.CommandContext(n.ctx, n.opts.NProbeExecPath, cmdArgs...)
	
	// Start the command
	stderr, err := n.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	if err := n.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start nProbe: %w", err)
	}

	// Handle stderr in a goroutine
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.Printf("nProbe: %s", scanner.Text())
		}
	}()

	// Start flow collector in the background
	go n.collectFlows()

	// Start processor in the background
	go n.processFlows()

	log.Println("nProbe connector started successfully")
	return nil
}

// Stop stops the nProbe process
func (n *NProbeConnector) Stop() error {
	n.cmdLock.Lock()
	defer n.cmdLock.Unlock()

	if n.cmd == nil {
		return nil // Already stopped
	}

	// Cancel the context to stop all goroutines
	n.cancel()

	// Wait for the process to exit
	err := n.cmd.Wait()
	n.cmd = nil

	log.Println("nProbe connector stopped")
	return err
}

// collectFlows collects flows from nProbe via ZMQ
func (n *NProbeConnector) collectFlows() {
	// In a real implementation, this would connect to nProbe's ZMQ port
	// and receive flow data in JSON format
	
	// Wait a moment for nProbe to start
	time.Sleep(2 * time.Second)
	
	// Connect to nProbe's ZMQ port
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", n.opts.ZMQHost, n.opts.ZMQPort))
	if err != nil {
		log.Printf("Failed to connect to nProbe ZMQ: %v", err)
		return
	}
	defer conn.Close()
	
	reader := bufio.NewReader(conn)
	
	for {
		select {
		case <-n.ctx.Done():
			return // Context canceled, exit
		default:
			// Read a line from the ZMQ connection
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					log.Println("nProbe connection closed, reconnecting...")
					// In a real implementation, would attempt to reconnect
					time.Sleep(5 * time.Second)
					continue
				}
				log.Printf("Error reading from nProbe: %v", err)
				continue
			}
			
			// Parse the JSON flow
			var flow NProbeFlow
			if err := json.Unmarshal([]byte(line), &flow); err != nil {
				log.Printf("Error parsing flow data: %v", err)
				continue
			}
			
			// Skip flows with no application information
			if flow.Application == "" || flow.Application == "Unknown" {
				continue
			}
			
			// Set timestamp if not present
			if flow.Timestamp.IsZero() {
				flow.Timestamp = time.Now()
			}
			
			// Send to processing channel
			select {
			case n.flowChan <- flow:
				// Successfully sent
			default:
				// Channel full, log and continue
				log.Println("Flow channel full, dropping flow")
			}
		}
	}
}

// processFlows processes flows received from nProbe
func (n *NProbeConnector) processFlows() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-n.ctx.Done():
			return // Context canceled, exit
			
		case flow := <-n.flowChan:
			// Process the flow
			n.updateStats(flow)
			
			// In a real implementation, would apply more sophisticated
			// processing and potentially trigger policy updates
			
		case <-ticker.C:
			// Periodically generate reports and update policies
			n.generateApplicationReport()
			n.updateApplicationPolicies()
		}
	}
}

// updateStats updates application statistics based on a flow
func (n *NProbeConnector) updateStats(flow NProbeFlow) {
	n.statsLock.Lock()
	defer n.statsLock.Unlock()
	
	app := flow.Application
	
	// Get or initialize app stats
	stats, exists := n.appStats[app]
	if !exists {
		stats = AppStats{
			Hosts:      make(map[string]bool),
			Categories: make(map[string]int64),
		}
	}
	
	// Update statistics
	stats.Flows++
	stats.Bytes += flow.Bytes
	stats.Packets += flow.Packets
	stats.LastSeen = flow.Timestamp
	
	// Track hosts using this application
	stats.Hosts[flow.SrcIP] = true
	stats.Hosts[flow.DstIP] = true
	
	// Track categories
	if flow.Category != "" {
		stats.Categories[flow.Category]++
	}
	
	// Update the stats
	n.appStats[app] = stats
}

// generateApplicationReport generates a report of detected applications
func (n *NProbeConnector) generateApplicationReport() {
	n.statsLock.RLock()
	defer n.statsLock.RUnlock()
	
	log.Println("=== Application Report ===")
	for app, stats := range n.appStats {
		log.Printf("Application: %s", app)
		log.Printf("  Flows: %d", stats.Flows)
		log.Printf("  Bytes: %d", stats.Bytes)
		log.Printf("  Hosts: %d", len(stats.Hosts))
		log.Printf("  Last Seen: %s", stats.LastSeen.Format(time.RFC3339))
		
		// Log categories
		categories := make([]string, 0, len(stats.Categories))
		for cat, count := range stats.Categories {
			categories = append(categories, fmt.Sprintf("%s (%d)", cat, count))
		}
		log.Printf("  Categories: %s", strings.Join(categories, ", "))
		
		// Log application definition if available
		if def, ok := n.appDefinitions[app]; ok {
			log.Printf("  Description: %s", def.Description)
			if len(def.Risks) > 0 {
				log.Printf("  Risks: %s", strings.Join(def.Risks, ", "))
			}
		}
		
		log.Println()
	}
	log.Println("=========================")
}

// updateApplicationPolicies updates Cilium policies based on detected applications
func (n *NProbeConnector) updateApplicationPolicies() {
	// Skip if no Cilium client configured
	if n.ciliumClient == nil {
		return
	}
	
	n.statsLock.RLock()
	defer n.statsLock.RUnlock()
	
	// Convert application stats to Cilium app policies
	appPolicies := make(map[string]cilium.AppPolicy)
	
	for app, stats := range n.appStats {
		// Skip if not enough data
		if stats.Flows < 10 {
			continue
		}
		
		// Determine action based on application category
		action := "allow"
		priority := 1
		
		// Check for high-risk categories
		for category := range stats.Categories {
			if isHighRiskCategory(category) {
				action = "log"
				priority = 2
				break
			}
		}
		
		// Check application risks
		if def, ok := n.appDefinitions[app]; ok {
			if hasHighRisk(def.Risks) {
				action = "log"
				priority = 2
			}
		}
		
		// Create the policy
		appPolicies[app] = cilium.AppPolicy{
			Application: app,
			Action:      action,
			Priority:    priority,
			DSCP:        0, // No QoS marking by default
		}
	}
	
	// Apply policies if any
	if len(appPolicies) > 0 {
		// Use a background context since our main context might be canceled
		ctx := context.Background()
		if err := n.ciliumClient.ConfigureDPIIntegration(ctx, &cilium.DPIIntegrationConfig{
			EnableAppDetection: true,
			AppPolicies:        appPolicies,
		}); err != nil {
			log.Printf("Failed to update application policies: %v", err)
		} else {
			log.Printf("Updated Cilium policies for %d applications", len(appPolicies))
		}
	}
}

// GetApplicationStats returns statistics for a specific application
func (n *NProbeConnector) GetApplicationStats(app string) (AppStats, error) {
	n.statsLock.RLock()
	defer n.statsLock.RUnlock()
	
	stats, exists := n.appStats[app]
	if !exists {
		return AppStats{}, fmt.Errorf("no statistics for application: %s", app)
	}
	
	return stats, nil
}

// GetAllApplicationStats returns statistics for all applications
func (n *NProbeConnector) GetAllApplicationStats() map[string]AppStats {
	n.statsLock.RLock()
	defer n.statsLock.RUnlock()
	
	// Make a copy to avoid concurrency issues
	statsCopy := make(map[string]AppStats, len(n.appStats))
	for app, stats := range n.appStats {
		// Deep copy the hosts map
		hostsCopy := make(map[string]bool, len(stats.Hosts))
		for host, val := range stats.Hosts {
			hostsCopy[host] = val
		}
		
		// Deep copy the categories map
		categoriesCopy := make(map[string]int64, len(stats.Categories))
		for cat, count := range stats.Categories {
			categoriesCopy[cat] = count
		}
		
		// Create a copy of the stats with the copied maps
		statsCopy[app] = AppStats{
			Flows:      stats.Flows,
			Bytes:      stats.Bytes,
			Packets:    stats.Packets,
			Hosts:      hostsCopy,
			LastSeen:   stats.LastSeen,
			Categories: categoriesCopy,
		}
	}
	
	return statsCopy
}

// GetApplicationDefinition returns metadata for an application
func (n *NProbeConnector) GetApplicationDefinition(app string) (AppDefinition, error) {
	def, exists := n.appDefinitions[app]
	if !exists {
		return AppDefinition{}, fmt.Errorf("no definition for application: %s", app)
	}
	
	return def, nil
}

// Helper functions

// loadAppDefinitions loads application definitions
func loadAppDefinitions() map[string]AppDefinition {
	// In a real implementation, this would load from a file or database
	
	// Sample application definitions
	return map[string]AppDefinition{
		"HTTP": {
			Name:         "HTTP",
			Category:     "Web",
			Description:  "Hypertext Transfer Protocol",
			DefaultPorts: []string{"80"},
			Risks:        []string{"Unencrypted", "Potential data leakage"},
			References:   []string{"https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"},
		},
		"HTTPS": {
			Name:         "HTTPS",
			Category:     "Web",
			Description:  "HTTP Secure",
			DefaultPorts: []string{"443"},
			Risks:        []string{"Potential for malicious sites", "Certificate issues"},
			References:   []string{"https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"},
		},
		"SSH": {
			Name:         "SSH",
			Category:     "Remote Access",
			Description:  "Secure Shell",
			DefaultPorts: []string{"22"},
			Risks:        []string{"Brute force attacks", "Unauthorized access"},
			References:   []string{"https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"},
		},
		"DNS": {
			Name:         "DNS",
			Category:     "Network",
			Description:  "Domain Name System",
			DefaultPorts: []string{"53"},
			Risks:        []string{"DNS tunneling", "Cache poisoning"},
			References:   []string{"https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"},
		},
		"BitTorrent": {
			Name:         "BitTorrent",
			Category:     "File Sharing",
			Description:  "BitTorrent P2P file sharing protocol",
			DefaultPorts: []string{"6881-6889"},
			Risks:        []string{"Copyright infringement", "Malware distribution", "High bandwidth usage"},
			References:   []string{"https://www.bittorrent.org/"},
		},
		"SMTP": {
			Name:         "SMTP",
			Category:     "Email",
			Description:  "Simple Mail Transfer Protocol",
			DefaultPorts: []string{"25", "587"},
			Risks:        []string{"Spam relay", "Email spoofing"},
			References:   []string{"https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"},
		},
	}
}

// isHighRiskCategory determines if a category is high risk
func isHighRiskCategory(category string) bool {
	highRiskCategories := map[string]bool{
		"Malware":       true,
		"Attack":        true,
		"Mining":        true,
		"Botnet":        true,
		"FileSharing":   true,
		"Illegal":       true,
		"Cryptomining":  true,
		"Gambling":      true,
	}
	
	return highRiskCategories[category]
}

// hasHighRisk checks if application has high-risk factors
func hasHighRisk(risks []string) bool {
	highRiskFactors := map[string]bool{
		"Malware distribution":   true,
		"Data exfiltration":      true,
		"Command and control":    true,
		"Unauthorized access":    true,
		"Brute force attacks":    true,
		"Cryptomining":           true,
	}
	
	for _, risk := range risks {
		if highRiskFactors[risk] {
			return true
		}
	}
	
	return false
}