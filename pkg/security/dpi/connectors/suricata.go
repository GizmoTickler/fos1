package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/your-org/fos1/pkg/cilium"
)

// SuricataConnector integrates Suricata with Cilium
type SuricataConnector struct {
	// Configuration
	evePath        string
	rulesetPath    string
	listPath       string
	mode           string // "ids" or "ips"
	ciliumClient   cilium.CiliumClient
	networkCtrl    *cilium.NetworkController
	
	// State
	watcher        *fsnotify.Watcher
	alertRules     map[string]*cilium.NetworkPolicy
	ipLists        map[string][]string
	
	// Locking
	mu             sync.RWMutex
	
	// Control
	ctx            context.Context
	cancel         context.CancelFunc
}

// SuricataOptions configures the Suricata connector
type SuricataOptions struct {
	EvePath        string
	RulesetPath    string
	ListPath       string
	Mode           string // "ids" or "ips"
	CiliumClient   cilium.CiliumClient
}

// NewSuricataConnector creates a new Suricata connector
func NewSuricataConnector(opts SuricataOptions) (*SuricataConnector, error) {
	if opts.EvePath == "" {
		opts.EvePath = "/var/log/suricata/eve.json"
	}
	
	if opts.RulesetPath == "" {
		opts.RulesetPath = "/etc/suricata/rules"
	}
	
	if opts.ListPath == "" {
		opts.ListPath = "/etc/suricata/lists"
	}
	
	if opts.Mode == "" {
		opts.Mode = "ids" // Default to IDS mode
	} else if opts.Mode != "ids" && opts.Mode != "ips" {
		return nil, fmt.Errorf("invalid mode: %s (must be 'ids' or 'ips')", opts.Mode)
	}
	
	if opts.CiliumClient == nil {
		return nil, fmt.Errorf("cilium client is required")
	}
	
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	connector := &SuricataConnector{
		evePath:      opts.EvePath,
		rulesetPath:  opts.RulesetPath,
		listPath:     opts.ListPath,
		mode:         opts.Mode,
		ciliumClient: opts.CiliumClient,
		networkCtrl:  cilium.NewNetworkController(opts.CiliumClient),
		watcher:      watcher,
		alertRules:   make(map[string]*cilium.NetworkPolicy),
		ipLists:      make(map[string][]string),
		ctx:          ctx,
		cancel:       cancel,
	}
	
	return connector, nil
}

// Start starts the Suricata connector
func (c *SuricataConnector) Start() error {
	// Monitor the Eve file for new alerts
	err := c.watcher.Add(c.evePath)
	if err != nil {
		return fmt.Errorf("failed to watch eve.json: %w", err)
	}
	
	// Load IP lists
	if err := c.loadIPLists(); err != nil {
		return fmt.Errorf("failed to load IP lists: %w", err)
	}
	
	// Start processing events
	go c.processEvents()
	
	return nil
}

// Stop stops the Suricata connector
func (c *SuricataConnector) Stop() error {
	c.cancel()
	return c.watcher.Close()
}

// processEvents processes events from Suricata
func (c *SuricataConnector) processEvents() {
	// Start a file tailer for the Eve file
	go c.tailEveFile()
	
	// Process watcher events
	for {
		select {
		case <-c.ctx.Done():
			return
		case event, ok := <-c.watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write && event.Name == c.evePath {
				// Eve file was updated, but we're already tailing it
			}
		case err, ok := <-c.watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("Watcher error: %v\n", err)
		}
	}
}

// tailEveFile tails the Eve file for new alerts
func (c *SuricataConnector) tailEveFile() {
	file, err := os.Open(c.evePath)
	if err != nil {
		fmt.Printf("Failed to open eve.json: %v\n", err)
		return
	}
	defer file.Close()
	
	// Seek to the end of the file
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		fmt.Printf("Failed to seek to end of eve.json: %v\n", err)
		return
	}
	
	// Read new lines as they are written
	buffer := make([]byte, 4096)
	offset := int64(0)
	
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			// Read new content
			n, err := file.ReadAt(buffer, offset)
			if err != nil && err != io.EOF {
				fmt.Printf("Error reading eve.json: %v\n", err)
				time.Sleep(1 * time.Second)
				continue
			}
			
			if n == 0 {
				// No new data, wait and try again
				time.Sleep(100 * time.Millisecond)
				continue
			}
			
			// Process new content
			lines := strings.Split(string(buffer[:n]), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}
				
				// Parse JSON
				var event map[string]interface{}
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					continue
				}
				
				// Process alert
				if eventType, ok := event["event_type"].(string); ok && eventType == "alert" {
					c.processAlert(event)
				}
			}
			
			// Update offset
			offset += int64(n)
		}
	}
}

// processAlert processes a Suricata alert
func (c *SuricataConnector) processAlert(event map[string]interface{}) {
	// Extract alert information
	alert, ok := event["alert"].(map[string]interface{})
	if !ok {
		return
	}
	
	signature, ok := alert["signature"].(string)
	if !ok {
		return
	}
	
	category, _ := alert["category"].(string)
	action, _ := alert["action"].(string)
	
	// Extract source and destination
	src, ok := event["src_ip"].(string)
	if !ok {
		return
	}
	
	dest, ok := event["dest_ip"].(string)
	if !ok {
		return
	}
	
	srcPort, _ := event["src_port"].(float64)
	destPort, _ := event["dest_port"].(float64)
	proto, _ := event["proto"].(string)
	
	// Process in IPS mode - create blocking policies
	if c.mode == "ips" && action != "allowed" {
		c.createBlockingPolicy(signature, category, src, dest, int(srcPort), int(destPort), proto)
	}
	
	// In IDS mode, we just log the alert
	fmt.Printf("Suricata Alert: %s (%s) - %s:%v -> %s:%v [%s]\n", 
		signature, category, src, int(srcPort), dest, int(destPort), proto)
}

// createBlockingPolicy creates a Cilium policy to block traffic
func (c *SuricataConnector) createBlockingPolicy(signature, category, src, dest string, srcPort, destPort int, proto string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Normalize policy name
	policyName := fmt.Sprintf("suricata-block-%s", normalizeString(signature))
	
	// Check if we already have a policy for this alert
	if _, exists := c.alertRules[policyName]; exists {
		// Policy already exists, no need to create a new one
		return
	}
	
	// Create a policy that denies the specific traffic
	policy := &cilium.NetworkPolicy{
		Name: policyName,
		Labels: map[string]string{
			"app":       "suricata",
			"signature": normalizeString(signature),
			"category":  normalizeString(category),
		},
	}
	
	// Configure the policy based on the alert
	protocol := strings.ToLower(proto)
	
	// Create CIDR-based rules
	// First convert IPs to CIDR notation
	srcCIDR := src
	if !strings.Contains(src, "/") {
		srcCIDR = src + "/32"
	}
	
	destCIDR := dest
	if !strings.Contains(dest, "/") {
		destCIDR = dest + "/32"
	}
	
	// Create rules for both directions since attacks can be bidirectional
	
	// Rule to block traffic from source to destination
	policy.Ingress = append(policy.Ingress, cilium.PolicyRule{
		FromCIDR: []string{srcCIDR},
		ToPorts: []cilium.PortRule{
			{
				Ports: []cilium.Port{
					{
						Port:     uint16(destPort),
						Protocol: protocol,
					},
				},
			},
		},
		Denied: true,
	})
	
	// Rule to block traffic from destination to source
	policy.Egress = append(policy.Egress, cilium.PolicyRule{
		ToCIDR: []string{srcCIDR},
		ToPorts: []cilium.PortRule{
			{
				Ports: []cilium.Port{
					{
						Port:     uint16(srcPort),
						Protocol: protocol,
					},
				},
			},
		},
		Denied: true,
	})
	
	// Store the policy
	c.alertRules[policyName] = policy
	
	// Apply the policy
	if err := c.networkCtrl.ApplyDynamicPolicy(c.ctx, policy); err != nil {
		fmt.Printf("Failed to apply blocking policy: %v\n", err)
	} else {
		fmt.Printf("Applied blocking policy %s for alert: %s\n", policyName, signature)
	}
}

// loadIPLists loads IP lists from the list directory
func (c *SuricataConnector) loadIPLists() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Clear existing lists
	c.ipLists = make(map[string][]string)
	
	// List files in the list directory
	files, err := os.ReadDir(c.listPath)
	if err != nil {
		return fmt.Errorf("failed to read lists directory: %w", err)
	}
	
	for _, file := range files {
		if file.IsDir() || strings.HasPrefix(file.Name(), ".") {
			continue
		}
		
		// Read list file
		listName := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
		listPath := filepath.Join(c.listPath, file.Name())
		
		content, err := os.ReadFile(listPath)
		if err != nil {
			fmt.Printf("Failed to read list %s: %v\n", listName, err)
			continue
		}
		
		// Parse list
		var ips []string
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			ips = append(ips, line)
		}
		
		// Store list
		c.ipLists[listName] = ips
		
		// Watch list file for changes
		if err := c.watcher.Add(listPath); err != nil {
			fmt.Printf("Failed to watch list %s: %v\n", listName, err)
		}
	}
	
	return nil
}

// ConfigureIPSMode configures Suricata to run in IPS mode
func (c *SuricataConnector) ConfigureIPSMode(enable bool) error {
	// Update connector mode
	if enable {
		c.mode = "ips"
	} else {
		c.mode = "ids"
	}
	
	// This should also update the Suricata configuration
	// In a real implementation, this would modify the Suricata configuration
	// and restart the service
	
	return nil
}

// UpdateIPList updates a Suricata IP list
func (c *SuricataConnector) UpdateIPList(listName string, ips []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Create list directory if it doesn't exist
	if err := os.MkdirAll(c.listPath, 0755); err != nil {
		return fmt.Errorf("failed to create lists directory: %w", err)
	}
	
	// Write list to file
	listPath := filepath.Join(c.listPath, listName+".list")
	content := strings.Join(ips, "\n")
	
	if err := os.WriteFile(listPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write list %s: %w", listName, err)
	}
	
	// Store list in memory
	c.ipLists[listName] = ips
	
	// Watch list file for changes if not already watching
	if err := c.watcher.Add(listPath); err != nil {
		fmt.Printf("Failed to watch list %s: %v\n", listName, err)
	}
	
	return nil
}

// GetIPList gets a Suricata IP list
func (c *SuricataConnector) GetIPList(listName string) ([]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	ips, ok := c.ipLists[listName]
	if !ok {
		return nil, fmt.Errorf("list %s not found", listName)
	}
	
	return ips, nil
}

// Helper functions

// normalizeString normalizes a string for use as a Kubernetes resource name
func normalizeString(s string) string {
	// Replace characters not allowed in Kubernetes resource names
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	
	// Ensure name is not too long
	if len(s) > 63 {
		s = s[:63]
	}
	
	return s
}