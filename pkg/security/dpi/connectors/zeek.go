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
	"github.com/varuntirumala1/fos1/pkg/cilium"
)

// ZeekConnector integrates Zeek with Cilium
type ZeekConnector struct {
	// Configuration
	logsPath      string
	policyPath    string
	ciliumClient  cilium.CiliumClient
	networkCtrl   *cilium.NetworkController
	
	// State
	watcher       *fsnotify.Watcher
	policies      map[string]*cilium.NetworkPolicy
	
	// Locking
	mu            sync.RWMutex
	
	// Control
	ctx           context.Context
	cancel        context.CancelFunc
}

// ZeekOptions configures the Zeek connector
type ZeekOptions struct {
	LogsPath     string
	PolicyPath   string
	CiliumClient cilium.CiliumClient
}

// NewZeekConnector creates a new Zeek connector
func NewZeekConnector(opts ZeekOptions) (*ZeekConnector, error) {
	if opts.LogsPath == "" {
		opts.LogsPath = "/usr/local/zeek/logs/current"
	}
	
	if opts.PolicyPath == "" {
		opts.PolicyPath = "/usr/local/zeek/share/zeek/policy"
	}
	
	if opts.CiliumClient == nil {
		return nil, fmt.Errorf("cilium client is required")
	}
	
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	connector := &ZeekConnector{
		logsPath:     opts.LogsPath,
		policyPath:   opts.PolicyPath,
		ciliumClient: opts.CiliumClient,
		networkCtrl:  cilium.NewNetworkController(opts.CiliumClient),
		watcher:      watcher,
		policies:     make(map[string]*cilium.NetworkPolicy),
		ctx:          ctx,
		cancel:       cancel,
	}
	
	return connector, nil
}

// Start starts the Zeek connector
func (c *ZeekConnector) Start() error {
	// Watch the notice.log, conn.log, and http.log files
	noticePath := filepath.Join(c.logsPath, "notice.log")
	if err := c.watcher.Add(noticePath); err != nil {
		fmt.Printf("Failed to watch notice.log: %v\n", err)
	}
	
	connPath := filepath.Join(c.logsPath, "conn.log")
	if err := c.watcher.Add(connPath); err != nil {
		fmt.Printf("Failed to watch conn.log: %v\n", err)
	}
	
	httpPath := filepath.Join(c.logsPath, "http.log")
	if err := c.watcher.Add(httpPath); err != nil {
		fmt.Printf("Failed to watch http.log: %v\n", err)
	}
	
	sslPath := filepath.Join(c.logsPath, "ssl.log")
	if err := c.watcher.Add(sslPath); err != nil {
		fmt.Printf("Failed to watch ssl.log: %v\n", err)
	}
	
	dnsPath := filepath.Join(c.logsPath, "dns.log")
	if err := c.watcher.Add(dnsPath); err != nil {
		fmt.Printf("Failed to watch dns.log: %v\n", err)
	}
	
	// Start processing events
	go c.processEvents()
	
	return nil
}

// Stop stops the Zeek connector
func (c *ZeekConnector) Stop() error {
	c.cancel()
	return c.watcher.Close()
}

// processEvents processes events from Zeek
func (c *ZeekConnector) processEvents() {
	// Monitor notice.log for changes
	go c.tailNoticeLog()
	
	// Process watcher events
	for {
		select {
		case <-c.ctx.Done():
			return
		case event, ok := <-c.watcher.Events:
			if !ok {
				return
			}
			
			// Process file changes
			if event.Op&fsnotify.Write == fsnotify.Write {
				// Check which log file changed
				fileName := filepath.Base(event.Name)
				switch fileName {
				case "conn.log":
					// Process connection logs
					go c.processConnLog(event.Name)
				case "http.log":
					// Process HTTP logs
					go c.processHTTPLog(event.Name)
				case "ssl.log":
					// Process SSL logs
					go c.processSSLLog(event.Name)
				case "dns.log":
					// Process DNS logs
					go c.processDNSLog(event.Name)
				}
			}
		case err, ok := <-c.watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("Watcher error: %v\n", err)
		}
	}
}

// tailNoticeLog tails the notice.log file for new notices
func (c *ZeekConnector) tailNoticeLog() {
	noticePath := filepath.Join(c.logsPath, "notice.log")
	file, err := os.Open(noticePath)
	if err != nil {
		fmt.Printf("Failed to open notice.log: %v\n", err)
		return
	}
	defer file.Close()
	
	// Seek to the end of the file
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		fmt.Printf("Failed to seek to end of notice.log: %v\n", err)
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
				fmt.Printf("Error reading notice.log: %v\n", err)
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
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				
				// Process notice log entry
				c.processNoticeEntry(line)
			}
			
			// Update offset
			offset += int64(n)
		}
	}
}

// processNoticeEntry processes a Zeek notice log entry
func (c *ZeekConnector) processNoticeEntry(line string) {
	// Parse tab-separated fields
	fields := strings.Split(line, "\t")
	if len(fields) < 12 {
		return
	}
	
	// Extract fields
	// Format: ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tfqdn\tproto\tnote\tmsg\tsub\tsrc
	ts := fields[0]
	uid := fields[1]
	srcIP := fields[2]
	srcPort := fields[3]
	destIP := fields[4]
	destPort := fields[5]
	fqdn := fields[6]
	proto := fields[7]
	noteType := fields[8]
	msg := fields[9]
	sub := fields[10]
	src := fields[11]
	
	// Create policy for significant notices
	if isSignificantNotice(noteType) {
		c.createZeekPolicy(noteType, msg, srcIP, destIP, srcPort, destPort, proto, sub, fqdn)
	}
	
	// Log the notice
	fmt.Printf("Zeek Notice: [%s] %s - %s:%s -> %s:%s [%s] - %s\n",
		noteType, msg, srcIP, srcPort, destIP, destPort, proto, sub)
}

// isSignificantNotice determines if a notice is significant enough to create a policy
func isSignificantNotice(noteType string) bool {
	// These are some common Zeek notice types that might indicate malicious activity
	significantNotices := []string{
		"Scan::Port_Scan",
		"Scan::Address_Scan",
		"Scan::Random_Scan",
		"HTTP::SQL_Injection_Attacker",
		"HTTP::XSS_Attacker",
		"SSL::Invalid_Server_Cert",
		"SSL::Certificate_Expired",
		"SSL::Self_Signed_Cert",
		"DNS::Suspicious_Domain",
		"FTP::Bruteforcing",
		"SSH::Password_Guessing",
		"SSH::External_Login",
		"Traceroute::Detected",
		"TeamCymruMalwareHashRegistry::Match",
	}
	
	for _, notice := range significantNotices {
		if noteType == notice {
			return true
		}
	}
	
	return false
}

// createZeekPolicy creates a Cilium policy based on a Zeek notice
func (c *ZeekConnector) createZeekPolicy(noteType, msg, srcIP, destIP, srcPort, destPort, proto, sub, fqdn string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Normalize policy name
	policyName := fmt.Sprintf("zeek-notice-%s", normalizeString(noteType))
	
	// Check if we already have a policy for this notice type
	if _, exists := c.policies[policyName]; exists {
		// Policy already exists, update it or add new rules
		return
	}
	
	// Create a policy that denies the specific traffic
	policy := &cilium.NetworkPolicy{
		Name: policyName,
		Labels: map[string]string{
			"app":       "zeek",
			"notice":    normalizeString(noteType),
			"component": "security",
		},
	}
	
	// Configure the policy based on the notice
	protocol := strings.ToLower(proto)
	
	// Create CIDR-based rules
	// First convert IPs to CIDR notation if needed
	srcCIDR := srcIP
	if !strings.Contains(srcIP, "/") && srcIP != "-" {
		srcCIDR = srcIP + "/32"
	}
	
	destCIDR := destIP
	if !strings.Contains(destIP, "/") && destIP != "-" {
		destCIDR = destIP + "/32"
	}
	
	// Only create rules if we have valid IPs
	if srcIP != "-" && destIP != "-" {
		// Create rules for both directions
		
		// Rule to block traffic from source to destination
		if srcPort != "-" && destPort != "-" {
			srcPortNum, srcPortErr := strconv.Atoi(srcPort)
			destPortNum, destPortErr := strconv.Atoi(destPort)
			
			if destPortErr == nil {
				policy.Ingress = append(policy.Ingress, cilium.PolicyRule{
					FromCIDR: []string{srcCIDR},
					ToPorts: []cilium.PortRule{
						{
							Ports: []cilium.Port{
								{
									Port:     uint16(destPortNum),
									Protocol: protocol,
								},
							},
						},
					},
					Denied: true,
				})
			}
			
			// Rule to block traffic from destination to source
			if srcPortErr == nil {
				policy.Egress = append(policy.Egress, cilium.PolicyRule{
					ToCIDR: []string{srcCIDR},
					ToPorts: []cilium.PortRule{
						{
							Ports: []cilium.Port{
								{
									Port:     uint16(srcPortNum),
									Protocol: protocol,
								},
							},
						},
					},
					Denied: true,
				})
			}
		}
	}
	
	// Add domain-based rules if available
	if fqdn != "-" && fqdn != "" {
		policy.Egress = append(policy.Egress, cilium.PolicyRule{
			ToFQDNs: []cilium.MatchFQDN{
				{
					MatchPattern: fqdn,
				},
			},
			Denied: true,
		})
	}
	
	// Store the policy if it has any rules
	if len(policy.Ingress) > 0 || len(policy.Egress) > 0 {
		c.policies[policyName] = policy
		
		// Apply the policy
		if err := c.networkCtrl.ApplyDynamicPolicy(c.ctx, policy); err != nil {
			fmt.Printf("Failed to apply Zeek policy: %v\n", err)
		} else {
			fmt.Printf("Applied Zeek policy %s for notice: %s\n", policyName, noteType)
		}
	}
}

// processConnLog processes a Zeek connection log
func (c *ZeekConnector) processConnLog(path string) {
	// This would process the connection log
	// Skipping implementation details for brevity
	// In a real implementation, this would parse the conn.log and extract
	// useful information for traffic analysis
}

// processHTTPLog processes a Zeek HTTP log
func (c *ZeekConnector) processHTTPLog(path string) {
	// This would process the HTTP log
	// Skipping implementation details for brevity
	// In a real implementation, this would parse the http.log and extract
	// useful information for HTTP traffic analysis
}

// processSSLLog processes a Zeek SSL log
func (c *ZeekConnector) processSSLLog(path string) {
	// This would process the SSL log
	// Skipping implementation details for brevity
	// In a real implementation, this would parse the ssl.log and extract
	// useful information for SSL/TLS traffic analysis
}

// processDNSLog processes a Zeek DNS log
func (c *ZeekConnector) processDNSLog(path string) {
	// This would process the DNS log
	// Skipping implementation details for brevity
	// In a real implementation, this would parse the dns.log and extract
	// useful information for DNS traffic analysis
}

// ExtractProtocols extracts application protocols identified by Zeek
func (c *ZeekConnector) ExtractProtocols() (map[string]int, error) {
	// This would extract protocol information from Zeek logs
	// For simplicity, returning a sample map
	return map[string]int{
		"http":  100,
		"https": 200,
		"ssh":   50,
		"dns":   150,
		"ftp":   10,
	}, nil
}

// GetProtocolStats gets statistics for a specific protocol
func (c *ZeekConnector) GetProtocolStats(protocol string) (map[string]interface{}, error) {
	// This would extract protocol statistics from Zeek logs
	// For simplicity, returning a sample map
	stats := map[string]interface{}{
		"connections": 100,
		"bytes":       1024000,
		"packets":     5000,
		"duration":    300,
	}
	
	return stats, nil
}