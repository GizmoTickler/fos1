package connectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/varuntirumala1/fos1/pkg/cilium"
	"github.com/varuntirumala1/fos1/pkg/security/dpi"
)

// ZeekConnector integrates Zeek with Cilium and implements the ZeekConnectorInterface
type ZeekConnector struct {
	// Configuration
	logsPath      string
	policyPath    string
	ciliumClient  cilium.CiliumClient
	networkCtrl   *cilium.NetworkController
	vlanAware     bool
	vlans         map[int]VLANConfig

	// State
	watcher       *fsnotify.Watcher
	policies      map[string]*cilium.NetworkPolicy
	protocolStats map[string]*ProtocolStats
	applicationMap map[string]string // Maps service names to application names

	// Locking
	mu            sync.RWMutex

	// Event handling
	eventChan     chan dpi.DPIEvent

	// Control
	ctx           context.Context
	cancel        context.CancelFunc
	startTime     time.Time
	logsProcessed int64
	lastError     string
}

// ZeekOptions configures the Zeek connector
type ZeekOptions struct {
	LogsPath       string
	PolicyPath     string
	CiliumClient   cilium.CiliumClient
	KubernetesMode bool   // Whether running in Kubernetes
	Namespace      string // Kubernetes namespace

	// VLAN configuration
	VLANAware      bool              // Whether to process VLAN tags
	VLANs          map[int]VLANConfig // VLAN configurations

	// TLS configuration
	TLSEnabled     bool   // Whether to use TLS for communication
	TLSCertPath    string // Path to TLS certificate
	TLSKeyPath     string // Path to TLS key
	TLSCAPath      string // Path to TLS CA certificate
}

// ProtocolStats contains statistics for a protocol
type ProtocolStats struct {
	Connections int64
	Bytes       int64
	Packets     int64
	Duration    int64
	Hosts       map[string]bool
	VLANs        map[int]int64 // Count of connections per VLAN
	LastSeen    time.Time
}

// VLANConfig contains configuration for a VLAN
type VLANConfig struct {
	ID          int
	Name        string
	Subnet      string
	DefaultPolicy string // "allow", "deny", or "restrict"
	Applications []string // Allowed applications
}

// NewZeekConnector creates a new Zeek connector
func NewZeekConnector(opts ZeekOptions) (*ZeekConnector, error) {
	// Set default paths based on environment
	if opts.LogsPath == "" {
		if opts.KubernetesMode {
			// In Kubernetes, logs are typically mounted at /zeek-logs
			opts.LogsPath = "/zeek-logs/current"
		} else {
			// Default path for non-Kubernetes environments
			opts.LogsPath = "/usr/local/zeek/logs/current"
		}
	}

	if opts.PolicyPath == "" {
		if opts.KubernetesMode {
			// In Kubernetes, policy path is typically mounted at /zeek-policy
			opts.PolicyPath = "/zeek-policy"
		} else {
			// Default path for non-Kubernetes environments
			opts.PolicyPath = "/usr/local/zeek/share/zeek/policy"
		}
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
		logsPath:      opts.LogsPath,
		policyPath:    opts.PolicyPath,
		ciliumClient:  opts.CiliumClient,
		networkCtrl:   cilium.NewNetworkController(opts.CiliumClient),
		vlanAware:     opts.VLANAware,
		vlans:         opts.VLANs,
		watcher:       watcher,
		policies:      make(map[string]*cilium.NetworkPolicy),
		protocolStats: make(map[string]*ProtocolStats),
		applicationMap: initApplicationMap(),
		eventChan:     make(chan dpi.DPIEvent, 1000),
		ctx:           ctx,
		cancel:        cancel,
		startTime:     time.Now(),
	}

	return connector, nil
}

// Start starts the Zeek connector
func (c *ZeekConnector) Start() error {
	// Ensure log directory exists
	if _, err := os.Stat(c.logsPath); os.IsNotExist(err) {
		fmt.Printf("Zeek logs directory %s does not exist, waiting for it to be created\n", c.logsPath)

		// In Kubernetes, the directory might be created after we start
		// Start a goroutine to wait for the directory
		go c.waitForLogsDirectory()
		return nil
	}

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
	// Open the conn.log file
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Failed to open conn.log: %v\n", err)
		return
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	// Skip header lines
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			break
		}
	}

	// Process each line
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse tab-separated fields
		fields := strings.Split(line, "\t")
		if len(fields) < 20 { // Conn log has at least 20 fields
			continue
		}

		// Extract fields
		// Format: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service ...
		ts := fields[0]
		uid := fields[1]
		srcIP := fields[2]
		srcPort := fields[3]
		destIP := fields[4]
		destPort := fields[5]
		proto := fields[6]
		service := fields[7] // This is the application protocol

		// Skip entries with missing data
		if srcIP == "-" || destIP == "-" {
			continue
		}

		// Parse numeric fields
		srcPortNum, _ := strconv.Atoi(srcPort)
		destPortNum, _ := strconv.Atoi(destPort)

		// Extract VLAN information if available (field 9 in newer Zeek versions with vlan-logging.zeek)
		vlan := 0
		if len(fields) > 9 && c.vlanAware {
			vlanStr := fields[9]
			if vlanStr != "-" {
				vlan, _ = strconv.Atoi(vlanStr)
			}
		}

		// Map service to application
		application := service
		if service != "-" {
			if mappedApp, exists := c.applicationMap[service]; exists {
				application = mappedApp
			}
		} else {
			// Try to determine application based on port
			application = determineApplicationByPort(destPortNum, proto)
		}

		// Parse timestamp
		timestamp, err := time.Parse("2006-01-02T15:04:05.999999", ts)
		if err != nil {
			timestamp = time.Now() // Use current time if parsing fails
		}

		// Extract additional fields for statistics
		origBytes := int64(0)
		respBytes := int64(0)
		origPkts := int64(0)
		respPkts := int64(0)
		duration := int64(0)

		if len(fields) > 9 && fields[9] != "-" {
			origBytes, _ = strconv.ParseInt(fields[9], 10, 64)
		}
		if len(fields) > 10 && fields[10] != "-" {
			respBytes, _ = strconv.ParseInt(fields[10], 10, 64)
		}
		if len(fields) > 11 && fields[11] != "-" {
			origPkts, _ = strconv.ParseInt(fields[11], 10, 64)
		}
		if len(fields) > 12 && fields[12] != "-" {
			respPkts, _ = strconv.ParseInt(fields[12], 10, 64)
		}
		if len(fields) > 8 && fields[8] != "-" {
			duration, _ = strconv.ParseInt(fields[8], 10, 64)
		}

		// Update protocol statistics
		c.updateProtocolStats(application, srcIP, destIP, origBytes+respBytes, origPkts+respPkts, duration, vlan)

		// Check if this application is allowed on this VLAN
		allowed := true
		if c.vlanAware && vlan > 0 {
			if vlanConfig, exists := c.vlans[vlan]; exists {
				// Check if application is in the allowed list
				allowed = isApplicationAllowed(application, vlanConfig.Applications)

				// If not allowed and policy is deny, create a blocking policy
				if !allowed && vlanConfig.DefaultPolicy == "deny" {
					c.createVLANBlockingPolicy(vlan, application, srcIP, destIP, uint16(srcPortNum), uint16(destPortNum), proto)
				}
			}
		}

		// Create a DPI event for this connection
		event := dpi.DPIEvent{
			Timestamp:   timestamp,
			SourceIP:    srcIP,
			DestIP:      destIP,
			SourcePort:  srcPortNum,
			DestPort:    destPortNum,
			Protocol:    proto,
			Application: application,
			Category:    categorizeApplication(application),
			EventType:   "flow",
			Severity:    0, // Normal flow, no severity
			Description: fmt.Sprintf("%s flow from %s:%d to %s:%d", application, srcIP, srcPortNum, destIP, destPortNum),
			SessionID:   uid,
			RawData: map[string]interface{}{
				"bytes":    origBytes + respBytes,
				"packets":  origPkts + respPkts,
				"duration": duration,
				"vlan":     vlan,
				"allowed":  allowed,
				"service":  service,
			},
		}

		// Send the event
		select {
		case c.eventChan <- event:
			// Successfully sent
		default:
			// Channel full, log and continue
			fmt.Println("Event channel full, dropping event")
		}

		// Increment logs processed counter
		c.mu.Lock()
		c.logsProcessed++
		c.mu.Unlock()
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading conn.log: %v\n", err)
		c.mu.Lock()
		c.lastError = fmt.Sprintf("Error reading conn.log: %v", err)
		c.mu.Unlock()
	}
}

// processHTTPLog processes a Zeek HTTP log
func (c *ZeekConnector) processHTTPLog(path string) {
	// Open the http.log file
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Failed to open http.log: %v\n", err)
		return
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	// Skip header lines
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			break
		}
	}

	// Process each line
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse tab-separated fields
		fields := strings.Split(line, "\t")
		if len(fields) < 15 { // HTTP log has at least 15 fields
			continue
		}

		// Extract fields
		// Format: ts uid id.orig_h id.orig_p id.resp_h id.resp_p method host uri ...
		ts := fields[0]
		uid := fields[1]
		srcIP := fields[2]
		srcPort := fields[3]
		destIP := fields[4]
		destPort := fields[5]
		method := fields[7]
		host := fields[8]
		uri := fields[9]
		userAgent := fields[12]

		// Skip entries with missing data
		if srcIP == "-" || destIP == "-" {
			continue
		}

		// Parse numeric fields
		srcPortNum, _ := strconv.Atoi(srcPort)
		destPortNum, _ := strconv.Atoi(destPort)

		// Parse timestamp
		timestamp, err := time.Parse("2006-01-02T15:04:05.999999", ts)
		if err != nil {
			timestamp = time.Now() // Use current time if parsing fails
		}

		// Create a DPI event for this HTTP request
		event := dpi.DPIEvent{
			Timestamp:   timestamp,
			SourceIP:    srcIP,
			DestIP:      destIP,
			SourcePort:  srcPortNum,
			DestPort:    destPortNum,
			Protocol:    "tcp",
			Application: "http",
			Category:    "web",
			EventType:   "http",
			Severity:    0, // Normal HTTP request, no severity
			Description: fmt.Sprintf("HTTP %s %s", method, uri),
			SessionID:   uid,
			RawData: map[string]interface{}{
				"method":     method,
				"host":       host,
				"uri":        uri,
				"user_agent": userAgent,
			},
		}

		// Send the event
		select {
		case c.eventChan <- event:
			// Successfully sent
		default:
			// Channel full, log and continue
			fmt.Println("Event channel full, dropping event")
		}

		// Increment logs processed counter
		c.mu.Lock()
		c.logsProcessed++
		c.mu.Unlock()
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading http.log: %v\n", err)
		c.mu.Lock()
		c.lastError = fmt.Sprintf("Error reading http.log: %v", err)
		c.mu.Unlock()
	}
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
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Convert protocol stats to a simple count map
	result := make(map[string]int)
	for proto, stats := range c.protocolStats {
		result[proto] = int(stats.Connections)
	}

	// If no protocols have been detected yet, return some defaults
	if len(result) == 0 {
		return map[string]int{
			"http":  0,
			"https": 0,
			"ssh":   0,
			"dns":   0,
			"ftp":   0,
		}, nil
	}

	return result, nil
}

// GetProtocolStats gets statistics for a specific protocol
func (c *ZeekConnector) GetProtocolStats(protocol string) (map[string]interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if we have stats for this protocol
	stats, exists := c.protocolStats[protocol]
	if !exists {
		return nil, fmt.Errorf("no statistics for protocol: %s", protocol)
	}

	// Convert to a map
	result := map[string]interface{}{
		"connections": stats.Connections,
		"bytes":       stats.Bytes,
		"packets":     stats.Packets,
		"duration":    stats.Duration,
		"hosts":       len(stats.Hosts),
		"last_seen":   stats.LastSeen.Format(time.RFC3339),
	}

	return result, nil
}

// updateProtocolStats updates statistics for a protocol
func (c *ZeekConnector) updateProtocolStats(protocol, srcIP, destIP string, bytes, packets, duration int64, vlan int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get or initialize protocol stats
	stats, exists := c.protocolStats[protocol]
	if !exists {
		stats = &ProtocolStats{
			Hosts: make(map[string]bool),
			VLANs: make(map[int]int64),
		}
		c.protocolStats[protocol] = stats
	}

	// Update statistics
	stats.Connections++
	stats.Bytes += bytes
	stats.Packets += packets
	stats.Duration += duration
	stats.LastSeen = time.Now()

	// Track hosts using this protocol
	stats.Hosts[srcIP] = true
	stats.Hosts[destIP] = true

	// Track VLANs if VLAN-aware
	if c.vlanAware && vlan > 0 {
		stats.VLANs[vlan]++
	}
}

// GetEvents returns a channel of DPI events
func (c *ZeekConnector) GetEvents(ctx context.Context) (<-chan dpi.DPIEvent, error) {
	// Create a new channel for the caller
	events := make(chan dpi.DPIEvent, 100)

	// Start a goroutine to forward events from the internal channel to the caller's channel
	go func() {
		defer close(events)

		for {
			select {
			case <-ctx.Done():
				return // Context canceled, exit

			case <-c.ctx.Done():
				return // Connector stopped, exit

			case event := <-c.eventChan:
				// Forward the event to the caller's channel
				select {
				case events <- event:
					// Successfully sent
				case <-ctx.Done():
					return // Context canceled, exit
				case <-c.ctx.Done():
					return // Connector stopped, exit
				default:
					// Channel full, log and continue
					fmt.Println("Event channel full, dropping event")
				}
			}
		}
	}()

	return events, nil
}

// Configure configures the Zeek connector
func (c *ZeekConnector) Configure(config interface{}) error {
	// Type assertion to check if the config is of the expected type
	cfg, ok := config.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid configuration type: %T", config)
	}

	// Apply configuration
	if logsPath, ok := cfg["logs_path"]; ok {
		if logsPathStr, ok := logsPath.(string); ok {
			c.logsPath = logsPathStr
		}
	}

	if policyPath, ok := cfg["policy_path"]; ok {
		if policyPathStr, ok := policyPath.(string); ok {
			c.policyPath = policyPathStr
		}
	}

	fmt.Printf("Zeek connector configured with logs path %s, policy path %s\n", c.logsPath, c.policyPath)
	return nil
}

// Status returns the status of the Zeek engine
func (c *ZeekConnector) Status() (dpi.ZeekStatus, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := dpi.ZeekStatus{
		Running:      true, // If this function is called, the connector is running
		Uptime:       time.Since(c.startTime),
		LogsProcessed: c.logsProcessed,
		LastError:    c.lastError,
		Version:      "Zeek Connector v1.0", // In a real implementation, would get from Zeek
	}

	return status, nil
}

// categorizeApplication categorizes an application protocol
func categorizeApplication(app string) string {
	categories := map[string]string{
		// Web applications
		"http":     "web",
		"https":    "web",

		// Email applications
		"smtp":     "email",
		"pop3":     "email",
		"imap":     "email",
		"email":    "email",

		// File transfer
		"ftp":      "file-transfer",
		"sftp":     "file-transfer",
		"scp":      "file-transfer",
		"file-transfer": "file-transfer",

		// Remote access
		"ssh":      "remote-access",
		"rdp":      "remote-access",
		"telnet":   "remote-access",
		"vnc":      "remote-access",
		"remote-access": "remote-access",

		// Streaming services
		"rtmp":     "streaming",
		"rtsp":     "streaming",
		"rtp":      "streaming",
		"streaming": "streaming",
		"netflix":  "streaming",
		"youtube":  "streaming",
		"spotify":  "streaming",
		"hulu":     "streaming",
		"disney-plus": "streaming",
		"amazon-video": "streaming",
		"hbo-max":  "streaming",
		"twitch":   "streaming",
		"apple-tv": "streaming",
		"peacock":  "streaming",
		"paramount-plus": "streaming",
		"tubi":     "streaming",
		"crunchyroll": "streaming",

		// Video conferencing
		"zoom":     "video-conferencing",
		"ms-teams": "video-conferencing",
		"google-meet": "video-conferencing",
		"webex":    "video-conferencing",
		"video-conferencing": "video-conferencing",

		// Social media
		"facebook": "social-media",
		"instagram": "social-media",
		"twitter":  "social-media",
		"tiktok":   "social-media",
		"snapchat": "social-media",
		"pinterest": "social-media",
		"reddit":   "social-media",
		"social-media": "social-media",

		// Gaming
		"steam":    "gaming",
		"epic-games": "gaming",
		"xbox-live": "gaming",
		"playstation-network": "gaming",
		"nintendo": "gaming",
		"roblox":   "gaming",
		"minecraft": "gaming",
		"gaming":   "gaming",

		// Messaging
		"xmpp":     "messaging",
		"sip":      "voip",
		"slack":    "messaging",
		"discord":  "messaging",
		"messaging": "messaging",
		"voip":     "voip",

		// IoT
		"mqtt":     "iot",
		"coap":     "iot",
		"modbus":   "iot",
		"iot":      "iot",
		"amazon-echo": "iot",
		"google-home": "iot",
		"nest":     "iot",
		"ring":     "iot",
		"philips-hue": "iot",
		"sonos":    "iot",
		"roku":     "iot",
		"chromecast": "iot",
		"smart-tv": "iot",
		"samsung-tv": "iot",
		"lg-tv":    "iot",
		"vizio-tv": "iot",
		"smart-plug": "iot",
		"smart-bulb": "iot",
		"smart-lock": "iot",
		"smart-thermostat": "iot",
		"smart-doorbell": "iot",
		"smart-camera": "iot",
		"smart-speaker": "iot",

		// Network services
		"dns":      "network-service",
		"dhcp":     "network-service",
		"ntp":      "network-service",
		"snmp":     "network-service",
		"network-service": "network-service",

		// Databases
		"mysql":    "database",
		"postgres": "database",
		"mongodb":  "database",
		"redis":    "database",
		"database": "database",

		// Productivity
		"office365": "productivity",
		"google-docs": "productivity",
		"dropbox":  "productivity",
		"box":      "productivity",
		"onedrive": "productivity",
		"sharepoint": "productivity",
		"productivity": "productivity",
	}

	category, exists := categories[app]
	if !exists {
		return "other"
	}

	return category
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

// waitForLogsDirectory waits for the Zeek logs directory to be created
func (c *ZeekConnector) waitForLogsDirectory() {
	for {
		select {
		case <-c.ctx.Done():
			// Context canceled, exit
			return

		default:
			// Check if directory exists
			if _, err := os.Stat(c.logsPath); err == nil {
				// Directory exists, start watching
				fmt.Printf("Zeek logs directory %s now exists, starting connector\n", c.logsPath)
				if err := c.Start(); err != nil {
					fmt.Printf("Failed to start Zeek connector: %v\n", err)
				}
				return
			}

			// Wait before checking again
			time.Sleep(5 * time.Second)
		}
	}
}

// initApplicationMap initializes the application mapping
func initApplicationMap() map[string]string {
	return map[string]string{
		// Web applications
		"http":       "http",
		"https":      "https",
		"ssl":        "https",
		"http/2":     "http",

		// Email applications
		"smtp":       "email",
		"pop3":       "email",
		"imap":       "email",

		// File transfer
		"ftp":        "file-transfer",
		"sftp":       "file-transfer",
		"scp":        "file-transfer",

		// Remote access
		"ssh":        "remote-access",
		"rdp":        "remote-access",
		"telnet":     "remote-access",
		"vnc":        "remote-access",

		// Streaming
		"rtmp":       "streaming",
		"rtsp":       "streaming",
		"rtp":        "streaming",
		"netflix":    "netflix",
		"youtube":    "youtube",
		"spotify":    "spotify",
		"hulu":       "hulu",
		"disney-plus": "disney-plus",
		"amazon-video": "amazon-video",
		"hbo-max":    "hbo-max",
		"twitch":     "twitch",
		"apple-tv":   "apple-tv",
		"peacock":    "peacock",
		"paramount-plus": "paramount-plus",
		"tubi":       "tubi",
		"crunchyroll": "crunchyroll",

		// Video conferencing
		"zoom":       "zoom",
		"ms-teams":   "ms-teams",
		"google-meet": "google-meet",
		"webex":      "webex",
		"slack":      "slack",
		"discord":    "discord",

		// Social media
		"facebook":   "facebook",
		"instagram":  "instagram",
		"twitter":    "twitter",
		"tiktok":     "tiktok",
		"snapchat":   "snapchat",
		"pinterest":  "pinterest",
		"reddit":     "reddit",

		// Gaming
		"steam":      "steam",
		"epic-games": "epic-games",
		"xbox-live":  "xbox-live",
		"playstation-network": "playstation-network",
		"nintendo":   "nintendo",
		"roblox":     "roblox",
		"minecraft":  "minecraft",

		// Messaging
		"xmpp":       "messaging",
		"sip":        "voip",

		// IoT protocols
		"mqtt":       "iot",
		"coap":       "iot",
		"modbus":     "iot",

		// IoT devices
		"amazon-echo": "amazon-echo",
		"google-home": "google-home",
		"nest":       "nest",
		"ring":       "ring",
		"philips-hue": "philips-hue",
		"sonos":      "sonos",
		"roku":       "roku",
		"chromecast": "chromecast",
		"smart-tv":   "smart-tv",
		"samsung-tv": "samsung-tv",
		"lg-tv":      "lg-tv",
		"vizio-tv":   "vizio-tv",
		"smart-plug": "smart-plug",
		"smart-bulb": "smart-bulb",
		"smart-lock": "smart-lock",
		"smart-thermostat": "smart-thermostat",
		"smart-doorbell": "smart-doorbell",
		"smart-camera": "smart-camera",
		"smart-speaker": "smart-speaker",

		// Network services
		"dns":        "network-service",
		"dhcp":       "network-service",
		"ntp":        "network-service",
		"snmp":       "network-service",

		// Databases
		"mysql":      "database",
		"postgres":   "database",
		"mongodb":    "database",
		"redis":      "database",
	}
}

// determineApplicationByPort tries to determine the application based on port and protocol
func determineApplicationByPort(port int, protocol string) string {
	// Common port to application mappings
	portMap := map[int]string{
		// Web
		80:    "http",
		443:   "https",
		8080:  "http",
		8443:  "https",

		// Email
		25:    "smtp",
		587:   "smtp",
		465:   "smtp",
		110:   "pop3",
		995:   "pop3",
		143:   "imap",
		993:   "imap",

		// File transfer
		21:    "ftp",
		22:    "ssh",  // SSH/SFTP

		// Remote access
		3389:  "rdp",
		23:    "telnet",
		5900:  "vnc",

		// Streaming
		1935:  "rtmp",
		554:   "rtsp",

		// Messaging
		5222:  "xmpp",
		5060:  "sip",
		5061:  "sip",

		// IoT
		1883:  "mqtt",
		8883:  "mqtt",
		5683:  "coap",
		502:   "modbus",

		// Network services
		53:    "dns",
		67:    "dhcp",
		68:    "dhcp",
		123:   "ntp",
		161:   "snmp",

		// Databases
		3306:  "mysql",
		5432:  "postgres",
		27017: "mongodb",
		6379:  "redis",
	}

	if app, exists := portMap[port]; exists {
		return app
	}

	return "unknown"
}

// isApplicationAllowed checks if an application is in the allowed list
func isApplicationAllowed(application string, allowedApps []string) bool {
	// If no allowed apps specified, allow all
	if len(allowedApps) == 0 {
		return true
	}

	// Check if application is in allowed list
	for _, app := range allowedApps {
		if app == application || app == "*" {
			return true
		}
	}

	return false
}

// createVLANBlockingPolicy creates a policy to block traffic for an application on a VLAN
func (c *ZeekConnector) createVLANBlockingPolicy(vlan int, application, srcIP, destIP string, srcPort, destPort uint16, proto string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create a policy name
	policyName := fmt.Sprintf("vlan-%d-block-%s", vlan, normalizeString(application))

	// Check if we already have this policy
	if _, exists := c.policies[policyName]; exists {
		return
	}

	// Create a policy that denies the specific traffic
	policy := &cilium.NetworkPolicy{
		Name: policyName,
		Labels: map[string]string{
			"app":         "zeek",
			"vlan":        fmt.Sprintf("%d", vlan),
			"application": normalizeString(application),
			"component":   "security",
		},
	}

	// Add rules to block the application
	policy.Egress = append(policy.Egress, cilium.PolicyRule{
		ToPorts: []cilium.PortRule{
			{
				Ports: []cilium.Port{
					{
						Port:     destPort,
						Protocol: proto,
					},
				},
				Rules: map[string]string{
					"l7proto": application,
				},
			},
		},
		Denied: true,
	})

	// Store the policy
	c.policies[policyName] = policy

	// Apply the policy
	if err := c.networkCtrl.ApplyDynamicPolicy(c.ctx, policy); err != nil {
		fmt.Printf("Failed to apply VLAN blocking policy: %v\n", err)
	} else {
		fmt.Printf("Applied VLAN %d blocking policy for %s\n", vlan, application)
	}
}