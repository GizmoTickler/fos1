package connectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/security/dpi/common"
	"github.com/fsnotify/fsnotify"
)

const (
	defaultZeekLogsPath             = "/usr/local/zeek/logs/current"
	defaultZeekKubernetesLogsPath   = "/var/log/zeek/current"
	defaultZeekPolicyPath           = "/usr/local/zeek/share/zeek/policy"
	defaultZeekKubernetesPolicyPath = "/zeek-policy"
)

// ZeekConnector integrates Zeek with Cilium and implements the ZeekConnectorInterface
type ZeekConnector struct {
	// Configuration
	logsPath     string
	policyPath   string
	ciliumClient cilium.CiliumClient
	networkCtrl  *cilium.NetworkController
	vlanAware    bool
	vlans        map[int]VLANConfig

	// State
	watcher        *fsnotify.Watcher
	policies       map[string]*cilium.CiliumPolicy
	protocolStats  map[string]*ProtocolStats
	applicationMap map[string]string // Maps service names to application names

	// Locking
	mu sync.RWMutex

	// Event handling
	eventChan chan common.DPIEvent

	// Control
	ctx           context.Context
	cancel        context.CancelFunc
	startTime     time.Time
	logsProcessed int64
	lastError     string
	running       bool
}

// ZeekOptions configures the Zeek connector
type ZeekOptions struct {
	LogsPath       string
	PolicyPath     string
	CiliumClient   cilium.CiliumClient
	KubernetesMode bool   // Whether running in Kubernetes
	Namespace      string // Kubernetes namespace

	// VLAN configuration
	VLANAware bool               // Whether to process VLAN tags
	VLANs     map[int]VLANConfig // VLAN configurations

	// TLS configuration
	TLSEnabled  bool   // Whether to use TLS for communication
	TLSCertPath string // Path to TLS certificate
	TLSKeyPath  string // Path to TLS key
	TLSCAPath   string // Path to TLS CA certificate
}

// ProtocolStats contains statistics for a protocol
type ProtocolStats struct {
	Connections int64
	Bytes       int64
	Packets     int64
	Duration    int64
	Hosts       map[string]bool
	VLANs       map[int]int64 // Count of connections per VLAN
	LastSeen    time.Time
}

// VLANConfig contains configuration for a VLAN
type VLANConfig struct {
	ID            int
	Name          string
	Subnet        string
	DefaultPolicy string   // "allow", "deny", or "restrict"
	Applications  []string // Allowed applications
}

// NewZeekConnector creates a new Zeek connector
func NewZeekConnector(opts ZeekOptions) (*ZeekConnector, error) {
	// Set default paths based on environment
	if opts.LogsPath == "" {
		if opts.KubernetesMode {
			opts.LogsPath = defaultZeekKubernetesLogsPath
		} else {
			opts.LogsPath = defaultZeekLogsPath
		}
	}

	if opts.PolicyPath == "" {
		if opts.KubernetesMode {
			opts.PolicyPath = defaultZeekKubernetesPolicyPath
		} else {
			opts.PolicyPath = defaultZeekPolicyPath
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
		logsPath:       opts.LogsPath,
		policyPath:     opts.PolicyPath,
		ciliumClient:   opts.CiliumClient,
		networkCtrl:    cilium.NewNetworkController(opts.CiliumClient),
		vlanAware:      opts.VLANAware,
		vlans:          opts.VLANs,
		watcher:        watcher,
		policies:       make(map[string]*cilium.CiliumPolicy),
		protocolStats:  make(map[string]*ProtocolStats),
		applicationMap: initApplicationMap(),
		eventChan:      make(chan common.DPIEvent, 1000),
		ctx:            ctx,
		cancel:         cancel,
		startTime:      time.Now(),
	}

	return connector, nil
}

// Start starts the Zeek connector
func (c *ZeekConnector) Start() error {
	if err := validateZeekLogsPath(c.logsPath); err != nil {
		return err
	}

	if err := c.watcher.Add(c.logsPath); err != nil {
		return fmt.Errorf("failed to watch Zeek logs directory %q: %w", c.logsPath, err)
	}

	// Start processing events
	go c.processEvents()

	c.running = true
	return nil
}

func validateZeekLogsPath(logsPath string) error {
	info, err := os.Stat(logsPath)
	if err != nil {
		if os.IsNotExist(err) {
			parent := filepath.Dir(logsPath)
			if _, parentErr := os.Stat(parent); parentErr == nil {
				return fmt.Errorf("Zeek logs path %q does not exist; expected the shared log mount to expose this directory. Check the Zeek and dpi-manager volume mounts", logsPath)
			}

			return fmt.Errorf("Zeek logs path %q does not exist and parent directory %q is also missing; check the shared host log contract and mount paths", logsPath, parent)
		}

		return fmt.Errorf("failed to stat Zeek logs path %q: %w", logsPath, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("Zeek logs path %q is not a directory; check the shared log mount configuration", logsPath)
	}

	return nil
}

// Stop stops the Zeek connector
func (c *ZeekConnector) Stop() error {
	c.cancel()
	c.running = false
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
	// ts := fields[0]
	// uid := fields[1]
	srcIP := fields[2]
	srcPort := fields[3]
	destIP := fields[4]
	destPort := fields[5]
	fqdn := fields[6]
	proto := fields[7]
	noteType := fields[8]
	msg := fields[9]
	sub := fields[10]
	// src := fields[11]

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
	policyName := fmt.Sprintf("zeek-notice-%s", zeekNormalizeString(noteType))

	// Check if we already have a policy for this notice type
	if _, exists := c.policies[policyName]; exists {
		// Policy already exists, update it or add new rules
		return
	}

	// Create a policy that denies the specific traffic
	policy := &cilium.CiliumPolicy{
		Name: policyName,
		Labels: map[string]string{
			"app":       "zeek",
			"notice":    zeekNormalizeString(noteType),
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

	// Convert destination IP to CIDR notation if needed
	// destCIDR := destIP
	if !strings.Contains(destIP, "/") && destIP != "-" {
		// destCIDR = destIP + "/32"
		// Using destIP directly in rules below
	}

	// Only create rules if we have valid IPs
	if srcIP != "-" && destIP != "-" {
		// Create rules for both directions

		// Rule to block traffic from source to destination
		if srcPort != "-" && destPort != "-" {
			srcPortNum, srcPortErr := strconv.Atoi(srcPort)
			destPortNum, destPortErr := strconv.Atoi(destPort)

			if destPortErr == nil {
				policy.Rules = append(policy.Rules, cilium.CiliumRule{
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
				policy.Rules = append(policy.Rules, cilium.CiliumRule{
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
		policy.Rules = append(policy.Rules, cilium.CiliumRule{
			ToFQDNs: []cilium.MatchFQDN{
				{
					MatchPattern: fqdn,
				},
			},
			Denied: true,
		})
	}

	// Store the policy if it has any rules
	if len(policy.Rules) > 0 {
		c.policies[policyName] = policy

		// Apply the policy
		if err := c.ciliumClient.ApplyNetworkPolicy(c.ctx, policy); err != nil {
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
		event := common.DPIEvent{
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
		event := common.DPIEvent{
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
	// Open the ssl.log file
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Failed to open ssl.log: %v\n", err)
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
		if len(fields) < 15 { // SSL log has at least 15 fields
			continue
		}

		// Extract fields
		// Format: ts uid id.orig_h id.orig_p id.resp_h id.resp_p version cipher server_name subject issuer
		ts := fields[0]
		uid := fields[1]
		srcIP := fields[2]
		srcPort := fields[3]
		destIP := fields[4]
		destPort := fields[5]
		version := fields[6]
		cipher := fields[7]
		serverName := fields[8]
		subject := fields[9]
		issuer := fields[10]

		// Additional fields for certificate validation
		validationStatus := "-"
		if len(fields) > 11 {
			validationStatus = fields[11]
		}

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

		// Determine if this is likely DNS over TLS (DoT)
		isDOT := false
		if destPortNum == 853 || srcPortNum == 853 {
			isDOT = true
		}

		// Determine application
		application := "https"
		category := "web"

		// Check for DNS over TLS
		if isDOT {
			application = "dns-over-tls"
			category = "network-service"
		} else if serverName != "-" {
			// Check for other applications based on SNI
			if strings.Contains(serverName, "mqtt") || destPortNum == 8883 {
				application = "mqtt"
				category = "iot"
			} else if strings.Contains(serverName, "doh") ||
				strings.Contains(serverName, "dns-query") ||
				strings.Contains(serverName, "dns.google") ||
				strings.Contains(serverName, "cloudflare-dns") {
				application = "dns-over-https"
				category = "network-service"
			}
		}

		// Create a DPI event for this SSL connection
		event := common.DPIEvent{
			Timestamp:   timestamp,
			SourceIP:    srcIP,
			DestIP:      destIP,
			SourcePort:  srcPortNum,
			DestPort:    destPortNum,
			Protocol:    "tcp",
			Application: application,
			Category:    category,
			EventType:   "ssl",
			Severity:    0, // Normal SSL connection, no severity by default
			Description: fmt.Sprintf("SSL/TLS %s connection to %s", version, serverName),
			SessionID:   uid,
			RawData: map[string]interface{}{
				"version":     version,
				"cipher":      cipher,
				"server_name": serverName,
				"subject":     subject,
				"issuer":      issuer,
				"validation":  validationStatus,
			},
		}

		// Check for certificate validation issues
		if validationStatus != "-" && validationStatus != "ok" {
			event.EventType = "alert"
			event.Severity = 2 // Medium severity for certificate issues
			event.Description = fmt.Sprintf("SSL/TLS certificate validation failed: %s", validationStatus)
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
		fmt.Printf("Error reading ssl.log: %v\n", err)
		c.mu.Lock()
		c.lastError = fmt.Sprintf("Error reading ssl.log: %v", err)
		c.mu.Unlock()
	}
}

// processDNSLog processes a Zeek DNS log
func (c *ZeekConnector) processDNSLog(path string) {
	// Open the dns.log file
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Failed to open dns.log: %v\n", err)
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
		if len(fields) < 15 { // DNS log has at least 15 fields
			continue
		}

		// Extract fields
		// Format: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id query qclass qtype rcode answers TTLs
		ts := fields[0]
		uid := fields[1]
		srcIP := fields[2]
		srcPort := fields[3]
		destIP := fields[4]
		destPort := fields[5]
		proto := fields[6]
		transID := fields[7]
		query := fields[8]
		qclass := fields[9]
		qtype := fields[10]
		rcode := fields[11]
		answers := fields[12]
		ttls := fields[13]

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

		// Determine application
		application := "dns"
		category := "network-service"

		// Check for DNSCrypt
		// DNSCrypt typically uses port 443/tcp or 443/udp or 5353
		isDNSCrypt := false
		if (destPortNum == 443 || srcPortNum == 443 || destPortNum == 5353 || srcPortNum == 5353) &&
			(query == "-" || strings.Contains(query, "dnscrypt") || strings.Contains(query, "dns-crypt")) {
			isDNSCrypt = true
			application = "dnscrypt"
		}

		// Check for DNS over HTTPS (DoH) - this is a heuristic since DoH is hard to detect from DNS logs alone
		// DoH typically uses port 443 and may have specific patterns in queries
		if destPortNum == 443 && !isDNSCrypt &&
			(strings.Contains(query, "doh") || strings.Contains(query, "dns-query")) {
			application = "dns-over-https"
		}

		// Create a DPI event for this DNS query
		event := common.DPIEvent{
			Timestamp:   timestamp,
			SourceIP:    srcIP,
			DestIP:      destIP,
			SourcePort:  srcPortNum,
			DestPort:    destPortNum,
			Protocol:    strings.ToLower(proto),
			Application: application,
			Category:    category,
			EventType:   "dns",
			Severity:    0, // Normal DNS query, no severity by default
			Description: fmt.Sprintf("DNS query for %s (type: %s)", query, qtype),
			SessionID:   uid,
			RawData: map[string]interface{}{
				"trans_id":    transID,
				"query":       query,
				"qclass":      qclass,
				"qtype":       qtype,
				"rcode":       rcode,
				"answers":     answers,
				"ttls":        ttls,
				"is_dnscrypt": isDNSCrypt,
			},
		}

		// Check for suspicious DNS activity
		if isSuspiciousDNSQuery(query, qtype) {
			event.EventType = "alert"
			event.Severity = 2 // Medium severity for suspicious DNS
			event.Description = fmt.Sprintf("Suspicious DNS query for %s (type: %s)", query, qtype)
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
		fmt.Printf("Error reading dns.log: %v\n", err)
		c.mu.Lock()
		c.lastError = fmt.Sprintf("Error reading dns.log: %v", err)
		c.mu.Unlock()
	}
}

// isSuspiciousDNSQuery checks if a DNS query is suspicious
func isSuspiciousDNSQuery(query, qtype string) bool {
	// Check for unusually long domain names (potential DNS tunneling)
	if len(query) > 100 {
		return true
	}

	// Check for high entropy in domain name (potential DGA - Domain Generation Algorithm)
	if calculateEntropy(query) > 4.0 {
		return true
	}

	// Check for unusual query types that might indicate tunneling
	unusualTypes := map[string]bool{
		"TXT":   true,
		"NULL":  true,
		"CNAME": false, // Common, but can be used for tunneling
		"MX":    false, // Common, but can be used for tunneling
	}

	if isUnusual, exists := unusualTypes[qtype]; exists && isUnusual {
		return true
	}

	// Check for known malicious domains or patterns
	maliciousPatterns := []string{
		".evil.com",
		".malware.",
		".ddns.",
		".dyndns.",
		".no-ip.",
		".onion.", // Tor hidden services
	}

	for _, pattern := range maliciousPatterns {
		if strings.Contains(query, pattern) {
			return true
		}
	}

	return false
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	charCounts := make(map[rune]int)
	for _, c := range s {
		charCounts[c]++
	}

	// Calculate entropy
	length := float64(len(s))
	entropy := 0.0

	for _, count := range charCounts {
		freq := float64(count) / length
		entropy -= freq * math.Log2(freq)
	}

	return entropy
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

	// If no protocols have been detected yet, scan the logs directory
	if len(result) == 0 && c.running {
		// In a real implementation, we would parse Zeek logs to extract protocols
		// For this implementation, we'll scan the conn.log file if it exists
		connLogPath := filepath.Join(c.logsPath, "conn.log")
		if _, err := os.Stat(connLogPath); err == nil {
			// Parse conn.log to extract protocols
			file, err := os.Open(connLogPath)
			if err != nil {
				return nil, fmt.Errorf("failed to open conn.log: %w", err)
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
				if len(fields) < 6 {
					continue
				}

				// Extract service field (protocol)
				service := "-"
				if len(fields) > 7 {
					service = fields[7]
				}

				// Skip entries with no service identified
				if service == "-" {
					// Try to identify by port
					destPort := fields[5]
					portNum, err := strconv.Atoi(destPort)
					if err == nil {
						switch portNum {
						case 80:
							service = "http"
						case 443:
							service = "https"
						case 53:
							service = "dns"
						case 853:
							service = "dns-over-tls"
						case 22:
							service = "ssh"
						case 1883, 8883:
							service = "mqtt"
						}
					}
					if service == "-" {
						continue
					}
				}

				// Increment protocol count
				result[service]++
			}

			if err := scanner.Err(); err != nil {
				return nil, fmt.Errorf("error reading conn.log: %w", err)
			}
		}
	}

	// If still no protocols have been detected, return some defaults
	if len(result) == 0 {
		return map[string]int{
			"http":           0,
			"https":          0,
			"ssh":            0,
			"dns":            0,
			"dns-over-tls":   0,
			"dns-over-https": 0,
			"dnscrypt":       0,
			"mqtt":           0,
			"ftp":            0,
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
func (c *ZeekConnector) GetEvents(ctx context.Context) (<-chan common.DPIEvent, error) {
	// Create a new channel for the caller
	events := make(chan common.DPIEvent, 100)

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
func (c *ZeekConnector) Status() (common.ZeekStatus, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := common.ZeekStatus{
		Running:       true, // If this function is called, the connector is running
		Uptime:        time.Since(c.startTime),
		LogsProcessed: c.logsProcessed,
		LastError:     c.lastError,
		Version:       "Zeek Connector v1.0", // In a real implementation, would get from Zeek
	}

	return status, nil
}

// GetLogsPath returns the path to Zeek logs
func (c *ZeekConnector) GetLogsPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.logsPath
}

// GetPolicyPath returns the path to Zeek policy files
func (c *ZeekConnector) GetPolicyPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policyPath
}

// categorizeApplication categorizes an application protocol
func categorizeApplication(app string) string {
	categories := map[string]string{
		// Web applications
		"http":  "web",
		"https": "web",

		// Email applications
		"smtp":  "email",
		"pop3":  "email",
		"imap":  "email",
		"email": "email",

		// File transfer
		"ftp":           "file-transfer",
		"sftp":          "file-transfer",
		"scp":           "file-transfer",
		"file-transfer": "file-transfer",

		// Remote access
		"ssh":           "remote-access",
		"rdp":           "remote-access",
		"telnet":        "remote-access",
		"vnc":           "remote-access",
		"remote-access": "remote-access",

		// Streaming services
		"rtmp":           "streaming",
		"rtsp":           "streaming",
		"rtp":            "streaming",
		"streaming":      "streaming",
		"netflix":        "streaming",
		"youtube":        "streaming",
		"spotify":        "streaming",
		"hulu":           "streaming",
		"disney-plus":    "streaming",
		"amazon-video":   "streaming",
		"hbo-max":        "streaming",
		"twitch":         "streaming",
		"apple-tv":       "streaming",
		"peacock":        "streaming",
		"paramount-plus": "streaming",
		"tubi":           "streaming",
		"crunchyroll":    "streaming",

		// Video conferencing
		"zoom":               "video-conferencing",
		"ms-teams":           "video-conferencing",
		"google-meet":        "video-conferencing",
		"webex":              "video-conferencing",
		"video-conferencing": "video-conferencing",

		// Social media
		"facebook":     "social-media",
		"instagram":    "social-media",
		"twitter":      "social-media",
		"tiktok":       "social-media",
		"snapchat":     "social-media",
		"pinterest":    "social-media",
		"reddit":       "social-media",
		"social-media": "social-media",

		// Gaming
		"steam":               "gaming",
		"epic-games":          "gaming",
		"xbox-live":           "gaming",
		"playstation-network": "gaming",
		"nintendo":            "gaming",
		"roblox":              "gaming",
		"minecraft":           "gaming",
		"gaming":              "gaming",

		// Messaging
		"xmpp":      "messaging",
		"sip":       "voip",
		"slack":     "messaging",
		"discord":   "messaging",
		"messaging": "messaging",
		"voip":      "voip",

		// IoT
		"mqtt":             "iot",
		"coap":             "iot",
		"modbus":           "iot",
		"iot":              "iot",
		"amazon-echo":      "iot",
		"google-home":      "iot",
		"nest":             "iot",
		"ring":             "iot",
		"philips-hue":      "iot",
		"sonos":            "iot",
		"roku":             "iot",
		"chromecast":       "iot",
		"smart-tv":         "iot",
		"samsung-tv":       "iot",
		"lg-tv":            "iot",
		"vizio-tv":         "iot",
		"smart-plug":       "iot",
		"smart-bulb":       "iot",
		"smart-lock":       "iot",
		"smart-thermostat": "iot",
		"smart-doorbell":   "iot",
		"smart-camera":     "iot",
		"smart-speaker":    "iot",

		// Network services
		"dns":             "network-service",
		"dnscrypt":        "network-service",
		"dns-over-tls":    "network-service",
		"dns-over-https":  "network-service",
		"dhcp":            "network-service",
		"ntp":             "network-service",
		"snmp":            "network-service",
		"network-service": "network-service",

		// Databases
		"mysql":    "database",
		"postgres": "database",
		"mongodb":  "database",
		"redis":    "database",
		"database": "database",

		// Productivity
		"office365":    "productivity",
		"google-docs":  "productivity",
		"dropbox":      "productivity",
		"box":          "productivity",
		"onedrive":     "productivity",
		"sharepoint":   "productivity",
		"productivity": "productivity",
	}

	category, exists := categories[app]
	if !exists {
		return "other"
	}

	return category
}

// zeekNormalizeString normalizes a string for use in policy names
func zeekNormalizeString(s string) string {
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
		"http":   "http",
		"https":  "https",
		"ssl":    "https",
		"http/2": "http",

		// Email applications
		"smtp": "email",
		"pop3": "email",
		"imap": "email",

		// File transfer
		"ftp":  "file-transfer",
		"sftp": "file-transfer",
		"scp":  "file-transfer",

		// Remote access
		"ssh":    "remote-access",
		"rdp":    "remote-access",
		"telnet": "remote-access",
		"vnc":    "remote-access",

		// Streaming
		"rtmp":           "streaming",
		"rtsp":           "streaming",
		"rtp":            "streaming",
		"netflix":        "netflix",
		"youtube":        "youtube",
		"spotify":        "spotify",
		"hulu":           "hulu",
		"disney-plus":    "disney-plus",
		"amazon-video":   "amazon-video",
		"hbo-max":        "hbo-max",
		"twitch":         "twitch",
		"apple-tv":       "apple-tv",
		"peacock":        "peacock",
		"paramount-plus": "paramount-plus",
		"tubi":           "tubi",
		"crunchyroll":    "crunchyroll",

		// Video conferencing
		"zoom":        "zoom",
		"ms-teams":    "ms-teams",
		"google-meet": "google-meet",
		"webex":       "webex",
		"slack":       "slack",
		"discord":     "discord",

		// Social media
		"facebook":  "facebook",
		"instagram": "instagram",
		"twitter":   "twitter",
		"tiktok":    "tiktok",
		"snapchat":  "snapchat",
		"pinterest": "pinterest",
		"reddit":    "reddit",

		// Gaming
		"steam":               "steam",
		"epic-games":          "epic-games",
		"xbox-live":           "xbox-live",
		"playstation-network": "playstation-network",
		"nintendo":            "nintendo",
		"roblox":              "roblox",
		"minecraft":           "minecraft",

		// Messaging
		"xmpp": "messaging",
		"sip":  "voip",

		// IoT protocols
		"mqtt":    "iot",
		"mqtt-sn": "iot",
		"coap":    "iot",
		"amqp":    "iot",
		"zigbee":  "iot",
		"zwave":   "iot",
		"thread":  "iot",
		"bacnet":  "iot",
		"modbus":  "iot",
		"knx":     "iot",
		"lora":    "iot",
		"sigfox":  "iot",
		"weave":   "iot",
		"homekit": "iot",

		// IoT devices
		"amazon-echo":      "amazon-echo",
		"google-home":      "google-home",
		"nest":             "nest",
		"ring":             "ring",
		"philips-hue":      "philips-hue",
		"sonos":            "sonos",
		"roku":             "roku",
		"chromecast":       "chromecast",
		"smart-tv":         "smart-tv",
		"samsung-tv":       "samsung-tv",
		"lg-tv":            "lg-tv",
		"vizio-tv":         "vizio-tv",
		"smart-plug":       "smart-plug",
		"smart-bulb":       "smart-bulb",
		"smart-lock":       "smart-lock",
		"smart-thermostat": "smart-thermostat",
		"smart-doorbell":   "smart-doorbell",
		"smart-camera":     "smart-camera",
		"smart-speaker":    "smart-speaker",

		// Network services
		"dns":            "network-service",
		"dnscrypt":       "network-service",
		"dns-over-tls":   "network-service",
		"dns-over-https": "network-service",
		"dhcp":           "network-service",
		"ntp":            "network-service",
		"snmp":           "network-service",

		// Databases
		"mysql":    "database",
		"postgres": "database",
		"mongodb":  "database",
		"redis":    "database",
	}
}

// determineApplicationByPort tries to determine the application based on port and protocol
func determineApplicationByPort(port int, protocol string) string {
	// Common port to application mappings
	portMap := map[int]string{
		// Web
		80:   "http",
		443:  "https",
		8080: "http",
		8443: "https",

		// Email
		25:  "smtp",
		587: "smtp",
		465: "smtp",
		110: "pop3",
		995: "pop3",
		143: "imap",
		993: "imap",

		// File transfer
		21: "ftp",
		22: "ssh", // SSH/SFTP

		// Remote access
		3389: "rdp",
		23:   "telnet",
		5900: "vnc",

		// Streaming
		1935: "rtmp",
		554:  "rtsp",

		// Messaging
		5222: "xmpp",
		5060: "sip",
		5061: "sip",

		// IoT
		1883: "mqtt",
		8883: "mqtt",
		5683: "coap",
		502:  "modbus",

		// Network services
		53:  "dns",
		67:  "dhcp",
		68:  "dhcp",
		123: "ntp",
		161: "snmp",

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
	policy := &cilium.CiliumPolicy{
		Name: policyName,
		Labels: map[string]string{
			"app":         "zeek",
			"vlan":        fmt.Sprintf("%d", vlan),
			"application": normalizeString(application),
			"component":   "security",
		},
	}

	// Add rules to block the application
	policy.Rules = append(policy.Rules, cilium.CiliumRule{
		ToPorts: []cilium.PortRule{
			{
				Ports: []cilium.Port{
					{
						Port:     destPort,
						Protocol: proto,
					},
				},
			},
		},
		Denied: true,
	})

	// Store the policy
	c.policies[policyName] = policy

	// Apply the policy
	if err := c.ciliumClient.ApplyNetworkPolicy(c.ctx, policy); err != nil {
		fmt.Printf("Failed to apply VLAN blocking policy: %v\n", err)
	} else {
		fmt.Printf("Applied VLAN %d blocking policy for %s\n", vlan, application)
	}
}
