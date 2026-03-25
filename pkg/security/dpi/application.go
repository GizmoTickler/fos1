package dpi

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/GizmoTickler/fos1/pkg/security/dpi/common"
)

// ApplicationDetector detects applications in network traffic
type ApplicationDetector struct {
	// This would integrate with nDPI, Suricata, etc.
	mu              sync.RWMutex
	applicationInfo map[string]*common.ApplicationInfo
	signatures      map[string]*AppSignature
	categories      map[string][]string

	// Engine connectors
	engines         []DPIEngineConnector
}

// NewApplicationDetector creates a new application detector
func NewApplicationDetector() *ApplicationDetector {
	// Initialize with some predefined applications
	info := make(map[string]*common.ApplicationInfo)
	for _, app := range []string{"http", "https", "ssh", "dns", "ftp", "smtp"} {
		info[app] = &common.ApplicationInfo{
			Name:        app,
			Category:    categorizeApplication(app),
			Description: fmt.Sprintf("%s protocol", strings.ToUpper(app)),
			Ports:       getDefaultPortsAsInts(app),
			Protocols:   []string{"tcp", "udp"},
		}
	}

	// Initialize signatures
	signatures := make(map[string]*AppSignature)

	// Initialize categories
	categories := map[string][]string{
		"web":           {"http", "https"},
		"remote_access": {"ssh", "telnet", "rdp", "vnc"},
		"network_service": {"dns", "dns-over-tls", "dns-over-https", "dnscrypt", "dhcp", "ntp"},
		"file_transfer": {"ftp", "sftp", "scp"},
		"email":         {"smtp", "pop3", "imap"},
		"database":      {"mysql", "postgres", "mongodb", "redis", "mssql"},
		"messaging":     {"xmpp", "sip", "irc"},
		"streaming":     {"rtsp", "rtmp", "hls"},
		"vpn":           {"openvpn", "ipsec", "wireguard"},
		"gaming":        {"steam", "xbox", "playstation"},
		"iot":           {"mqtt", "coap", "modbus", "bacnet", "zigbee"},
	}

	return &ApplicationDetector{
		applicationInfo: info,
		signatures:      signatures,
		categories:      categories,
	}
}

// AddEngine adds a DPI engine connector to the application detector
func (d *ApplicationDetector) AddEngine(engine DPIEngineConnector) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.engines = append(d.engines, engine)
}

// GetApplicationInfo gets information about an application
func (d *ApplicationDetector) GetApplicationInfo(applicationName string) (*common.ApplicationInfo, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	info, exists := d.applicationInfo[applicationName]
	if !exists {
		return nil, fmt.Errorf("application %s not found", applicationName)
	}

	return info, nil
}

// GetAllApplications returns all known applications
func (d *ApplicationDetector) GetAllApplications() []*common.ApplicationInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	apps := make([]*common.ApplicationInfo, 0, len(d.applicationInfo))
	for _, app := range d.applicationInfo {
		apps = append(apps, app)
	}

	return apps
}

// DetectApplicationFromFlow detects an application from flow information
func (d *ApplicationDetector) DetectApplicationFromFlow(srcIP, dstIP string, srcPort, dstPort int, protocol string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// First check if any of our engines have already identified this flow
	// In a real implementation, we would query the DPI engines here
	// For now, we'll just use port-based detection

	// Fall back to port-based detection
	portMap := map[int]string{
		// Web protocols
		80: "http",
		443: "https",
		8080: "http",
		8443: "https",

		// Secure shell
		22: "ssh",

		// DNS and secure DNS variants
		53: "dns",
		853: "dns-over-tls", // DNS over TLS
		784: "dnscrypt",     // DNSCrypt (one of the common ports)

		// File transfer
		21: "ftp",

		// Email
		25: "smtp",
		587: "smtp",
		465: "smtp",
		110: "pop3",
		995: "pop3",
		143: "imap",
		993: "imap",

		// Databases
		3306: "mysql",
		5432: "postgres",
		1433: "mssql",
		27017: "mongodb",
		6379: "redis",

		// IoT and messaging
		1883: "mqtt",       // MQTT
		8883: "mqtt",       // MQTT over TLS
		5683: "coap",       // CoAP
		5684: "coap",       // CoAP over DTLS

		// Remote access
		3389: "rdp",        // Remote Desktop Protocol
		5900: "vnc",        // VNC

		// Streaming
		1935: "rtmp",       // Real-Time Messaging Protocol
		554: "rtsp",        // Real-Time Streaming Protocol
	}

	// Check source and destination ports
	if app, exists := portMap[srcPort]; exists {
		return app, nil
	}

	if app, exists := portMap[dstPort]; exists {
		return app, nil
	}

	// Special case for DNS over HTTPS which uses HTTPS port but is a different application
	if (srcPort == 443 || dstPort == 443) && protocol == "tcp" {
		// We can't definitively determine if this is DoH just from the port
		// In a real implementation, we would need deeper packet inspection
		// For now, we'll return https as the default for port 443
		return "https", nil
	}

	// If we can't determine the application, return unknown
	return "unknown", nil
}

// AddApplicationInfo adds or updates information about an application
func (d *ApplicationDetector) AddApplicationInfo(app *common.ApplicationInfo) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.applicationInfo[app.Name] = app

	// Update categories
	category := app.Category
	if category != "" {
		d.categories[category] = append(d.categories[category], app.Name)
	}
}

// GetApplicationsByCategory returns applications in a category
func (d *ApplicationDetector) GetApplicationsByCategory(category string) []*common.ApplicationInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var apps []*common.ApplicationInfo

	if appNames, exists := d.categories[category]; exists {
		for _, name := range appNames {
			if app, exists := d.applicationInfo[name]; exists {
				apps = append(apps, app)
			}
		}
	}

	return apps
}

// ApplicationInfo is now defined in the common package

// AppSignature represents a signature for detecting an application
type AppSignature struct {
	Name        string
	Pattern     []byte
	PortHints   []int
	Confidence  float64
}

// Helper functions for the application detector

func categorizeApplication(app string) string {
	categories := map[string]string{
		// Web applications
		"http":     "web",
		"https":    "web",

		// Remote access
		"ssh":      "remote_access",
		"telnet":   "remote_access",
		"rdp":      "remote_access",
		"vnc":      "remote_access",

		// Network services
		"dns":           "network_service",
		"dns-over-tls":  "network_service",
		"dns-over-https": "network_service",
		"dnscrypt":      "network_service",
		"dhcp":          "network_service",
		"ntp":           "network_service",

		// File transfer
		"ftp":      "file_transfer",
		"sftp":     "file_transfer",
		"scp":      "file_transfer",

		// Email
		"smtp":     "email",
		"pop3":     "email",
		"imap":     "email",

		// Databases
		"mysql":    "database",
		"postgres": "database",
		"mongodb":  "database",
		"redis":    "database",
		"mssql":    "database",

		// IoT protocols
		"mqtt":     "iot",
		"coap":     "iot",
		"modbus":   "iot",
		"bacnet":   "iot",
		"zigbee":   "iot",

		// Streaming
		"rtsp":     "streaming",
		"rtmp":     "streaming",
		"hls":      "streaming",

		// VPN
		"openvpn":  "vpn",
		"ipsec":    "vpn",
		"wireguard": "vpn",

		// Messaging
		"xmpp":     "messaging",
		"sip":      "messaging",
		"irc":      "messaging",
	}

	category, exists := categories[app]
	if !exists {
		return "other"
	}

	return category
}

func getDefaultPorts(app string) []string {
	ports := map[string][]string{
		// Web protocols
		"http":     {"80", "8080"},
		"https":    {"443", "8443"},

		// Remote access
		"ssh":      {"22"},
		"telnet":   {"23"},
		"rdp":      {"3389"},
		"vnc":      {"5900"},

		// Network services
		"dns":           {"53"},
		"dns-over-tls":  {"853"},
		"dns-over-https": {"443"},
		"dnscrypt":      {"443", "5353", "784"},
		"dhcp":          {"67", "68"},
		"ntp":           {"123"},

		// File transfer
		"ftp":      {"21"},
		"sftp":     {"22"},
		"scp":      {"22"},

		// Email
		"smtp":     {"25", "587", "465"},
		"pop3":     {"110", "995"},
		"imap":     {"143", "993"},

		// Databases
		"mysql":    {"3306"},
		"postgres": {"5432"},
		"mongodb":  {"27017"},
		"redis":    {"6379"},
		"mssql":    {"1433"},

		// IoT protocols
		"mqtt":     {"1883", "8883"},
		"coap":     {"5683", "5684"},
		"modbus":   {"502"},
		"bacnet":   {"47808"},

		// Streaming
		"rtsp":     {"554"},
		"rtmp":     {"1935"},

		// VPN
		"openvpn":  {"1194", "1197", "1198"},
		"ipsec":    {"500", "4500"},
		"wireguard": {"51820"},

		// Messaging
		"xmpp":     {"5222", "5269"},
		"sip":      {"5060", "5061"},
		"irc":      {"6667", "6697"},
	}

	defaultPorts, exists := ports[app]
	if !exists {
		return []string{}
	}

	return defaultPorts
}

func getDefaultPortsAsInts(app string) []int {
	portStrings := getDefaultPorts(app)
	ports := make([]int, 0, len(portStrings))

	for _, portStr := range portStrings {
		port, err := strconv.Atoi(portStr)
		if err == nil {
			ports = append(ports, port)
		}
	}

	return ports
}

func getApplicationRisks(app string) []string {
	risks := map[string][]string{
		// Web protocols
		"http":     {"Unencrypted", "Potential data leakage", "Web attacks"},
		"https":    {"Potential for malicious sites", "Certificate issues", "TLS vulnerabilities"},

		// Remote access
		"ssh":      {"Brute force attacks", "Unauthorized access", "Key management issues"},
		"telnet":   {"Unencrypted", "Plaintext credentials", "No authentication"},
		"rdp":      {"Brute force attacks", "BlueKeep vulnerability", "Man-in-the-middle"},
		"vnc":      {"Weak authentication", "Unencrypted by default", "Screen capture"},

		// Network services
		"dns":           {"DNS tunneling", "Cache poisoning", "Amplification attacks"},
		"dns-over-tls":  {"Certificate validation", "Limited adoption", "Potential blocking"},
		"dns-over-https": {"Bypassing network controls", "Certificate validation", "Potential misuse"},
		"dnscrypt":      {"Implementation vulnerabilities", "Key management", "Limited adoption"},
		"dhcp":          {"DHCP spoofing", "Unauthorized servers", "IP exhaustion"},
		"ntp":           {"Time shifting attacks", "Amplification attacks", "Synchronization issues"},

		// File transfer
		"ftp":      {"Unencrypted credentials", "Anonymous access", "Clear text transfer"},
		"sftp":     {"Key management", "Brute force attacks", "Implementation vulnerabilities"},
		"scp":      {"Key management", "Implementation vulnerabilities"},

		// Email
		"smtp":     {"Spam relay", "Email spoofing", "Open relay"},
		"pop3":     {"Unencrypted by default", "Password attacks", "Session hijacking"},
		"imap":     {"Unencrypted by default", "Password attacks", "Session hijacking"},

		// Databases
		"mysql":    {"SQL injection", "Unauthorized access", "Default credentials"},
		"postgres": {"SQL injection", "Unauthorized access", "Default credentials"},
		"mongodb":  {"NoSQL injection", "Unauthorized access", "Default configuration"},
		"redis":    {"Unencrypted by default", "No authentication by default", "Data exposure"},
		"mssql":    {"SQL injection", "Privilege escalation", "Default credentials"},

		// IoT protocols
		"mqtt":     {"Weak authentication", "Unencrypted by default", "Unauthorized publishing"},
		"coap":     {"Limited security", "Amplification attacks", "Unauthorized access"},
		"modbus":   {"No authentication", "No encryption", "Critical infrastructure risks"},
		"bacnet":   {"No authentication", "Building automation risks", "Information disclosure"},

		// Streaming
		"rtsp":     {"Unencrypted", "Authentication bypass", "Stream hijacking"},
		"rtmp":     {"Unencrypted", "Authentication issues", "Stream hijacking"},

		// VPN
		"openvpn":  {"Configuration errors", "Certificate management", "Key compromise"},
		"ipsec":    {"Complex configuration", "Implementation vulnerabilities", "Pre-shared key risks"},
		"wireguard": {"Key management", "Limited auditing", "Implementation vulnerabilities"},
	}

	appRisks, exists := risks[app]
	if !exists {
		return []string{}
	}

	return appRisks
}
