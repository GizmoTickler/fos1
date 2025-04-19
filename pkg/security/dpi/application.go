package dpi

import (
	"fmt"
	"strings"
	"sync"
)

// ApplicationDetector detects applications in network traffic
type ApplicationDetector struct {
	// This would integrate with nDPI, Suricata, etc.
	mu              sync.RWMutex
	applicationInfo map[string]*ApplicationInfo
	signatures      map[string]*AppSignature
	categories      map[string][]string

	// Engine connectors
	engines         []DPIEngineConnector
}

// NewApplicationDetector creates a new application detector
func NewApplicationDetector() *ApplicationDetector {
	// Initialize with some predefined applications
	info := make(map[string]*ApplicationInfo)
	for _, app := range []string{"http", "https", "ssh", "dns", "ftp", "smtp"} {
		info[app] = &ApplicationInfo{
			Name:        app,
			Category:    categorizeApplication(app),
			Description: fmt.Sprintf("%s protocol", strings.ToUpper(app)),
			DefaultPorts: getDefaultPorts(app),
			Risks:        getApplicationRisks(app),
		}
	}

	// Initialize signatures
	signatures := make(map[string]*AppSignature)

	// Initialize categories
	categories := map[string][]string{
		"web":           {"http", "https"},
		"remote_access": {"ssh", "telnet", "rdp"},
		"network":       {"dns", "dhcp", "ntp"},
		"file_transfer": {"ftp", "sftp", "scp"},
		"email":         {"smtp", "pop3", "imap"},
		"database":      {"mysql", "postgres", "mongodb"},
		"messaging":     {"xmpp", "sip", "irc"},
		"streaming":     {"rtsp", "rtmp", "hls"},
		"vpn":           {"openvpn", "ipsec", "wireguard"},
		"gaming":        {"steam", "xbox", "playstation"},
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
func (d *ApplicationDetector) GetApplicationInfo(applicationName string) (*ApplicationInfo, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	info, exists := d.applicationInfo[applicationName]
	if !exists {
		return nil, fmt.Errorf("application %s not found", applicationName)
	}

	return info, nil
}

// GetAllApplications returns all known applications
func (d *ApplicationDetector) GetAllApplications() []*ApplicationInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	apps := make([]*ApplicationInfo, 0, len(d.applicationInfo))
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
	for _, engine := range d.engines {
		// In a real implementation, would query the engine for this flow
		// For now, just continue to the port-based detection
	}

	// Fall back to port-based detection
	if srcPort == 80 || dstPort == 80 {
		return "http", nil
	} else if srcPort == 443 || dstPort == 443 {
		return "https", nil
	} else if srcPort == 22 || dstPort == 22 {
		return "ssh", nil
	} else if srcPort == 53 || dstPort == 53 {
		return "dns", nil
	} else if srcPort == 21 || dstPort == 21 {
		return "ftp", nil
	} else if srcPort == 25 || dstPort == 25 || srcPort == 587 || dstPort == 587 {
		return "smtp", nil
	} else if srcPort == 3306 || dstPort == 3306 {
		return "mysql", nil
	} else if srcPort == 5432 || dstPort == 5432 {
		return "postgres", nil
	} else if srcPort == 1433 || dstPort == 1433 {
		return "mssql", nil
	} else if srcPort == 27017 || dstPort == 27017 {
		return "mongodb", nil
	} else if srcPort == 6379 || dstPort == 6379 {
		return "redis", nil
	}

	// If we can't determine the application, return unknown
	return "unknown", nil
}

// AddApplicationInfo adds or updates information about an application
func (d *ApplicationDetector) AddApplicationInfo(app *ApplicationInfo) {
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
func (d *ApplicationDetector) GetApplicationsByCategory(category string) []*ApplicationInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var apps []*ApplicationInfo

	if appNames, exists := d.categories[category]; exists {
		for _, name := range appNames {
			if app, exists := d.applicationInfo[name]; exists {
				apps = append(apps, app)
			}
		}
	}

	return apps
}

// ApplicationInfo represents information about an application
type ApplicationInfo struct {
	Name         string
	Category     string
	Description  string
	DefaultPorts []string
	Risks        []string
}

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
		"http":     "web",
		"https":    "web",
		"ssh":      "remote_access",
		"dns":      "network",
		"ftp":      "file_transfer",
		"smtp":     "email",
		"pop3":     "email",
		"imap":     "email",
		"mysql":    "database",
		"postgres": "database",
		"mongodb":  "database",
		"redis":    "database",
		"telnet":   "remote_access",
		"rdp":      "remote_access",
		"vnc":      "remote_access",
	}

	category, exists := categories[app]
	if !exists {
		return "other"
	}

	return category
}

func getDefaultPorts(app string) []string {
	ports := map[string][]string{
		"http":     {"80"},
		"https":    {"443"},
		"ssh":      {"22"},
		"dns":      {"53"},
		"ftp":      {"21"},
		"smtp":     {"25", "587"},
		"pop3":     {"110", "995"},
		"imap":     {"143", "993"},
		"mysql":    {"3306"},
		"postgres": {"5432"},
		"mongodb":  {"27017"},
		"redis":    {"6379"},
		"telnet":   {"23"},
		"rdp":      {"3389"},
		"vnc":      {"5900"},
	}

	defaultPorts, exists := ports[app]
	if !exists {
		return []string{}
	}

	return defaultPorts
}

func getApplicationRisks(app string) []string {
	risks := map[string][]string{
		"http":     {"Unencrypted", "Potential data leakage"},
		"https":    {"Potential for malicious sites", "Certificate issues"},
		"ssh":      {"Brute force attacks", "Unauthorized access"},
		"dns":      {"DNS tunneling", "Cache poisoning"},
		"ftp":      {"Unencrypted credentials", "Anonymous access"},
		"smtp":     {"Spam relay", "Email spoofing"},
		"telnet":   {"Unencrypted", "Plaintext credentials"},
		"rdp":      {"Brute force attacks", "BlueKeep vulnerability"},
		"mysql":    {"SQL injection", "Unauthorized access"},
		"postgres": {"SQL injection", "Unauthorized access"},
		"mongodb":  {"NoSQL injection", "Unauthorized access"},
	}

	appRisks, exists := risks[app]
	if !exists {
		return []string{}
	}

	return appRisks
}
