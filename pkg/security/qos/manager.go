package qos

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// QoSManager manages Quality of Service functionality
type QoSManager struct {
	mu       sync.Mutex
	profiles map[string]*QoSProfile
	stats    map[string]map[string]*ClassStatistics
}

// NewQoSManager creates a new QoS manager
func NewQoSManager() *QoSManager {
	return &QoSManager{
		profiles: make(map[string]*QoSProfile),
		stats:    make(map[string]map[string]*ClassStatistics),
	}
}

// AddProfile adds a QoS profile
func (m *QoSManager) AddProfile(profile *QoSProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.profiles[profile.Interface]; exists {
		return fmt.Errorf("profile for interface %s already exists", profile.Interface)
	}

	// Validate the profile
	if err := m.validateProfile(profile); err != nil {
		return fmt.Errorf("invalid profile: %w", err)
	}

	m.profiles[profile.Interface] = profile
	m.stats[profile.Interface] = make(map[string]*ClassStatistics)
	for _, class := range profile.Classes {
		m.stats[profile.Interface][class.Name] = &ClassStatistics{}
	}

	// Apply the profile
	if err := m.applyProfile(profile); err != nil {
		delete(m.profiles, profile.Interface)
		delete(m.stats, profile.Interface)
		return fmt.Errorf("failed to apply profile: %w", err)
	}

	return nil
}

// UpdateProfile updates a QoS profile
func (m *QoSManager) UpdateProfile(profile *QoSProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.profiles[profile.Interface]; !exists {
		return fmt.Errorf("profile for interface %s does not exist", profile.Interface)
	}

	// Validate the profile
	if err := m.validateProfile(profile); err != nil {
		return fmt.Errorf("invalid profile: %w", err)
	}

	// Remove the old profile
	if err := m.removeProfile(profile.Interface); err != nil {
		return fmt.Errorf("failed to remove old profile: %w", err)
	}

	m.profiles[profile.Interface] = profile
	m.stats[profile.Interface] = make(map[string]*ClassStatistics)
	for _, class := range profile.Classes {
		m.stats[profile.Interface][class.Name] = &ClassStatistics{}
	}

	// Apply the new profile
	if err := m.applyProfile(profile); err != nil {
		return fmt.Errorf("failed to apply profile: %w", err)
	}

	return nil
}

// DeleteProfile deletes a QoS profile
func (m *QoSManager) DeleteProfile(interfaceName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.profiles[interfaceName]; !exists {
		return fmt.Errorf("profile for interface %s does not exist", interfaceName)
	}

	// Remove the profile
	if err := m.removeProfile(interfaceName); err != nil {
		return fmt.Errorf("failed to remove profile: %w", err)
	}

	delete(m.profiles, interfaceName)
	delete(m.stats, interfaceName)

	return nil
}

// GetClassStatistics gets statistics for a traffic class
func (m *QoSManager) GetClassStatistics(interfaceName, className string) (*ClassStatistics, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	interfaceStats, exists := m.stats[interfaceName]
	if !exists {
		return nil, fmt.Errorf("no statistics for interface %s", interfaceName)
	}

	classStats, exists := interfaceStats[className]
	if !exists {
		return nil, fmt.Errorf("no statistics for class %s on interface %s", className, interfaceName)
	}

	// In a real implementation, you'd update the stats from tc here
	// For now, we'll just return the current stats
	return classStats, nil
}

// UpdateClassStatistics updates statistics for all traffic classes
func (m *QoSManager) UpdateClassStatistics() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for interfaceName := range m.profiles {
		// Get stats from tc
		cmd := exec.Command("tc", "-s", "class", "show", "dev", interfaceName)
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get statistics from tc: %w", err)
		}

		// Parse the output
		classIDRegex := regexp.MustCompile(`class htb (\d+:\d+)`)
		statsRegex := regexp.MustCompile(`Sent (\d+) bytes (\d+) pkt \(dropped (\d+)`)

		lines := strings.Split(string(output), "\n")
		var currentClass string
		for _, line := range lines {
			if match := classIDRegex.FindStringSubmatch(line); match != nil {
				classID := match[1]
				// Find the class name for this ID
				currentClass = ""
				for className, stats := range m.stats[interfaceName] {
					if stats.ClassID == classID {
						currentClass = className
						break
					}
				}
			} else if currentClass != "" && statsRegex.MatchString(line) {
				match := statsRegex.FindStringSubmatch(line)
				if len(match) >= 4 {
					bytes, _ := strconv.ParseInt(match[1], 10, 64)
					packets, _ := strconv.ParseInt(match[2], 10, 64)
					drops, _ := strconv.ParseInt(match[3], 10, 64)

					stats := m.stats[interfaceName][currentClass]
					stats.Bytes = bytes
					stats.Packets = packets
					stats.Drops = drops
				}
			}
		}
	}

	return nil
}

// validateProfile validates a QoS profile
func (m *QoSManager) validateProfile(profile *QoSProfile) error {
	if profile.Interface == "" {
		return fmt.Errorf("interface is required")
	}

	if len(profile.Classes) == 0 {
		return fmt.Errorf("at least one traffic class is required")
	}

	// Check for duplicate class names
	classNames := make(map[string]bool)
	for _, class := range profile.Classes {
		if class.Name == "" {
			return fmt.Errorf("class name is required")
		}

		if classNames[class.Name] {
			return fmt.Errorf("duplicate class name: %s", class.Name)
		}

		classNames[class.Name] = true

		if class.Priority < 1 || class.Priority > 7 {
			return fmt.Errorf("priority must be between 1 and 7")
		}

		if class.DSCP < 0 || class.DSCP > 63 {
			return fmt.Errorf("DSCP must be between 0 and 63")
		}
	}

	// Check if default class exists
	if profile.DefaultClass != "" && !classNames[profile.DefaultClass] {
		return fmt.Errorf("default class %s does not exist", profile.DefaultClass)
	}

	return nil
}

// applyProfile applies a QoS profile using tc
func (m *QoSManager) applyProfile(profile *QoSProfile) error {
	// Check if the interface exists
	if err := checkInterfaceExists(profile.Interface); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Create a qdisc for the interface
	cmd := exec.Command("tc", "qdisc", "add", "dev", profile.Interface, "root", "handle", "1:", "htb", "default", "10")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create root qdisc: %w", err)
	}

	// Create a class for each traffic class
	for i, class := range profile.Classes {
		// Calculate class ID
		classID := fmt.Sprintf("1:%d", i+1)

		// Store the class ID for statistics
		m.stats[profile.Interface][class.Name].ClassID = classID

		// Create the class
		args := []string{"class", "add", "dev", profile.Interface, "parent", "1:", "classid", classID, "htb"}

		// Add rate and ceil
		if class.MinBandwidth != "" {
			args = append(args, "rate", class.MinBandwidth)
		} else {
			args = append(args, "rate", "1mbit")
		}

		if class.MaxBandwidth != "" {
			args = append(args, "ceil", class.MaxBandwidth)
		} else {
			args = append(args, "ceil", profile.UploadBandwidth)
		}

		// Add burst
		if class.Burst != "" {
			args = append(args, "burst", class.Burst)
		}

		// Add priority
		args = append(args, "prio", fmt.Sprintf("%d", class.Priority))

		// Create the class
		cmd = exec.Command("tc", args...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to create class: %w", err)
		}

		// Create a filter for the class based on DSCP
		if class.DSCP > 0 {
			// Create a filter for the class
			cmd = exec.Command("tc", "filter", "add", "dev", profile.Interface, "parent", "1:", "protocol", "ip",
				"prio", "1", "u32", "match", "ip", "tos", fmt.Sprintf("0x%x", class.DSCP<<2), "0xfc",
				"flowid", classID)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to create filter: %w", err)
			}
		}

		// TODO: Create filters for applications, source/destination addresses, ports, etc.
		// This would require integration with the DPI engine and iptables/nftables
	}

	return nil
}

// removeProfile removes a QoS profile
func (m *QoSManager) removeProfile(interfaceName string) error {
	// Check if the interface exists
	if err := checkInterfaceExists(interfaceName); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Remove the qdisc
	cmd := exec.Command("tc", "qdisc", "del", "dev", interfaceName, "root")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove qdisc: %w", err)
	}

	return nil
}

// checkInterfaceExists checks if an interface exists
func checkInterfaceExists(name string) error {
	cmd := exec.Command("ip", "link", "show", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("interface %s does not exist", name)
	}
	return nil
}

// QoSProfile represents a QoS profile
type QoSProfile struct {
	Interface         string
	UploadBandwidth   string
	DownloadBandwidth string
	DefaultClass      string
	Classes           []TrafficClass
}

// TrafficClass represents a traffic class
type TrafficClass struct {
	Name                 string
	Priority             int
	MinBandwidth         string
	MaxBandwidth         string
	Burst                string
	DSCP                 int
	Applications         []string
	ApplicationCategories []string
	SourceAddresses      []string
	DestinationAddresses []string
	SourcePort           string
	DestinationPort      string
	Protocol             string
}

// ClassStatistics represents statistics for a traffic class
type ClassStatistics struct {
	ClassID string
	Packets int64
	Bytes   int64
	Drops   int64
}