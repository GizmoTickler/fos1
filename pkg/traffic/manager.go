package traffic

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// manager implements the Manager interface
type manager struct {
	mutex            sync.RWMutex
	configs          map[string]*Configuration // key: interface name
	statuses         map[string]*Status
	classifier       Classifier
	bandwidthAllocator BandwidthAllocator
	updateInterval   time.Duration
	stopCh           chan struct{}
}

// NewManager creates a new traffic manager
func NewManager(classifier Classifier, bandwidthAllocator BandwidthAllocator, updateInterval time.Duration) Manager {
	m := &manager{
		configs:          make(map[string]*Configuration),
		statuses:         make(map[string]*Status),
		classifier:       classifier,
		bandwidthAllocator: bandwidthAllocator,
		updateInterval:   updateInterval,
		stopCh:           make(chan struct{}),
	}

	// Start the statistics update goroutine
	go m.updateStatisticsLoop()

	return m
}

// ApplyConfiguration applies a traffic management configuration
func (m *manager) ApplyConfiguration(config *Configuration) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	klog.Infof("Applying traffic management configuration for interface %s", config.Interface)

	// Check if the interface exists
	if err := checkInterfaceExists(config.Interface); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Store the configuration
	m.configs[config.Interface] = config

	// Initialize or update status
	status, exists := m.statuses[config.Interface]
	if !exists {
		status = &Status{
			Interface:           config.Interface,
			UploadBandwidth:     config.UploadBandwidth,
			DownloadBandwidth:   config.DownloadBandwidth,
			ClassStatistics:     make(map[string]*ClassStatistics),
			InterfaceStatistics: &InterfaceStatistics{},
			LastUpdated:         time.Now(),
		}
		m.statuses[config.Interface] = status
	} else {
		status.UploadBandwidth = config.UploadBandwidth
		status.DownloadBandwidth = config.DownloadBandwidth
		status.LastUpdated = time.Now()
	}

	// Initialize class statistics
	for _, class := range config.Classes {
		if _, exists := status.ClassStatistics[class.Name]; !exists {
			status.ClassStatistics[class.Name] = &ClassStatistics{}
		}
	}

	// Apply the configuration
	if err := m.applyTrafficControl(config); err != nil {
		return fmt.Errorf("failed to apply traffic control: %w", err)
	}

	// Apply bandwidth allocation
	for _, class := range config.Classes {
		if err := m.bandwidthAllocator.AllocateBandwidth(config.Interface, class.Name, class.MinBandwidth, class.MaxBandwidth); err != nil {
			klog.Warningf("Failed to allocate bandwidth for class %s on interface %s: %v", class.Name, config.Interface, err)
		}
	}

	// Apply classification rules
	for _, class := range config.Classes {
		rule := ClassificationRule{
			Name:                 fmt.Sprintf("%s-%s", config.Interface, class.Name),
			Priority:             class.Priority,
			ClassName:            class.Name,
			SourceAddresses:      class.SourceAddresses,
			DestinationAddresses: class.DestinationAddresses,
			Protocol:             class.Protocol,
			Applications:         class.Applications,
			ApplicationCategories: class.ApplicationCategories,
			DSCP:                 class.DSCP,
		}

		// Add source port
		if class.SourcePort != "" {
			rule.SourcePorts = []string{class.SourcePort}
		}

		// Add destination port
		if class.DestinationPort != "" {
			rule.DestinationPorts = []string{class.DestinationPort}
		}

		if err := m.classifier.AddClassificationRule(rule); err != nil {
			klog.Warningf("Failed to add classification rule for class %s on interface %s: %v", class.Name, config.Interface, err)
		}
	}

	return nil
}

// DeleteConfiguration deletes a traffic management configuration
func (m *manager) DeleteConfiguration(interfaceName string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	klog.Infof("Deleting traffic management configuration for interface %s", interfaceName)

	// Check if the configuration exists
	config, exists := m.configs[interfaceName]
	if !exists {
		return fmt.Errorf("traffic management configuration for interface %s does not exist", interfaceName)
	}

	// Remove traffic control
	if err := m.removeTrafficControl(interfaceName); err != nil {
		return fmt.Errorf("failed to remove traffic control: %w", err)
	}

	// Release bandwidth allocation
	for _, class := range config.Classes {
		if err := m.bandwidthAllocator.ReleaseBandwidth(interfaceName, class.Name); err != nil {
			klog.Warningf("Failed to release bandwidth for class %s on interface %s: %v", class.Name, interfaceName, err)
		}
	}

	// Remove classification rules
	for _, class := range config.Classes {
		ruleName := fmt.Sprintf("%s-%s", interfaceName, class.Name)
		if err := m.classifier.RemoveClassificationRule(ruleName); err != nil {
			klog.Warningf("Failed to remove classification rule for class %s on interface %s: %v", class.Name, interfaceName, err)
		}
	}

	// Remove the configuration and status
	delete(m.configs, interfaceName)
	delete(m.statuses, interfaceName)

	return nil
}

// GetStatus gets the status of a traffic management configuration
func (m *manager) GetStatus(interfaceName string) (*Status, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	status, exists := m.statuses[interfaceName]
	if !exists {
		return nil, fmt.Errorf("traffic management configuration for interface %s does not exist", interfaceName)
	}

	return status, nil
}

// ListConfigurations lists all traffic management configurations
func (m *manager) ListConfigurations() ([]*Configuration, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	configs := make([]*Configuration, 0, len(m.configs))
	for _, config := range m.configs {
		configs = append(configs, config)
	}

	return configs, nil
}

// GetClassStatistics gets statistics for a traffic class
func (m *manager) GetClassStatistics(interfaceName, className string) (*ClassStatistics, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	status, exists := m.statuses[interfaceName]
	if !exists {
		return nil, fmt.Errorf("traffic management configuration for interface %s does not exist", interfaceName)
	}

	stats, exists := status.ClassStatistics[className]
	if !exists {
		return nil, fmt.Errorf("traffic class %s does not exist on interface %s", className, interfaceName)
	}

	return stats, nil
}

// GetInterfaceStatistics gets statistics for an interface
func (m *manager) GetInterfaceStatistics(interfaceName string) (*InterfaceStatistics, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	status, exists := m.statuses[interfaceName]
	if !exists {
		return nil, fmt.Errorf("traffic management configuration for interface %s does not exist", interfaceName)
	}

	return status.InterfaceStatistics, nil
}

// updateStatisticsLoop periodically updates statistics
func (m *manager) updateStatisticsLoop() {
	ticker := time.NewTicker(m.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.updateStatistics(); err != nil {
				klog.Errorf("Failed to update statistics: %v", err)
			}
		case <-m.stopCh:
			klog.Info("Stopping statistics update loop")
			return
		}
	}
}

// updateStatistics updates statistics for all interfaces
func (m *manager) updateStatistics() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for interfaceName := range m.configs {
		// Update interface statistics
		ifStats, err := m.getInterfaceStatistics(interfaceName)
		if err != nil {
			klog.Warningf("Failed to get interface statistics for %s: %v", interfaceName, err)
			continue
		}

		m.statuses[interfaceName].InterfaceStatistics = ifStats
		m.statuses[interfaceName].LastUpdated = time.Now()

		// Update class statistics
		for className := range m.statuses[interfaceName].ClassStatistics {
			classStats, err := m.getClassStatistics(interfaceName, className)
			if err != nil {
				klog.Warningf("Failed to get class statistics for %s on interface %s: %v", className, interfaceName, err)
				continue
			}

			m.statuses[interfaceName].ClassStatistics[className] = classStats
		}
	}

	return nil
}

// getInterfaceStatistics gets statistics for an interface
func (m *manager) getInterfaceStatistics(interfaceName string) (*InterfaceStatistics, error) {
	// Get interface statistics from /proc/net/dev
	cmd := exec.Command("cat", "/proc/net/dev")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface statistics: %w", err)
	}

	// Parse the output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, interfaceName+":") {
			// Extract statistics
			fields := strings.Fields(line)
			if len(fields) < 17 {
				return nil, fmt.Errorf("invalid interface statistics format")
			}

			// Parse statistics
			rxBytes, _ := strconv.ParseInt(fields[1], 10, 64)
			rxPackets, _ := strconv.ParseInt(fields[2], 10, 64)
			rxErrors, _ := strconv.ParseInt(fields[3], 10, 64)
			rxDrops, _ := strconv.ParseInt(fields[4], 10, 64)
			txBytes, _ := strconv.ParseInt(fields[9], 10, 64)
			txPackets, _ := strconv.ParseInt(fields[10], 10, 64)
			txErrors, _ := strconv.ParseInt(fields[11], 10, 64)
			txDrops, _ := strconv.ParseInt(fields[12], 10, 64)

			// Calculate rates and utilization
			// In a real implementation, we would track previous values and calculate rates
			// For now, we'll just use dummy values
			rxRate := rxBytes * 8 / 1000 // kbps
			txRate := txBytes * 8 / 1000 // kbps

			// Get interface speed
			speed, err := getInterfaceSpeed(interfaceName)
			if err != nil {
				klog.Warningf("Failed to get interface speed for %s: %v", interfaceName, err)
				speed = 1000000 // Default to 1 Gbps
			}

			// Calculate utilization
			rxUtilization := float64(rxRate) / float64(speed) * 100
			txUtilization := float64(txRate) / float64(speed) * 100

			return &InterfaceStatistics{
				RxPackets:      rxPackets,
				RxBytes:        rxBytes,
				RxDrops:        rxDrops,
				RxErrors:       rxErrors,
				TxPackets:      txPackets,
				TxBytes:        txBytes,
				TxDrops:        txDrops,
				TxErrors:       txErrors,
				RxRate:         rxRate,
				TxRate:         txRate,
				RxUtilization:  rxUtilization,
				TxUtilization:  txUtilization,
			}, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", interfaceName)
}

// getClassStatistics gets statistics for a traffic class
func (m *manager) getClassStatistics(interfaceName, className string) (*ClassStatistics, error) {
	// Get class ID
	classID := ""
	for _, class := range m.configs[interfaceName].Classes {
		if class.Name == className {
			// In a real implementation, we would store the class ID
			// For now, we'll use a dummy value
			classID = fmt.Sprintf("1:%d", class.Priority)
			break
		}
	}

	if classID == "" {
		return nil, fmt.Errorf("class %s not found on interface %s", className, interfaceName)
	}

	// Get class statistics from tc
	cmd := exec.Command("tc", "-s", "class", "show", "dev", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get class statistics: %w", err)
	}

	// Parse the output
	classRegex := regexp.MustCompile(fmt.Sprintf(`class htb %s.*?Sent (\d+) bytes (\d+) pkt \(dropped (\d+)`, classID))
	match := classRegex.FindStringSubmatch(string(output))
	if match == nil {
		return nil, fmt.Errorf("class %s not found in tc output", classID)
	}

	// Parse statistics
	bytes, _ := strconv.ParseInt(match[1], 10, 64)
	packets, _ := strconv.ParseInt(match[2], 10, 64)
	drops, _ := strconv.ParseInt(match[3], 10, 64)

	// Calculate rate and utilization
	// In a real implementation, we would track previous values and calculate rates
	// For now, we'll just use dummy values
	rate := bytes * 8 / 1000 // kbps

	// Get class bandwidth
	var maxBandwidth string
	for _, class := range m.configs[interfaceName].Classes {
		if class.Name == className {
			maxBandwidth = class.MaxBandwidth
			break
		}
	}

	// Parse bandwidth
	var bandwidthValue int64
	if strings.HasSuffix(maxBandwidth, "Mbit") {
		bandwidthValue, _ = strconv.ParseInt(strings.TrimSuffix(maxBandwidth, "Mbit"), 10, 64)
		bandwidthValue *= 1000 // Convert to kbps
	} else if strings.HasSuffix(maxBandwidth, "Kbit") {
		bandwidthValue, _ = strconv.ParseInt(strings.TrimSuffix(maxBandwidth, "Kbit"), 10, 64)
	} else if strings.HasSuffix(maxBandwidth, "%") {
		// Get interface speed
		speed, err := getInterfaceSpeed(interfaceName)
		if err != nil {
			klog.Warningf("Failed to get interface speed for %s: %v", interfaceName, err)
			speed = 1000000 // Default to 1 Gbps
		}

		// Calculate bandwidth as a percentage of interface speed
		percentage, _ := strconv.ParseInt(strings.TrimSuffix(maxBandwidth, "%"), 10, 64)
		bandwidthValue = speed * percentage / 100
	} else {
		bandwidthValue = 1000000 // Default to 1 Gbps
	}

	// Calculate utilization
	utilization := float64(rate) / float64(bandwidthValue) * 100

	return &ClassStatistics{
		Packets:     packets,
		Bytes:       bytes,
		Drops:       drops,
		Rate:        rate,
		Utilization: utilization,
	}, nil
}

// applyTrafficControl applies traffic control to an interface
func (m *manager) applyTrafficControl(config *Configuration) error {
	// Check if the interface exists
	if err := checkInterfaceExists(config.Interface); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Remove any existing traffic control
	if err := m.removeTrafficControl(config.Interface); err != nil {
		klog.Warningf("Failed to remove existing traffic control for interface %s: %v", config.Interface, err)
	}

	// Create a qdisc for the interface
	cmd := exec.Command("tc", "qdisc", "add", "dev", config.Interface, "root", "handle", "1:", "htb", "default", "10")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create root qdisc: %w", err)
	}

	// Create a class for each traffic class
	for i, class := range config.Classes {
		// Calculate class ID
		classID := fmt.Sprintf("1:%d", i+1)

		// Create the class
		args := []string{"class", "add", "dev", config.Interface, "parent", "1:", "classid", classID, "htb"}

		// Add rate and ceil
		if class.MinBandwidth != "" {
			args = append(args, "rate", class.MinBandwidth)
		} else {
			args = append(args, "rate", "1mbit")
		}

		if class.MaxBandwidth != "" {
			args = append(args, "ceil", class.MaxBandwidth)
		} else {
			args = append(args, "ceil", config.UploadBandwidth)
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
			cmd = exec.Command("tc", "filter", "add", "dev", config.Interface, "parent", "1:", "protocol", "ip",
				"prio", "1", "u32", "match", "ip", "tos", fmt.Sprintf("0x%x", class.DSCP<<2), "0xfc",
				"flowid", classID)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to create filter: %w", err)
			}
		}
	}

	return nil
}

// removeTrafficControl removes traffic control from an interface
func (m *manager) removeTrafficControl(interfaceName string) error {
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
func checkInterfaceExists(interfaceName string) error {
	cmd := exec.Command("ip", "link", "show", interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("interface %s does not exist", interfaceName)
	}
	return nil
}

// getInterfaceSpeed gets the speed of an interface
func getInterfaceSpeed(interfaceName string) (int64, error) {
	// Get interface speed from ethtool
	cmd := exec.Command("ethtool", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to get interface speed: %w", err)
	}

	// Parse the output
	speedRegex := regexp.MustCompile(`Speed: (\d+)([GMK])bit/s`)
	match := speedRegex.FindStringSubmatch(string(output))
	if match == nil {
		return 0, fmt.Errorf("failed to parse interface speed")
	}

	// Parse speed
	speed, _ := strconv.ParseInt(match[1], 10, 64)
	unit := match[2]

	// Convert to kbps
	switch unit {
	case "G":
		speed *= 1000000
	case "M":
		speed *= 1000
	}

	return speed, nil
}
