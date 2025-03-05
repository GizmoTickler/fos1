package chrony

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"k8s.io/klog/v2"

	"github.com/fos/pkg/ntp"
)

// Manager handles the management of Chrony NTP server
type Manager struct {
	configFile    string
	keysFile      string
	chronyCommand string
	configLock    sync.Mutex
}

// NewManager creates a new Chrony manager
func NewManager(configFile, keysFile, chronyCommand string) *Manager {
	return &Manager{
		configFile:    configFile,
		keysFile:      keysFile,
		chronyCommand: chronyCommand,
	}
}

// UpdateConfig updates the Chrony configuration file
func (m *Manager) UpdateConfig(config string) error {
	m.configLock.Lock()
	defer m.configLock.Unlock()

	// Ensure the directory exists
	dir := filepath.Dir(m.configFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write the configuration to the file
	if err := ioutil.WriteFile(m.configFile, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write configuration to %s: %w", m.configFile, err)
	}

	klog.Infof("Updated Chrony configuration at %s", m.configFile)
	return nil
}

// UpdateKeys updates the Chrony authentication keys
func (m *Manager) UpdateKeys(keys []ntp.AuthKey) error {
	m.configLock.Lock()
	defer m.configLock.Unlock()

	// Create keys file content
	var sb strings.Builder
	for _, key := range keys {
		// Format: keynum hash algorithm value
		sb.WriteString(fmt.Sprintf("%d %s %s\n", key.ID, strings.ToLower(key.Type), key.Value))
	}

	// Ensure the directory exists
	dir := filepath.Dir(m.keysFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write the keys to the file
	if err := ioutil.WriteFile(m.keysFile, []byte(sb.String()), 0600); err != nil {
		return fmt.Errorf("failed to write keys to %s: %w", m.keysFile, err)
	}

	klog.Infof("Updated Chrony keys at %s", m.keysFile)
	return nil
}

// RestartService restarts the Chrony service
func (m *Manager) RestartService() error {
	m.configLock.Lock()
	defer m.configLock.Unlock()

	klog.Infof("Restarting Chrony service")

	// In a real implementation, this would use systemd or another service manager
	// to restart the Chrony service. For this placeholder, we'll use a command-line
	// call to a hypothetical restart command.

	// This is just a placeholder for demonstration
	// cmd := exec.Command("sudo", "systemctl", "restart", "chronyd")
	// if err := cmd.Run(); err != nil {
	//     return fmt.Errorf("failed to restart Chrony: %w", err)
	// }

	// For now, we'll simulate a restart by sending a reload signal to Chrony
	// using the chronyc command
	cmd := exec.Command(m.chronyCommand, "reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload Chrony: %w", err)
	}

	klog.Info("Chrony service restarted successfully")
	return nil
}

// CheckStatus checks the status of the Chrony service
func (m *Manager) CheckStatus() (ntp.Status, error) {
	status := ntp.Status{
		Sources: make([]ntp.Source, 0),
	}

	// Check if Chrony is running
	cmdPid := exec.Command("pgrep", "chronyd")
	if err := cmdPid.Run(); err != nil {
		status.Running = false
		status.LastError = "Chrony is not running"
		return status, nil
	}
	status.Running = true

	// Get tracking information using chronyc tracking
	cmdTracking := exec.Command(m.chronyCommand, "tracking")
	trackingOutput, err := cmdTracking.Output()
	if err != nil {
		status.LastError = fmt.Sprintf("Failed to get tracking info: %v", err)
		return status, nil
	}

	// Parse tracking output to get synchronization status, stratum, offset, and jitter
	if err := m.parseTrackingOutput(string(trackingOutput), &status); err != nil {
		status.LastError = fmt.Sprintf("Failed to parse tracking info: %v", err)
		return status, nil
	}

	// Get sources information using chronyc sources
	cmdSources := exec.Command(m.chronyCommand, "sources")
	sourcesOutput, err := cmdSources.Output()
	if err != nil {
		status.LastError = fmt.Sprintf("Failed to get sources info: %v", err)
		return status, nil
	}

	// Parse sources output to get list of time sources
	if err := m.parseSourcesOutput(string(sourcesOutput), &status); err != nil {
		status.LastError = fmt.Sprintf("Failed to parse sources info: %v", err)
		return status, nil
	}

	return status, nil
}

// parseTrackingOutput parses the output of 'chronyc tracking'
func (m *Manager) parseTrackingOutput(output string, status *ntp.Status) error {
	// Example tracking output:
	// Reference ID    : 192.168.1.1 (time.example.com)
	// Stratum         : 3
	// Ref time (UTC)  : Wed May 12 09:13:15 2021
	// System time     : 0.000012352 seconds slow of NTP time
	// Last offset     : +0.000008273 seconds
	// RMS offset      : 0.000027694 seconds
	// Frequency       : 6.187 ppm slow
	// Residual freq   : -0.004 ppm
	// Skew            : 0.182 ppm
	// Root delay      : 0.001112 seconds
	// Root dispersion : 0.022692 seconds
	// Update interval : 1032.2 seconds
	// Leap status     : Normal

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Stratum") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				stratum, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err == nil {
					status.Stratum = stratum
				}
			}
		} else if strings.Contains(line, "System time") {
			// Parse offset
			if strings.Contains(line, "synchronized") {
				status.Synchronized = true
				status.Offset = 0
			} else {
				status.Synchronized = true // If we get system time info, we're synchronized
				
				// Extract offset value
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					offsetParts := strings.Fields(strings.TrimSpace(parts[1]))
					if len(offsetParts) >= 2 {
						offset, err := strconv.ParseFloat(offsetParts[0], 64)
						if err == nil {
							// Convert seconds to milliseconds
							status.Offset = offset * 1000
						}
					}
				}
			}
		} else if strings.Contains(line, "RMS offset") {
			// Parse jitter
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				jitterParts := strings.Fields(strings.TrimSpace(parts[1]))
				if len(jitterParts) >= 2 {
					jitter, err := strconv.ParseFloat(jitterParts[0], 64)
					if err == nil {
						// Convert seconds to milliseconds
						status.Jitter = jitter * 1000
					}
				}
			}
		}
	}

	return nil
}

// parseSourcesOutput parses the output of 'chronyc sources'
func (m *Manager) parseSourcesOutput(output string, status *ntp.Status) error {
	// Example sources output:
	// 210 Number of sources = 4
	// MS Name/IP address         Stratum Poll Reach LastRx Last sample
	// ===============================================================================
	// ^* time.example.com              2  10   377    12   -44us[  -52us] +/-   51ms
	// ^- ntp1.example.net              1   9   377    11  -631us[ -631us] +/-   84ms
	// ^- ntp2.example.net              2  10   377    11  +538us[ +538us] +/-   59ms
	// ^? bad.clock.example.org        16  10     0     -     +0ns[   +0ns] +/-    0ns

	lines := strings.Split(output, "\n")
	var sources []ntp.Source

	// Count the number of sources
	for i, line := range lines {
		if i < 3 {
			// Skip header lines
			continue
		}
		
		if len(line) == 0 {
			// Skip empty lines
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			// Line doesn't have enough fields
			continue
		}

		sourceType := ""
		selected := false
		
		// First field contains selection state and selection type
		if len(fields[0]) >= 2 {
			switch fields[0][1:2] {
			case "*":
				selected = true
				sourceType = "Server"
			case "+":
				sourceType = "Server"
			case "-":
				sourceType = "Server"
			case "?":
				sourceType = "Unknown"
			case "~":
				sourceType = "Local"
			case "^":
				sourceType = "Server"
			case "#":
				sourceType = "Server"
			}
		}

		// Parse stratum
		stratum, _ := strconv.Atoi(fields[2])

		// Parse reach value
		reach, _ := strconv.ParseInt(fields[4], 8, 32) // Reach is displayed in octal

		// Parse offset from the last sample
		offset := 0.0
		if len(fields) >= 8 {
			// Format varies, but we'll try to extract the offset value
			sample := fields[7]
			if strings.HasPrefix(sample, "[") && strings.HasSuffix(sample, "]") {
				// Extract value inside brackets
				sample = sample[1 : len(sample)-1]
			}
			
			// Remove units and parse as float
			sample = strings.TrimRight(sample, "uns")
			if val, err := strconv.ParseFloat(sample, 64); err == nil {
				// Convert to milliseconds based on unit
				if strings.HasSuffix(fields[7], "ms") {
					offset = val
				} else if strings.HasSuffix(fields[7], "us") {
					offset = val / 1000
				} else if strings.HasSuffix(fields[7], "ns") {
					offset = val / 1000000
				} else {
					// Assume seconds
					offset = val * 1000
				}
			}
		}

		source := ntp.Source{
			Name:     fields[1],
			Type:     sourceType,
			Stratum:  stratum,
			Offset:   offset,
			Reach:    int(reach),
			Selected: selected,
		}

		sources = append(sources, source)
	}

	status.Sources = sources
	status.SourceCount = len(sources)

	return nil
}

// CollectMetrics collects metrics from Chrony
func (m *Manager) CollectMetrics() (ntp.Metrics, error) {
	metrics := ntp.Metrics{}

	// Get current status
	status, err := m.CheckStatus()
	if err != nil {
		return metrics, fmt.Errorf("failed to get status: %w", err)
	}

	// Convert status to metrics
	metrics.Offset = status.Offset
	metrics.Jitter = status.Jitter
	metrics.Stratum = status.Stratum
	metrics.SyncStatus = status.Synchronized
	metrics.SourceCount = status.SourceCount

	// Count reachable sources
	reachableSources := 0
	for _, source := range status.Sources {
		if source.Reach > 0 {
			reachableSources++
		}
	}
	metrics.SourcesReachable = reachableSources

	// Get frequency drift using chronyc tracking
	cmdTracking := exec.Command(m.chronyCommand, "tracking")
	trackingOutput, err := cmdTracking.Output()
	if err != nil {
		return metrics, fmt.Errorf("failed to get tracking info: %w", err)
	}

	lines := strings.Split(string(trackingOutput), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Frequency") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				freqParts := strings.Fields(strings.TrimSpace(parts[1]))
				if len(freqParts) >= 3 {
					drift, err := strconv.ParseFloat(freqParts[0], 64)
					if err == nil {
						// Store in parts per million
						metrics.FrequencyDrift = drift
						if freqParts[1] == "ppm" && freqParts[2] == "slow" {
							metrics.FrequencyDrift = -drift
						}
					}
				}
			}
		}
	}

	return metrics, nil
}