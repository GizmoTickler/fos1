package multiwan

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// monitor implements monitoring for multi-WAN
type monitor struct {
	mutex      sync.RWMutex
	manager    *manager
	configs    map[string]map[string]WANMonitoring // key: config name, value: map[wan name]monitoring
	stopCh     map[string]chan struct{}            // key: config name
	failCounts map[string]map[string]int           // key: config name, value: map[wan name]fail count
	succCounts map[string]map[string]int           // key: config name, value: map[wan name]success count
}

// newMonitor creates a new monitor
func newMonitor(manager *manager) *monitor {
	return &monitor{
		manager:    manager,
		configs:    make(map[string]map[string]WANMonitoring),
		stopCh:     make(map[string]chan struct{}),
		failCounts: make(map[string]map[string]int),
		succCounts: make(map[string]map[string]int),
	}
}

// startMonitoring starts monitoring for a configuration
func (m *monitor) startMonitoring(config Configuration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Store the monitoring configuration
	wanMonitoring := make(map[string]WANMonitoring)
	for _, wan := range config.WANInterfaces {
		wanMonitoring[wan.Name] = wan.Monitoring
	}
	m.configs[config.Name] = wanMonitoring

	// Initialize fail and success counts
	m.failCounts[config.Name] = make(map[string]int)
	m.succCounts[config.Name] = make(map[string]int)
	for _, wan := range config.WANInterfaces {
		m.failCounts[config.Name][wan.Name] = 0
		m.succCounts[config.Name][wan.Name] = 0
	}

	// Check if monitoring is already running
	if _, exists := m.stopCh[config.Name]; exists {
		// Stop the existing monitoring
		close(m.stopCh[config.Name])
	}

	// Create a new stop channel
	m.stopCh[config.Name] = make(chan struct{})

	// Start monitoring in a goroutine
	go m.runMonitoring(config, m.stopCh[config.Name])
}

// stopMonitoring stops monitoring for a configuration
func (m *monitor) stopMonitoring(configName string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if monitoring is running
	if stopCh, exists := m.stopCh[configName]; exists {
		// Stop the monitoring
		close(stopCh)
		delete(m.stopCh, configName)
	}

	// Remove the configuration
	delete(m.configs, configName)
	delete(m.failCounts, configName)
	delete(m.succCounts, configName)
}

// runMonitoring runs monitoring for a configuration
func (m *monitor) runMonitoring(config Configuration, stopCh <-chan struct{}) {
	klog.Infof("Starting monitoring for multi-WAN configuration %s", config.Name)

	// Create a ticker for periodic checks
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check each WAN interface
			for _, wan := range config.WANInterfaces {
				go m.checkWAN(config.Name, wan)
			}
		case <-stopCh:
			klog.Infof("Stopping monitoring for multi-WAN configuration %s", config.Name)
			return
		}
	}
}

// checkWAN checks a WAN interface
func (m *monitor) checkWAN(configName string, wan WANInterface) {
	m.mutex.Lock()
	monitoring, exists := m.configs[configName][wan.Name]
	if !exists {
		m.mutex.Unlock()
		return
	}
	m.mutex.Unlock()

	// Check if there are any targets
	if len(monitoring.Targets) == 0 {
		return
	}

	// Check each target
	for _, target := range monitoring.Targets {
		// Check the target based on the monitoring method
		var success bool
		var rtt int
		var err error

		switch monitoring.Method {
		case "ping":
			success, rtt, err = m.pingTarget(target, monitoring.Timeout)
		case "http":
			success, rtt, err = m.httpTarget(target, monitoring.Timeout)
		case "dns":
			success, rtt, err = m.dnsTarget(target, monitoring.Timeout)
		default:
			success, rtt, err = m.pingTarget(target, monitoring.Timeout)
		}

		if err != nil {
			klog.Warningf("Failed to check target %s for WAN %s: %v", target, wan.Name, err)
			continue
		}

		// Update fail and success counts
		m.mutex.Lock()
		if success {
			m.failCounts[configName][wan.Name] = 0
			m.succCounts[configName][wan.Name]++
		} else {
			m.failCounts[configName][wan.Name]++
			m.succCounts[configName][wan.Name] = 0
		}

		// Check if the WAN state should change
		failCount := m.failCounts[configName][wan.Name]
		succCount := m.succCounts[configName][wan.Name]
		failThreshold := monitoring.FailThreshold
		succThreshold := monitoring.SuccessThreshold
		m.mutex.Unlock()

		// Get the current WAN state
		status, err := m.manager.GetStatus(configName)
		if err != nil {
			klog.Warningf("Failed to get status for multi-WAN configuration %s: %v", configName, err)
			continue
		}

		var currentState string
		for _, wanStatus := range status.ActiveWANs {
			if wanStatus.Name == wan.Name {
				currentState = wanStatus.State
				break
			}
		}

		// Update the WAN state if needed
		if currentState == "up" && failCount >= failThreshold {
			// Mark the WAN as down
			m.manager.updateWANStatus(configName, wan.Name, "down", rtt, 100.0)
			// Notify the failover handler
			m.manager.failover.handleWANStateChange(configName, wan.Name, "down")
		} else if currentState != "up" && succCount >= succThreshold {
			// Mark the WAN as up
			m.manager.updateWANStatus(configName, wan.Name, "up", rtt, 0.0)
			// Notify the failover handler
			m.manager.failover.handleWANStateChange(configName, wan.Name, "up")
		} else {
			// Update the RTT
			m.manager.updateWANStatus(configName, wan.Name, currentState, rtt, 0.0)
		}

		// We only need to check one target successfully
		if success {
			break
		}
	}
}

// pingTarget pings a target
func (m *monitor) pingTarget(target string, timeout int) (bool, int, error) {
	// Create the ping command
	cmd := exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeout), target)

	// Execute the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, 0, nil // Not an error, just a failed ping
	}

	// Parse the output to get the RTT
	outputStr := string(output)
	rttIndex := strings.Index(outputStr, "time=")
	if rttIndex == -1 {
		return true, 0, nil
	}

	rttStr := outputStr[rttIndex+5:]
	rttEnd := strings.Index(rttStr, " ")
	if rttEnd == -1 {
		return true, 0, nil
	}

	rttStr = rttStr[:rttEnd]
	rtt, err := strconv.ParseFloat(rttStr, 64)
	if err != nil {
		return true, 0, nil
	}

	return true, int(rtt), nil
}

// httpTarget checks an HTTP target
func (m *monitor) httpTarget(target string, timeout int) (bool, int, error) {
	// Create a client with a timeout
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Start the timer
	start := time.Now()

	// Make the request
	resp, err := client.Get(target)
	if err != nil {
		return false, 0, nil // Not an error, just a failed request
	}
	defer resp.Body.Close()

	// Calculate the RTT
	rtt := int(time.Since(start).Milliseconds())

	// Check if the response is successful
	return resp.StatusCode >= 200 && resp.StatusCode < 300, rtt, nil
}

// dnsTarget checks a DNS target
func (m *monitor) dnsTarget(target string, timeout int) (bool, int, error) {
	// Create a resolver with a timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Duration(timeout) * time.Second,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	// Start the timer
	start := time.Now()

	// Resolve the target
	_, err := resolver.LookupHost(context.Background(), target)
	if err != nil {
		return false, 0, nil // Not an error, just a failed resolution
	}

	// Calculate the RTT
	rtt := int(time.Since(start).Milliseconds())

	return true, rtt, nil
}
