package multiwan

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/network/routing"
)

// failover implements failover for multi-WAN
type failover struct {
	mutex      sync.RWMutex
	manager    *manager
	configs    map[string]Failover // key: config name
	stopCh     map[string]chan struct{} // key: config name
	lastChange map[string]time.Time // key: config name, value: last change time
}

// newFailover creates a new failover
func newFailover(manager *manager) *failover {
	return &failover{
		manager:    manager,
		configs:    make(map[string]Failover),
		stopCh:     make(map[string]chan struct{}),
		lastChange: make(map[string]time.Time),
	}
}

// startFailover starts failover for a configuration
func (f *failover) startFailover(config Configuration) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// Store the failover configuration
	f.configs[config.Name] = config.Failover

	// Check if failover is already running
	if _, exists := f.stopCh[config.Name]; exists {
		// Stop the existing failover
		close(f.stopCh[config.Name])
	}

	// Create a new stop channel
	f.stopCh[config.Name] = make(chan struct{})

	// Start failover in a goroutine
	go f.runFailover(config, f.stopCh[config.Name])
}

// stopFailover stops failover for a configuration
func (f *failover) stopFailover(configName string) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// Check if failover is running
	if stopCh, exists := f.stopCh[configName]; exists {
		// Stop the failover
		close(stopCh)
		delete(f.stopCh, configName)
	}

	// Remove the configuration
	delete(f.configs, configName)
}

// runFailover runs failover for a configuration
func (f *failover) runFailover(config Configuration, stopCh <-chan struct{}) {
	klog.Infof("Starting failover for multi-WAN configuration %s", config.Name)

	// Create a ticker for periodic checks
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check for failover
			if err := f.checkFailover(config); err != nil {
				klog.Errorf("Failed to check failover for multi-WAN configuration %s: %v", config.Name, err)
			}
		case <-stopCh:
			klog.Infof("Stopping failover for multi-WAN configuration %s", config.Name)
			return
		}
	}
}

// checkFailover checks for failover
func (f *failover) checkFailover(config Configuration) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// Check if failover is enabled
	failover, exists := f.configs[config.Name]
	if !exists || !failover.Enabled {
		return nil
	}

	// Get the current status
	status, exists := f.manager.statuses[config.Name]
	if !exists {
		return fmt.Errorf("multi-WAN status for %s does not exist", config.Name)
	}

	// Get active WAN interfaces
	activeWANs := make([]WANInterface, 0)
	for _, wanStatus := range status.ActiveWANs {
		if wanStatus.State == "up" {
			// Find the WAN interface
			for _, wan := range config.WANInterfaces {
				if wan.Name == wanStatus.Name {
					activeWANs = append(activeWANs, wan)
					break
				}
			}
		}
	}

	// Sort active WANs by priority
	sort.Slice(activeWANs, func(i, j int) bool {
		return activeWANs[i].Priority < activeWANs[j].Priority
	})

	// Check if there are any active WAN interfaces
	if len(activeWANs) == 0 {
		return fmt.Errorf("no active WAN interfaces for multi-WAN configuration %s", config.Name)
	}

	// Get the current primary
	currentPrimary := status.CurrentPrimary

	// If there's no current primary, set it to the highest priority active WAN
	if currentPrimary == "" {
		f.manager.setCurrentPrimary(config.Name, activeWANs[0].Name)
		f.lastChange[config.Name] = time.Now()
		return nil
	}

	// Check if the current primary is still active
	primaryActive := false
	for _, wan := range activeWANs {
		if wan.Name == currentPrimary {
			primaryActive = true
			break
		}
	}

	// If the current primary is not active, failover to the highest priority active WAN
	if !primaryActive {
		f.manager.setCurrentPrimary(config.Name, activeWANs[0].Name)
		f.lastChange[config.Name] = time.Now()
		return nil
	}

	// If preempt is enabled, check if we should preempt back to a higher priority WAN
	if failover.Preempt {
		// Get the current primary's priority
		var currentPrimaryPriority int
		for _, wan := range config.WANInterfaces {
			if wan.Name == currentPrimary {
				currentPrimaryPriority = wan.Priority
				break
			}
		}

		// Check if there's a higher priority active WAN
		if activeWANs[0].Priority < currentPrimaryPriority {
			// Check if the preempt delay has passed
			lastChangeTime, exists := f.lastChange[config.Name]
			if !exists || time.Since(lastChangeTime).Seconds() > float64(failover.PreemptDelay) {
				// Preempt to the higher priority WAN
				f.manager.setCurrentPrimary(config.Name, activeWANs[0].Name)
				f.lastChange[config.Name] = time.Now()
			}
		}
	}

	return nil
}

// handleWANStateChange handles a WAN state change
func (f *failover) handleWANStateChange(configName, wanName, state string) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// Check if failover is enabled
	failover, exists := f.configs[configName]
	if !exists || !failover.Enabled {
		return
	}

	// Get the current status
	status, exists := f.manager.statuses[configName]
	if !exists {
		klog.Warningf("Cannot handle WAN state change: multi-WAN status for %s does not exist", configName)
		return
	}

	// Get the current primary
	currentPrimary := status.CurrentPrimary

	// If the WAN that changed state is the current primary and it went down, trigger failover
	if wanName == currentPrimary && state == "down" {
		// Get the configuration
		config, exists := f.manager.configs[configName]
		if !exists {
			klog.Warningf("Cannot handle WAN state change: multi-WAN configuration %s does not exist", configName)
			return
		}

		// Get active WAN interfaces
		activeWANs := make([]WANInterface, 0)
		for _, wanStatus := range status.ActiveWANs {
			if wanStatus.State == "up" && wanStatus.Name != wanName {
				// Find the WAN interface
				for _, wan := range config.WANInterfaces {
					if wan.Name == wanStatus.Name {
						activeWANs = append(activeWANs, wan)
						break
					}
				}
			}
		}

		// Sort active WANs by priority
		sort.Slice(activeWANs, func(i, j int) bool {
			return activeWANs[i].Priority < activeWANs[j].Priority
		})

		// Check if there are any active WAN interfaces
		if len(activeWANs) == 0 {
			klog.Warningf("No active WAN interfaces for multi-WAN configuration %s", configName)
			return
		}

		// Failover to the highest priority active WAN
		f.manager.setCurrentPrimary(configName, activeWANs[0].Name)
		f.lastChange[configName] = time.Now()
	}
}
