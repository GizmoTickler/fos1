package multiwan

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/network/routing"
)

// loadBalancer implements load balancing for multi-WAN
type loadBalancer struct {
	mutex      sync.RWMutex
	manager    *manager
	configs    map[string]LoadBalancing // key: config name
	stopCh     map[string]chan struct{} // key: config name
	stickyMap  map[string]string        // key: source IP, value: WAN name
	lastUpdate map[string]time.Time     // key: source IP, value: last update time
}

// newLoadBalancer creates a new load balancer
func newLoadBalancer(manager *manager) *loadBalancer {
	return &loadBalancer{
		manager:    manager,
		configs:    make(map[string]LoadBalancing),
		stopCh:     make(map[string]chan struct{}),
		stickyMap:  make(map[string]string),
		lastUpdate: make(map[string]time.Time),
	}
}

// startLoadBalancing starts load balancing for a configuration
func (lb *loadBalancer) startLoadBalancing(config Configuration) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	// Store the load balancing configuration
	lb.configs[config.Name] = config.LoadBalancing

	// Check if load balancing is already running
	if _, exists := lb.stopCh[config.Name]; exists {
		// Stop the existing load balancing
		close(lb.stopCh[config.Name])
	}

	// Create a new stop channel
	lb.stopCh[config.Name] = make(chan struct{})

	// Start load balancing in a goroutine
	go lb.runLoadBalancing(config, lb.stopCh[config.Name])
}

// stopLoadBalancing stops load balancing for a configuration
func (lb *loadBalancer) stopLoadBalancing(configName string) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	// Check if load balancing is running
	if stopCh, exists := lb.stopCh[configName]; exists {
		// Stop the load balancing
		close(stopCh)
		delete(lb.stopCh, configName)
	}

	// Remove the configuration
	delete(lb.configs, configName)
}

// runLoadBalancing runs load balancing for a configuration
func (lb *loadBalancer) runLoadBalancing(config Configuration, stopCh <-chan struct{}) {
	klog.Infof("Starting load balancing for multi-WAN configuration %s", config.Name)

	// Create a ticker for periodic cleanup
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Clean up expired sticky entries
			lb.cleanupStickyEntries(config.LoadBalancing.StickyTimeout)
		case <-stopCh:
			klog.Infof("Stopping load balancing for multi-WAN configuration %s", config.Name)
			return
		}
	}
}

// cleanupStickyEntries cleans up expired sticky entries
func (lb *loadBalancer) cleanupStickyEntries(timeout int) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	now := time.Now()
	for sourceIP, lastUpdate := range lb.lastUpdate {
		if now.Sub(lastUpdate).Seconds() > float64(timeout) {
			// Remove expired entry
			delete(lb.stickyMap, sourceIP)
			delete(lb.lastUpdate, sourceIP)
		}
	}
}

// selectWAN selects a WAN interface for a packet
func (lb *loadBalancer) selectWAN(configName string, sourceIP string) (string, error) {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	// Check if the configuration exists
	config, exists := lb.manager.configs[configName]
	if !exists {
		return "", fmt.Errorf("multi-WAN configuration %s does not exist", configName)
	}

	// Check if load balancing is enabled
	loadBalancing, exists := lb.configs[configName]
	if !exists || !loadBalancing.Enabled {
		return "", fmt.Errorf("load balancing is not enabled for multi-WAN configuration %s", configName)
	}

	// Check if sticky connections are enabled
	if loadBalancing.Sticky {
		// Check if there's a sticky entry for this source IP
		if wanName, exists := lb.stickyMap[sourceIP]; exists {
			// Update the last update time
			lb.lastUpdate[sourceIP] = time.Now()
			return wanName, nil
		}
	}

	// Get active WAN interfaces
	status, exists := lb.manager.statuses[configName]
	if !exists {
		return "", fmt.Errorf("multi-WAN status for %s does not exist", configName)
	}

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

	// Check if there are any active WAN interfaces
	if len(activeWANs) == 0 {
		return "", fmt.Errorf("no active WAN interfaces for multi-WAN configuration %s", configName)
	}

	// Select a WAN interface based on the load balancing method
	var selectedWAN WANInterface
	switch loadBalancing.Method {
	case "weighted":
		selectedWAN = lb.selectWANWeighted(activeWANs)
	case "round-robin":
		selectedWAN = lb.selectWANRoundRobin(configName, activeWANs)
	case "random":
		selectedWAN = lb.selectWANRandom(activeWANs)
	default:
		selectedWAN = lb.selectWANWeighted(activeWANs)
	}

	// If sticky connections are enabled, store the selected WAN
	if loadBalancing.Sticky {
		lb.stickyMap[sourceIP] = selectedWAN.Name
		lb.lastUpdate[sourceIP] = time.Now()
	}

	return selectedWAN.Name, nil
}

// selectWANWeighted selects a WAN interface using weighted load balancing
func (lb *loadBalancer) selectWANWeighted(wans []WANInterface) WANInterface {
	// Calculate the total weight
	totalWeight := 0
	for _, wan := range wans {
		totalWeight += wan.Weight
	}

	// Select a random weight
	randomWeight := rand.Intn(totalWeight) + 1

	// Find the WAN interface for this weight
	currentWeight := 0
	for _, wan := range wans {
		currentWeight += wan.Weight
		if randomWeight <= currentWeight {
			return wan
		}
	}

	// Fallback to the first WAN interface
	return wans[0]
}

// selectWANRoundRobin selects a WAN interface using round-robin load balancing
func (lb *loadBalancer) selectWANRoundRobin(configName string, wans []WANInterface) WANInterface {
	// Use the first WAN interface
	return wans[0]
}

// selectWANRandom selects a WAN interface randomly
func (lb *loadBalancer) selectWANRandom(wans []WANInterface) WANInterface {
	// Select a random WAN interface
	return wans[rand.Intn(len(wans))]
}
