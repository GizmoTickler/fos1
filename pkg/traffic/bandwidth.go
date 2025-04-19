package traffic

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"k8s.io/klog/v2"
)

// bandwidthAllocator implements the BandwidthAllocator interface
type bandwidthAllocator struct {
	mutex       sync.RWMutex
	allocations map[string]map[string]allocation // key: interface name, value: map[class name]allocation
}

// allocation represents a bandwidth allocation
type allocation struct {
	// MinBandwidth is the minimum guaranteed bandwidth
	MinBandwidth string
	
	// MaxBandwidth is the maximum bandwidth limit
	MaxBandwidth string
}

// NewBandwidthAllocator creates a new bandwidth allocator
func NewBandwidthAllocator() BandwidthAllocator {
	return &bandwidthAllocator{
		allocations: make(map[string]map[string]allocation),
	}
}

// AllocateBandwidth allocates bandwidth to a class
func (b *bandwidthAllocator) AllocateBandwidth(interfaceName, className string, minBandwidth, maxBandwidth string) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Check if the interface exists
	if err := checkInterfaceExists(interfaceName); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Initialize allocations for the interface if needed
	if _, exists := b.allocations[interfaceName]; !exists {
		b.allocations[interfaceName] = make(map[string]allocation)
	}

	// Check if the allocation already exists
	if _, exists := b.allocations[interfaceName][className]; exists {
		// Update the allocation
		b.allocations[interfaceName][className] = allocation{
			MinBandwidth: minBandwidth,
			MaxBandwidth: maxBandwidth,
		}
		return nil
	}

	// Add the allocation
	b.allocations[interfaceName][className] = allocation{
		MinBandwidth: minBandwidth,
		MaxBandwidth: maxBandwidth,
	}

	// Apply the allocation
	return b.applyAllocation(interfaceName, className, minBandwidth, maxBandwidth)
}

// ReleaseBandwidth releases bandwidth from a class
func (b *bandwidthAllocator) ReleaseBandwidth(interfaceName, className string) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Check if the interface exists
	if err := checkInterfaceExists(interfaceName); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Check if the allocation exists
	if _, exists := b.allocations[interfaceName]; !exists {
		return fmt.Errorf("no allocations for interface %s", interfaceName)
	}

	if _, exists := b.allocations[interfaceName][className]; !exists {
		return fmt.Errorf("no allocation for class %s on interface %s", className, interfaceName)
	}

	// Remove the allocation
	delete(b.allocations[interfaceName], className)

	// If there are no more allocations for the interface, remove it
	if len(b.allocations[interfaceName]) == 0 {
		delete(b.allocations, interfaceName)
	}

	// Remove the allocation from the system
	return b.removeAllocation(interfaceName, className)
}

// GetBandwidthAllocation gets the bandwidth allocation for a class
func (b *bandwidthAllocator) GetBandwidthAllocation(interfaceName, className string) (string, string, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	// Check if the allocation exists
	if _, exists := b.allocations[interfaceName]; !exists {
		return "", "", fmt.Errorf("no allocations for interface %s", interfaceName)
	}

	if allocation, exists := b.allocations[interfaceName][className]; !exists {
		return "", "", fmt.Errorf("no allocation for class %s on interface %s", className, interfaceName)
	} else {
		return allocation.MinBandwidth, allocation.MaxBandwidth, nil
	}
}

// GetTotalBandwidth gets the total bandwidth for an interface
func (b *bandwidthAllocator) GetTotalBandwidth(interfaceName string) (string, error) {
	// Check if the interface exists
	if err := checkInterfaceExists(interfaceName); err != nil {
		return "", fmt.Errorf("interface check failed: %w", err)
	}

	// Get interface speed
	speed, err := getInterfaceSpeed(interfaceName)
	if err != nil {
		return "", fmt.Errorf("failed to get interface speed: %w", err)
	}

	// Convert to string
	if speed >= 1000000 {
		return fmt.Sprintf("%dGbit", speed/1000000), nil
	} else if speed >= 1000 {
		return fmt.Sprintf("%dMbit", speed/1000), nil
	} else {
		return fmt.Sprintf("%dKbit", speed), nil
	}
}

// GetAvailableBandwidth gets the available bandwidth for an interface
func (b *bandwidthAllocator) GetAvailableBandwidth(interfaceName string) (string, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	// Check if the interface exists
	if err := checkInterfaceExists(interfaceName); err != nil {
		return "", fmt.Errorf("interface check failed: %w", err)
	}

	// Get interface speed
	speed, err := getInterfaceSpeed(interfaceName)
	if err != nil {
		return "", fmt.Errorf("failed to get interface speed: %w", err)
	}

	// Calculate allocated bandwidth
	var allocatedBandwidth int64
	if allocations, exists := b.allocations[interfaceName]; exists {
		for _, allocation := range allocations {
			// Parse max bandwidth
			maxBandwidth := allocation.MaxBandwidth
			if maxBandwidth == "" {
				continue
			}

			// Parse bandwidth value
			var bandwidthValue int64
			if strings.HasSuffix(maxBandwidth, "Gbit") {
				bandwidthValue, _ = strconv.ParseInt(strings.TrimSuffix(maxBandwidth, "Gbit"), 10, 64)
				bandwidthValue *= 1000000 // Convert to kbps
			} else if strings.HasSuffix(maxBandwidth, "Mbit") {
				bandwidthValue, _ = strconv.ParseInt(strings.TrimSuffix(maxBandwidth, "Mbit"), 10, 64)
				bandwidthValue *= 1000 // Convert to kbps
			} else if strings.HasSuffix(maxBandwidth, "Kbit") {
				bandwidthValue, _ = strconv.ParseInt(strings.TrimSuffix(maxBandwidth, "Kbit"), 10, 64)
			} else if strings.HasSuffix(maxBandwidth, "%") {
				// Calculate bandwidth as a percentage of interface speed
				percentage, _ := strconv.ParseInt(strings.TrimSuffix(maxBandwidth, "%"), 10, 64)
				bandwidthValue = speed * percentage / 100
			}

			allocatedBandwidth += bandwidthValue
		}
	}

	// Calculate available bandwidth
	availableBandwidth := speed - allocatedBandwidth
	if availableBandwidth < 0 {
		availableBandwidth = 0
	}

	// Convert to string
	if availableBandwidth >= 1000000 {
		return fmt.Sprintf("%dGbit", availableBandwidth/1000000), nil
	} else if availableBandwidth >= 1000 {
		return fmt.Sprintf("%dMbit", availableBandwidth/1000), nil
	} else {
		return fmt.Sprintf("%dKbit", availableBandwidth), nil
	}
}

// applyAllocation applies a bandwidth allocation to a class
func (b *bandwidthAllocator) applyAllocation(interfaceName, className string, minBandwidth, maxBandwidth string) error {
	// In a real implementation, we would apply the allocation to the system
	// For now, we'll just log it
	klog.Infof("Applied bandwidth allocation for class %s on interface %s: min=%s, max=%s", className, interfaceName, minBandwidth, maxBandwidth)
	return nil
}

// removeAllocation removes a bandwidth allocation from a class
func (b *bandwidthAllocator) removeAllocation(interfaceName, className string) error {
	// In a real implementation, we would remove the allocation from the system
	// For now, we'll just log it
	klog.Infof("Removed bandwidth allocation for class %s on interface %s", className, interfaceName)
	return nil
}
