// Package offload provides functionality for managing hardware offloading features.
package offload

import (
	"context"
	"fmt"
	"sync"

	"github.com/safchain/ethtool"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// Manager implements the types.OffloadManager interface.
type Manager struct {
	ethtool        *ethtool.Ethtool
	capabilities   map[string]*types.OffloadCapabilities
	capabilitiesMu sync.RWMutex
}

// NewManager creates a new Offload Manager.
func NewManager() (*Manager, error) {
	ethtoolHandler, err := ethtool.NewEthtool()
	if err != nil {
		return nil, fmt.Errorf("failed to create ethtool handler: %w", err)
	}

	return &Manager{
		ethtool:      ethtoolHandler,
		capabilities: make(map[string]*types.OffloadCapabilities),
	}, nil
}

// Initialize initializes the Offload Manager.
func (m *Manager) Initialize(ctx context.Context) error {
	return nil
}

// Shutdown shuts down the Offload Manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	if m.ethtool != nil {
		m.ethtool.Close()
	}

	return nil
}

// ConfigureOffload configures hardware offloading features for an interface.
func (m *Manager) ConfigureOffload(ifName string, features types.OffloadFeatures) error {
	// Get current features
	featureMap, err := m.ethtool.Features(ifName)
	if err != nil {
		return fmt.Errorf("failed to get feature states: %w", err)
	}

	// Prepare features to change
	changes := make(map[string]bool)

	// Map our OffloadFeatures struct to ethtool features
	// Note: The exact mapping will depend on the actual feature names which can vary by driver
	if val, ok := featureMap["tx-checksumming"]; ok && val != features.TxChecksum {
		changes["tx-checksumming"] = features.TxChecksum
	}
	if val, ok := featureMap["rx-checksumming"]; ok && val != features.RxChecksum {
		changes["rx-checksumming"] = features.RxChecksum
	}
	if val, ok := featureMap["tcp-segmentation-offload"]; ok && val != features.TSO {
		changes["tcp-segmentation-offload"] = features.TSO
	}
	if val, ok := featureMap["generic-segmentation-offload"]; ok && val != features.GSO {
		changes["generic-segmentation-offload"] = features.GSO
	}
	if val, ok := featureMap["generic-receive-offload"]; ok && val != features.GRO {
		changes["generic-receive-offload"] = features.GRO
	}
	if val, ok := featureMap["large-receive-offload"]; ok && val != features.LRO {
		changes["large-receive-offload"] = features.LRO
	}
	if val, ok := featureMap["rx-packet-steering"]; ok && val != features.RPS {
		changes["rx-packet-steering"] = features.RPS
	}
	if val, ok := featureMap["tx-packet-steering"]; ok && val != features.XPS {
		changes["tx-packet-steering"] = features.XPS
	}
	if val, ok := featureMap["rx-flow-hash-filter"]; ok && val != features.NTUPLE {
		changes["rx-flow-hash-filter"] = features.NTUPLE
	}
	if val, ok := featureMap["receive-flow-steering"]; ok && val != features.RFS {
		changes["receive-flow-steering"] = features.RFS
	}

	// Apply changes
	for feature, enabled := range changes {
		if err := m.ethtool.Change(ifName, feature, enabled); err != nil {
			return fmt.Errorf("failed to change feature %s to %v: %w", feature, enabled, err)
		}
	}

	return nil
}

// GetOffloadCapabilities gets the offload capabilities of an interface.
func (m *Manager) GetOffloadCapabilities(ifName string) (*types.OffloadCapabilities, error) {
	// Check if capabilities are already cached
	m.capabilitiesMu.RLock()
	capabilities, ok := m.capabilities[ifName]
	m.capabilitiesMu.RUnlock()

	if ok {
		return capabilities, nil
	}

	// Get features
	featureMap, err := m.ethtool.Features(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to get features: %w", err)
	}

	// Create new capabilities
	capabilities = &types.OffloadCapabilities{}

	// Determine which features are supported by checking if they exist in the feature map
	// Note: This only checks if the feature exists, not if it can be enabled/disabled
	_, capabilities.SupportsTxChecksum = featureMap["tx-checksumming"]
	_, capabilities.SupportsRxChecksum = featureMap["rx-checksumming"]
	_, capabilities.SupportsTSO = featureMap["tcp-segmentation-offload"]
	_, capabilities.SupportsGSO = featureMap["generic-segmentation-offload"]
	_, capabilities.SupportsGRO = featureMap["generic-receive-offload"]
	_, capabilities.SupportsLRO = featureMap["large-receive-offload"]
	_, capabilities.SupportsRPS = featureMap["rx-packet-steering"]
	_, capabilities.SupportsXPS = featureMap["tx-packet-steering"]
	_, capabilities.SupportsNTUPLE = featureMap["rx-flow-hash-filter"]
	_, capabilities.SupportsRFS = featureMap["receive-flow-steering"]

	// Cache capabilities
	m.capabilitiesMu.Lock()
	m.capabilities[ifName] = capabilities
	m.capabilitiesMu.Unlock()

	return capabilities, nil
}

// ResetOffload resets all hardware offloading features for an interface to their default values.
func (m *Manager) ResetOffload(ifName string) error {
	// Get current features
	featureMap, err := m.ethtool.Features(ifName)
	if err != nil {
		return fmt.Errorf("failed to get feature states: %w", err)
	}

	// Default hardware offloading configuration
	// These defaults are conservative for better compatibility
	defaults := map[string]bool{
		"tx-checksumming":           true,  // Enable TX checksum offloading
		"rx-checksumming":           true,  // Enable RX checksum offloading
		"tcp-segmentation-offload":  true,  // Enable TCP segmentation offloading
		"generic-segmentation-offload": true,  // Enable generic segmentation offloading
		"generic-receive-offload":   true,  // Enable generic receive offloading
		"large-receive-offload":     false, // Disable large receive offloading (can cause issues)
		"rx-packet-steering":        true,  // Enable RX packet steering
		"tx-packet-steering":        true,  // Enable TX packet steering
		"rx-flow-hash-filter":       false, // Disable NTUPLE filtering (complex to configure)
		"receive-flow-steering":     false, // Disable RFS (complex to configure)
	}

	// Apply defaults where features exist
	for feature, defaultValue := range defaults {
		if _, ok := featureMap[feature]; ok {
			if err := m.ethtool.Change(ifName, feature, defaultValue); err != nil {
				return fmt.Errorf("failed to reset feature %s to %v: %w", feature, defaultValue, err)
			}
		}
	}

	return nil
}

// GetSupportedOffloadFeatures gets a list of supported offload features for an interface.
func (m *Manager) GetSupportedOffloadFeatures(ifName string) (map[string]bool, error) {
	// Get features
	featureMap, err := m.ethtool.Features(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to get features: %w", err)
	}

	return featureMap, nil
}

// GetOptimalOffloadConfiguration gets the optimal offload configuration for an interface based on its capabilities.
func (m *Manager) GetOptimalOffloadConfiguration(ifName string) (types.OffloadFeatures, error) {
	// Get capabilities
	capabilities, err := m.GetOffloadCapabilities(ifName)
	if err != nil {
		return types.OffloadFeatures{}, fmt.Errorf("failed to get capabilities: %w", err)
	}

	// Create optimal configuration based on capabilities
	features := types.OffloadFeatures{
		TxChecksum: capabilities.SupportsTxChecksum,
		RxChecksum: capabilities.SupportsRxChecksum,
		TSO:        capabilities.SupportsTSO,
		GSO:        capabilities.SupportsGSO,
		GRO:        capabilities.SupportsGRO,
		// LRO is often not recommended due to potential issues with packet reordering
		LRO:        false,
		RPS:        capabilities.SupportsRPS,
		XPS:        capabilities.SupportsXPS,
		// NTUPLE and RFS are more advanced and may require specific configuration
		NTUPLE:     false,
		RFS:        false,
	}

	return features, nil
}
