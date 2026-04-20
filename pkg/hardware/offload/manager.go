//go:build linux

// Package offload provides functionality for managing hardware offloading features.
package offload

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"

	"github.com/safchain/ethtool"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

var ErrOffloadStatisticsNotSupported = errors.New("offload statistics not supported")

type ethtoolClient interface {
	Features(string) (map[string]bool, error)
	Change(string, map[string]bool) error
	Stats(string) (map[string]uint64, error)
	Close()
}

// Manager implements the types.OffloadManager interface.
type Manager struct {
	ethtool        ethtoolClient
	capabilities   map[string]*types.OffloadCapabilities
	capabilitiesMu sync.RWMutex
}

type offloadStatDescriptor struct {
	field   string
	aliases []string
	assign  func(*types.OffloadStatistics, uint64)
}

var offloadStatDescriptors = []offloadStatDescriptor{
	{
		field:   "TxChecksumIPv4",
		aliases: []string{"tx_checksum_ipv4", "tx_ipv4_checksum", "tx_ip4_csum", "tx_ip4_csum_offload", "tx_tcp4_csum_offload", "tx_tcp_v4_csum", "tx_csum_ip4"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.TxChecksumIPv4 = value
		},
	},
	{
		field:   "TxChecksumIPv6",
		aliases: []string{"tx_checksum_ipv6", "tx_ipv6_checksum", "tx_ip6_csum", "tx_ip6_csum_offload", "tx_tcp6_csum_offload", "tx_tcp_v6_csum", "tx_csum_ip6"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.TxChecksumIPv6 = value
		},
	},
	{
		field:   "TxChecksumTCP",
		aliases: []string{"tx_checksum_tcp", "tx_tcp_checksum", "tx_tcp_csum", "tx_tcp_csum_offload", "tx_csum_tcp", "tx_tcp_checksum_offload"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.TxChecksumTCP = value
		},
	},
	{
		field:   "TxChecksumUDP",
		aliases: []string{"tx_checksum_udp", "tx_udp_checksum", "tx_udp_csum", "tx_udp_csum_offload", "tx_csum_udp", "tx_udp_checksum_offload"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.TxChecksumUDP = value
		},
	},
	{
		field:   "RxChecksumIPv4",
		aliases: []string{"rx_checksum_ipv4", "rx_ipv4_checksum", "rx_ip4_csum", "rx_ip4_csum_offload", "rx_tcp4_csum_offload", "rx_tcp_v4_csum", "rx_csum_ip4"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.RxChecksumIPv4 = value
		},
	},
	{
		field:   "RxChecksumIPv6",
		aliases: []string{"rx_checksum_ipv6", "rx_ipv6_checksum", "rx_ip6_csum", "rx_ip6_csum_offload", "rx_tcp6_csum_offload", "rx_tcp_v6_csum", "rx_csum_ip6"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.RxChecksumIPv6 = value
		},
	},
	{
		field:   "RxChecksumTCP",
		aliases: []string{"rx_checksum_tcp", "rx_tcp_checksum", "rx_tcp_csum", "rx_tcp_csum_offload", "rx_csum_tcp", "rx_tcp_checksum_offload"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.RxChecksumTCP = value
		},
	},
	{
		field:   "RxChecksumUDP",
		aliases: []string{"rx_checksum_udp", "rx_udp_checksum", "rx_udp_csum", "rx_udp_csum_offload", "rx_csum_udp", "rx_udp_checksum_offload"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.RxChecksumUDP = value
		},
	},
	{
		field:   "TxTCPSegmentation",
		aliases: []string{"tx_tcp_segmentation", "tx_tcp_seg_good", "tx_tcp_seg_offload", "tx_tso_packets", "tso_packets", "tx_tso", "tso_offload_packets"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.TxTCPSegmentation = value
		},
	},
	{
		field:   "TxUDPFragmentation",
		aliases: []string{"tx_udp_fragmentation", "tx_udp_segmentation", "tx_udp_fragments", "tx_udp_seg_packets", "udp_tso_packets", "tx_udp_tso_packets", "tx_udp_seg_offload"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.TxUDPFragmentation = value
		},
	},
	{
		field:   "RxGRO",
		aliases: []string{"rx_gro", "rx_gro_packets", "gro_packets", "gro_pkts", "gro_aggregated", "rx_gro_pkts"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.RxGRO = value
		},
	},
	{
		field:   "RxLRO",
		aliases: []string{"rx_lro", "rx_lro_packets", "lro_packets", "lro_pkts", "lro_aggregated", "rx_lro_pkts"},
		assign: func(stats *types.OffloadStatistics, value uint64) {
			stats.RxLRO = value
		},
	},
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
	if len(changes) > 0 {
		if err := m.ethtool.Change(ifName, changes); err != nil {
			return fmt.Errorf("failed to change offload features: %w", err)
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
	_, capabilities.TxChecksumTCP = featureMap["tx-checksumming"]
	_, capabilities.RxChecksumTCP = featureMap["rx-checksumming"]
	_, capabilities.TxTCPSegmentation = featureMap["tcp-segmentation-offload"]
	_, capabilities.TxUDPFragmentation = featureMap["generic-segmentation-offload"]
	_, capabilities.RxGRO = featureMap["generic-receive-offload"]
	_, capabilities.RxLRO = featureMap["large-receive-offload"]
	_, capabilities.NTuple = featureMap["rx-flow-hash-filter"]
	_, capabilities.RSSHash = featureMap["receive-flow-steering"]

	// Cache capabilities
	m.capabilitiesMu.Lock()
	m.capabilities[ifName] = capabilities
	m.capabilitiesMu.Unlock()

	return capabilities, nil
}

// SetOffloadFeature enables or disables an offload feature for an interface.
func (m *Manager) SetOffloadFeature(name string, feature string, enabled bool) error {
	changes := map[string]bool{feature: enabled}
	if err := m.ethtool.Change(name, changes); err != nil {
		return fmt.Errorf("failed to set feature %s to %v on %s: %w", feature, enabled, name, err)
	}
	// Invalidate cached capabilities
	m.capabilitiesMu.Lock()
	delete(m.capabilities, name)
	m.capabilitiesMu.Unlock()
	return nil
}

// GetOffloadStatistics gets statistics for offloaded operations on an interface.
func (m *Manager) GetOffloadStatistics(name string) (*types.OffloadStatistics, error) {
	rawStats, err := m.ethtool.Stats(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get offload statistics: %w", err)
	}

	normalizedStats := normalizeOffloadStats(rawStats)
	stats := &types.OffloadStatistics{
		Interface: name,
	}

	matchedCounters := 0
	unsupportedCounters := make([]string, 0, len(offloadStatDescriptors))

	for _, descriptor := range offloadStatDescriptors {
		value, ok := findOffloadStatValue(normalizedStats, descriptor.aliases)
		if !ok {
			unsupportedCounters = append(unsupportedCounters, descriptor.field)
			continue
		}

		descriptor.assign(stats, value)
		matchedCounters++
	}

	if matchedCounters == 0 {
		return nil, fmt.Errorf("%w for interface %s", ErrOffloadStatisticsNotSupported, name)
	}

	stats.UnsupportedCounters = unsupportedCounters

	return stats, nil
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
		"tx-checksumming":              true,  // Enable TX checksum offloading
		"rx-checksumming":              true,  // Enable RX checksum offloading
		"tcp-segmentation-offload":     true,  // Enable TCP segmentation offloading
		"generic-segmentation-offload": true,  // Enable generic segmentation offloading
		"generic-receive-offload":      true,  // Enable generic receive offloading
		"large-receive-offload":        false, // Disable large receive offloading (can cause issues)
		"rx-packet-steering":           true,  // Enable RX packet steering
		"tx-packet-steering":           true,  // Enable TX packet steering
		"rx-flow-hash-filter":          false, // Disable NTUPLE filtering (complex to configure)
		"receive-flow-steering":        false, // Disable RFS (complex to configure)
	}

	// Apply defaults where features exist
	changes := make(map[string]bool)
	for feature, defaultValue := range defaults {
		if _, ok := featureMap[feature]; ok {
			changes[feature] = defaultValue
		}
	}
	if len(changes) > 0 {
		if err := m.ethtool.Change(ifName, changes); err != nil {
			return fmt.Errorf("failed to reset offload features: %w", err)
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
		TxChecksum: capabilities.TxChecksumTCP,
		RxChecksum: capabilities.RxChecksumTCP,
		TSO:        capabilities.TxTCPSegmentation,
		GSO:        capabilities.TxUDPFragmentation,
		GRO:        capabilities.RxGRO,
		// LRO is often not recommended due to potential issues with packet reordering
		LRO: false,
		RPS: false,
		XPS: false,
		// NTUPLE and RFS are more advanced and may require specific configuration
		NTUPLE: false,
		RFS:    false,
	}

	return features, nil
}

func normalizeOffloadStats(rawStats map[string]uint64) map[string]uint64 {
	normalized := make(map[string]uint64, len(rawStats))
	for name, value := range rawStats {
		normalized[normalizeOffloadStatName(name)] = value
	}

	return normalized
}

func findOffloadStatValue(rawStats map[string]uint64, aliases []string) (uint64, bool) {
	for _, alias := range aliases {
		value, ok := rawStats[normalizeOffloadStatName(alias)]
		if ok {
			return value, true
		}
	}

	return 0, false
}

func normalizeOffloadStatName(name string) string {
	var builder strings.Builder
	builder.Grow(len(name))

	lastUnderscore := false
	for _, r := range name {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(unicode.ToLower(r))
			lastUnderscore = false
		case !lastUnderscore:
			builder.WriteByte('_')
			lastUnderscore = true
		}
	}

	return strings.Trim(builder.String(), "_")
}
