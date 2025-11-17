package vlan

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

// StatsCollector handles statistics collection for VLAN interfaces
type StatsCollector struct{}

// NewStatsCollector creates a new statistics collector
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{}
}

// CollectStats collects statistics for a network interface
func (s *StatsCollector) CollectStats(link netlink.Link) VLANStats {
	stats := VLANStats{
		LastUpdated: time.Now().Unix(),
	}

	// Try to get statistics from netlink first (most reliable)
	if linkStats := link.Attrs().Statistics; linkStats != nil {
		stats.RxPackets = linkStats.RxPackets
		stats.TxPackets = linkStats.TxPackets
		stats.RxBytes = linkStats.RxBytes
		stats.TxBytes = linkStats.TxBytes
		stats.RxErrors = linkStats.RxErrors
		stats.TxErrors = linkStats.TxErrors
		stats.RxDropped = linkStats.RxDropped
		stats.TxDropped = linkStats.TxDropped
		return stats
	}

	// Fallback to reading from sysfs if netlink stats not available
	ifname := link.Attrs().Name
	sysfsStats, err := s.readSysfsStats(ifname)
	if err != nil {
		klog.V(4).Infof("Failed to read sysfs stats for %s: %v", ifname, err)
		return stats
	}

	return sysfsStats
}

// readSysfsStats reads statistics from /sys/class/net/<ifname>/statistics/
func (s *StatsCollector) readSysfsStats(ifname string) (VLANStats, error) {
	stats := VLANStats{
		LastUpdated: time.Now().Unix(),
	}

	basePath := filepath.Join("/sys/class/net", ifname, "statistics")

	// Check if directory exists
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		return stats, fmt.Errorf("statistics directory not found for interface %s", ifname)
	}

	// Read each statistic file
	var err error

	stats.RxPackets, err = s.readStat(basePath, "rx_packets")
	if err != nil {
		klog.V(4).Infof("Failed to read rx_packets for %s: %v", ifname, err)
	}

	stats.TxPackets, err = s.readStat(basePath, "tx_packets")
	if err != nil {
		klog.V(4).Infof("Failed to read tx_packets for %s: %v", ifname, err)
	}

	stats.RxBytes, err = s.readStat(basePath, "rx_bytes")
	if err != nil {
		klog.V(4).Infof("Failed to read rx_bytes for %s: %v", ifname, err)
	}

	stats.TxBytes, err = s.readStat(basePath, "tx_bytes")
	if err != nil {
		klog.V(4).Infof("Failed to read tx_bytes for %s: %v", ifname, err)
	}

	stats.RxErrors, err = s.readStat(basePath, "rx_errors")
	if err != nil {
		klog.V(4).Infof("Failed to read rx_errors for %s: %v", ifname, err)
	}

	stats.TxErrors, err = s.readStat(basePath, "tx_errors")
	if err != nil {
		klog.V(4).Infof("Failed to read tx_errors for %s: %v", ifname, err)
	}

	stats.RxDropped, err = s.readStat(basePath, "rx_dropped")
	if err != nil {
		klog.V(4).Infof("Failed to read rx_dropped for %s: %v", ifname, err)
	}

	stats.TxDropped, err = s.readStat(basePath, "tx_dropped")
	if err != nil {
		klog.V(4).Infof("Failed to read tx_dropped for %s: %v", ifname, err)
	}

	return stats, nil
}

// readStat reads a single statistic file from sysfs
func (s *StatsCollector) readStat(basePath, statName string) (uint64, error) {
	filePath := filepath.Join(basePath, statName)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	// Parse the value
	valueStr := strings.TrimSpace(string(data))
	value, err := strconv.ParseUint(valueStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse value %s: %w", valueStr, err)
	}

	return value, nil
}

// GetDetailedStats retrieves detailed statistics including error breakdowns
func (s *StatsCollector) GetDetailedStats(ifname string) (*DetailedStats, error) {
	basePath := filepath.Join("/sys/class/net", ifname, "statistics")

	// Check if directory exists
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("statistics directory not found for interface %s", ifname)
	}

	detailed := &DetailedStats{
		BasicStats: VLANStats{
			LastUpdated: time.Now().Unix(),
		},
	}

	// Read basic stats
	var err error
	detailed.BasicStats.RxPackets, _ = s.readStat(basePath, "rx_packets")
	detailed.BasicStats.TxPackets, _ = s.readStat(basePath, "tx_packets")
	detailed.BasicStats.RxBytes, _ = s.readStat(basePath, "rx_bytes")
	detailed.BasicStats.TxBytes, _ = s.readStat(basePath, "tx_bytes")
	detailed.BasicStats.RxErrors, _ = s.readStat(basePath, "rx_errors")
	detailed.BasicStats.TxErrors, _ = s.readStat(basePath, "tx_errors")
	detailed.BasicStats.RxDropped, _ = s.readStat(basePath, "rx_dropped")
	detailed.BasicStats.TxDropped, _ = s.readStat(basePath, "tx_dropped")

	// Read detailed error stats
	detailed.RxCRCErrors, err = s.readStat(basePath, "rx_crc_errors")
	if err != nil {
		klog.V(4).Infof("rx_crc_errors not available for %s", ifname)
	}

	detailed.RxFrameErrors, err = s.readStat(basePath, "rx_frame_errors")
	if err != nil {
		klog.V(4).Infof("rx_frame_errors not available for %s", ifname)
	}

	detailed.RxFIFOErrors, err = s.readStat(basePath, "rx_fifo_errors")
	if err != nil {
		klog.V(4).Infof("rx_fifo_errors not available for %s", ifname)
	}

	detailed.RxMissedErrors, err = s.readStat(basePath, "rx_missed_errors")
	if err != nil {
		klog.V(4).Infof("rx_missed_errors not available for %s", ifname)
	}

	detailed.TxAbortedErrors, err = s.readStat(basePath, "tx_aborted_errors")
	if err != nil {
		klog.V(4).Infof("tx_aborted_errors not available for %s", ifname)
	}

	detailed.TxCarrierErrors, err = s.readStat(basePath, "tx_carrier_errors")
	if err != nil {
		klog.V(4).Infof("tx_carrier_errors not available for %s", ifname)
	}

	detailed.TxFIFOErrors, err = s.readStat(basePath, "tx_fifo_errors")
	if err != nil {
		klog.V(4).Infof("tx_fifo_errors not available for %s", ifname)
	}

	detailed.Collisions, err = s.readStat(basePath, "collisions")
	if err != nil {
		klog.V(4).Infof("collisions not available for %s", ifname)
	}

	// Read multicast stats
	detailed.Multicast, err = s.readStat(basePath, "multicast")
	if err != nil {
		klog.V(4).Infof("multicast not available for %s", ifname)
	}

	return detailed, nil
}

// DetailedStats contains detailed interface statistics
type DetailedStats struct {
	BasicStats       VLANStats
	RxCRCErrors      uint64
	RxFrameErrors    uint64
	RxFIFOErrors     uint64
	RxMissedErrors   uint64
	TxAbortedErrors  uint64
	TxCarrierErrors  uint64
	TxFIFOErrors     uint64
	Collisions       uint64
	Multicast        uint64
}

// MonitorStats continuously monitors interface statistics
func (s *StatsCollector) MonitorStats(ifname string, interval time.Duration, callback func(VLANStats)) chan struct{} {
	stopCh := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				link, err := netlink.LinkByName(ifname)
				if err != nil {
					klog.V(4).Infof("Failed to get link %s for stats monitoring: %v", ifname, err)
					continue
				}

				stats := s.CollectStats(link)
				callback(stats)

			case <-stopCh:
				return
			}
		}
	}()

	return stopCh
}
