//go:build linux

package ebpf

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// XDPStats holds statistics collected from XDP program maps.
type XDPStats struct {
	BlacklistSize    int
	RateLimitEntries int
	FlowCount        int
	IPv6FlowCount    int
	CollectedAt      time.Time
}

// TCStats holds statistics collected from TC program maps.
type TCStats struct {
	FlowCount   int
	CollectedAt time.Time
}

// ProgramStats holds aggregated statistics for a loaded eBPF program.
type ProgramStats struct {
	ProgramName string
	XDP         *XDPStats
	TC          *TCStats
	CollectedAt time.Time
}

// StatsCollector periodically reads eBPF map statistics.
type StatsCollector struct {
	mapOps   *TypedMapOps
	interval time.Duration
	stats    map[string]*ProgramStats
	mu       sync.RWMutex
}

// NewStatsCollector creates a new statistics collector.
func NewStatsCollector(mapOps *TypedMapOps, interval time.Duration) *StatsCollector {
	if interval == 0 {
		interval = 10 * time.Second
	}
	return &StatsCollector{
		mapOps:   mapOps,
		interval: interval,
		stats:    make(map[string]*ProgramStats),
	}
}

// CollectXDPStats reads statistics from XDP program maps.
func (c *StatsCollector) CollectXDPStats(programName string) (*XDPStats, error) {
	stats := &XDPStats{
		CollectedAt: time.Now(),
	}

	// Count blacklist entries
	if blStats, err := c.mapOps.GetMapStats("ipv4_blacklist"); err == nil {
		stats.BlacklistSize = int(blStats.MaxEntries) // approximate; iterate for exact
	}

	// Count rate limit entries
	if rlStats, err := c.mapOps.GetRateLimitStats(); err == nil {
		stats.RateLimitEntries = len(rlStats)
	}

	// Count active flows
	if flowCount, err := c.mapOps.GetFlowCount(); err == nil {
		stats.FlowCount = flowCount
	}

	// Count IPv6 flows
	if v6Count, err := c.mapOps.GetIPv6FlowCount(); err == nil {
		stats.IPv6FlowCount = v6Count
	}

	c.mu.Lock()
	if _, exists := c.stats[programName]; !exists {
		c.stats[programName] = &ProgramStats{ProgramName: programName}
	}
	c.stats[programName].XDP = stats
	c.stats[programName].CollectedAt = time.Now()
	c.mu.Unlock()

	klog.V(5).Infof("Collected XDP stats for %s: blacklist=%d ratelimit=%d flows=%d",
		programName, stats.BlacklistSize, stats.RateLimitEntries, stats.FlowCount)

	return stats, nil
}

// CollectTCStats reads statistics from TC program maps.
func (c *StatsCollector) CollectTCStats(programName string) (*TCStats, error) {
	stats := &TCStats{
		CollectedAt: time.Now(),
	}

	if flowCount, err := c.mapOps.GetFlowCount(); err == nil {
		stats.FlowCount = flowCount
	}

	c.mu.Lock()
	if _, exists := c.stats[programName]; !exists {
		c.stats[programName] = &ProgramStats{ProgramName: programName}
	}
	c.stats[programName].TC = stats
	c.stats[programName].CollectedAt = time.Now()
	c.mu.Unlock()

	return stats, nil
}

// GetStats returns the most recent stats for a program.
func (c *StatsCollector) GetStats(programName string) (*ProgramStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	s, ok := c.stats[programName]
	if !ok {
		return nil, fmt.Errorf("no stats for program %s", programName)
	}
	return s, nil
}

// GetAllStats returns stats for all programs.
func (c *StatsCollector) GetAllStats() map[string]*ProgramStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]*ProgramStats, len(c.stats))
	for k, v := range c.stats {
		result[k] = v
	}
	return result
}
