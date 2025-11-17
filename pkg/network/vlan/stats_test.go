package vlan

import (
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// TestStatsCollectorCreation tests stats collector creation
func TestStatsCollectorCreation(t *testing.T) {
	collector := NewStatsCollector()
	if collector == nil {
		t.Fatal("Failed to create stats collector")
	}
}

// TestCollectStats tests statistics collection
func TestCollectStats(t *testing.T) {
	collector := NewStatsCollector()

	// Create a dummy link for testing
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:  "test-stats",
			Index: 100,
			Statistics: &netlink.LinkStatistics{
				RxPackets: 1000,
				TxPackets: 2000,
				RxBytes:   50000,
				TxBytes:   100000,
				RxErrors:  10,
				TxErrors:  5,
				RxDropped: 2,
				TxDropped: 1,
			},
		},
	}

	stats := collector.CollectStats(link)

	// Verify statistics were collected
	if stats.RxPackets != 1000 {
		t.Errorf("Expected RxPackets 1000, got %d", stats.RxPackets)
	}

	if stats.TxPackets != 2000 {
		t.Errorf("Expected TxPackets 2000, got %d", stats.TxPackets)
	}

	if stats.RxBytes != 50000 {
		t.Errorf("Expected RxBytes 50000, got %d", stats.RxBytes)
	}

	if stats.TxBytes != 100000 {
		t.Errorf("Expected TxBytes 100000, got %d", stats.TxBytes)
	}

	if stats.RxErrors != 10 {
		t.Errorf("Expected RxErrors 10, got %d", stats.RxErrors)
	}

	if stats.TxErrors != 5 {
		t.Errorf("Expected TxErrors 5, got %d", stats.TxErrors)
	}

	if stats.RxDropped != 2 {
		t.Errorf("Expected RxDropped 2, got %d", stats.RxDropped)
	}

	if stats.TxDropped != 1 {
		t.Errorf("Expected TxDropped 1, got %d", stats.TxDropped)
	}

	// Verify timestamp is recent
	now := time.Now().Unix()
	if stats.LastUpdated < now-10 || stats.LastUpdated > now+10 {
		t.Errorf("Expected recent timestamp, got %d (now: %d)", stats.LastUpdated, now)
	}
}

// TestCollectStatsNoStatistics tests stats collection when no statistics available
func TestCollectStatsNoStatistics(t *testing.T) {
	collector := NewStatsCollector()

	// Create a dummy link without statistics
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:  "test-nostats",
			Index: 101,
		},
	}

	stats := collector.CollectStats(link)

	// Should return empty stats with current timestamp
	if stats.RxPackets != 0 {
		t.Errorf("Expected RxPackets 0, got %d", stats.RxPackets)
	}

	if stats.TxPackets != 0 {
		t.Errorf("Expected TxPackets 0, got %d", stats.TxPackets)
	}

	// Timestamp should still be set
	if stats.LastUpdated == 0 {
		t.Error("Expected LastUpdated to be set")
	}
}

// TestVLANStatsStructure tests the VLAN stats structure
func TestVLANStatsStructure(t *testing.T) {
	stats := VLANStats{
		RxPackets:   100,
		TxPackets:   200,
		RxBytes:     10000,
		TxBytes:     20000,
		RxErrors:    1,
		TxErrors:    2,
		RxDropped:   0,
		TxDropped:   0,
		LastUpdated: time.Now().Unix(),
	}

	// Verify all fields are accessible
	if stats.RxPackets == 0 {
		t.Error("RxPackets should not be zero")
	}

	if stats.TxPackets == 0 {
		t.Error("TxPackets should not be zero")
	}

	if stats.LastUpdated == 0 {
		t.Error("LastUpdated should not be zero")
	}
}

// TestDetailedStatsStructure tests the detailed stats structure
func TestDetailedStatsStructure(t *testing.T) {
	detailed := DetailedStats{
		BasicStats: VLANStats{
			RxPackets:   1000,
			TxPackets:   2000,
			RxBytes:     50000,
			TxBytes:     100000,
			LastUpdated: time.Now().Unix(),
		},
		RxCRCErrors:     5,
		RxFrameErrors:   3,
		RxFIFOErrors:    1,
		RxMissedErrors:  2,
		TxAbortedErrors: 0,
		TxCarrierErrors: 1,
		TxFIFOErrors:    0,
		Collisions:      10,
		Multicast:       50,
	}

	// Verify basic stats
	if detailed.BasicStats.RxPackets != 1000 {
		t.Errorf("Expected RxPackets 1000, got %d", detailed.BasicStats.RxPackets)
	}

	// Verify detailed error stats
	if detailed.RxCRCErrors != 5 {
		t.Errorf("Expected RxCRCErrors 5, got %d", detailed.RxCRCErrors)
	}

	if detailed.Collisions != 10 {
		t.Errorf("Expected Collisions 10, got %d", detailed.Collisions)
	}

	if detailed.Multicast != 50 {
		t.Errorf("Expected Multicast 50, got %d", detailed.Multicast)
	}
}

// TestStatsMonitoring tests statistics monitoring
func TestStatsMonitoring(t *testing.T) {
	// This test is limited because we can't create real interfaces
	// We just verify the monitoring goroutine can be started and stopped

	collector := NewStatsCollector()

	callbackCount := 0
	callback := func(stats VLANStats) {
		callbackCount++
	}

	// Note: This will fail if interface doesn't exist, which is expected in unit tests
	// In integration tests with real interfaces, this would work
	stopCh := collector.MonitorStats("nonexistent", 100*time.Millisecond, callback)

	// Stop the monitoring
	close(stopCh)

	// Give it time to stop
	time.Sleep(200 * time.Millisecond)

	// In a real environment with actual interfaces, we would verify callbackCount > 0
	// For unit tests, we just verify the mechanism doesn't panic
}

// TestStatsComparison tests comparing statistics over time
func TestStatsComparison(t *testing.T) {
	stats1 := VLANStats{
		RxPackets:   1000,
		TxPackets:   2000,
		RxBytes:     50000,
		TxBytes:     100000,
		LastUpdated: time.Now().Unix(),
	}

	// Simulate stats after some time
	time.Sleep(10 * time.Millisecond)

	stats2 := VLANStats{
		RxPackets:   1100,
		TxPackets:   2200,
		RxBytes:     55000,
		TxBytes:     110000,
		LastUpdated: time.Now().Unix(),
	}

	// Calculate deltas
	deltaRxPackets := stats2.RxPackets - stats1.RxPackets
	deltaTxPackets := stats2.TxPackets - stats1.TxPackets
	deltaRxBytes := stats2.RxBytes - stats1.RxBytes
	deltaTxBytes := stats2.TxBytes - stats1.TxBytes

	if deltaRxPackets != 100 {
		t.Errorf("Expected delta RxPackets 100, got %d", deltaRxPackets)
	}

	if deltaTxPackets != 200 {
		t.Errorf("Expected delta TxPackets 200, got %d", deltaTxPackets)
	}

	if deltaRxBytes != 5000 {
		t.Errorf("Expected delta RxBytes 5000, got %d", deltaRxBytes)
	}

	if deltaTxBytes != 10000 {
		t.Errorf("Expected delta TxBytes 10000, got %d", deltaTxBytes)
	}

	// Calculate rate (bytes per second)
	timeDelta := stats2.LastUpdated - stats1.LastUpdated
	if timeDelta > 0 {
		rxRate := float64(deltaRxBytes) / float64(timeDelta)
		txRate := float64(deltaTxBytes) / float64(timeDelta)

		t.Logf("RX rate: %.2f bytes/sec", rxRate)
		t.Logf("TX rate: %.2f bytes/sec", txRate)
	}
}

// TestStatsErrorRates tests calculating error rates
func TestStatsErrorRates(t *testing.T) {
	stats := VLANStats{
		RxPackets: 10000,
		TxPackets: 20000,
		RxErrors:  100,
		TxErrors:  50,
		RxDropped: 20,
		TxDropped: 10,
	}

	// Calculate error rates
	rxErrorRate := float64(stats.RxErrors) / float64(stats.RxPackets) * 100
	txErrorRate := float64(stats.TxErrors) / float64(stats.TxPackets) * 100

	if rxErrorRate != 1.0 {
		t.Errorf("Expected RX error rate 1.0%%, got %.2f%%", rxErrorRate)
	}

	if txErrorRate != 0.25 {
		t.Errorf("Expected TX error rate 0.25%%, got %.2f%%", txErrorRate)
	}

	// Calculate drop rates
	rxDropRate := float64(stats.RxDropped) / float64(stats.RxPackets) * 100
	txDropRate := float64(stats.TxDropped) / float64(stats.TxPackets) * 100

	if rxDropRate != 0.2 {
		t.Errorf("Expected RX drop rate 0.2%%, got %.2f%%", rxDropRate)
	}

	if txDropRate != 0.05 {
		t.Errorf("Expected TX drop rate 0.05%%, got %.2f%%", txDropRate)
	}
}

// TestZeroStats tests handling of zero statistics
func TestZeroStats(t *testing.T) {
	stats := VLANStats{}

	// Verify all fields are zero
	if stats.RxPackets != 0 {
		t.Error("RxPackets should be zero")
	}

	if stats.TxPackets != 0 {
		t.Error("TxPackets should be zero")
	}

	if stats.RxBytes != 0 {
		t.Error("RxBytes should be zero")
	}

	if stats.TxBytes != 0 {
		t.Error("TxBytes should be zero")
	}

	// Should be safe to calculate rates with zero packets
	if stats.RxPackets == 0 {
		// Don't divide by zero
		t.Log("Cannot calculate error rate with zero packets (expected)")
	}
}

// TestStatsOverflow tests handling of counter overflow
func TestStatsOverflow(t *testing.T) {
	// Simulate counter approaching max uint64
	stats1 := VLANStats{
		RxPackets: ^uint64(0) - 100, // Near max uint64
		RxBytes:   ^uint64(0) - 1000,
	}

	stats2 := VLANStats{
		RxPackets: 50, // Wrapped around
		RxBytes:   500,
	}

	// In real monitoring, you'd detect overflow and handle it
	// Here we just verify the values can be stored
	if stats1.RxPackets <= stats2.RxPackets {
		t.Log("Counter overflow detected (expected in this test)")
	}
}
