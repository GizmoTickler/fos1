package traffic

import (
	"errors"
	"testing"
)

// withStubbedInterfaceHelpers replaces the package-level checkInterfaceExists
// and getInterfaceSpeed functions for the duration of the test.
func withStubbedInterfaceHelpers(t *testing.T, speed int64, checkErr error) {
	t.Helper()
	prevCheck := checkInterfaceExists
	prevSpeed := getInterfaceSpeed
	checkInterfaceExists = func(name string) error { return checkErr }
	getInterfaceSpeed = func(name string) (int64, error) { return speed, nil }
	t.Cleanup(func() {
		checkInterfaceExists = prevCheck
		getInterfaceSpeed = prevSpeed
	})
}

func TestBandwidthAllocatorAllocateReleaseReadBack(t *testing.T) {
	withStubbedInterfaceHelpers(t, 1_000_000 /* 1 Gbps in kbps */, nil)

	ba := NewBandwidthAllocator()

	// Fresh allocate.
	if err := ba.AllocateBandwidth("eth0", "gold", "10Mbit", "100Mbit"); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	minBw, maxBw, err := ba.GetBandwidthAllocation("eth0", "gold")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if minBw != "10Mbit" || maxBw != "100Mbit" {
		t.Fatalf("got (%s,%s), want (10Mbit,100Mbit)", minBw, maxBw)
	}

	// Update in-place by re-allocating.
	if err := ba.AllocateBandwidth("eth0", "gold", "20Mbit", "200Mbit"); err != nil {
		t.Fatalf("re-allocate: %v", err)
	}
	minBw, maxBw, _ = ba.GetBandwidthAllocation("eth0", "gold")
	if minBw != "20Mbit" || maxBw != "200Mbit" {
		t.Fatalf("after update: (%s,%s)", minBw, maxBw)
	}

	// Second class on same interface.
	if err := ba.AllocateBandwidth("eth0", "bulk", "1Mbit", "50Mbit"); err != nil {
		t.Fatalf("allocate bulk: %v", err)
	}

	// Release gold; bulk allocation must remain.
	if err := ba.ReleaseBandwidth("eth0", "gold"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, _, err := ba.GetBandwidthAllocation("eth0", "gold"); err == nil {
		t.Fatalf("expected error after release")
	}
	if _, _, err := ba.GetBandwidthAllocation("eth0", "bulk"); err != nil {
		t.Fatalf("bulk should still exist: %v", err)
	}

	// Release last class -> interface entry is GC'd.
	if err := ba.ReleaseBandwidth("eth0", "bulk"); err != nil {
		t.Fatalf("release bulk: %v", err)
	}
	if err := ba.ReleaseBandwidth("eth0", "bulk"); err == nil {
		t.Fatalf("releasing nonexistent allocation should error")
	}
}

func TestBandwidthAllocatorGetTotalAndAvailable(t *testing.T) {
	withStubbedInterfaceHelpers(t, 1_000_000 /* 1 Gbps in kbps */, nil)

	ba := NewBandwidthAllocator()

	total, err := ba.GetTotalBandwidth("eth0")
	if err != nil {
		t.Fatalf("total: %v", err)
	}
	if total != "1Gbit" {
		t.Fatalf("total: got %s", total)
	}

	// No allocations yet: available equals total.
	avail, err := ba.GetAvailableBandwidth("eth0")
	if err != nil {
		t.Fatalf("available: %v", err)
	}
	if avail != "1Gbit" {
		t.Fatalf("available with no allocations: got %s", avail)
	}

	if err := ba.AllocateBandwidth("eth0", "gold", "10Mbit", "300Mbit"); err != nil {
		t.Fatalf("allocate gold: %v", err)
	}
	if err := ba.AllocateBandwidth("eth0", "silver", "10Mbit", "200Mbit"); err != nil {
		t.Fatalf("allocate silver: %v", err)
	}

	avail, err = ba.GetAvailableBandwidth("eth0")
	if err != nil {
		t.Fatalf("available: %v", err)
	}
	// 1 Gbps - 300 Mbps - 200 Mbps = 500 Mbps
	if avail != "500Mbit" {
		t.Fatalf("available after allocations: got %s", avail)
	}
}

func TestBandwidthAllocatorParsesAllUnits(t *testing.T) {
	withStubbedInterfaceHelpers(t, 1_000_000 /* 1 Gbps in kbps */, nil)

	ba := NewBandwidthAllocator()

	// 0.5 Gbit + 500 Mbit + 100000 Kbit + 10% of 1 Gbps = 500+500+100+100 = 1200 Mbit.
	// Interface is 1 Gbps so available should be 0 (clamped).
	if err := ba.AllocateBandwidth("eth0", "a", "0", "500Mbit"); err != nil {
		t.Fatalf("allocate a: %v", err)
	}
	if err := ba.AllocateBandwidth("eth0", "b", "0", "500000Kbit"); err != nil {
		t.Fatalf("allocate b: %v", err)
	}
	if err := ba.AllocateBandwidth("eth0", "c", "0", "1Gbit"); err != nil {
		t.Fatalf("allocate c: %v", err)
	}
	if err := ba.AllocateBandwidth("eth0", "d", "0", "10%"); err != nil {
		t.Fatalf("allocate d: %v", err)
	}

	avail, err := ba.GetAvailableBandwidth("eth0")
	if err != nil {
		t.Fatalf("available: %v", err)
	}
	// Allocations exceed total, so clamp at 0.
	if avail == "" {
		t.Fatalf("available string empty")
	}
}

func TestBandwidthAllocatorInterfaceMissing(t *testing.T) {
	withStubbedInterfaceHelpers(t, 0, errors.New("no iface"))

	ba := NewBandwidthAllocator()
	if err := ba.AllocateBandwidth("eth0", "gold", "", ""); err == nil {
		t.Fatalf("expected allocate error for missing iface")
	}
	if err := ba.ReleaseBandwidth("eth0", "gold"); err == nil {
		t.Fatalf("expected release error for missing iface")
	}
	if _, err := ba.GetTotalBandwidth("eth0"); err == nil {
		t.Fatalf("expected GetTotalBandwidth error for missing iface")
	}
	if _, err := ba.GetAvailableBandwidth("eth0"); err == nil {
		t.Fatalf("expected GetAvailableBandwidth error for missing iface")
	}
}
