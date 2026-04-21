package traffic

import (
	"errors"
	"sort"
	"sync"
	"testing"
	"time"
)

// fakeClassifier is a test double for the Classifier interface that records
// every call. It is used to assert ApplyConfiguration/DeleteConfiguration
// reconcile the configured set of rules with the classifier.
type fakeClassifier struct {
	mu       sync.Mutex
	added    []ClassificationRule
	removed  []string
	listErr  error
	addErr   error
	delErr   error
}

func (f *fakeClassifier) ClassifyPacket(packet PacketInfo) (string, error) {
	return "", nil
}

func (f *fakeClassifier) AddClassificationRule(rule ClassificationRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, rule)
	return nil
}

func (f *fakeClassifier) RemoveClassificationRule(ruleName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return f.delErr
	}
	f.removed = append(f.removed, ruleName)
	return nil
}

func (f *fakeClassifier) ListClassificationRules() ([]ClassificationRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]ClassificationRule, len(f.added))
	copy(out, f.added)
	return out, nil
}

// fakeBandwidthAllocator records bandwidth operations so tests can assert that
// the manager reconciles allocations with a real-looking backend.
type fakeBandwidthAllocator struct {
	mu        sync.Mutex
	allocated map[string]allocRecord
	released  []string
}

type allocRecord struct {
	min string
	max string
}

func newFakeBandwidthAllocator() *fakeBandwidthAllocator {
	return &fakeBandwidthAllocator{
		allocated: make(map[string]allocRecord),
	}
}

func key(ifName, class string) string { return ifName + "/" + class }

func (f *fakeBandwidthAllocator) AllocateBandwidth(interfaceName, className, minBandwidth, maxBandwidth string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allocated[key(interfaceName, className)] = allocRecord{min: minBandwidth, max: maxBandwidth}
	return nil
}

func (f *fakeBandwidthAllocator) ReleaseBandwidth(interfaceName, className string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.allocated, key(interfaceName, className))
	f.released = append(f.released, key(interfaceName, className))
	return nil
}

func (f *fakeBandwidthAllocator) GetBandwidthAllocation(interfaceName, className string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.allocated[key(interfaceName, className)]
	if !ok {
		return "", "", errors.New("not found")
	}
	return rec.min, rec.max, nil
}

func (f *fakeBandwidthAllocator) GetTotalBandwidth(interfaceName string) (string, error) {
	return "1Gbit", nil
}

func (f *fakeBandwidthAllocator) GetAvailableBandwidth(interfaceName string) (string, error) {
	return "500Mbit", nil
}

// newTestManager builds a manager with background goroutines disabled and a
// stubbed checkInterfaceExists hook, so tests can drive reconciliation
// deterministically without kernel privileges.
func newTestManager(t *testing.T, cls Classifier, ba BandwidthAllocator) *manager {
	t.Helper()

	prevCheck := checkInterfaceExists
	checkInterfaceExists = func(name string) error { return nil }
	t.Cleanup(func() { checkInterfaceExists = prevCheck })

	m := newManager(cls, ba, time.Hour, false)
	// Replace tc hooks with in-memory recorders so we don't shell out.
	var appliedIfaces []string
	var removedIfaces []string
	var mu sync.Mutex
	m.trafficControlApplier = func(cfg *Configuration) error {
		mu.Lock()
		defer mu.Unlock()
		appliedIfaces = append(appliedIfaces, cfg.Interface)
		return nil
	}
	m.trafficControlRemover = func(name string) error {
		mu.Lock()
		defer mu.Unlock()
		removedIfaces = append(removedIfaces, name)
		return nil
	}
	return m
}

func sampleConfiguration(iface string) *Configuration {
	return &Configuration{
		Interface:         iface,
		UploadBandwidth:   "100Mbit",
		DownloadBandwidth: "200Mbit",
		DefaultClass:      "default",
		Classes: []Class{
			{
				Name:         "gold",
				Priority:     1,
				MinBandwidth: "10Mbit",
				MaxBandwidth: "50Mbit",
				DSCP:         46,
				Applications: []string{"voip"},
				Protocol:     "udp",
			},
			{
				Name:            "bulk",
				Priority:        5,
				MinBandwidth:    "1Mbit",
				MaxBandwidth:    "20Mbit",
				DestinationPort: "8080",
				SourcePort:      "10000-20000",
				Protocol:        "tcp",
			},
		},
	}
}

func TestManagerApplyAndReadBackReconcilesClassifierAndBandwidth(t *testing.T) {
	cls := &fakeClassifier{}
	ba := newFakeBandwidthAllocator()
	m := newTestManager(t, cls, ba)

	cfg := sampleConfiguration("eth0")
	if err := m.ApplyConfiguration(cfg); err != nil {
		t.Fatalf("ApplyConfiguration: %v", err)
	}

	// --- Read back: configurations are stored ---
	got, err := m.ListConfigurations()
	if err != nil {
		t.Fatalf("ListConfigurations: %v", err)
	}
	if len(got) != 1 || got[0].Interface != "eth0" {
		t.Fatalf("expected one config for eth0, got %+v", got)
	}

	// --- Read back: classifier received a rule per class ---
	if len(cls.added) != len(cfg.Classes) {
		t.Fatalf("expected %d classifier rules, got %d", len(cfg.Classes), len(cls.added))
	}
	ruleNames := make([]string, 0, len(cls.added))
	for _, r := range cls.added {
		ruleNames = append(ruleNames, r.Name)
	}
	sort.Strings(ruleNames)
	expected := []string{"eth0-bulk", "eth0-gold"}
	for i := range expected {
		if ruleNames[i] != expected[i] {
			t.Fatalf("rule %d: expected %s, got %s", i, expected[i], ruleNames[i])
		}
	}

	// --- Read back: source/destination port expansion ---
	var bulk ClassificationRule
	for _, r := range cls.added {
		if r.ClassName == "bulk" {
			bulk = r
		}
	}
	if got, want := bulk.SourcePorts, []string{"10000-20000"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("bulk source ports: want %v, got %v", want, got)
	}
	if got, want := bulk.DestinationPorts, []string{"8080"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("bulk destination ports: want %v, got %v", want, got)
	}

	// --- Read back: bandwidth allocator received allocations ---
	if _, _, err := ba.GetBandwidthAllocation("eth0", "gold"); err != nil {
		t.Fatalf("expected gold allocation, got err: %v", err)
	}
	minBw, maxBw, err := ba.GetBandwidthAllocation("eth0", "bulk")
	if err != nil {
		t.Fatalf("expected bulk allocation, got err: %v", err)
	}
	if minBw != "1Mbit" || maxBw != "20Mbit" {
		t.Fatalf("bulk allocation: got (%s,%s), want (1Mbit,20Mbit)", minBw, maxBw)
	}

	// --- Read back: status matches input ---
	st, err := m.GetStatus("eth0")
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if st.UploadBandwidth != "100Mbit" || st.DownloadBandwidth != "200Mbit" {
		t.Fatalf("status bandwidth: got %s/%s", st.UploadBandwidth, st.DownloadBandwidth)
	}
	if _, ok := st.ClassStatistics["gold"]; !ok {
		t.Fatalf("gold class stats missing")
	}
}

func TestManagerApplyIsIdempotentAndUpdatesExistingConfig(t *testing.T) {
	cls := &fakeClassifier{}
	ba := newFakeBandwidthAllocator()
	m := newTestManager(t, cls, ba)

	cfg := sampleConfiguration("eth0")
	if err := m.ApplyConfiguration(cfg); err != nil {
		t.Fatalf("initial apply: %v", err)
	}

	// Modify the config and re-apply. The manager should retain a single
	// configuration for eth0 and update the bandwidth fields.
	updated := sampleConfiguration("eth0")
	updated.UploadBandwidth = "500Mbit"
	if err := m.ApplyConfiguration(updated); err != nil {
		t.Fatalf("update apply: %v", err)
	}

	got, _ := m.ListConfigurations()
	if len(got) != 1 {
		t.Fatalf("expected 1 config after update, got %d", len(got))
	}
	st, err := m.GetStatus("eth0")
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if st.UploadBandwidth != "500Mbit" {
		t.Fatalf("expected updated upload bw, got %s", st.UploadBandwidth)
	}
}

func TestManagerDeleteReconcilesAwayClassifierAndBandwidth(t *testing.T) {
	cls := &fakeClassifier{}
	ba := newFakeBandwidthAllocator()
	m := newTestManager(t, cls, ba)

	cfg := sampleConfiguration("eth0")
	if err := m.ApplyConfiguration(cfg); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if err := m.DeleteConfiguration("eth0"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Configuration disappears from the manager.
	if got, _ := m.ListConfigurations(); len(got) != 0 {
		t.Fatalf("expected 0 configs after delete, got %d", len(got))
	}
	if _, err := m.GetStatus("eth0"); err == nil {
		t.Fatalf("expected GetStatus error after delete")
	}

	// Classifier rules are removed and bandwidth released.
	if len(cls.removed) != len(cfg.Classes) {
		t.Fatalf("expected %d classifier removes, got %d", len(cfg.Classes), len(cls.removed))
	}
	for _, c := range cfg.Classes {
		if _, _, err := ba.GetBandwidthAllocation("eth0", c.Name); err == nil {
			t.Fatalf("class %s bandwidth should be released", c.Name)
		}
	}
}

func TestManagerDeleteUnknownInterfaceReturnsError(t *testing.T) {
	cls := &fakeClassifier{}
	ba := newFakeBandwidthAllocator()
	m := newTestManager(t, cls, ba)

	err := m.DeleteConfiguration("missing")
	if err == nil {
		t.Fatalf("expected error deleting unknown interface")
	}
}

func TestManagerGetClassStatisticsReturnsInitializedEntry(t *testing.T) {
	cls := &fakeClassifier{}
	ba := newFakeBandwidthAllocator()
	m := newTestManager(t, cls, ba)

	cfg := sampleConfiguration("eth0")
	if err := m.ApplyConfiguration(cfg); err != nil {
		t.Fatalf("apply: %v", err)
	}

	stats, err := m.GetClassStatistics("eth0", "gold")
	if err != nil {
		t.Fatalf("GetClassStatistics: %v", err)
	}
	if stats == nil {
		t.Fatalf("expected non-nil stats")
	}

	if _, err := m.GetClassStatistics("eth0", "missing"); err == nil {
		t.Fatalf("expected error for missing class")
	}
	if _, err := m.GetClassStatistics("eth1", "gold"); err == nil {
		t.Fatalf("expected error for missing interface")
	}
}

func TestManagerInterfaceStatisticsForMissingInterface(t *testing.T) {
	cls := &fakeClassifier{}
	ba := newFakeBandwidthAllocator()
	m := newTestManager(t, cls, ba)

	if _, err := m.GetInterfaceStatistics("eth42"); err == nil {
		t.Fatalf("expected GetInterfaceStatistics error for missing interface")
	}
}

func TestManagerApplyFailsWhenInterfaceMissing(t *testing.T) {
	cls := &fakeClassifier{}
	ba := newFakeBandwidthAllocator()
	m := newTestManager(t, cls, ba)

	// Swap checkInterfaceExists to simulate missing link.
	checkInterfaceExists = func(name string) error { return errors.New("no such interface") }

	err := m.ApplyConfiguration(sampleConfiguration("eth0"))
	if err == nil {
		t.Fatalf("expected error when interface missing")
	}
}
