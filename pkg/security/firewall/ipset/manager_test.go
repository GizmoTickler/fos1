package ipset

import (
	"fmt"
	"testing"
)

// mockKernel implements KernelOperations for testing.
type mockKernel struct {
	sets    map[string]bool
	flushes int
	errors  map[string]error // method name -> error to return
}

func newMockKernel() *mockKernel {
	return &mockKernel{
		sets:   make(map[string]bool),
		errors: make(map[string]error),
	}
}

func (m *mockKernel) CreateSet(config Config) error {
	if err, ok := m.errors["CreateSet"]; ok {
		return err
	}
	m.sets[config.Name] = true
	return nil
}

func (m *mockKernel) DeleteSet(table, name string) error {
	if err, ok := m.errors["DeleteSet"]; ok {
		return err
	}
	delete(m.sets, name)
	return nil
}

func (m *mockKernel) AddElements(table, setName string, elements []Element) error {
	if err, ok := m.errors["AddElements"]; ok {
		return err
	}
	return nil
}

func (m *mockKernel) RemoveElements(table, setName string, elements []Element) error {
	if err, ok := m.errors["RemoveElements"]; ok {
		return err
	}
	return nil
}

func (m *mockKernel) FlushSet(table, setName string) error {
	if err, ok := m.errors["FlushSet"]; ok {
		return err
	}
	return nil
}

func (m *mockKernel) Flush() error {
	m.flushes++
	if err, ok := m.errors["Flush"]; ok {
		return err
	}
	return nil
}

func TestCreateAndDeleteSet(t *testing.T) {
	k := newMockKernel()
	mgr := NewManager("fos1-filter", k)

	config := Config{
		Name:     "blocklist",
		Type:     SetTypeIPv4Addr,
		Interval: true,
	}

	if err := mgr.CreateSet(config); err != nil {
		t.Fatalf("CreateSet: %v", err)
	}

	if !mgr.SetExists("blocklist") {
		t.Error("set should exist after creation")
	}

	// Duplicate should fail
	if err := mgr.CreateSet(config); err == nil {
		t.Error("creating duplicate set should fail")
	}

	if err := mgr.DeleteSet("blocklist"); err != nil {
		t.Fatalf("DeleteSet: %v", err)
	}

	if mgr.SetExists("blocklist") {
		t.Error("set should not exist after deletion")
	}
}

func TestAddAndRemoveElements(t *testing.T) {
	k := newMockKernel()
	mgr := NewManager("fos1-filter", k)

	mgr.CreateSet(Config{Name: "test", Type: SetTypeIPv4Addr})

	elements := []Element{
		{Value: "10.0.0.1"},
		{Value: "10.0.0.2"},
		{Value: "10.0.0.3"},
	}

	if err := mgr.AddElements("test", elements); err != nil {
		t.Fatalf("AddElements: %v", err)
	}

	listed, err := mgr.ListElements("test")
	if err != nil {
		t.Fatalf("ListElements: %v", err)
	}
	if len(listed) != 3 {
		t.Errorf("expected 3 elements, got %d", len(listed))
	}

	// Remove one
	if err := mgr.RemoveElements("test", []Element{{Value: "10.0.0.2"}}); err != nil {
		t.Fatalf("RemoveElements: %v", err)
	}

	listed, _ = mgr.ListElements("test")
	if len(listed) != 2 {
		t.Errorf("expected 2 elements after remove, got %d", len(listed))
	}
}

func TestReplaceElements(t *testing.T) {
	k := newMockKernel()
	mgr := NewManager("fos1-filter", k)

	mgr.CreateSet(Config{Name: "feed", Type: SetTypeIPv4Addr})

	// Add initial elements
	mgr.AddElements("feed", []Element{{Value: "1.1.1.1"}, {Value: "2.2.2.2"}})

	// Replace with new set
	newElements := []Element{{Value: "3.3.3.3"}, {Value: "4.4.4.4"}, {Value: "5.5.5.5"}}
	if err := mgr.ReplaceElements("feed", newElements); err != nil {
		t.Fatalf("ReplaceElements: %v", err)
	}

	listed, _ := mgr.ListElements("feed")
	if len(listed) != 3 {
		t.Errorf("expected 3 elements after replace, got %d", len(listed))
	}
}

func TestFlushSet(t *testing.T) {
	k := newMockKernel()
	mgr := NewManager("fos1-filter", k)

	mgr.CreateSet(Config{Name: "test", Type: SetTypeIPv4Addr})
	mgr.AddElements("test", []Element{{Value: "1.1.1.1"}})

	if err := mgr.FlushSet("test"); err != nil {
		t.Fatalf("FlushSet: %v", err)
	}

	listed, _ := mgr.ListElements("test")
	if len(listed) != 0 {
		t.Errorf("expected 0 elements after flush, got %d", len(listed))
	}
}

func TestGetSetInfo(t *testing.T) {
	k := newMockKernel()
	mgr := NewManager("fos1-filter", k)

	mgr.CreateSet(Config{
		Name:     "blocklist",
		Type:     SetTypeIPv4Addr,
		Interval: true,
		Counter:  true,
	})
	mgr.AddElements("blocklist", []Element{{Value: "10.0.0.0/8"}, {Value: "192.168.0.0/16"}})

	info, err := mgr.GetSetInfo("blocklist")
	if err != nil {
		t.Fatalf("GetSetInfo: %v", err)
	}

	if info.Name != "blocklist" {
		t.Errorf("expected name blocklist, got %s", info.Name)
	}
	if info.ElementCount != 2 {
		t.Errorf("expected 2 elements, got %d", info.ElementCount)
	}
	if !info.HasInterval {
		t.Error("expected interval flag")
	}
	if !info.HasCounter {
		t.Error("expected counter flag")
	}
}

func TestListSets(t *testing.T) {
	k := newMockKernel()
	mgr := NewManager("fos1-filter", k)

	mgr.CreateSet(Config{Name: "set1", Type: SetTypeIPv4Addr})
	mgr.CreateSet(Config{Name: "set2", Type: SetTypeIPv6Addr})
	mgr.CreateSet(Config{Name: "set3", Type: SetTypePort})

	sets, err := mgr.ListSets()
	if err != nil {
		t.Fatalf("ListSets: %v", err)
	}
	if len(sets) != 3 {
		t.Errorf("expected 3 sets, got %d", len(sets))
	}
}

func TestOperationsOnNonexistentSet(t *testing.T) {
	k := newMockKernel()
	mgr := NewManager("fos1-filter", k)

	if err := mgr.AddElements("nonexistent", []Element{{Value: "1.1.1.1"}}); err == nil {
		t.Error("AddElements on nonexistent set should fail")
	}
	if err := mgr.RemoveElements("nonexistent", []Element{{Value: "1.1.1.1"}}); err == nil {
		t.Error("RemoveElements on nonexistent set should fail")
	}
	if err := mgr.FlushSet("nonexistent"); err == nil {
		t.Error("FlushSet on nonexistent set should fail")
	}
	if err := mgr.DeleteSet("nonexistent"); err == nil {
		t.Error("DeleteSet on nonexistent set should fail")
	}
	if _, err := mgr.ListElements("nonexistent"); err == nil {
		t.Error("ListElements on nonexistent set should fail")
	}
	if _, err := mgr.GetSetInfo("nonexistent"); err == nil {
		t.Error("GetSetInfo on nonexistent set should fail")
	}
}

func TestKernelError(t *testing.T) {
	k := newMockKernel()
	k.errors["CreateSet"] = fmt.Errorf("kernel error")
	mgr := NewManager("fos1-filter", k)

	if err := mgr.CreateSet(Config{Name: "test", Type: SetTypeIPv4Addr}); err == nil {
		t.Error("should propagate kernel error")
	}

	if mgr.SetExists("test") {
		t.Error("set should not be tracked after kernel error")
	}
}

func TestAtomicFlushCalls(t *testing.T) {
	k := newMockKernel()
	mgr := NewManager("fos1-filter", k)

	k.flushes = 0
	mgr.CreateSet(Config{Name: "test", Type: SetTypeIPv4Addr})
	if k.flushes != 1 {
		t.Errorf("CreateSet should trigger 1 flush, got %d", k.flushes)
	}

	k.flushes = 0
	mgr.ReplaceElements("test", []Element{{Value: "1.1.1.1"}})
	if k.flushes != 1 {
		t.Errorf("ReplaceElements should trigger 1 atomic flush, got %d", k.flushes)
	}
}
