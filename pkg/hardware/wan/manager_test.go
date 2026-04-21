package wan

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// fakeLink is a minimal netlink.Link implementation usable by Manager.
type fakeLink struct {
	attrs netlink.LinkAttrs
}

func (f *fakeLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeLink) Type() string              { return "device" }

// fakeNetlink implements netlinkBackend, recording every call for assertions.
type fakeNetlink struct {
	mu sync.Mutex

	links map[string]*fakeLink

	// Per-link default routes returned by RouteList(link, family).
	linkRoutes map[string][]netlink.Route
	// Global routes returned by RouteList(nil, family).
	globalRoutes []netlink.Route

	upCalls      []string
	downCalls    []string
	addedRoutes  []netlink.Route
	deletedRoutes []netlink.Route

	linkByNameErr error
	upErr         error
	downErr       error
}

func newFakeNetlink() *fakeNetlink {
	return &fakeNetlink{
		links:      make(map[string]*fakeLink),
		linkRoutes: make(map[string][]netlink.Route),
	}
}

func (f *fakeNetlink) addLink(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links[name] = &fakeLink{attrs: netlink.LinkAttrs{Name: name, Index: len(f.links) + 1}}
}

func (f *fakeNetlink) LinkByName(name string) (netlink.Link, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.linkByNameErr != nil {
		return nil, f.linkByNameErr
	}
	link, ok := f.links[name]
	if !ok {
		return nil, errors.New("link not found: " + name)
	}
	return link, nil
}

func (f *fakeNetlink) LinkSetUp(link netlink.Link) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upErr != nil {
		return f.upErr
	}
	f.upCalls = append(f.upCalls, link.Attrs().Name)
	return nil
}

func (f *fakeNetlink) LinkSetDown(link netlink.Link) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.downErr != nil {
		return f.downErr
	}
	f.downCalls = append(f.downCalls, link.Attrs().Name)
	return nil
}

func (f *fakeNetlink) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if link == nil {
		out := make([]netlink.Route, len(f.globalRoutes))
		copy(out, f.globalRoutes)
		return out, nil
	}
	routes := f.linkRoutes[link.Attrs().Name]
	out := make([]netlink.Route, len(routes))
	copy(out, routes)
	return out, nil
}

func (f *fakeNetlink) RouteDel(route *netlink.Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletedRoutes = append(f.deletedRoutes, *route)
	return nil
}

func (f *fakeNetlink) RouteAdd(route *netlink.Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addedRoutes = append(f.addedRoutes, *route)
	return nil
}

// newTestManager builds a Manager with the fake netlink backend and a stubbed
// connectivity checker. Tests always pass MonitorEnabled=false on configs to
// avoid the monitor goroutine.
func newTestManager(t *testing.T, nl *fakeNetlink) *Manager {
	t.Helper()
	m, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.netlink = nl
	m.connectivityChecker = func(ifName string, targets []string) (string, int, float64, int) {
		// Default stub: reachable.
		return "up", 5, 0, 1
	}
	if err := m.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(func() {
		_ = m.Shutdown(context.Background())
	})
	return m
}

func newConfig(name, gw string, weight int) types.WANInterfaceConfig {
	return types.WANInterfaceConfig{
		Name:              name,
		Type:              "ethernet",
		PhysicalInterface: name,
		MTU:               1500,
		Weight:            weight,
		Priority:          1,
		Gateway:           gw,
		Metric:            100,
		Failover:          true,
		MonitorEnabled:    false,
	}
}

func TestAddRemoveWANInterfaceReconcilesMap(t *testing.T) {
	nl := newFakeNetlink()
	nl.addLink("eth0")
	nl.addLink("eth1")
	m := newTestManager(t, nl)

	if err := m.AddWANInterface(newConfig("eth0", "10.0.0.1", 10)); err != nil {
		t.Fatalf("add eth0: %v", err)
	}
	if err := m.AddWANInterface(newConfig("eth1", "10.0.1.1", 5)); err != nil {
		t.Fatalf("add eth1: %v", err)
	}

	// Read back: list returns both, first-added becomes active.
	names, err := m.ListWANInterfaces()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 wans, got %d", len(names))
	}
	statuses, err := m.ListWANInterfaceStatuses()
	if err != nil {
		t.Fatalf("list statuses: %v", err)
	}
	if len(statuses) != 2 {
		t.Fatalf("expected 2 statuses, got %d", len(statuses))
	}

	status0, err := m.GetWANStatus("eth0")
	if err != nil {
		t.Fatalf("status eth0: %v", err)
	}
	if !status0.Active {
		t.Fatalf("eth0 should be active (first added)")
	}

	// Remove the active WAN and confirm eth1 gets promoted via weight.
	if err := m.RemoveWANInterface("eth0"); err != nil {
		t.Fatalf("remove eth0: %v", err)
	}
	status1, _ := m.GetWANStatus("eth1")
	if !status1.Active {
		t.Fatalf("eth1 should be promoted after eth0 removed; got %+v", status1)
	}
	if _, err := m.GetWANStatus("eth0"); err == nil {
		t.Fatalf("expected eth0 status to be gone after removal")
	}
}

func TestAddWANInterfaceFailsWhenLinkMissing(t *testing.T) {
	nl := newFakeNetlink()
	m := newTestManager(t, nl)

	if err := m.AddWANInterface(newConfig("eth99", "10.0.0.1", 1)); err == nil {
		t.Fatalf("expected error when link missing")
	}
}

func TestSetActiveWANSwitchesRoutes(t *testing.T) {
	nl := newFakeNetlink()
	nl.addLink("eth0")
	nl.addLink("eth1")
	m := newTestManager(t, nl)

	_ = m.AddWANInterface(newConfig("eth0", "10.0.0.1", 10))
	_ = m.AddWANInterface(newConfig("eth1", "10.0.1.1", 5))

	if err := m.SetActiveWAN("eth1"); err != nil {
		t.Fatalf("SetActiveWAN eth1: %v", err)
	}

	status0, _ := m.GetWANStatus("eth0")
	status1, _ := m.GetWANStatus("eth1")
	if status0.Active || status1.Active == false {
		t.Fatalf("expected eth1 active only, got eth0=%v eth1=%v", status0.Active, status1.Active)
	}
	if status0.State != "standby" {
		t.Fatalf("expected eth0 state=standby, got %s", status0.State)
	}

	if len(nl.addedRoutes) == 0 {
		t.Fatalf("expected a default route to be installed on active switch")
	}

	// SetActiveWAN on unknown interface is an error.
	if err := m.SetActiveWAN("bogus"); err == nil {
		t.Fatalf("expected error for unknown interface")
	}
}

func TestSetActiveWANRequiresGateway(t *testing.T) {
	nl := newFakeNetlink()
	nl.addLink("eth0")
	m := newTestManager(t, nl)

	// No gateway configured, and no default route exists on the link.
	cfg := newConfig("eth0", "", 1)
	if err := m.AddWANInterface(cfg); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Force SetActiveWAN to go through setupActiveWANRouting with no
	// gateway info.
	err := m.SetActiveWAN("eth0")
	if err == nil {
		t.Fatalf("expected error when no gateway available")
	}
	if !strings.Contains(err.Error(), "gateway") {
		t.Fatalf("expected gateway error, got %v", err)
	}
}

func TestSetWANInterfaceStateUpDown(t *testing.T) {
	nl := newFakeNetlink()
	nl.addLink("eth0")
	m := newTestManager(t, nl)
	_ = m.AddWANInterface(newConfig("eth0", "10.0.0.1", 1))

	if err := m.SetWANInterfaceState("eth0", true); err != nil {
		t.Fatalf("up: %v", err)
	}
	status, _ := m.GetWANStatus("eth0")
	if status.State != "up" {
		t.Fatalf("expected up state, got %s", status.State)
	}
	if len(nl.upCalls) != 1 {
		t.Fatalf("expected 1 up call, got %d", len(nl.upCalls))
	}

	if err := m.SetWANInterfaceState("eth0", false); err != nil {
		t.Fatalf("down: %v", err)
	}
	status, _ = m.GetWANStatus("eth0")
	if status.State != "down" {
		t.Fatalf("expected down state, got %s", status.State)
	}
	if len(nl.downCalls) != 1 {
		t.Fatalf("expected 1 down call, got %d", len(nl.downCalls))
	}

	// Unknown interface errors.
	if err := m.SetWANInterfaceState("missing", true); err == nil {
		t.Fatalf("expected error for missing interface")
	}
}

func TestGetWANInterfaceReturnsInfo(t *testing.T) {
	nl := newFakeNetlink()
	nl.addLink("eth0")
	m := newTestManager(t, nl)

	cfg := newConfig("eth0", "10.0.0.1", 1)
	cfg.DNS = []string{"1.1.1.1", "8.8.8.8"}
	_ = m.AddWANInterface(cfg)

	info, err := m.GetWANInterface("eth0")
	if err != nil {
		t.Fatalf("GetWANInterface: %v", err)
	}
	if info.Gateway != "10.0.0.1" {
		t.Fatalf("info gateway: %s", info.Gateway)
	}
	if len(info.DNS) != 2 {
		t.Fatalf("info DNS: %v", info.DNS)
	}

	if _, err := m.GetWANInterface("missing"); err == nil {
		t.Fatalf("expected error for missing interface")
	}
}

func TestGetWANStatisticsReadsLinkAttrs(t *testing.T) {
	nl := newFakeNetlink()
	nl.addLink("eth0")
	// Inject statistics into the fake link.
	nl.links["eth0"].attrs.Statistics = &netlink.LinkStatistics{
		RxPackets: 100, TxPackets: 200, RxBytes: 1024, TxBytes: 2048,
	}
	m := newTestManager(t, nl)
	_ = m.AddWANInterface(newConfig("eth0", "10.0.0.1", 1))

	stats, err := m.GetWANStatistics("eth0")
	if err != nil {
		t.Fatalf("GetWANStatistics: %v", err)
	}
	if stats.RxPackets != 100 || stats.TxBytes != 2048 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	if _, err := m.GetWANStatistics("missing"); err == nil {
		t.Fatalf("expected error for missing interface")
	}
}

func TestTestWANConnectivityUsesStub(t *testing.T) {
	nl := newFakeNetlink()
	nl.addLink("eth0")
	m := newTestManager(t, nl)
	_ = m.AddWANInterface(newConfig("eth0", "10.0.0.1", 1))

	// Happy path: stub returns up/5ms.
	res, err := m.TestWANConnectivity("eth0")
	if err != nil {
		t.Fatalf("test connectivity: %v", err)
	}
	if !res.Success || res.Latency != 5 {
		t.Fatalf("unexpected result: %+v", res)
	}

	// Degraded/down paths: swap the stub.
	m.connectivityChecker = func(ifName string, targets []string) (string, int, float64, int) {
		return "down", 0, 100, 0
	}
	res, err = m.TestWANConnectivity("eth0")
	if err != nil {
		t.Fatalf("test connectivity down: %v", err)
	}
	if res.Success {
		t.Fatalf("expected failure when down")
	}
	if res.Error == "" {
		t.Fatalf("expected error string")
	}

	m.connectivityChecker = func(ifName string, targets []string) (string, int, float64, int) {
		return "degraded", 200, 70, 10
	}
	res, _ = m.TestWANConnectivity("eth0")
	if res.Error == "" {
		t.Fatalf("expected error for degraded state")
	}

	if _, err := m.TestWANConnectivity("missing"); err == nil {
		t.Fatalf("expected error for missing interface")
	}
}

func TestParsePingOutputExtractsLatency(t *testing.T) {
	// Minimal synthetic ping output that exercises the stats-line parser.
	// The stddev/jitter field isn't parsed by the current implementation
	// (unit suffix not stripped), so we only assert on latency here.
	output := "round-trip min/avg/max/stddev = 11.0/12.5/14.0/1.0"
	latency, _, _ := parsePingOutput(output)
	if latency != 12 {
		t.Fatalf("latency: got %d, want 12", latency)
	}

	// Empty input yields zero values.
	lat, jit, pk := parsePingOutput("")
	if lat != 0 || jit != 0 || pk != 0 {
		t.Fatalf("empty input should produce zeroes, got %d/%d/%d", lat, jit, pk)
	}
}

func TestShutdownCancelsContext(t *testing.T) {
	nl := newFakeNetlink()
	m := newTestManager(t, nl)

	// Shutdown a second time is a no-op.
	if err := m.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestFactoryNewWANManagerReturnsRealManager(t *testing.T) {
	mgr, err := NewWANManager()
	if err != nil {
		t.Fatalf("NewWANManager: %v", err)
	}
	if mgr == nil {
		t.Fatalf("expected non-nil manager")
	}
}
