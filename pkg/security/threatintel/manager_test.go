package threatintel

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// recordingCilium captures ApplyNetworkPolicy / DeleteNetworkPolicy calls so
// tests can assert which policies the manager pushed to Cilium.
type recordingCilium struct {
	mu             sync.Mutex
	Applied        []*cilium.CiliumPolicy
	Deleted        []string
	ApplyErr       error
	DeleteErr      error
	DeleteErrOnce  string // return DeleteErr only the first time this policy is deleted
	deletedOnceHit bool
}

func (c *recordingCilium) ApplyNetworkPolicy(ctx context.Context, policy *cilium.CiliumPolicy) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ApplyErr != nil {
		return c.ApplyErr
	}
	// Store a shallow copy so later mutations by the caller don't affect
	// recorded history.
	p := *policy
	c.Applied = append(c.Applied, &p)
	return nil
}

func (c *recordingCilium) DeleteNetworkPolicy(ctx context.Context, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.DeleteErr != nil {
		if c.DeleteErrOnce != "" {
			if name == c.DeleteErrOnce && !c.deletedOnceHit {
				c.deletedOnceHit = true
				return c.DeleteErr
			}
		} else {
			return c.DeleteErr
		}
	}
	c.Deleted = append(c.Deleted, name)
	return nil
}

func (c *recordingCilium) AppliedNames() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.Applied))
	for _, p := range c.Applied {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

func (c *recordingCilium) DeletedNames() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.Deleted))
	copy(out, c.Deleted)
	sort.Strings(out)
	return out
}

// stub implementations for the rest of cilium.CiliumClient.
func (c *recordingCilium) CreateNAT(context.Context, *cilium.CiliumNATConfig) error { return nil }
func (c *recordingCilium) RemoveNAT(context.Context, *cilium.CiliumNATConfig) error { return nil }
func (c *recordingCilium) CreateNAT64(context.Context, *cilium.NAT64Config) error   { return nil }
func (c *recordingCilium) RemoveNAT64(context.Context, *cilium.NAT64Config) error   { return nil }
func (c *recordingCilium) CreatePortForward(context.Context, *cilium.PortForwardConfig) error {
	return nil
}
func (c *recordingCilium) RemovePortForward(context.Context, *cilium.PortForwardConfig) error {
	return nil
}
func (c *recordingCilium) ConfigureVLANRouting(context.Context, *cilium.CiliumVLANRoutingConfig) error {
	return nil
}
func (c *recordingCilium) ConfigureDPIIntegration(context.Context, *cilium.CiliumDPIIntegrationConfig) error {
	return nil
}
func (c *recordingCilium) ListRoutes(context.Context) ([]cilium.Route, error) { return nil, nil }
func (c *recordingCilium) ListVRFRoutes(context.Context, int) ([]cilium.Route, error) {
	return nil, nil
}
func (c *recordingCilium) AddRoute(cilium.Route) error            { return nil }
func (c *recordingCilium) DeleteRoute(cilium.Route) error         { return nil }
func (c *recordingCilium) AddVRFRoute(cilium.Route, int) error    { return nil }
func (c *recordingCilium) DeleteVRFRoute(cilium.Route, int) error { return nil }

// staticFetcher returns a fixed indicator set on every call. Tests swap it
// out between Refresh calls to simulate feed drift.
type staticFetcher struct {
	mu         sync.Mutex
	Indicators []Indicator
	Err        error
	Calls      int
}

func (f *staticFetcher) Fetch(ctx context.Context) ([]Indicator, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls++
	if f.Err != nil {
		return nil, f.Err
	}
	out := make([]Indicator, len(f.Indicators))
	copy(out, f.Indicators)
	return out, nil
}

func TestManagerRefresh_AppliesNewIndicators(t *testing.T) {
	cc := &recordingCilium{}
	fetcher := &staticFetcher{Indicators: []Indicator{
		{URL: "http://evil.example/"},
		{URL: "http://bad.example/"},
	}}
	mgr := NewManager("urlhaus", fetcher, cc, time.Hour)

	res, err := mgr.Refresh(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(res.Created) != 2 {
		t.Errorf("expected 2 created, got %d", len(res.Created))
	}
	if len(res.Refreshed) != 0 {
		t.Errorf("expected 0 refreshed on first fetch, got %d", len(res.Refreshed))
	}
	if mgr.ActiveCount() != 2 {
		t.Errorf("expected 2 active, got %d", mgr.ActiveCount())
	}
	if got, want := len(cc.Applied), 2; got != want {
		t.Errorf("expected %d applied to Cilium, got %d", want, got)
	}
}

func TestManagerRefresh_DeduplicatesAcrossCycles(t *testing.T) {
	cc := &recordingCilium{}
	fetcher := &staticFetcher{Indicators: []Indicator{
		{URL: "http://evil.example/"},
	}}
	mgr := NewManager("urlhaus", fetcher, cc, time.Hour)

	if _, err := mgr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := len(cc.Applied); got != 1 {
		t.Errorf("expected 1 apply across 2 refreshes, got %d", got)
	}
	if mgr.ActiveCount() != 1 {
		t.Errorf("expected 1 active, got %d", mgr.ActiveCount())
	}
}

func TestManagerRefresh_ExpiresStaleIndicators(t *testing.T) {
	cc := &recordingCilium{}
	base := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	clock := base
	fetcher := &staticFetcher{Indicators: []Indicator{
		{URL: "http://evil.example/"},
		{URL: "http://bad.example/"},
	}}

	mgr := NewManager("urlhaus", fetcher, cc, 30*time.Minute)
	mgr.Now = func() time.Time { return clock }

	// First refresh: both indicators applied.
	if _, err := mgr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mgr.ActiveCount() != 2 {
		t.Fatalf("expected 2 active, got %d", mgr.ActiveCount())
	}

	// Advance time and swap out fetcher to return only one of the two.
	clock = base.Add(45 * time.Minute)
	fetcher.mu.Lock()
	fetcher.Indicators = []Indicator{{URL: "http://evil.example/"}}
	fetcher.mu.Unlock()

	res, err := mgr.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Refreshed) != 1 {
		t.Errorf("expected 1 refreshed, got %d", len(res.Refreshed))
	}
	if len(res.Expired) != 1 {
		t.Errorf("expected 1 expired, got %d", len(res.Expired))
	}
	if mgr.ActiveCount() != 1 {
		t.Errorf("expected 1 active after expiry, got %d", mgr.ActiveCount())
	}
	if len(cc.Deleted) != 1 {
		t.Errorf("expected 1 Cilium delete, got %d", len(cc.Deleted))
	}
}

func TestManagerRefresh_ZeroMaxAgeDisablesExpiry(t *testing.T) {
	cc := &recordingCilium{}
	base := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	clock := base
	fetcher := &staticFetcher{Indicators: []Indicator{
		{URL: "http://evil.example/"},
	}}

	mgr := NewManager("urlhaus", fetcher, cc, 0)
	mgr.Now = func() time.Time { return clock }

	if _, err := mgr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	clock = base.Add(24 * time.Hour)
	fetcher.mu.Lock()
	fetcher.Indicators = nil // empty feed
	fetcher.mu.Unlock()

	res, err := mgr.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Expired) != 0 {
		t.Errorf("MaxAge=0 should disable expiry, got %d expired", len(res.Expired))
	}
	if mgr.ActiveCount() != 1 {
		t.Errorf("expected 1 still-active indicator, got %d", mgr.ActiveCount())
	}
}

func TestManagerRefresh_FetchErrorPreservesState(t *testing.T) {
	cc := &recordingCilium{}
	fetcher := &staticFetcher{Indicators: []Indicator{{URL: "http://evil.example/"}}}
	mgr := NewManager("urlhaus", fetcher, cc, time.Hour)
	if _, err := mgr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	fetcher.mu.Lock()
	fetcher.Err = errors.New("upstream 503")
	fetcher.mu.Unlock()

	_, err := mgr.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected fetch error to propagate")
	}
	if mgr.ActiveCount() != 1 {
		t.Errorf("fetch error should not wipe active state, got %d", mgr.ActiveCount())
	}
}

func TestManagerShutdown_DeletesAllPolicies(t *testing.T) {
	cc := &recordingCilium{}
	fetcher := &staticFetcher{Indicators: []Indicator{
		{URL: "http://a.example/"},
		{URL: "http://b.example/"},
		{URL: "http://c.example/"},
	}}
	mgr := NewManager("urlhaus", fetcher, cc, time.Hour)
	if _, err := mgr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mgr.ActiveCount() != 3 {
		t.Fatalf("expected 3 active before shutdown, got %d", mgr.ActiveCount())
	}

	mgr.Shutdown(context.Background())
	if mgr.ActiveCount() != 0 {
		t.Errorf("expected 0 active after shutdown, got %d", mgr.ActiveCount())
	}
	if len(cc.Deleted) != 3 {
		t.Errorf("expected 3 deletes, got %d", len(cc.Deleted))
	}
}
