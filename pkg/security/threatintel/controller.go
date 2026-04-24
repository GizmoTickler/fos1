package threatintel

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// FeedStore abstracts read/update access to ThreatFeed CRs. The production
// implementation wraps a typed client-go client; the tests supply an in-memory
// double so reconcile logic can be exercised without a real API server.
type FeedStore interface {
	// List returns every ThreatFeed currently present in the cluster. The
	// controller calls this once per reconcile cycle.
	List(ctx context.Context) ([]securityv1alpha1.ThreatFeed, error)

	// UpdateStatus writes the provided status back to the named ThreatFeed.
	// Implementations must be idempotent; controller will retry on error.
	UpdateStatus(ctx context.Context, name string, status securityv1alpha1.ThreatFeedStatus) error
}

// SecretReader abstracts Secret lookups so authenticated feed formats can
// pull credentials without wiring the full client-go dependency chain. The
// production implementation shells out to kubectl (matching the rest of the
// package's external-state access pattern); tests inject an in-memory map.
//
// Read returns the raw byte values keyed by the Secret's data keys (i.e.
// already base64-decoded). Missing Secrets must return an error whose text
// is safe to surface on the ThreatFeed CR status.
type SecretReader interface {
	Read(ctx context.Context, namespace, name string) (map[string][]byte, error)
}

// Controller drives the ThreatFeed CRD. One Controller instance manages all
// ThreatFeed CRs in the cluster; per-feed state lives inside a Manager.
//
// The controller is polling-based (not informer-based) for simplicity; the
// v0 reconcile frequency is derived from each CR's RefreshInterval. The
// tickers are coalesced into a single reconcile loop that runs every
// TickInterval and checks each feed's next-due time.
type Controller struct {
	// Store provides CR access.
	Store FeedStore

	// Cilium is the network-policy client passed to each Manager.
	Cilium cilium.CiliumClient

	// TickInterval bounds how often the reconcile loop evaluates feeds.
	// Feeds with shorter RefreshInterval values are still clamped to this
	// floor.
	TickInterval time.Duration

	// HTTPClient is injected into new URLhausFetcher instances. If nil, a
	// default client with a 30s timeout is used.
	HTTPClient *http.Client

	// NewFetcher constructs a Fetcher for a given feed. If nil, the
	// controller dispatches on Spec.Format:
	//   - urlhaus-csv → URLhausFetcher (no auth)
	//   - misp-json   → MISPFetcher (API key loaded via Secrets)
	// Unknown formats surface as an Invalid condition on the CR.
	NewFetcher func(spec securityv1alpha1.ThreatFeedSpec) (Fetcher, error)

	// Secrets is the lookup used to fetch auth credentials for feed
	// formats that require them (currently: misp-json). When nil and an
	// authenticated feed is encountered, the controller records an
	// Invalid condition rather than panicking.
	Secrets SecretReader

	// DefaultSecretNamespace is used when AuthSecretRef.Namespace is
	// empty. It mirrors how ConfigMap/Secret references work against a
	// controller that runs outside the feed's namespace. Defaults to
	// "security".
	DefaultSecretNamespace string

	// Now returns the current time. Injected for tests.
	Now func() time.Time

	mu       sync.Mutex
	managers map[string]*managedFeed
}

// managedFeed keeps per-feed runtime state (the Manager plus scheduling
// metadata) across reconcile cycles.
type managedFeed struct {
	manager    *Manager
	nextFetch  time.Time
	lastStatus securityv1alpha1.ThreatFeedStatus
	spec       securityv1alpha1.ThreatFeedSpec
}

// NewController constructs a Controller with sane defaults. The caller must
// still populate Store and Cilium before calling Reconcile.
func NewController(store FeedStore, client cilium.CiliumClient) *Controller {
	return &Controller{
		Store:        store,
		Cilium:       client,
		TickInterval: 15 * time.Second,
		managers:     make(map[string]*managedFeed),
	}
}

// Run executes the reconcile loop until ctx is cancelled. Returns the context
// error when it is.
func (c *Controller) Run(ctx context.Context) error {
	interval := c.TickInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Reconcile once immediately so new deployments do not wait a full tick.
	if err := c.Reconcile(ctx); err != nil {
		klog.Warningf("threatintel: initial reconcile: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.Reconcile(ctx); err != nil {
				klog.Warningf("threatintel: reconcile: %v", err)
			}
		}
	}
}

// Reconcile is a single pass over every ThreatFeed CR. Exposed separately from
// Run so tests can drive it directly and sprint-integration scripts can
// trigger a refresh on demand.
func (c *Controller) Reconcile(ctx context.Context) error {
	feeds, err := c.Store.List(ctx)
	if err != nil {
		return fmt.Errorf("list threatfeeds: %w", err)
	}

	seen := make(map[string]struct{}, len(feeds))
	for i := range feeds {
		feed := &feeds[i]
		seen[feed.Name] = struct{}{}
		if err := c.reconcileFeed(ctx, feed); err != nil {
			klog.Warningf("threatintel: reconcile feed %s: %v", feed.Name, err)
		}
	}

	// Garbage-collect managers for deleted feeds.
	c.mu.Lock()
	stale := make([]string, 0)
	for name := range c.managers {
		if _, ok := seen[name]; !ok {
			stale = append(stale, name)
		}
	}
	c.mu.Unlock()

	for _, name := range stale {
		c.mu.Lock()
		mf, ok := c.managers[name]
		if ok {
			delete(c.managers, name)
		}
		c.mu.Unlock()
		if mf != nil {
			mf.manager.Shutdown(ctx)
		}
	}

	return nil
}

// reconcileFeed handles a single ThreatFeed CR.
func (c *Controller) reconcileFeed(ctx context.Context, feed *securityv1alpha1.ThreatFeed) error {
	now := c.now()

	if !feed.Spec.Enabled {
		// Disabled feed: leave active indicators in place but do not
		// poll. Status reflects "not fetching".
		return c.writeStatus(ctx, feed, func(s *securityv1alpha1.ThreatFeedStatus) {
			s.LastFetchError = ""
			setCondition(s, securityv1alpha1.ThreatFeedConditionFetchSucceeded, "False", "Disabled", "feed is disabled", now)
			setCondition(s, securityv1alpha1.ThreatFeedConditionReady, "False", "Disabled", "feed is disabled", now)
		})
	}

	mf, err := c.getOrCreateManager(feed)
	if err != nil {
		return c.writeStatus(ctx, feed, func(s *securityv1alpha1.ThreatFeedStatus) {
			s.LastFetchError = err.Error()
			setCondition(s, securityv1alpha1.ThreatFeedConditionFetchSucceeded, "False", "ConfigError", err.Error(), now)
			setCondition(s, securityv1alpha1.ThreatFeedConditionReady, "False", "ConfigError", err.Error(), now)
		})
	}

	if !now.Before(mf.nextFetch) {
		refresh := feed.Spec.RefreshInterval.Duration
		if refresh <= 0 {
			refresh = 5 * time.Minute
		}
		mf.nextFetch = now.Add(refresh)

		res, ferr := mf.manager.Refresh(ctx)
		if ferr != nil {
			return c.writeStatus(ctx, feed, func(s *securityv1alpha1.ThreatFeedStatus) {
				s.LastFetchError = ferr.Error()
				setCondition(s, securityv1alpha1.ThreatFeedConditionFetchSucceeded, "False", "FetchFailed", ferr.Error(), now)
			})
		}

		return c.writeStatus(ctx, feed, func(s *securityv1alpha1.ThreatFeedStatus) {
			s.LastFetchTime = metav1.NewTime(res.FetchedAt)
			s.LastFetchError = ""
			s.EntryCount = int32(res.EntryCount)
			s.ActiveIndicators = int32(mf.manager.ActiveCount())
			setCondition(s, securityv1alpha1.ThreatFeedConditionFetchSucceeded, "True", "FetchSucceeded",
				fmt.Sprintf("fetched %d entries (%d unresolved); applied=%d refreshed=%d expired=%d",
					res.EntryCount, res.UnresolvedCount, len(res.Created), len(res.Refreshed), len(res.Expired)), now)
			readyStatus := "True"
			readyReason := "Enforcing"
			readyMessage := fmt.Sprintf("%d indicators active", mf.manager.ActiveCount())
			if mf.manager.ActiveCount() == 0 {
				readyStatus = "False"
				readyReason = "NoIndicators"
				readyMessage = "no active indicators"
			}
			setCondition(s, securityv1alpha1.ThreatFeedConditionReady, readyStatus, readyReason, readyMessage, now)
		})
	}

	// Between fetches: refresh the expiry pass so indicators age out at
	// MaxAge even when the feed publishes rarely.
	mf.manager.ExpireStale(ctx)
	return nil
}

// getOrCreateManager returns the per-feed Manager, allocating and
// registering it on first use.
func (c *Controller) getOrCreateManager(feed *securityv1alpha1.ThreatFeed) (*managedFeed, error) {
	c.mu.Lock()
	mf, ok := c.managers[feed.Name]
	c.mu.Unlock()
	if ok {
		// Update cached spec each reconcile; MaxAge changes must take
		// effect without a restart. If the feed URL or Format changed,
		// rebuild the fetcher so the next Refresh hits the new source.
		mf.manager.MaxAge = feed.Spec.MaxAge.Duration
		if specSourceChanged(mf.spec, feed.Spec) {
			newFetcher, err := c.buildFetcher(feed.Spec)
			if err != nil {
				return nil, err
			}
			mf.manager.Fetcher = newFetcher
		}
		mf.spec = feed.Spec
		return mf, nil
	}

	fetcher, err := c.buildFetcher(feed.Spec)
	if err != nil {
		return nil, err
	}

	manager := NewManager(feed.Name, fetcher, c.Cilium, feed.Spec.MaxAge.Duration)
	if c.Now != nil {
		manager.Now = c.Now
	}

	mf = &managedFeed{
		manager: manager,
		spec:    feed.Spec,
	}
	c.mu.Lock()
	c.managers[feed.Name] = mf
	c.mu.Unlock()
	return mf, nil
}

// buildFetcher translates a ThreatFeedSpec into a concrete Fetcher, honouring
// any injected factory in c.NewFetcher. For MISP feeds the controller loads
// the referenced Secret and extracts the API key; other authenticated feed
// types are expected to follow the same pattern.
func (c *Controller) buildFetcher(spec securityv1alpha1.ThreatFeedSpec) (Fetcher, error) {
	if c.NewFetcher != nil {
		return c.NewFetcher(spec)
	}
	switch spec.Format {
	case securityv1alpha1.ThreatFeedFormatURLhausCSV:
		return &URLhausFetcher{
			URL:    spec.URL,
			Client: c.HTTPClient,
		}, nil
	case securityv1alpha1.ThreatFeedFormatMISPJSON:
		apiKey, err := c.loadAPIKey(context.Background(), spec)
		if err != nil {
			return nil, err
		}
		return &MISPFetcher{
			URL:    spec.URL,
			APIKey: apiKey,
			Client: c.HTTPClient,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported threat feed format %q (supported: %q, %q)", spec.Format,
			securityv1alpha1.ThreatFeedFormatURLhausCSV,
			securityv1alpha1.ThreatFeedFormatMISPJSON)
	}
}

// loadAPIKey resolves an AuthSecretRef into the raw API key string. It
// surfaces the specific failure mode (missing ref, missing Secret, missing
// key) in the error so the ThreatFeed.Status condition is diagnosable.
func (c *Controller) loadAPIKey(ctx context.Context, spec securityv1alpha1.ThreatFeedSpec) (string, error) {
	if spec.AuthSecretRef == nil || spec.AuthSecretRef.Name == "" {
		return "", fmt.Errorf("authSecretRef is required for format %q", spec.Format)
	}
	if c.Secrets == nil {
		return "", fmt.Errorf("no Secret reader configured; cannot resolve authSecretRef %q", spec.AuthSecretRef.Name)
	}
	ns := spec.AuthSecretRef.Namespace
	if ns == "" {
		ns = c.DefaultSecretNamespace
	}
	if ns == "" {
		ns = "security"
	}
	data, err := c.Secrets.Read(ctx, ns, spec.AuthSecretRef.Name)
	if err != nil {
		return "", fmt.Errorf("read secret %s/%s: %w", ns, spec.AuthSecretRef.Name, err)
	}
	raw, ok := data[securityv1alpha1.ThreatFeedAuthSecretAPIKey]
	if !ok || len(raw) == 0 {
		return "", fmt.Errorf("secret %s/%s missing %q data key", ns, spec.AuthSecretRef.Name, securityv1alpha1.ThreatFeedAuthSecretAPIKey)
	}
	return string(raw), nil
}

// writeStatus marshalls a status-update closure and persists the result.
func (c *Controller) writeStatus(ctx context.Context, feed *securityv1alpha1.ThreatFeed, mutate func(*securityv1alpha1.ThreatFeedStatus)) error {
	status := feed.Status.DeepCopy()
	if status == nil {
		status = &securityv1alpha1.ThreatFeedStatus{}
	}
	mutate(status)
	if err := c.Store.UpdateStatus(ctx, feed.Name, *status); err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	c.mu.Lock()
	if mf, ok := c.managers[feed.Name]; ok {
		mf.lastStatus = *status
	}
	c.mu.Unlock()

	feed.Status = *status
	return nil
}

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// specSourceChanged reports whether the upstream source identity changed
// between two spec snapshots. Only fields that influence the fetcher's
// identity are compared; RefreshInterval/MaxAge/Enabled are handled in the
// hot path directly. AuthSecretRef is included so rotating the credential
// Secret (pointing at a different Secret) forces a fresh fetcher build and
// re-loads the API key on the next reconcile.
func specSourceChanged(a, b securityv1alpha1.ThreatFeedSpec) bool {
	if a.URL != b.URL || a.Format != b.Format {
		return true
	}
	return !secretRefEqual(a.AuthSecretRef, b.AuthSecretRef)
}

// secretRefEqual reports whether two SecretReference pointers select the same
// Secret. Nil and empty are treated as equivalent.
func secretRefEqual(a, b *corev1.SecretReference) bool {
	aName, aNS := "", ""
	if a != nil {
		aName, aNS = a.Name, a.Namespace
	}
	bName, bNS := "", ""
	if b != nil {
		bName, bNS = b.Name, b.Namespace
	}
	return aName == bName && aNS == bNS
}

// setCondition replaces any existing condition of the same Type and appends
// otherwise. Matches the pattern used by FilterPolicy / NAT controllers.
func setCondition(s *securityv1alpha1.ThreatFeedStatus, condType, status, reason, message string, now time.Time) {
	cond := securityv1alpha1.ThreatFeedCondition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.NewTime(now),
	}
	for i, existing := range s.Conditions {
		if existing.Type == condType {
			if existing.Status == status && existing.Reason == reason && existing.Message == message {
				// No change; preserve prior transition time.
				return
			}
			s.Conditions[i] = cond
			return
		}
	}
	s.Conditions = append(s.Conditions, cond)
}
