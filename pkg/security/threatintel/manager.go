// Package threatintel implements the Sprint-30 Ticket-44 v0 threat-intelligence
// feed ingester: fetch a blocklist on an interval, translate indicators into
// Cilium deny policies, and expire them on a max-age timer.
//
// The package is deliberately feed-agnostic in its public API even though v0
// ships with a single URLhaus CSV connector. Additional formats plug in as
// Fetcher implementations registered with the Manager.
package threatintel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"k8s.io/klog/v2"
)

// Fetcher returns a slice of Indicator records for the configured feed. The
// concrete URLhausFetcher is the v0 implementation; tests inject in-memory
// doubles.
type Fetcher interface {
	Fetch(ctx context.Context) ([]Indicator, error)
}

// FetchResult summarizes what a single refresh cycle changed.
type FetchResult struct {
	// FetchedAt is the timestamp the refresh started.
	FetchedAt time.Time

	// EntryCount is the number of rows produced by the feed parser
	// (including duplicates and unresolvable entries).
	EntryCount int

	// UnresolvedCount tracks rows the translator could not turn into a
	// policy (malformed URL, empty host).
	UnresolvedCount int

	// Created is the set of indicator keys newly added this cycle.
	Created []string

	// Refreshed is the set of indicator keys seen again this cycle (their
	// last-seen time advanced; no policy re-apply needed).
	Refreshed []string

	// Expired is the set of indicator keys whose MaxAge elapsed and whose
	// corresponding Cilium policies were removed.
	Expired []string
}

// activeIndicator is the manager's bookkeeping record for a single enforced
// indicator. It mirrors the DPI policy pipeline's ActivePolicy struct, but
// is keyed by the stable translator key (not an event source IP).
type activeIndicator struct {
	PolicyName string
	Policy     *cilium.CiliumPolicy
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Manager owns the lifecycle of one ThreatFeed's indicators. It is safe for
// concurrent use.
type Manager struct {
	// FeedName is the ThreatFeed CR name; used by the translator to scope
	// policy names.
	FeedName string

	// Fetcher produces indicators for each refresh cycle.
	Fetcher Fetcher

	// Cilium is the client used to apply and delete network policies.
	Cilium cilium.CiliumClient

	// MaxAge bounds how long an indicator stays enforced after it was last
	// observed in a successful fetch. A value of zero disables expiry.
	MaxAge time.Duration

	// Now returns the current time; injected for deterministic tests.
	// Defaults to time.Now.
	Now func() time.Time

	translator *Translator

	mu       sync.Mutex
	active   map[string]*activeIndicator
	lastSync time.Time
}

// NewManager constructs a Manager. It does not start any background loops;
// call Refresh directly, or wrap it in a controller reconcile.
func NewManager(feedName string, fetcher Fetcher, client cilium.CiliumClient, maxAge time.Duration) *Manager {
	return &Manager{
		FeedName:   feedName,
		Fetcher:    fetcher,
		Cilium:     client,
		MaxAge:     maxAge,
		translator: &Translator{FeedName: feedName},
		active:     make(map[string]*activeIndicator),
	}
}

// Translator returns the manager's underlying translator. Exposed so the
// controller can reuse the same naming scheme when it needs to reference a
// policy by indicator key outside a Refresh cycle.
func (m *Manager) Translator() *Translator { return m.translator }

// ActiveCount returns the number of indicators currently enforced.
func (m *Manager) ActiveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}

// Active returns a snapshot of the currently enforced indicators, keyed by
// the translator's stable indicator key.
func (m *Manager) Active() map[string]time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]time.Time, len(m.active))
	for k, v := range m.active {
		out[k] = v.LastSeen
	}
	return out
}

// Refresh runs a single fetch + translate + apply + expire cycle. It is safe
// to call concurrently with itself; internal locking serializes state updates.
func (m *Manager) Refresh(ctx context.Context) (*FetchResult, error) {
	if m.Fetcher == nil {
		return nil, fmt.Errorf("threatintel: no fetcher configured for feed %q", m.FeedName)
	}
	if m.Cilium == nil {
		return nil, fmt.Errorf("threatintel: no cilium client configured for feed %q", m.FeedName)
	}

	now := m.now()
	indicators, err := m.Fetcher.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("threatintel: fetch feed %q: %w", m.FeedName, err)
	}

	tr := m.translator.Translate(indicators)

	result := &FetchResult{
		FetchedAt:       now,
		EntryCount:      len(indicators),
		UnresolvedCount: tr.UnresolvedCount,
	}

	m.mu.Lock()
	// Apply the new/refreshed set. Keep the lock held while we touch the
	// active map so expiry pass sees a consistent view. ApplyNetworkPolicy
	// is tolerant of duplicate applies, so we only call it on first-seen
	// keys.
	m.mu.Unlock()

	for i, key := range tr.Keys {
		policy := tr.Policies[i]
		m.mu.Lock()
		existing, seen := m.active[key]
		m.mu.Unlock()

		if seen {
			existing.LastSeen = now
			result.Refreshed = append(result.Refreshed, key)
			continue
		}

		if err := m.Cilium.ApplyNetworkPolicy(ctx, policy); err != nil {
			klog.Warningf("threatintel: apply policy %s for feed %q: %v", policy.Name, m.FeedName, err)
			// Continue so one flaky apply doesn't strand the rest of the
			// fetch; the indicator will be retried on the next cycle.
			continue
		}

		m.mu.Lock()
		m.active[key] = &activeIndicator{
			PolicyName: policy.Name,
			Policy:     policy,
			FirstSeen:  now,
			LastSeen:   now,
		}
		m.mu.Unlock()
		result.Created = append(result.Created, key)
	}

	// Expire anything older than MaxAge, or (when MaxAge is zero) anything
	// missing from this fetch if the feed was non-empty. v0 policy is
	// strict last-seen expiry against MaxAge; we do not remove stale
	// entries on empty fetches because a transient upstream failure should
	// not wipe enforcement.
	expired := m.expireLocked(ctx, now)
	result.Expired = append(result.Expired, expired...)

	m.mu.Lock()
	m.lastSync = now
	m.mu.Unlock()

	return result, nil
}

// expireLocked walks the active set and removes indicators whose LastSeen is
// older than MaxAge. Errors deleting the Cilium policy are logged; the entry
// is retained so the next cycle can retry.
func (m *Manager) expireLocked(ctx context.Context, now time.Time) []string {
	if m.MaxAge <= 0 {
		return nil
	}

	var expired []string
	m.mu.Lock()
	keys := make([]string, 0, len(m.active))
	for k, v := range m.active {
		if now.Sub(v.LastSeen) > m.MaxAge {
			keys = append(keys, k)
		}
	}
	m.mu.Unlock()

	for _, key := range keys {
		m.mu.Lock()
		entry, ok := m.active[key]
		m.mu.Unlock()
		if !ok {
			continue
		}
		if err := m.Cilium.DeleteNetworkPolicy(ctx, entry.PolicyName); err != nil {
			klog.Warningf("threatintel: delete expired policy %s for feed %q: %v", entry.PolicyName, m.FeedName, err)
			continue
		}
		m.mu.Lock()
		delete(m.active, key)
		m.mu.Unlock()
		expired = append(expired, key)
		klog.Infof("threatintel: expired indicator %s (feed=%s policy=%s)", key, m.FeedName, entry.PolicyName)
	}
	return expired
}

// ExpireStale is a manual trigger for the expiry pass. Useful for tests and
// for controllers that want to advance time without running a full fetch.
func (m *Manager) ExpireStale(ctx context.Context) []string {
	return m.expireLocked(ctx, m.now())
}

// Shutdown removes every active policy. Intended for controller tear-down
// when a ThreatFeed CR is deleted. Errors are logged but not returned so one
// flaky delete doesn't block the rest.
func (m *Manager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	keys := make([]string, 0, len(m.active))
	for k := range m.active {
		keys = append(keys, k)
	}
	m.mu.Unlock()

	for _, key := range keys {
		m.mu.Lock()
		entry := m.active[key]
		m.mu.Unlock()
		if entry == nil {
			continue
		}
		if err := m.Cilium.DeleteNetworkPolicy(ctx, entry.PolicyName); err != nil {
			klog.Warningf("threatintel: shutdown delete %s: %v", entry.PolicyName, err)
			continue
		}
		m.mu.Lock()
		delete(m.active, key)
		m.mu.Unlock()
	}
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}
