package threatintel

import (
	"context"
	"fmt"
	"sync"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
)

// InMemoryFeedStore is a concurrent-safe FeedStore for tests and the CI
// harness. It is not suitable for production use.
type InMemoryFeedStore struct {
	mu    sync.Mutex
	feeds map[string]*securityv1alpha1.ThreatFeed
}

// NewInMemoryFeedStore constructs an empty store.
func NewInMemoryFeedStore() *InMemoryFeedStore {
	return &InMemoryFeedStore{feeds: make(map[string]*securityv1alpha1.ThreatFeed)}
}

// Put stores the supplied feed by .Name, replacing any existing entry. Used
// to seed the store before running Reconcile in tests.
func (s *InMemoryFeedStore) Put(feed securityv1alpha1.ThreatFeed) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := feed.DeepCopy()
	s.feeds[feed.Name] = copy
}

// Delete removes the named feed; matches controller GC semantics.
func (s *InMemoryFeedStore) Delete(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.feeds, name)
}

// Get returns a snapshot of the named feed.
func (s *InMemoryFeedStore) Get(name string) (*securityv1alpha1.ThreatFeed, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.feeds[name]
	if !ok {
		return nil, false
	}
	return f.DeepCopy(), true
}

// List implements FeedStore.
func (s *InMemoryFeedStore) List(ctx context.Context) ([]securityv1alpha1.ThreatFeed, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]securityv1alpha1.ThreatFeed, 0, len(s.feeds))
	for _, f := range s.feeds {
		out = append(out, *f.DeepCopy())
	}
	return out, nil
}

// UpdateStatus implements FeedStore.
func (s *InMemoryFeedStore) UpdateStatus(ctx context.Context, name string, status securityv1alpha1.ThreatFeedStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.feeds[name]
	if !ok {
		return fmt.Errorf("threatfeed %q not found", name)
	}
	status.DeepCopyInto(&f.Status)
	return nil
}
