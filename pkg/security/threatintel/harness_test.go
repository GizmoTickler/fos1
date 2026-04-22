//go:build harness

// Package threatintel harness test — this is the Sprint-30 Ticket-44
// CI harness. It boots a local HTTP server (the "test pod" equivalent of an
// in-cluster nginx), stands up an in-memory ThreatFeed store, runs the
// controller reconcile cycle, and asserts the end-to-end fetch -> translate
// -> apply -> expire pipeline operates against the canned feed.
//
// Run with:
//
//	go test -tags=harness ./pkg/security/threatintel/... -run Harness -v
//
// The test is behind a build tag so it never runs in the default verify
// path; the scripts/harness-threatintel.sh wrapper is the canonical invoker.
package threatintel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
)

const harnessCSV = `# URLhaus CSV (canned for Sprint-30 Ticket-44 harness)
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-04-21 12:00:00","http://harness-malware.example/drop.exe","online","2026-04-21 12:00:00","malware_download","exe,emotet","https://urlhaus.abuse.ch/url/1","harness"
"2","2026-04-21 12:00:00","https://harness-phish.example/login","online","2026-04-21 12:00:00","phishing","login","https://urlhaus.abuse.ch/url/2","harness"
"3","2026-04-21 12:00:00","http://harness-c2.example/beacon","online","2026-04-21 12:00:00","c2","beacon","https://urlhaus.abuse.ch/url/3","harness"
`

// TestHarness_EndToEnd is the end-to-end proof required by the ticket's
// acceptance criteria. It intentionally exercises the full pipeline:
// ThreatFeed CR -> controller reconcile -> HTTP fetch -> CSV parse ->
// translator -> Cilium apply; then advance the clock and prove TTL expiry
// removes every applied policy.
func TestHarness_EndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(harnessCSV))
	}))
	defer srv.Close()

	store := NewInMemoryFeedStore()
	cilium := &recordingCilium{}

	base := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	clock := base

	ctrl := NewController(store, cilium)
	ctrl.Now = func() time.Time { return clock }
	ctrl.TickInterval = 10 * time.Millisecond

	feed := securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "urlhaus-harness"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             srv.URL,
			Format:          securityv1alpha1.ThreatFeedFormatURLhausCSV,
			RefreshInterval: metav1.Duration{Duration: 50 * time.Millisecond},
			MaxAge:          metav1.Duration{Duration: 5 * time.Minute},
			Enabled:         true,
		},
	}
	store.Put(feed)

	// Step 1: reconcile — expect 3 policies applied.
	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("harness: reconcile 1: %v", err)
	}

	applied := cilium.AppliedNames()
	if len(applied) != 3 {
		t.Fatalf("harness: expected 3 Cilium policies applied, got %d: %v", len(applied), applied)
	}
	for _, name := range applied {
		if !strings.HasPrefix(name, "fos1-threatintel-urlhaus-harness-") {
			t.Errorf("harness: policy %q missing expected prefix", name)
		}
	}

	cur, _ := store.Get("urlhaus-harness")
	if cur.Status.EntryCount != 3 {
		t.Errorf("harness: expected EntryCount=3, got %d", cur.Status.EntryCount)
	}
	if cur.Status.ActiveIndicators != 3 {
		t.Errorf("harness: expected ActiveIndicators=3, got %d", cur.Status.ActiveIndicators)
	}
	if cur.Status.LastFetchError != "" {
		t.Errorf("harness: expected empty LastFetchError, got %q", cur.Status.LastFetchError)
	}

	fmt.Printf("HARNESS OK: initial reconcile applied %d policies: %v\n", len(applied), applied)

	// Step 2: swap feed to empty and advance past MaxAge. Expect expiry of
	// all 3 indicators.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# empty harness feed\n"))
	}))
	defer srv2.Close()

	clock = base.Add(10 * time.Minute)
	feed.Spec.URL = srv2.URL
	store.Put(feed)

	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("harness: reconcile 2: %v", err)
	}

	deleted := cilium.DeletedNames()
	if len(deleted) != 3 {
		t.Fatalf("harness: expected 3 Cilium deletes after TTL, got %d: %v", len(deleted), deleted)
	}
	sort.Strings(applied)
	sort.Strings(deleted)
	if strings.Join(applied, ",") != strings.Join(deleted, ",") {
		t.Errorf("harness: deleted set must match applied set; applied=%v deleted=%v", applied, deleted)
	}

	cur, _ = store.Get("urlhaus-harness")
	if cur.Status.ActiveIndicators != 0 {
		t.Errorf("harness: expected ActiveIndicators=0 after expiry, got %d", cur.Status.ActiveIndicators)
	}

	fmt.Printf("HARNESS OK: TTL expiry removed %d policies: %v\n", len(deleted), deleted)
}
