package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
)

// newTestCSVServer spins up an httptest.Server that serves a supplied CSV
// body. Helper so each controller test case can inject its own feed
// contents.
func newTestCSVServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte(body))
	}))
}

func TestController_UnsupportedFormat(t *testing.T) {
	store := NewInMemoryFeedStore()
	cc := &recordingCilium{}
	store.Put(securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "bogus"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             "http://nowhere",
			Format:          "stix",
			RefreshInterval: metav1.Duration{Duration: time.Minute},
			MaxAge:          metav1.Duration{Duration: time.Hour},
			Enabled:         true,
		},
	})

	ctrl := NewController(store, cc)
	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	feed, _ := store.Get("bogus")
	if feed.Status.LastFetchError == "" {
		t.Error("expected status to carry unsupported-format error")
	}
}

func TestController_DisabledFeed(t *testing.T) {
	store := NewInMemoryFeedStore()
	cc := &recordingCilium{}
	store.Put(securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-feed"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             "http://example/",
			Format:          securityv1alpha1.ThreatFeedFormatURLhausCSV,
			RefreshInterval: metav1.Duration{Duration: time.Minute},
			MaxAge:          metav1.Duration{Duration: time.Hour},
			Enabled:         false,
		},
	})

	ctrl := NewController(store, cc)
	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := len(cc.Applied); got != 0 {
		t.Errorf("disabled feed must not apply policies, got %d", got)
	}
	feed, _ := store.Get("disabled-feed")
	found := false
	for _, c := range feed.Status.Conditions {
		if c.Type == securityv1alpha1.ThreatFeedConditionFetchSucceeded && c.Reason == "Disabled" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected FetchSucceeded=Disabled condition, got %+v", feed.Status.Conditions)
	}
}

// TestController_EndToEndFetchApplyExpire drives the full pipeline using a
// test HTTP server backed by a CSV body. This is the deterministic in-process
// analogue of the CI harness described in the plan: fetch -> translate ->
// apply -> expire, with the canned CSV served by a local pod-equivalent.
func TestController_EndToEndFetchApplyExpire(t *testing.T) {
	feedCSV := `# URLhaus CSV
"1","2026-04-21 12:00:00","http://evil.example.com/drop","online","2026-04-21 12:00:00","malware_download","","",""
"2","2026-04-21 12:00:00","http://bad.example.org/login","online","2026-04-21 12:00:00","phishing","","",""
`
	srv := newTestCSVServer(feedCSV)
	defer srv.Close()

	store := NewInMemoryFeedStore()
	cc := &recordingCilium{}

	base := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	clock := base

	ctrl := NewController(store, cc)
	ctrl.Now = func() time.Time { return clock }

	store.Put(securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "urlhaus"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             srv.URL,
			Format:          securityv1alpha1.ThreatFeedFormatURLhausCSV,
			RefreshInterval: metav1.Duration{Duration: 100 * time.Millisecond},
			MaxAge:          metav1.Duration{Duration: 10 * time.Minute},
			Enabled:         true,
		},
	})

	// First reconcile: fetch, translate, apply.
	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if got := len(cc.Applied); got != 2 {
		t.Fatalf("expected 2 Cilium policies applied, got %d", got)
	}

	feed, _ := store.Get("urlhaus")
	if feed.Status.EntryCount != 2 {
		t.Errorf("expected EntryCount=2, got %d", feed.Status.EntryCount)
	}
	if feed.Status.ActiveIndicators != 2 {
		t.Errorf("expected ActiveIndicators=2, got %d", feed.Status.ActiveIndicators)
	}
	if feed.Status.LastFetchError != "" {
		t.Errorf("expected empty LastFetchError, got %q", feed.Status.LastFetchError)
	}
	if feed.Status.LastFetchTime.IsZero() {
		t.Error("expected LastFetchTime to be populated")
	}

	foundReady := false
	for _, c := range feed.Status.Conditions {
		if c.Type == securityv1alpha1.ThreatFeedConditionReady && c.Status == "True" {
			foundReady = true
		}
	}
	if !foundReady {
		t.Errorf("expected Ready=True condition, got %+v", feed.Status.Conditions)
	}

	// Advance time past MaxAge and flip the feed to empty so the
	// indicators age out.
	clock = base.Add(20 * time.Minute)

	srv2 := newTestCSVServer("# no entries\n")
	defer srv2.Close()
	store.Put(securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "urlhaus"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             srv2.URL,
			Format:          securityv1alpha1.ThreatFeedFormatURLhausCSV,
			RefreshInterval: metav1.Duration{Duration: 100 * time.Millisecond},
			MaxAge:          metav1.Duration{Duration: 10 * time.Minute},
			Enabled:         true,
		},
	})

	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	if got := len(cc.Deleted); got != 2 {
		t.Errorf("expected 2 Cilium policies deleted after TTL, got %d (names=%v)", got, cc.DeletedNames())
	}
	feed, _ = store.Get("urlhaus")
	if feed.Status.ActiveIndicators != 0 {
		t.Errorf("expected ActiveIndicators=0 after expiry, got %d", feed.Status.ActiveIndicators)
	}
}

func TestController_DeletedFeedShutsDownManager(t *testing.T) {
	feedCSV := `"1","2026-04-21 12:00:00","http://evil.example/","online","","malware","","",""
`
	srv := newTestCSVServer(feedCSV)
	defer srv.Close()

	store := NewInMemoryFeedStore()
	cc := &recordingCilium{}
	ctrl := NewController(store, cc)

	store.Put(securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "vanishing"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             srv.URL,
			Format:          securityv1alpha1.ThreatFeedFormatURLhausCSV,
			RefreshInterval: metav1.Duration{Duration: 10 * time.Millisecond},
			MaxAge:          metav1.Duration{Duration: time.Hour},
			Enabled:         true,
		},
	})
	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(cc.Applied) != 1 {
		t.Fatalf("expected 1 policy applied, got %d", len(cc.Applied))
	}

	// Remove the feed — next reconcile should shut its manager down and
	// delete every active policy.
	store.Delete("vanishing")
	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(cc.Deleted) != 1 {
		t.Errorf("expected 1 Cilium delete on feed removal, got %d", len(cc.Deleted))
	}
}

func TestController_MISPFormatRequiresAuthSecretRef(t *testing.T) {
	store := NewInMemoryFeedStore()
	cc := &recordingCilium{}
	ctrl := NewController(store, cc)
	ctrl.Secrets = NewInMemorySecretReader()

	store.Put(securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "misp-missing-ref"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             "https://misp.example.com",
			Format:          securityv1alpha1.ThreatFeedFormatMISPJSON,
			RefreshInterval: metav1.Duration{Duration: time.Minute},
			MaxAge:          metav1.Duration{Duration: time.Hour},
			Enabled:         true,
		},
	})

	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	feed, _ := store.Get("misp-missing-ref")
	if feed.Status.LastFetchError == "" {
		t.Error("expected error indicating authSecretRef required")
	}
	if !strings.Contains(feed.Status.LastFetchError, "authSecretRef") {
		t.Errorf("expected authSecretRef error, got %q", feed.Status.LastFetchError)
	}
}

func TestController_MISPFormatMissingSecret(t *testing.T) {
	store := NewInMemoryFeedStore()
	cc := &recordingCilium{}
	ctrl := NewController(store, cc)
	ctrl.Secrets = NewInMemorySecretReader()

	store.Put(securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "misp-missing-secret"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             "https://misp.example.com",
			Format:          securityv1alpha1.ThreatFeedFormatMISPJSON,
			AuthSecretRef:   &corev1.SecretReference{Name: "misp-creds", Namespace: "security"},
			RefreshInterval: metav1.Duration{Duration: time.Minute},
			MaxAge:          metav1.Duration{Duration: time.Hour},
			Enabled:         true,
		},
	})

	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	feed, _ := store.Get("misp-missing-secret")
	if feed.Status.LastFetchError == "" || !strings.Contains(feed.Status.LastFetchError, "not found") {
		t.Errorf("expected not-found error, got %q", feed.Status.LastFetchError)
	}
}

func TestController_MISPFormatMissingAPIKeyField(t *testing.T) {
	store := NewInMemoryFeedStore()
	cc := &recordingCilium{}
	secrets := NewInMemorySecretReader()
	// Secret exists but lacks the apiKey data key.
	secrets.Put("security", "misp-creds", map[string][]byte{"other": []byte("nope")})

	ctrl := NewController(store, cc)
	ctrl.Secrets = secrets

	store.Put(securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "misp-bad-secret"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             "https://misp.example.com",
			Format:          securityv1alpha1.ThreatFeedFormatMISPJSON,
			AuthSecretRef:   &corev1.SecretReference{Name: "misp-creds", Namespace: "security"},
			RefreshInterval: metav1.Duration{Duration: time.Minute},
			MaxAge:          metav1.Duration{Duration: time.Hour},
			Enabled:         true,
		},
	})

	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	feed, _ := store.Get("misp-bad-secret")
	if feed.Status.LastFetchError == "" || !strings.Contains(feed.Status.LastFetchError, securityv1alpha1.ThreatFeedAuthSecretAPIKey) {
		t.Errorf("expected missing-apiKey error, got %q", feed.Status.LastFetchError)
	}
}

// TestController_MISPEndToEnd drives the full MISP pipeline: ThreatFeed with
// format=misp-json + AuthSecretRef → secret resolved → fetcher calls the
// canned server (with the correct Authorization header) → Cilium policies
// applied.
func TestController_MISPEndToEnd(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":[{"Event":{"id":"1","info":"e2e","Attribute":[
			{"type":"url","value":"http://misp-e2e.example/drop"},
			{"type":"ip-dst","value":"203.0.113.77"}
		]}}]}`))
	}))
	defer srv.Close()

	store := NewInMemoryFeedStore()
	cc := &recordingCilium{}
	secrets := NewInMemorySecretReader()
	secrets.Put("security", "misp-creds", map[string][]byte{
		securityv1alpha1.ThreatFeedAuthSecretAPIKey: []byte("e2e-key"),
	})

	ctrl := NewController(store, cc)
	ctrl.Secrets = secrets
	ctrl.DefaultSecretNamespace = "security"

	store.Put(securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "misp-e2e"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             srv.URL,
			Format:          securityv1alpha1.ThreatFeedFormatMISPJSON,
			AuthSecretRef:   &corev1.SecretReference{Name: "misp-creds"},
			RefreshInterval: metav1.Duration{Duration: 50 * time.Millisecond},
			MaxAge:          metav1.Duration{Duration: 10 * time.Minute},
			Enabled:         true,
		},
	})

	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if gotAuth != "e2e-key" {
		t.Errorf("expected server to receive Authorization=e2e-key, got %q", gotAuth)
	}
	if got := len(cc.Applied); got != 2 {
		t.Fatalf("expected 2 Cilium policies applied, got %d (names=%v)", got, cc.AppliedNames())
	}
	feed, _ := store.Get("misp-e2e")
	if feed.Status.EntryCount != 2 {
		t.Errorf("expected EntryCount=2, got %d", feed.Status.EntryCount)
	}
	if feed.Status.LastFetchError != "" {
		t.Errorf("expected empty LastFetchError, got %q", feed.Status.LastFetchError)
	}
}

func TestController_UsesInjectedFetcher(t *testing.T) {
	store := NewInMemoryFeedStore()
	cc := &recordingCilium{}
	ctrl := NewController(store, cc)
	ctrl.NewFetcher = func(spec securityv1alpha1.ThreatFeedSpec) (Fetcher, error) {
		return &staticFetcher{Indicators: []Indicator{{URL: "http://injected.example/"}}}, nil
	}

	store.Put(securityv1alpha1.ThreatFeed{
		ObjectMeta: metav1.ObjectMeta{Name: "injected"},
		Spec: securityv1alpha1.ThreatFeedSpec{
			URL:             "unused",
			Format:          "anything", // fetcher factory is overridden
			RefreshInterval: metav1.Duration{Duration: 10 * time.Millisecond},
			MaxAge:          metav1.Duration{Duration: time.Hour},
			Enabled:         true,
		},
	})
	if err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := len(cc.Applied); got != 1 {
		t.Errorf("expected injected fetcher to produce 1 policy, got %d", got)
	}
}
