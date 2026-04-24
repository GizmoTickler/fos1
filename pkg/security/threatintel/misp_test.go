package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sampleMISPJSON is the canned MISP events/restSearch response used across
// the parser and fetcher tests. Three events with seven parseable attributes
// plus two that should be ignored (a hash and an email-src).
const sampleMISPJSON = `{
  "response": [
    {
      "Event": {
        "id": "1001",
        "info": "Phishing campaign",
        "timestamp": "1713720000",
        "Attribute": [
          { "type": "url", "value": "http://evil.example.com/phish" },
          { "type": "domain", "value": "evil.example.com" },
          { "type": "ip-dst", "value": "203.0.113.10" },
          { "type": "sha256", "value": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" }
        ]
      }
    },
    {
      "Event": {
        "id": "1002",
        "info": "C2 infrastructure",
        "timestamp": "1713806400",
        "Attribute": [
          { "type": "ip-src", "value": "198.51.100.42" },
          { "type": "domain", "value": "c2.example.net" },
          { "type": "email-src", "value": "attacker@example.com" }
        ]
      }
    },
    {
      "Event": {
        "id": "1003",
        "info": "Repeat observation",
        "timestamp": "1713892800",
        "Attribute": [
          { "type": "url", "value": "http://evil.example.com/phish" },
          { "type": "ip-dst", "value": "2001:db8::1" }
        ]
      }
    }
  ]
}`

func TestParseMISPJSON_ExtractsSupportedAttributes(t *testing.T) {
	indicators, err := ParseMISPJSON([]byte(sampleMISPJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Expected: 3 urls/domains + 2 ipv4 + 1 ipv6 = 6 unique supported
	// values. The url in event 1003 is a duplicate of event 1001 and must
	// be collapsed; sha256 and email-src are skipped.
	if got, want := len(indicators), 6; got != want {
		t.Fatalf("expected %d indicators, got %d: %+v", want, got, indicators)
	}

	// Every indicator should carry a non-zero DateAdded and a Threat hint.
	for _, ind := range indicators {
		if ind.URL == "" {
			t.Errorf("indicator missing URL: %+v", ind)
		}
		if ind.DateAdded.IsZero() {
			t.Errorf("indicator missing DateAdded: %+v", ind)
		}
	}
}

func TestParseMISPJSON_EmptyResponse(t *testing.T) {
	indicators, err := ParseMISPJSON([]byte(`{"response": []}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(indicators) != 0 {
		t.Errorf("expected 0 indicators from empty response, got %d", len(indicators))
	}
}

func TestParseMISPJSON_MalformedBody(t *testing.T) {
	_, err := ParseMISPJSON([]byte(`{"response": [BROKEN`))
	if err == nil {
		t.Fatal("expected decode error for malformed JSON")
	}
}

func TestMISPFetch_Success(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if !strings.HasSuffix(r.URL.Path, mispAPIPath) {
			t.Errorf("expected request to %s, got %s", mispAPIPath, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleMISPJSON))
	}))
	defer srv.Close()

	f := &MISPFetcher{URL: srv.URL, APIKey: "sekret-key", Client: &http.Client{Timeout: 5 * time.Second}}
	indicators, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(indicators) != 6 {
		t.Fatalf("expected 6 indicators, got %d", len(indicators))
	}
	if gotAuth != "sekret-key" {
		t.Errorf("expected Authorization header 'sekret-key', got %q", gotAuth)
	}
}

func TestMISPFetch_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	f := &MISPFetcher{URL: srv.URL, APIKey: "bad-key"}
	_, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected auth-failed error, got %v", err)
	}
	// The API key must not leak into the error message.
	if strings.Contains(err.Error(), "bad-key") {
		t.Errorf("error must not contain API key, got %v", err)
	}
}

func TestMISPFetch_RateLimitRetriesOnce(t *testing.T) {
	var calls int32
	var sleptFor time.Duration

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response": [{"Event": {"id":"1","info":"x","Attribute":[{"type":"url","value":"http://retry.example/"}]}}]}`))
	}))
	defer srv.Close()

	f := &MISPFetcher{
		URL:        srv.URL,
		APIKey:     "k",
		MaxRetries: 1,
		Sleep:      func(d time.Duration) { sleptFor = d },
	}
	indicators, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Errorf("expected 2 HTTP calls (429 then 200), got %d", calls)
	}
	if sleptFor != 2*time.Second {
		t.Errorf("expected 2s Retry-After sleep, got %v", sleptFor)
	}
	if len(indicators) != 1 {
		t.Errorf("expected 1 indicator, got %d", len(indicators))
	}
}

func TestMISPFetch_RateLimitExhaustsRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	f := &MISPFetcher{
		URL:        srv.URL,
		APIKey:     "k",
		MaxRetries: 1,
		Sleep:      func(d time.Duration) {}, // no-op sleeper
	}
	_, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected rate-limit error after retries exhausted")
	}
	if atomic.LoadInt32(&calls) != 2 {
		// Initial attempt + one retry.
		t.Errorf("expected 2 HTTP calls (1 initial + 1 retry), got %d", calls)
	}
}

func TestMISPFetch_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response": [BROKEN`))
	}))
	defer srv.Close()

	f := &MISPFetcher{URL: srv.URL, APIKey: "k"}
	_, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "decode response") {
		t.Errorf("expected decode-response error, got %v", err)
	}
}

func TestMISPFetch_MissingURL(t *testing.T) {
	f := &MISPFetcher{APIKey: "k"}
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error when URL is empty")
	}
}

func TestMISPFetch_MissingAPIKey(t *testing.T) {
	f := &MISPFetcher{URL: "http://unused"}
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error when APIKey is empty")
	}
}

func TestMISPEndpoint_PreservesExistingPath(t *testing.T) {
	// A base URL without the path gets /events/restSearch appended.
	got, err := mispEndpoint("https://misp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://misp.example.com/events/restSearch" {
		t.Errorf("bare base URL: got %s", got)
	}
	// A URL that already ends in /events/restSearch is preserved.
	got, err = mispEndpoint("https://misp.example.com/events/restSearch")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://misp.example.com/events/restSearch" {
		t.Errorf("pre-suffixed URL: got %s", got)
	}
	// Trailing slashes are tolerated.
	got, err = mispEndpoint("https://misp.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://misp.example.com/events/restSearch" {
		t.Errorf("trailing-slash URL: got %s", got)
	}
}

func TestParseRetryAfter_Forms(t *testing.T) {
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	// Integer seconds.
	if d := parseRetryAfter("30", now); d != 30*time.Second {
		t.Errorf("expected 30s, got %v", d)
	}
	// HTTP-date in the future.
	future := now.Add(2 * time.Minute).UTC().Format(http.TimeFormat)
	if d := parseRetryAfter(future, now); d < time.Minute || d > 3*time.Minute {
		t.Errorf("expected ~2m, got %v", d)
	}
	// Empty falls back to 5s default.
	if d := parseRetryAfter("", now); d != 5*time.Second {
		t.Errorf("expected 5s default, got %v", d)
	}
	// Garbage falls back to 5s.
	if d := parseRetryAfter("soon-ish", now); d != 5*time.Second {
		t.Errorf("expected 5s fallback, got %v", d)
	}
}
