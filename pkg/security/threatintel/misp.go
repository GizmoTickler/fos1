package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MISP attribute types this v0 implementation knows how to translate. Anything
// else is silently skipped — the translator would not be able to build a
// Cilium rule for hash / email / TTP indicators.
const (
	mispAttrURL    = "url"
	mispAttrDomain = "domain"
	mispAttrIPDst  = "ip-dst"
	mispAttrIPSrc  = "ip-src"
)

// mispAPIPath is appended to the feed URL when sending a search request. The
// MISP REST API exposes `POST /events/restSearch` (with `returnFormat=json`)
// as its canonical indicator-pull endpoint.
const mispAPIPath = "/events/restSearch"

// MISPFetcher fetches and parses a MISP event export, emitting Indicator
// records for supported attribute types (url / domain / ip-src / ip-dst).
//
// Authentication is API-key only in v0: the key is sent via the
// `Authorization` header as MISP expects. The key itself is not logged and
// the fetcher never surfaces it in error messages.
//
// The fetcher tolerates MISP's documented rate-limit behaviour (HTTP 429 with
// a `Retry-After` header) by waiting for the advertised duration and
// retrying exactly once before giving up. Subsequent 429s bubble up as
// errors so the controller can back off on the next reconcile.
type MISPFetcher struct {
	// URL is the MISP instance base URL (e.g. "https://misp.example.com").
	// The "/events/restSearch" suffix is appended automatically. A request
	// path already present on the URL is preserved (callers may point at a
	// non-standard MISP proxy).
	URL string

	// APIKey is the MISP auth key. Required.
	APIKey string

	// Client is the HTTP client used to talk to MISP. If nil, a default
	// client with a 30-second timeout is constructed per-fetch.
	Client *http.Client

	// MaxRetries bounds how many 429 retries the fetcher performs per call.
	// A value of 0 means "one retry allowed". Negative values disable retry.
	MaxRetries int

	// Now returns the current time; injected for deterministic tests. If
	// nil, time.Now is used.
	Now func() time.Time

	// Sleep is invoked to pause before a retry. Injected for tests so they
	// do not have to wait on real clock time. If nil, time.Sleep is used.
	Sleep func(d time.Duration)
}

// mispResponse mirrors the shape of a MISP `events/restSearch` JSON payload:
//
//	{"response": [ {"Event": {"id": "...", "info": "...", "Attribute": [...]}} ]}
//
// Only the fields this v0 uses are decoded; everything else is ignored so
// forward-compatible additions to the MISP schema don't break parsing.
type mispResponse struct {
	Response []mispEventEnvelope `json:"response"`
}

type mispEventEnvelope struct {
	Event mispEvent `json:"Event"`
}

type mispEvent struct {
	ID        string          `json:"id"`
	Info      string          `json:"info"`
	Timestamp string          `json:"timestamp"`
	Attribute []mispAttribute `json:"Attribute"`
}

type mispAttribute struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Timestamp string `json:"timestamp"`
	Category  string `json:"category"`
}

// Fetch retrieves the configured MISP feed and returns the parsed indicators.
// Duplicate values observed in multiple events collapse to a single Indicator
// (the translator would otherwise dedup them by host, but early dedup keeps
// status counts intuitive).
func (f *MISPFetcher) Fetch(ctx context.Context) ([]Indicator, error) {
	if f.URL == "" {
		return nil, fmt.Errorf("misp: feed URL is required")
	}
	if f.APIKey == "" {
		return nil, fmt.Errorf("misp: API key is required")
	}

	endpoint, err := mispEndpoint(f.URL)
	if err != nil {
		return nil, err
	}

	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	retries := f.MaxRetries
	if retries == 0 {
		retries = 1
	}

	var body []byte
	attempts := 0
	for {
		attempts++
		b, retryAfter, err := f.doRequest(ctx, client, endpoint)
		if err == nil {
			body = b
			break
		}
		if !errIsRateLimit(err) || attempts > retries {
			return nil, err
		}
		// Rate-limited: wait the advertised Retry-After and try again.
		f.sleep(retryAfter)
	}

	return parseMISPJSON(body)
}

// doRequest performs a single GET to the MISP endpoint and returns the body
// on 2xx, a rate-limit error carrying the Retry-After duration on 429, or a
// general error otherwise. The body is eagerly buffered because MISP servers
// sometimes stream large responses and we want a single read under timeout.
func (f *MISPFetcher) doRequest(ctx context.Context, client *http.Client, endpoint string) ([]byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("misp: build request: %w", err)
	}
	req.Header.Set("Authorization", f.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fos1-threatintel/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("misp: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		wait := parseRetryAfter(resp.Header.Get("Retry-After"), f.now())
		// Cap absurd Retry-After values so a misbehaving server can't stall
		// the reconcile loop indefinitely.
		if wait > 5*time.Minute {
			wait = 5 * time.Minute
		}
		return nil, wait, rateLimitError{retryAfter: wait}
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, 0, fmt.Errorf("misp: authentication failed (HTTP %d)", resp.StatusCode)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := make([]byte, 256)
		n, _ := io.ReadFull(resp.Body, snippet)
		return nil, 0, fmt.Errorf("misp: unexpected status %d: %s", resp.StatusCode, string(snippet[:n]))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("misp: read body: %w", err)
	}
	return body, 0, nil
}

// rateLimitError signals that the request hit a 429 with a Retry-After.
type rateLimitError struct {
	retryAfter time.Duration
}

func (e rateLimitError) Error() string {
	return fmt.Sprintf("misp: rate limited, retry after %s", e.retryAfter)
}

// errIsRateLimit reports whether the error is a rateLimitError.
func errIsRateLimit(err error) bool {
	_, ok := err.(rateLimitError)
	return ok
}

// parseMISPJSON decodes a MISP JSON response and emits Indicators. Exported
// via ParseMISPJSON for unit tests that want to exercise parsing without the
// HTTP layer.
func parseMISPJSON(body []byte) ([]Indicator, error) {
	var resp mispResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("misp: decode response: %w", err)
	}

	seen := make(map[string]struct{})
	indicators := make([]Indicator, 0)

	for _, env := range resp.Response {
		evt := env.Event
		for _, attr := range evt.Attribute {
			val := strings.TrimSpace(attr.Value)
			if val == "" {
				continue
			}

			// v0 only cares about url / domain / ip-src / ip-dst.
			switch strings.ToLower(strings.TrimSpace(attr.Type)) {
			case mispAttrURL, mispAttrDomain, mispAttrIPDst, mispAttrIPSrc:
			default:
				continue
			}

			key := strings.ToLower(val)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}

			// Feed the raw indicator through the shared translator by
			// reusing Indicator.URL for all supported MISP attribute types.
			// domain / ip-dst / ip-src values are not URLs, but extractHost
			// handles bare hostnames and IP literals (it prefixes "http://"
			// when no scheme is present), and isIPLiteral distinguishes the
			// CIDR vs FQDN output branch in the translator.
			ind := Indicator{
				URL:    val,
				Threat: fieldOrDefault(evt.Info, ""),
				Tags:   fieldOrDefault(attr.Category, ""),
			}
			if ts := parseMISPTimestamp(attr.Timestamp); !ts.IsZero() {
				ind.DateAdded = ts
			} else if ts := parseMISPTimestamp(evt.Timestamp); !ts.IsZero() {
				ind.DateAdded = ts
			}

			indicators = append(indicators, ind)
		}
	}

	return indicators, nil
}

// ParseMISPJSON is the exported entry point for tests that want to parse a
// canned MISP response from memory.
func ParseMISPJSON(body []byte) ([]Indicator, error) {
	return parseMISPJSON(body)
}

// mispEndpoint ensures the supplied base URL carries the restSearch suffix.
// Callers may pass either `https://misp.example.com` or the full
// `https://misp.example.com/events/restSearch` — both resolve to the same
// target.
func mispEndpoint(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("misp: empty URL")
	}
	// Strip trailing slash to keep concatenation predictable.
	trimmed = strings.TrimRight(trimmed, "/")
	if strings.HasSuffix(trimmed, mispAPIPath) {
		return trimmed, nil
	}
	return trimmed + mispAPIPath, nil
}

// parseRetryAfter understands both forms of the Retry-After header: an
// integer number of seconds, or an HTTP-date. Unparseable values fall back to
// a conservative default so the caller at least pauses briefly before retry.
func parseRetryAfter(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 5 * time.Second
	}
	if secs, err := strconv.Atoi(header); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(header); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 5 * time.Second
}

// parseMISPTimestamp accepts both the Unix-epoch string form ("1713720000")
// published in modern MISP responses and the ISO-8601 form used by some
// exports. Zero times signal "unknown".
func parseMISPTimestamp(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if epoch, err := strconv.ParseInt(s, 10, 64); err == nil && epoch > 0 {
		return time.Unix(epoch, 0).UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// fieldOrDefault returns s when non-empty, otherwise the fallback.
func fieldOrDefault(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// now returns the injected clock or time.Now.
func (f *MISPFetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// sleep pauses via the injected sleeper or time.Sleep.
func (f *MISPFetcher) sleep(d time.Duration) {
	if d <= 0 {
		return
	}
	if f.Sleep != nil {
		f.Sleep(d)
		return
	}
	time.Sleep(d)
}
