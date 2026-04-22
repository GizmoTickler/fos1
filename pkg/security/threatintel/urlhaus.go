package threatintel

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Indicator is a parsed entry from a threat-intelligence feed.
//
// URL carries the full indicator string as published by the feed. DateAdded
// is the ingestion-time timestamp reported by the feed (for dedup / ordering),
// and Threat is a free-form category tag. Fields empty in the source feed
// are left as zero values.
type Indicator struct {
	// URL is the full URL reported as malicious. Empty lines and offline
	// entries are filtered out during parsing.
	URL string

	// Threat is the classification tag from the feed (e.g. "malware_download").
	Threat string

	// DateAdded is the time the entry was first added to the feed.
	DateAdded time.Time

	// Tags is the raw tag list supplied by the feed, separated verbatim.
	Tags string
}

// URLhausFetcher fetches and parses the abuse.ch URLhaus CSV feed.
//
// The feed is comma-separated with one URL per row. Comment lines begin with
// "#" and are skipped. The expected header columns are:
//
//	id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
//
// Rows whose url_status is "offline" are filtered out so expired infrastructure
// is not re-enforced on every refresh.
type URLhausFetcher struct {
	// Client is the HTTP client used to fetch the feed. If nil, a default
	// client with a 30-second timeout is constructed per-fetch.
	Client *http.Client

	// URL is the feed endpoint. If empty, Fetch returns an error.
	URL string

	// Now returns the current time; injected for deterministic tests. If
	// nil, time.Now is used.
	Now func() time.Time
}

// Fetch retrieves the feed and returns the parsed indicators. The caller is
// responsible for deduplication and expiry; Fetch returns every row from the
// feed that passes the status/URL filters, in source order.
func (f *URLhausFetcher) Fetch(ctx context.Context) ([]Indicator, error) {
	if f.URL == "" {
		return nil, fmt.Errorf("urlhaus: feed URL is required")
	}

	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: build request: %w", err)
	}
	req.Header.Set("Accept", "text/csv,text/plain")
	req.Header.Set("User-Agent", "fos1-threatintel/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("urlhaus: fetch %s: %w", f.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain a small amount of the body for diagnostics but don't hold
		// the whole response in memory.
		snippet := make([]byte, 256)
		n, _ := io.ReadFull(resp.Body, snippet)
		return nil, fmt.Errorf("urlhaus: unexpected status %d: %s", resp.StatusCode, string(snippet[:n]))
	}

	return parseURLhausCSV(resp.Body)
}

// parseURLhausCSV parses the URLhaus CSV body. Exported via Parse for tests.
func parseURLhausCSV(r io.Reader) ([]Indicator, error) {
	reader := csv.NewReader(r)
	reader.Comment = '#'
	reader.FieldsPerRecord = -1 // tolerate trailing-comma variance
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	var indicators []Indicator
	lineNum := 0
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("urlhaus: parse line %d: %w", lineNum+1, err)
		}
		lineNum++

		// Skip header row if present.
		if len(row) > 0 && (row[0] == "id" || strings.EqualFold(row[0], "id")) {
			continue
		}

		// URLhaus schema: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
		// Accept short rows but require at least through url_status (index 3).
		if len(row) < 4 {
			continue
		}

		rawURL := strings.TrimSpace(row[2])
		if rawURL == "" {
			continue
		}

		status := strings.TrimSpace(row[3])
		// Skip offline entries — they should not drive active enforcement.
		if strings.EqualFold(status, "offline") {
			continue
		}

		ind := Indicator{URL: rawURL}
		if t, err := parseURLhausTime(strings.TrimSpace(row[1])); err == nil {
			ind.DateAdded = t
		}
		if len(row) > 5 {
			ind.Threat = strings.TrimSpace(row[5])
		}
		if len(row) > 6 {
			ind.Tags = strings.TrimSpace(row[6])
		}

		indicators = append(indicators, ind)
	}

	return indicators, nil
}

// ParseURLhausCSV is the public entry point for parsing a URLhaus CSV body.
// It exists so the fetcher package can be unit-tested against local fixtures
// without touching the network.
func ParseURLhausCSV(r io.Reader) ([]Indicator, error) {
	return parseURLhausCSV(r)
}

// parseURLhausTime accepts the timestamp format published by URLhaus
// ("YYYY-MM-DD HH:MM:SS", UTC). An unparseable value yields a zero time.
func parseURLhausTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	// URLhaus publishes naive UTC timestamps.
	layouts := []string{"2006-01-02 15:04:05", time.RFC3339}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time format: %q", s)
}
