package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const sampleURLhausCSV = `# URLhaus CSV feed (sample)
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-04-20 12:34:56","http://malicious.example.com/drop.exe","online","2026-04-21 00:00:00","malware_download","emotet,exe","https://urlhaus.abuse.ch/url/1","reporter1"
"2","2026-04-20 13:00:00","https://phish.example.org/login","online","2026-04-21 00:00:00","phishing","login,bank","https://urlhaus.abuse.ch/url/2","reporter2"
"3","2026-04-19 09:00:00","http://offline.example.net/","offline","2026-04-19 10:00:00","malware_download","old","https://urlhaus.abuse.ch/url/3","reporter1"
"4","2026-04-20 14:00:00","","online","2026-04-21 00:00:00","malware_download","","https://urlhaus.abuse.ch/url/4","reporter1"
"5","2026-04-20 15:00:00","http://ip-indicator.example/","online","2026-04-21 00:00:00","c2","ip","https://urlhaus.abuse.ch/url/5","reporter3"
`

func TestParseURLhausCSV_FiltersOfflineAndEmpty(t *testing.T) {
	indicators, err := ParseURLhausCSV(strings.NewReader(sampleURLhausCSV))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := len(indicators), 3; got != want {
		t.Fatalf("expected %d indicators (2 online + 1 c2, offline/empty excluded), got %d: %+v", want, got, indicators)
	}
	if indicators[0].URL != "http://malicious.example.com/drop.exe" {
		t.Errorf("unexpected first URL: %s", indicators[0].URL)
	}
	if indicators[0].Threat != "malware_download" {
		t.Errorf("expected threat malware_download, got %s", indicators[0].Threat)
	}
	if indicators[0].DateAdded.IsZero() {
		t.Errorf("expected DateAdded to be populated")
	}
}

func TestParseURLhausCSV_EmptyBody(t *testing.T) {
	indicators, err := ParseURLhausCSV(strings.NewReader(""))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(indicators) != 0 {
		t.Errorf("expected 0 indicators for empty body, got %d", len(indicators))
	}
}

func TestParseURLhausCSV_CommentsOnly(t *testing.T) {
	indicators, err := ParseURLhausCSV(strings.NewReader("# comment\n# another\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(indicators) != 0 {
		t.Errorf("expected 0 indicators for all-comment body, got %d", len(indicators))
	}
}

func TestURLhausFetcher_Fetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte(sampleURLhausCSV))
	}))
	defer srv.Close()

	f := &URLhausFetcher{URL: srv.URL, Client: &http.Client{Timeout: 5 * time.Second}}
	indicators, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(indicators) != 3 {
		t.Fatalf("expected 3 indicators, got %d", len(indicators))
	}
}

func TestURLhausFetcher_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := &URLhausFetcher{URL: srv.URL}
	_, err := f.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
}

func TestURLhausFetcher_EmptyURL(t *testing.T) {
	f := &URLhausFetcher{}
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error when URL is empty")
	}
}
