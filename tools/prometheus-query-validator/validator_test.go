package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// fakeResponse describes one scripted Prometheus reply. Set `bodyJSON`
// for the common happy path or `body`+`status` to emit a specific byte
// string.
type fakeResponse struct {
	status   int
	body     string
	bodyJSON interface{}
}

// newFakeServer spins up a local HTTP server that mimics the subset of the
// Prometheus `/api/v1/query` contract we rely on. The handler is indexed
// by the verbatim expression value so tests can craft per-expression
// responses.
func newFakeServer(t *testing.T, handler map[string]fakeResponse) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("parse form: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		query := form.Get("query")
		resp, ok := handler[query]
		if !ok {
			t.Errorf("fake server received unexpected query %q", query)
			http.Error(w, "unknown", http.StatusInternalServerError)
			return
		}
		if resp.status != 0 {
			w.WriteHeader(resp.status)
		}
		if resp.bodyJSON != nil {
			_ = json.NewEncoder(w).Encode(resp.bodyJSON)
			return
		}
		_, _ = io.WriteString(w, resp.body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestValidateExpressionsClassifications(t *testing.T) {
	handler := map[string]fakeResponse{
		"ntp_sync": {bodyJSON: map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"resultType": "vector",
				"result": []interface{}{
					map[string]interface{}{
						"metric": map[string]string{"__name__": "ntp_sync"},
						"value":  []interface{}{1.0, "1"},
					},
				},
			},
		}},
		"missing_metric": {bodyJSON: map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"resultType": "vector",
				"result":     []interface{}{},
			},
		}},
		"bad syntax ++": {status: 400, bodyJSON: map[string]interface{}{
			"status":    "error",
			"errorType": "bad_data",
			"error":     "parse error",
		}},
	}
	srv := newFakeServer(t, handler)

	allow, err := LoadAllowlist(filepath.Join("testdata", "allowlist.txt"))
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}

	exprs := []Expression{
		{Expr: "ntp_sync", Source: SourceAlertRule, File: "rules.yaml", Location: "r1"},
		{Expr: "missing_metric", Source: SourceDashboardPanel, File: "d.json", Location: "p1"},
		{Expr: "bad syntax ++", Source: SourceDashboardPanel, File: "d.json", Location: "p2"},
		{Expr: "abs(ntp_offset_milliseconds)", Source: SourceAlertRule, File: "rules.yaml", Location: "r2"},
	}

	client := NewHTTPPrometheusClient(srv.URL)
	results := ValidateExpressions(context.Background(), client, allow, exprs)
	if len(results) != len(exprs) {
		t.Fatalf("got %d results want %d", len(results), len(exprs))
	}

	if results[0].Classification != ClassResolved || results[0].SeriesCount != 1 {
		t.Errorf("first result: %+v", results[0])
	}
	if results[1].Classification != ClassEmpty {
		t.Errorf("second result: %+v", results[1])
	}
	if results[2].Classification != ClassError {
		t.Errorf("third result: %+v", results[2])
	}
	if !strings.Contains(results[2].ErrorMessage, "parse error") {
		t.Errorf("third error message missing parse error: %q", results[2].ErrorMessage)
	}
	if results[3].Classification != ClassAllowlisted {
		t.Errorf("fourth result: %+v", results[3])
	}

	summary := Summarize(results)
	if summary.Resolved != 1 || summary.Empty != 1 || summary.Error != 1 || summary.Allowlisted != 1 {
		t.Errorf("summary: %+v", summary)
	}
	if !summary.HasFailures() {
		t.Error("HasFailures=false, want true (empty+error present)")
	}
}

func TestValidateNoFailuresWhenAllAllowlistedOrResolved(t *testing.T) {
	handler := map[string]fakeResponse{
		"ntp_sync": {bodyJSON: map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"resultType": "vector",
				"result": []interface{}{
					map[string]interface{}{
						"metric": map[string]string{},
						"value":  []interface{}{1.0, "1"},
					},
				},
			},
		}},
	}
	srv := newFakeServer(t, handler)

	al, _ := LoadAllowlist(filepath.Join("testdata", "allowlist.txt"))
	exprs := []Expression{
		{Expr: "ntp_sync"},
		{Expr: "abs(ntp_offset_milliseconds)"},
	}
	results := ValidateExpressions(context.Background(), NewHTTPPrometheusClient(srv.URL), al, exprs)
	summary := Summarize(results)
	if summary.HasFailures() {
		t.Errorf("HasFailures=true, want false: %+v", summary)
	}
}

func TestHTTPPrometheusClientTransportError(t *testing.T) {
	// Point at a TCP port nothing is listening on.
	client := NewHTTPPrometheusClient("http://127.0.0.1:1")
	_, err := client.Query(context.Background(), "ntp_sync")
	if err == nil {
		t.Fatalf("expected transport error, got nil")
	}
}

func TestHTTPPrometheusClientBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<html>not json</html>")
	}))
	defer srv.Close()

	client := NewHTTPPrometheusClient(srv.URL)
	_, err := client.Query(context.Background(), "ntp_sync")
	if err == nil {
		t.Fatalf("expected decode error, got nil")
	}
	if !strings.Contains(err.Error(), "decode prometheus response") {
		t.Errorf("unexpected error: %v", err)
	}
}
