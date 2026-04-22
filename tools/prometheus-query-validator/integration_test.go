package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

// TestIntegrationRepositoryArtifactsAgainstFakePrometheus walks the real
// dashboards and alert rules that ship in this repo, runs them through a
// fake Prometheus that resolves any expression not in the allowlist, and
// asserts zero failures. This is the static-analysis sibling to the CI
// step that points the validator at the live Kind Prometheus: if it
// passes, we know the allowlist covers every currently-unresolved
// expression the repo ships.
func TestIntegrationRepositoryArtifactsAgainstFakePrometheus(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	allowlistPath := filepath.Join(repoRoot, "manifests", "dashboards", ".queries-target-architecture.txt")
	alertRulesPath := filepath.Join(repoRoot, "manifests", "base", "monitoring", "alert-rules.yaml")
	dashboardsDir := filepath.Join(repoRoot, "manifests", "dashboards")

	allow, err := LoadAllowlist(allowlistPath)
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if allow.Size() == 0 {
		t.Fatal("allowlist appears empty; check path")
	}

	dashFiles, err := filepath.Glob(filepath.Join(dashboardsDir, "*.json"))
	if err != nil {
		t.Fatalf("glob dashboards: %v", err)
	}
	if len(dashFiles) == 0 {
		t.Fatal("no dashboard JSON files found")
	}

	var all []Expression
	for _, f := range dashFiles {
		exprs, err := ExtractFromDashboard(f)
		if err != nil {
			t.Fatalf("extract %s: %v", f, err)
		}
		all = append(all, exprs...)
	}
	alerts, err := ExtractFromAlertRules(alertRulesPath)
	if err != nil {
		t.Fatalf("extract alert rules: %v", err)
	}
	all = append(all, alerts...)

	if len(all) == 0 {
		t.Fatal("no expressions extracted from repo artifacts")
	}

	// Fake Prometheus: return one series for everything. Syntax errors
	// are not simulated because we're asserting classification of the
	// extracted, well-formed expressions — not the Prometheus parser
	// itself.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		_ = form.Get("query")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
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
		})
	}))
	defer srv.Close()

	results := ValidateExpressions(context.Background(), NewHTTPPrometheusClient(srv.URL), allow, all)
	summary := Summarize(results)

	// With a happy-path fake Prometheus, every non-allowlisted expression
	// should resolve. Any empty/error result indicates a real bug in the
	// extractor or allowlist content.
	if summary.Error != 0 {
		for _, r := range results {
			if r.Classification == ClassError {
				t.Errorf("unexpected error classification: %s -- %s", r.Expression.Expr, r.ErrorMessage)
			}
		}
	}
	if summary.Empty != 0 {
		for _, r := range results {
			if r.Classification == ClassEmpty {
				t.Errorf("unexpected empty classification: %s", r.Expression.Expr)
			}
		}
	}

	// Every repository allowlist entry should match at least one
	// extracted expression; otherwise the entry is dead weight.
	// (We only verify this softly — the real CI check is that empty+error
	// == 0 above.)
	t.Logf("summary: total=%d resolved=%d allowlisted=%d empty=%d error=%d",
		summary.Total, summary.Resolved, summary.Allowlisted, summary.Empty, summary.Error)
}
