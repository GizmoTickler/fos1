package main

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestExtractFromDashboard(t *testing.T) {
	path := filepath.Join("testdata", "dashboard.json")
	got, err := ExtractFromDashboard(path)
	if err != nil {
		t.Fatalf("ExtractFromDashboard: %v", err)
	}

	want := []struct {
		expr   string
		source SourceKind
	}{
		// Panel targets (nested and top-level)
		{"sum(dpi_events_total)", SourceDashboardPanel},
		{"rate(dpi_zeek_logs_processed[5m])", SourceDashboardPanel},
		{"ntp_sync", SourceDashboardPanel},
		// Template variables: the datasource-type `ds` entry is filtered;
		// the structured query in `structured` is extracted via the nested
		// `.query` string.
		{"label_values(node_cpu_seconds_total, instance)", SourceDashboardTemplate},
		{"label_values(up, job)", SourceDashboardTemplate},
	}

	if len(got) != len(want) {
		t.Fatalf("extracted %d expressions, want %d: %+v", len(got), len(want), got)
	}

	gotKey := map[string]SourceKind{}
	for _, e := range got {
		gotKey[e.Expr] = e.Source
		if e.File != path {
			t.Errorf("expression %q has wrong file %q", e.Expr, e.File)
		}
		if e.Location == "" {
			t.Errorf("expression %q has empty location", e.Expr)
		}
	}
	for _, w := range want {
		if s, ok := gotKey[w.expr]; !ok {
			t.Errorf("missing expression %q", w.expr)
		} else if s != w.source {
			t.Errorf("expression %q source=%s want=%s", w.expr, s, w.source)
		}
	}
}

func TestExtractFromAlertRulesConfigMap(t *testing.T) {
	path := filepath.Join("testdata", "alert-rules.yaml")
	got, err := ExtractFromAlertRules(path)
	if err != nil {
		t.Fatalf("ExtractFromAlertRules: %v", err)
	}

	wantExprs := []string{
		"ntp_sync == 0",
		"sum(increase(dpi_events_total[5m])) > 50",
		"abs(ntp_offset_milliseconds)",
	}
	if len(got) != len(wantExprs) {
		t.Fatalf("got %d expressions, want %d (%+v)", len(got), len(wantExprs), got)
	}

	gotExprs := make([]string, len(got))
	for i, e := range got {
		gotExprs[i] = e.Expr
		if e.Source != SourceAlertRule {
			t.Errorf("expression %q source=%s want alert-rule", e.Expr, e.Source)
		}
		if e.File != path {
			t.Errorf("expression %q file=%q", e.Expr, e.File)
		}
		if e.Location == "" {
			t.Errorf("expression %q empty location", e.Expr)
		}
	}
	sort.Strings(gotExprs)
	sort.Strings(wantExprs)
	for i := range wantExprs {
		if gotExprs[i] != wantExprs[i] {
			t.Errorf("mismatch at %d: got %q want %q", i, gotExprs[i], wantExprs[i])
		}
	}
}

func TestExtractFromAlertRulesPlain(t *testing.T) {
	path := filepath.Join("testdata", "plain-rules.yaml")
	got, err := ExtractFromAlertRules(path)
	if err != nil {
		t.Fatalf("ExtractFromAlertRules: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d expressions, want 1 (%+v)", len(got), got)
	}
	if got[0].Expr != "ntp_sync == 0" {
		t.Errorf("expression text %q", got[0].Expr)
	}
}

func TestLoadAllowlist(t *testing.T) {
	al, err := LoadAllowlist(filepath.Join("testdata", "allowlist.txt"))
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if !al.Contains("abs(ntp_offset_milliseconds)") {
		t.Errorf("expected allowlist hit for abs(ntp_offset_milliseconds)")
	}
	if al.Contains("ntp_sync == 0") {
		t.Errorf("unexpected allowlist hit")
	}
	if al.Size() != 1 {
		t.Errorf("size=%d want 1", al.Size())
	}
}

func TestLoadAllowlistMissing(t *testing.T) {
	al, err := LoadAllowlist(filepath.Join("testdata", "does-not-exist.txt"))
	if err != nil {
		t.Fatalf("LoadAllowlist missing: %v", err)
	}
	if al.Size() != 0 {
		t.Errorf("expected empty allowlist on missing file, got size=%d", al.Size())
	}
}

func TestLoadAllowlistEmptyPath(t *testing.T) {
	al, err := LoadAllowlist("")
	if err != nil {
		t.Fatalf("LoadAllowlist empty: %v", err)
	}
	if al.Size() != 0 {
		t.Errorf("expected empty allowlist on empty path, got size=%d", al.Size())
	}
}
