// prometheus-query-validator walks Grafana dashboard JSON and
// Prometheus alert rule YAML manifests, extracts every PromQL
// expression, runs them against a live Prometheus instance, and
// classifies the outcome.
//
// Usage:
//
//	prometheus-query-validator \
//	    -prometheus-url http://127.0.0.1:9090 \
//	    -allowlist manifests/dashboards/.queries-target-architecture.txt \
//	    -dashboards manifests/dashboards \
//	    -alert-rules manifests/base/monitoring/alert-rules.yaml
//
// The tool exits 0 when every non-allowlisted expression resolves
// against the target Prometheus. Empty or error classifications that
// are not allowlisted cause a non-zero exit.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func main() {
	var (
		promURL       = flag.String("prometheus-url", "", "Prometheus base URL (e.g. http://127.0.0.1:19090)")
		allowlistPath = flag.String("allowlist", "", "path to allowlist of target-architecture expressions")
		format        = flag.String("format", "text", "report format: text or json")
		timeout       = flag.Duration("timeout", 2*time.Minute, "overall query timeout budget")
		dashboards    stringList
		alertRules    stringList
	)
	flag.Var(&dashboards, "dashboards", "comma-separated paths to dashboard JSON files or directories (repeat flag or comma-separate)")
	flag.Var(&alertRules, "alert-rules", "comma-separated paths to alert rule YAML files or directories")
	flag.Parse()

	if *promURL == "" {
		fmt.Fprintln(os.Stderr, "-prometheus-url is required")
		os.Exit(2)
	}
	if len(dashboards) == 0 && len(alertRules) == 0 {
		fmt.Fprintln(os.Stderr, "provide at least one -dashboards or -alert-rules path")
		os.Exit(2)
	}

	dashboardFiles, err := expandFiles(dashboards, ".json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "expand dashboards: %v\n", err)
		os.Exit(2)
	}
	alertFiles, err := expandFiles(alertRules, ".yaml", ".yml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "expand alert rules: %v\n", err)
		os.Exit(2)
	}

	var all []Expression
	for _, f := range dashboardFiles {
		exprs, err := ExtractFromDashboard(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "extract %s: %v\n", f, err)
			os.Exit(2)
		}
		all = append(all, exprs...)
	}
	for _, f := range alertFiles {
		exprs, err := ExtractFromAlertRules(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "extract %s: %v\n", f, err)
			os.Exit(2)
		}
		all = append(all, exprs...)
	}

	allow, err := LoadAllowlist(*allowlistPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load allowlist: %v\n", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := NewHTTPPrometheusClient(*promURL)
	results := ValidateExpressions(ctx, client, allow, all)
	summary := Summarize(results)

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			Summary Summary  `json:"summary"`
			Results []Result `json:"results"`
		}{Summary: summary, Results: results})
	default:
		printTextReport(os.Stdout, *promURL, allow, results, summary)
	}

	if summary.HasFailures() {
		os.Exit(1)
	}
}

// expandFiles walks each path argument. Directories are scanned
// non-recursively for files whose suffix matches one of the allowed
// extensions. Individual files are returned as-is. A missing path is
// treated as an error so typos surface immediately.
func expandFiles(paths []string, exts ...string) ([]string, error) {
	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, fmt.Errorf("read dir %s: %w", p, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			for _, want := range exts {
				if ext == want {
					out = append(out, filepath.Join(p, entry.Name()))
					break
				}
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func printTextReport(w *os.File, url string, allow *Allowlist, results []Result, summary Summary) {
	fmt.Fprintf(w, "prometheus-query-validator report\n")
	fmt.Fprintf(w, "  prometheus: %s\n", url)
	if allow.Source() != "" {
		fmt.Fprintf(w, "  allowlist:  %s (%d entries)\n", allow.Source(), allow.Size())
	} else {
		fmt.Fprintf(w, "  allowlist:  (none)\n")
	}
	fmt.Fprintln(w)

	// Buckets are emitted in failure-first order so the tail of the log is
	// actionable when CI captures only the last page.
	printBucket(w, "ERROR", results, ClassError)
	printBucket(w, "EMPTY", results, ClassEmpty)
	printBucket(w, "RESOLVED", results, ClassResolved)
	printBucket(w, "ALLOWLISTED", results, ClassAllowlisted)

	fmt.Fprintf(w, "\nsummary:\n")
	fmt.Fprintf(w, "  total:       %d\n", summary.Total)
	fmt.Fprintf(w, "  resolved:    %d\n", summary.Resolved)
	fmt.Fprintf(w, "  empty:       %d\n", summary.Empty)
	fmt.Fprintf(w, "  error:       %d\n", summary.Error)
	fmt.Fprintf(w, "  allowlisted: %d\n", summary.Allowlisted)
}

func printBucket(w *os.File, label string, results []Result, class Classification) {
	var matches []Result
	for _, r := range results {
		if r.Classification == class {
			matches = append(matches, r)
		}
	}
	if len(matches) == 0 {
		return
	}
	fmt.Fprintf(w, "%s (%d):\n", label, len(matches))
	for _, r := range matches {
		extra := ""
		switch r.Classification {
		case ClassResolved:
			extra = fmt.Sprintf(" series=%d", r.SeriesCount)
		case ClassError:
			extra = fmt.Sprintf(" error=%q", r.ErrorMessage)
		}
		fmt.Fprintf(w, "  %s [%s]%s\n", r.Expression.Location, r.Expression.Source, extra)
		fmt.Fprintf(w, "    file: %s\n", r.Expression.File)
		fmt.Fprintf(w, "    expr: %s\n", r.Expression.Expr)
	}
	fmt.Fprintln(w)
}
