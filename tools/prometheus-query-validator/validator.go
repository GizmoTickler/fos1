// Validator driver: queries Prometheus and classifies each expression.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Classification buckets a single validated expression into one of the
// four outcomes the tool reports.
type Classification string

const (
	// ClassResolved means the expression returned at least one series.
	ClassResolved Classification = "resolved"
	// ClassEmpty means the expression was valid PromQL but returned no
	// series. In the project's Kind harness that usually means the
	// referenced metric is not emitted by any owned exporter.
	ClassEmpty Classification = "empty"
	// ClassError means Prometheus rejected the expression (syntax or
	// evaluation error, or a transport-level failure we treat as fatal).
	ClassError Classification = "error"
	// ClassAllowlisted means the expression is recorded in the
	// target-architecture allowlist and was therefore skipped without
	// being queried.
	ClassAllowlisted Classification = "allowlisted"
)

// Result is the validator output for a single expression.
type Result struct {
	Expression     Expression     `json:"expression"`
	Classification Classification `json:"classification"`
	SeriesCount    int            `json:"seriesCount,omitempty"`
	ErrorMessage   string         `json:"errorMessage,omitempty"`
}

// PrometheusClient issues an instant query against Prometheus. The interface
// is narrow on purpose so tests can substitute a fake implementation.
type PrometheusClient interface {
	Query(ctx context.Context, expr string) (*QueryResponse, error)
}

// QueryResponse captures only the subset of the Prometheus response we
// care about. The raw JSON follows the documented `/api/v1/query` shape.
type QueryResponse struct {
	Status    string          `json:"status"`
	Data      QueryData       `json:"data"`
	ErrorType string          `json:"errorType,omitempty"`
	Error     string          `json:"error,omitempty"`
	Warnings  []string        `json:"warnings,omitempty"`
	Raw       json.RawMessage `json:"-"`
}

// QueryData holds the inner `data` field of a Prometheus query response.
// resultType determines how `result` should be decoded; we only need to
// count top-level entries for classification purposes so the untyped
// slice is sufficient.
type QueryData struct {
	ResultType string            `json:"resultType"`
	Result     []json.RawMessage `json:"result"`
}

// HTTPPrometheusClient implements PrometheusClient against a live
// Prometheus HTTP endpoint.
type HTTPPrometheusClient struct {
	BaseURL string
	Client  *http.Client
}

// NewHTTPPrometheusClient builds a client against the given base URL
// (e.g. "http://127.0.0.1:19090"). A trailing slash is tolerated.
func NewHTTPPrometheusClient(baseURL string) *HTTPPrometheusClient {
	return &HTTPPrometheusClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Query sends an instant query. The evaluation timestamp is left to
// Prometheus ("now"). The returned response has Status set on
// successful transport even when Prometheus itself returned an error.
func (c *HTTPPrometheusClient) Query(ctx context.Context, expr string) (*QueryResponse, error) {
	u := fmt.Sprintf("%s/api/v1/query", c.BaseURL)

	form := url.Values{}
	form.Set("query", expr)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read prometheus body: %w", err)
	}

	// Prometheus returns 4xx with a JSON body on user-input errors;
	// only 5xx or non-JSON bodies are considered transport failures.
	var out QueryResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode prometheus response (status %d): %w", resp.StatusCode, err)
	}
	out.Raw = body

	if resp.StatusCode >= 500 {
		return &out, fmt.Errorf("prometheus server error (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return &out, nil
}

// ValidateExpressions runs each expression through the client and classifies
// the outcome. Allowlisted expressions are short-circuited without being
// queried. Order is preserved.
func ValidateExpressions(ctx context.Context, client PrometheusClient, allowlist *Allowlist, exprs []Expression) []Result {
	results := make([]Result, 0, len(exprs))
	for _, e := range exprs {
		results = append(results, validateOne(ctx, client, allowlist, e))
	}
	return results
}

func validateOne(ctx context.Context, client PrometheusClient, allowlist *Allowlist, e Expression) Result {
	if allowlist.Contains(e.Expr) {
		return Result{Expression: e, Classification: ClassAllowlisted}
	}

	resp, err := client.Query(ctx, e.Expr)
	if err != nil {
		// Transport failure — surface as an error so CI fails fast.
		return Result{
			Expression:     e,
			Classification: ClassError,
			ErrorMessage:   err.Error(),
		}
	}

	if resp.Status != "success" {
		msg := resp.Error
		if msg == "" {
			msg = fmt.Sprintf("prometheus returned status=%q", resp.Status)
		}
		if resp.ErrorType != "" {
			msg = fmt.Sprintf("%s: %s", resp.ErrorType, msg)
		}
		return Result{
			Expression:     e,
			Classification: ClassError,
			ErrorMessage:   msg,
		}
	}

	seriesCount := len(resp.Data.Result)
	if seriesCount == 0 {
		return Result{
			Expression:     e,
			Classification: ClassEmpty,
			SeriesCount:    0,
		}
	}

	return Result{
		Expression:     e,
		Classification: ClassResolved,
		SeriesCount:    seriesCount,
	}
}

// Summary tallies results by classification for reporting and exit-code
// decisions.
type Summary struct {
	Total       int
	Resolved    int
	Empty       int
	Error       int
	Allowlisted int
}

// Summarize aggregates per-classification counts. Empty or Error outcomes
// that are not allowlisted fail the run.
func Summarize(results []Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Classification {
		case ClassResolved:
			s.Resolved++
		case ClassEmpty:
			s.Empty++
		case ClassError:
			s.Error++
		case ClassAllowlisted:
			s.Allowlisted++
		}
	}
	return s
}

// HasFailures returns true when any result indicates an out-of-allowlist
// empty or error classification.
func (s Summary) HasFailures() bool {
	return s.Empty > 0 || s.Error > 0
}
