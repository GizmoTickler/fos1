package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/security/dpi/common"
)

func TestMetricsServerUsesIndependentMuxes(t *testing.T) {
	t.Parallel()

	first := NewMetricsServer("127.0.0.1:0")
	second := NewMetricsServer("127.0.0.1:0")

	if first.mux == nil {
		t.Fatal("expected first metrics server mux to be initialized")
	}
	if second.mux == nil {
		t.Fatal("expected second metrics server mux to be initialized")
	}
	if first.mux == second.mux {
		t.Fatal("expected independent serve mux instances")
	}
	if first.server == nil || second.server == nil {
		t.Fatal("expected HTTP servers to be initialized")
	}
	if first.server.Handler != first.mux {
		t.Fatal("expected first server handler to use its own mux")
	}
	if second.server.Handler != second.mux {
		t.Fatal("expected second server handler to use its own mux")
	}
}

func TestTLSMetricsServerWrapsHandlerWithPeerSubjectAllowlist(t *testing.T) {
	server := newMetricsServer("127.0.0.1:0", &tls.Config{}, "controller-a")

	req := httptest.NewRequest(http.MethodGet, "https://example.test/healthz", nil)
	req.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{
			{Subject: pkix.Name{CommonName: "controller-a"}},
		}},
	}
	resp := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("allowed subject status = %d, want %d", resp.Code, http.StatusOK)
	}

	req = httptest.NewRequest(http.MethodGet, "https://example.test/healthz", nil)
	req.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{
			{Subject: pkix.Name{CommonName: "unknown-controller"}},
		}},
	}
	resp = httptest.NewRecorder()
	server.server.Handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("unknown subject status = %d, want %d", resp.Code, http.StatusForbidden)
	}
}

func TestMetricsServerServesEndpointsAndStopsCleanly(t *testing.T) {
	server := NewMetricsServer("127.0.0.1:0")
	server.HandleDPIEvent(DPIEvent{
		EventType:   "alert",
		Application: "dns",
		Category:    "network",
	})
	server.UpdateProtocolMetrics("tcp", 3, 1024)
	server.UpdateZeekStatus(true, 7)

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- server.Start()
	}()

	baseURL := waitForServer(t, server)

	assertStatus(t, baseURL+"/healthz", http.StatusOK)
	assertStatus(t, baseURL+"/readyz", http.StatusOK)

	metricsBody := getBody(t, baseURL+"/metrics")
	for _, metricName := range []string{
		"dpi_events_total",
		"dpi_protocol_connections",
		"dpi_protocol_bytes",
		"dpi_zeek_status",
		"dpi_zeek_logs_processed",
	} {
		if !strings.Contains(metricsBody, metricName) {
			t.Fatalf("expected /metrics output to contain %q", metricName)
		}
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Stop(stopCtx); err != nil {
		t.Fatalf("stop metrics server: %v", err)
	}

	select {
	case err := <-startErrCh:
		if err != nil {
			t.Fatalf("start returned unexpected error after shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for metrics server to stop")
	}

	client := &http.Client{Timeout: 250 * time.Millisecond}
	_, err := client.Get(baseURL + "/healthz")
	if err == nil {
		t.Fatal("expected requests to fail after shutdown")
	}
}

func TestMetricsServerHandlesCommonDPIEventAndExportsDerivedMetrics(t *testing.T) {
	server := NewMetricsServer("127.0.0.1:0")

	event := common.DPIEvent{
		Timestamp:   time.Now(),
		SourceIP:    "192.0.2.10",
		DestIP:      "198.51.100.5",
		SourcePort:  53000,
		DestPort:    80,
		Protocol:    "tcp",
		Application: "ticket1-http",
		Category:    "web",
		EventType:   "flow",
		Description: "ticket 1 flow event",
		SessionID:   "ticket-1-session",
		RawData: map[string]interface{}{
			"bytes":  int64(2048),
			"source": "zeek",
		},
	}

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- server.Start()
	}()

	baseURL := waitForServer(t, server)
	beforeMetricsBody := getBody(t, baseURL+"/metrics")
	beforeZeekLogs := metricValue(t, beforeMetricsBody, "dpi_zeek_logs_processed")

	server.HandleCommonDPIEvent(event)

	metricsBody := getBody(t, baseURL+"/metrics")
	for _, expected := range []string{
		`dpi_events_total{application="ticket1-http",category="web",event_type="flow"} 1`,
		`dpi_protocol_connections{protocol="ticket1-http"} 1`,
		`dpi_protocol_bytes{protocol="ticket1-http"} 2048`,
		`dpi_zeek_status{status="running"} 1`,
	} {
		if !strings.Contains(metricsBody, expected) {
			t.Fatalf("expected /metrics output to contain %q, got:\n%s", expected, metricsBody)
		}
	}

	afterZeekLogs := metricValue(t, metricsBody, "dpi_zeek_logs_processed")
	if afterZeekLogs-beforeZeekLogs != 1 {
		t.Fatalf("expected zeek logs processed to increase by 1, got %v", afterZeekLogs-beforeZeekLogs)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Stop(stopCtx); err != nil {
		t.Fatalf("stop metrics server: %v", err)
	}

	select {
	case err := <-startErrCh:
		if err != nil {
			t.Fatalf("start returned unexpected error after shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for metrics server to stop")
	}
}

func waitForServer(t *testing.T, server *MetricsServer) string {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	client := &http.Client{Timeout: 250 * time.Millisecond}

	for time.Now().Before(deadline) {
		addr := server.Addr()
		if addr != "" {
			baseURL := "http://" + addr
			resp, err := client.Get(baseURL + "/healthz")
			if err == nil {
				resp.Body.Close()
				return baseURL
			}
		}
		time.Sleep(25 * time.Millisecond)
	}

	t.Fatal("timed out waiting for metrics server to start")
	return ""
}

func assertStatus(t *testing.T, url string, want int) {
	t.Helper()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != want {
		t.Fatalf("GET %s: expected status %d, got %d", url, want, resp.StatusCode)
	}
}

func getBody(t *testing.T, url string) string {
	t.Helper()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(body)
}

func metricValue(t *testing.T, metricsBody, metricName string) float64 {
	t.Helper()

	for _, line := range strings.Split(metricsBody, "\n") {
		if strings.HasPrefix(line, metricName+" ") {
			value, err := strconv.ParseFloat(strings.TrimPrefix(line, metricName+" "), 64)
			if err != nil {
				t.Fatalf("parse %s value from %q: %v", metricName, line, err)
			}
			return value
		}
	}

	t.Fatalf("metric %s not found in:\n%s", metricName, metricsBody)
	return 0
}

func TestMetricsServerMultipleInstancesStartWithoutCollisions(t *testing.T) {
	first := NewMetricsServer("127.0.0.1:0")
	second := NewMetricsServer("127.0.0.1:0")

	firstErrCh := make(chan error, 1)
	secondErrCh := make(chan error, 1)

	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				firstErrCh <- errors.New("first metrics server panicked")
			}
		}()
		firstErrCh <- first.Start()
	}()

	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				secondErrCh <- errors.New("second metrics server panicked")
			}
		}()
		secondErrCh <- second.Start()
	}()

	firstURL := waitForServer(t, first)
	secondURL := waitForServer(t, second)

	assertStatus(t, firstURL+"/healthz", http.StatusOK)
	assertStatus(t, secondURL+"/healthz", http.StatusOK)

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := first.Stop(stopCtx); err != nil {
		t.Fatalf("stop first server: %v", err)
	}
	if err := second.Stop(stopCtx); err != nil {
		t.Fatalf("stop second server: %v", err)
	}

	for name, errCh := range map[string]chan error{
		"first":  firstErrCh,
		"second": secondErrCh,
	} {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("%s server returned unexpected error: %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %s server goroutine", name)
		}
	}
}
