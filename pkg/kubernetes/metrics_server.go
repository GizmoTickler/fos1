package kubernetes

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/GizmoTickler/fos1/pkg/security/certificates"
	"github.com/GizmoTickler/fos1/pkg/security/dpi/common"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Metrics for DPI events
	dpiEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dpi_events_total",
			Help: "Total number of DPI events by type and application",
		},
		[]string{"event_type", "application", "category"},
	)

	// Metrics for protocol statistics
	protocolConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dpi_protocol_connections",
			Help: "Number of connections by protocol",
		},
		[]string{"protocol"},
	)

	protocolBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dpi_protocol_bytes",
			Help: "Number of bytes by protocol",
		},
		[]string{"protocol"},
	)

	// Metrics for Zeek status
	zeekStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dpi_zeek_status",
			Help: "Status of Zeek (1 = running, 0 = not running)",
		},
		[]string{"status"},
	)

	zeekLogsProcessed = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dpi_zeek_logs_processed",
			Help: "Number of Zeek logs processed",
		},
	)
)

func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(dpiEvents)
	prometheus.MustRegister(protocolConnections)
	prometheus.MustRegister(protocolBytes)
	prometheus.MustRegister(zeekStatus)
	prometheus.MustRegister(zeekLogsProcessed)
}

// MetricsServer provides Prometheus metrics for the DPI system
type MetricsServer struct {
	addr      string
	mux       *http.ServeMux
	server    *http.Server
	listener  net.Listener
	tlsConfig *tls.Config
	tlsStop   context.CancelFunc
	mu        sync.Mutex
}

// NewMetricsServer creates a new plaintext metrics server.
func NewMetricsServer(addr string) *MetricsServer {
	return newMetricsServer(addr, nil)
}

// NewTLSMetricsServer creates a metrics server that serves HTTPS using
// material loaded from certDir. Sprint 32 / Ticket 56 requires mTLS and a
// Subject-CN allowlist for every owned controller listener; allowedSubjects
// is deny-by-default when omitted. The shared certificates.TLSReloader
// handles cert-manager rotation; the caller is responsible for invoking Stop
// on shutdown.
func NewTLSMetricsServer(addr, certDir string, allowedSubjects ...string) (*MetricsServer, error) {
	tlsCfg, reloader, err := certificates.LoadMutualTLSConfig(certDir)
	if err != nil {
		return nil, err
	}
	srv := newMetricsServer(addr, tlsCfg, allowedSubjects...)

	// Run the watcher under a context the server can cancel from Stop.
	watchCtx, cancel := context.WithCancel(context.Background())
	srv.tlsStop = cancel
	go func() {
		if werr := reloader.WatchAndReload(watchCtx, nil, tlsCfg, nil); werr != nil {
			log.Printf("metrics server: TLS watcher exited: %v", werr)
		}
	}()
	return srv, nil
}

func newMetricsServer(addr string, tlsCfg *tls.Config, allowedSubjects ...string) *MetricsServer {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ready")
	})

	var handler http.Handler = mux
	if tlsCfg != nil {
		handler = certificates.RequireAllowedPeerSubject(allowedSubjects, mux)
	}

	return &MetricsServer{
		addr: addr,
		mux:  mux,
		server: &http.Server{
			Addr:      addr,
			Handler:   handler,
			TLSConfig: tlsCfg,
		},
		tlsConfig: tlsCfg,
	}
}

// HandleDPIEvent handles a DPI event and updates metrics
func (s *MetricsServer) HandleDPIEvent(event DPIEvent) {
	dpiEvents.WithLabelValues(event.EventType, event.Application, event.Category).Inc()
}

// HandleCommonDPIEvent handles a real DPI manager event and updates derived metrics.
func (s *MetricsServer) HandleCommonDPIEvent(event common.DPIEvent) {
	s.HandleDPIEvent(DPIEvent{
		Timestamp:   event.Timestamp,
		SourceIP:    event.SourceIP,
		DestIP:      event.DestIP,
		SourcePort:  event.SourcePort,
		DestPort:    event.DestPort,
		Protocol:    event.Protocol,
		Application: event.Application,
		Category:    event.Category,
		EventType:   event.EventType,
		Severity:    event.Severity,
		Description: event.Description,
		Signature:   event.Signature,
		SessionID:   event.SessionID,
		RawData:     event.RawData,
	})

	if protocol := protocolMetricLabel(event); protocol != "" {
		protocolConnections.WithLabelValues(protocol).Add(1)
		if bytes, ok := rawInt64(event.RawData, "bytes"); ok {
			protocolBytes.WithLabelValues(protocol).Add(float64(bytes))
		}
	}

	if isZeekEvent(event) {
		logsProcessed := int64(1)
		if value, ok := rawInt64(event.RawData, "logs_processed"); ok && value > 0 {
			logsProcessed = value
		}
		s.UpdateZeekStatus(true, logsProcessed)
	}
}

// Start starts the metrics server. When the server was constructed via
// NewTLSMetricsServer it serves HTTPS; otherwise plaintext HTTP.
func (s *MetricsServer) Start() error {
	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		return errors.New("metrics server already started")
	}
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.listener = listener
	tlsCfg := s.tlsConfig
	s.mu.Unlock()

	if tlsCfg != nil {
		log.Printf("Starting metrics server on %s (TLS)", listener.Addr().String())
		// Wrap the listener; the embedded tls.Config.GetCertificate
		// handles cert rotation transparently.
		tlsListener := tls.NewListener(listener, tlsCfg)
		err = s.server.Serve(tlsListener)
	} else {
		log.Printf("Starting metrics server on %s", listener.Addr().String())
		err = s.server.Serve(listener)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Stop shuts down the metrics server cleanly.
func (s *MetricsServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	server := s.server
	listener := s.listener
	tlsStop := s.tlsStop
	s.mu.Unlock()

	if server == nil || listener == nil {
		return nil
	}

	err := server.Shutdown(ctx)

	s.mu.Lock()
	s.listener = nil
	s.mu.Unlock()

	if tlsStop != nil {
		tlsStop()
	}

	return err
}

// Addr returns the active listener address when running.
func (s *MetricsServer) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// UpdateZeekStatus updates Zeek status metrics
func (s *MetricsServer) UpdateZeekStatus(running bool, logsProcessed int64) {
	if running {
		zeekStatus.WithLabelValues("running").Set(1)
		zeekStatus.WithLabelValues("stopped").Set(0)
	} else {
		zeekStatus.WithLabelValues("running").Set(0)
		zeekStatus.WithLabelValues("stopped").Set(1)
	}

	zeekLogsProcessed.Add(float64(logsProcessed))
}

// UpdateProtocolMetrics updates protocol metrics
func (s *MetricsServer) UpdateProtocolMetrics(protocol string, connections int, bytes int64) {
	protocolConnections.WithLabelValues(protocol).Set(float64(connections))
	protocolBytes.WithLabelValues(protocol).Set(float64(bytes))
}

func protocolMetricLabel(event common.DPIEvent) string {
	if event.Application != "" {
		return strings.ToLower(event.Application)
	}
	if service, ok := event.RawData["service"].(string); ok && service != "" {
		return strings.ToLower(service)
	}
	return strings.ToLower(event.Protocol)
}

func isZeekEvent(event common.DPIEvent) bool {
	source, ok := event.RawData["source"].(string)
	return ok && strings.EqualFold(source, "zeek")
}

func rawInt64(raw map[string]interface{}, key string) (int64, bool) {
	if raw == nil {
		return 0, false
	}

	value, ok := raw[key]
	if !ok {
		return 0, false
	}

	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case float32:
		return int64(typed), true
	case float64:
		return int64(typed), true
	default:
		return 0, false
	}
}
