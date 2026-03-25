package kubernetes

import (
	"log"
	"net/http"

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
	addr string
}

// NewMetricsServer creates a new metrics server
func NewMetricsServer(addr string) *MetricsServer {
	return &MetricsServer{
		addr: addr,
	}
}

// HandleDPIEvent handles a DPI event and updates metrics
func (s *MetricsServer) HandleDPIEvent(event DPIEvent) {
	dpiEvents.WithLabelValues(event.EventType, event.Application, event.Category).Inc()
}

// Start starts the metrics server
func (s *MetricsServer) Start() {
	// Add health check endpoint for Kubernetes probes
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Add readiness check endpoint for Kubernetes probes
	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Simple readiness check
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})

	// Set up HTTP server
	http.Handle("/metrics", promhttp.Handler())
	log.Printf("Starting metrics server on %s", s.addr)
	if err := http.ListenAndServe(s.addr, nil); err != nil {
		log.Printf("Error starting metrics server: %v", err)
	}
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
