package kubernetes

import (
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/varuntirumala1/fos1/pkg/security/dpi"
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

// StartMetricsServer starts the metrics server for Prometheus
func StartMetricsServer(addr string, manager *dpi.DPIManager) {
	// Register event handler to update metrics
	manager.RegisterEventHandler(func(event dpi.DPIEvent) {
		dpiEvents.WithLabelValues(event.EventType, event.Application, event.Category).Inc()
	})

	// Start a goroutine to update protocol metrics
	go updateProtocolMetrics(manager)

	// Add health check endpoint for Kubernetes probes
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Add readiness check endpoint for Kubernetes probes
	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Check if Zeek is running
		status, err := manager.GetZeekStatus()
		if err != nil || !status.Running {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("zeek not ready"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})

	// Set up HTTP server
	http.Handle("/metrics", promhttp.Handler())
	log.Printf("Starting metrics server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Printf("Error starting metrics server: %v", err)
	}
}

// updateProtocolMetrics updates protocol metrics periodically
func updateProtocolMetrics(manager *dpi.DPIManager) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Update Zeek status
		status, err := manager.GetZeekStatus()
		if err != nil {
			zeekStatus.WithLabelValues("error").Set(0)
			continue
		}

		if status.Running {
			zeekStatus.WithLabelValues("running").Set(1)
			zeekStatus.WithLabelValues("stopped").Set(0)
		} else {
			zeekStatus.WithLabelValues("running").Set(0)
			zeekStatus.WithLabelValues("stopped").Set(1)
		}

		zeekLogsProcessed.Add(float64(status.LogsProcessed))

		// Update protocol metrics
		protocols, err := manager.GetDetectedProtocols()
		if err != nil {
			log.Printf("Error getting detected protocols: %v", err)
			continue
		}

		for protocol, count := range protocols {
			protocolConnections.WithLabelValues(protocol).Set(float64(count))

			// Get protocol stats
			stats, err := manager.GetProtocolStats(protocol)
			if err != nil {
				continue
			}

			if bytes, ok := stats["bytes"].(int64); ok {
				protocolBytes.WithLabelValues(protocol).Set(float64(bytes))
			}
		}
	}
}
