package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/ntp"
	"github.com/GizmoTickler/fos1/pkg/ntp/chrony"
)

// Exporter manages exporting NTP metrics
type Exporter struct {
	chronyManager *chrony.Manager
	interval      time.Duration
	port          int
	server        *http.Server
	metrics       ntp.Metrics
	metricsMutex  sync.RWMutex
	stopCh        chan struct{}
}

// Config holds exporter configuration
type Config struct {
	Port          int
	Interval      time.Duration
	ChronyManager *chrony.Manager
}

// NewExporter creates a new NTP metrics exporter
func NewExporter(config *Config) (*Exporter, error) {
	if config.ChronyManager == nil {
		return nil, fmt.Errorf("chrony manager is required")
	}

	if config.Interval == 0 {
		config.Interval = 15 * time.Second
	}

	if config.Port == 0 {
		config.Port = 9559 // Standard port for the NTP exporter
	}

	return &Exporter{
		chronyManager: config.ChronyManager,
		interval:      config.Interval,
		port:          config.Port,
		stopCh:        make(chan struct{}),
	}, nil
}

// Start starts the metrics exporter
func (e *Exporter) Start() error {
	// Set up HTTP server for Prometheus metrics
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", e.handleMetrics)
	mux.HandleFunc("/healthz", e.handleHealthz)

	e.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", e.port),
		Handler: mux,
	}

	// Start HTTP server in a goroutine
	go func() {
		klog.Infof("Starting NTP metrics server on port %d", e.port)
		if err := e.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			klog.Errorf("Error starting NTP metrics server: %v", err)
		}
	}()

	// Start metrics collection loop in a goroutine
	go e.collectMetricsLoop()

	return nil
}

// Stop stops the metrics exporter
func (e *Exporter) Stop() error {
	// Signal the collection loop to stop
	close(e.stopCh)

	// Shut down HTTP server
	if e.server != nil {
		klog.Info("Shutting down NTP metrics server")
		return e.server.Close()
	}

	return nil
}

// collectMetricsLoop collects metrics at regular intervals
func (e *Exporter) collectMetricsLoop() {
	// Collect metrics immediately on start
	e.collectMetrics()

	// Set up ticker for regular collection
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.collectMetrics()
		case <-e.stopCh:
			klog.Info("Stopping NTP metrics collection")
			return
		}
	}
}

// collectMetrics collects NTP metrics from Chrony
func (e *Exporter) collectMetrics() {
	metrics, err := e.chronyManager.CollectMetrics()
	if err != nil {
		klog.Errorf("Error collecting NTP metrics: %v", err)
		return
	}

	e.metricsMutex.Lock()
	e.metrics = metrics
	e.metricsMutex.Unlock()

	klog.V(4).Infof("Collected NTP metrics: offset=%.3fms, jitter=%.3fms, stratum=%d, sources=%d",
		metrics.Offset, metrics.Jitter, metrics.Stratum, metrics.SourceCount)
}

// handleMetrics handles Prometheus metrics endpoint requests
func (e *Exporter) handleMetrics(w http.ResponseWriter, r *http.Request) {
	e.metricsMutex.RLock()
	metrics := e.metrics
	e.metricsMutex.RUnlock()

	w.Header().Set("Content-Type", "text/plain")
	
	// Write metrics in Prometheus format
	fmt.Fprintf(w, "# HELP ntp_offset_milliseconds Offset of the system clock from NTP time in milliseconds\n")
	fmt.Fprintf(w, "# TYPE ntp_offset_milliseconds gauge\n")
	fmt.Fprintf(w, "ntp_offset_milliseconds %f\n", metrics.Offset)

	fmt.Fprintf(w, "# HELP ntp_jitter_milliseconds Clock jitter in milliseconds\n")
	fmt.Fprintf(w, "# TYPE ntp_jitter_milliseconds gauge\n")
	fmt.Fprintf(w, "ntp_jitter_milliseconds %f\n", metrics.Jitter)

	fmt.Fprintf(w, "# HELP ntp_stratum NTP stratum level of the system\n")
	fmt.Fprintf(w, "# TYPE ntp_stratum gauge\n")
	fmt.Fprintf(w, "ntp_stratum %d\n", metrics.Stratum)

	fmt.Fprintf(w, "# HELP ntp_sync Whether the system is synchronized with NTP (1 = yes, 0 = no)\n")
	fmt.Fprintf(w, "# TYPE ntp_sync gauge\n")
	syncValue := 0
	if metrics.SyncStatus {
		syncValue = 1
	}
	fmt.Fprintf(w, "ntp_sync %d\n", syncValue)

	fmt.Fprintf(w, "# HELP ntp_source_count Number of NTP sources\n")
	fmt.Fprintf(w, "# TYPE ntp_source_count gauge\n")
	fmt.Fprintf(w, "ntp_source_count %d\n", metrics.SourceCount)

	fmt.Fprintf(w, "# HELP ntp_sources_reachable Number of reachable NTP sources\n")
	fmt.Fprintf(w, "# TYPE ntp_sources_reachable gauge\n")
	fmt.Fprintf(w, "ntp_sources_reachable %d\n", metrics.SourcesReachable)

	fmt.Fprintf(w, "# HELP ntp_frequency_drift_ppm System clock frequency drift in parts per million\n")
	fmt.Fprintf(w, "# TYPE ntp_frequency_drift_ppm gauge\n")
	fmt.Fprintf(w, "ntp_frequency_drift_ppm %f\n", metrics.FrequencyDrift)
}

// handleHealthz handles health check endpoint
func (e *Exporter) handleHealthz(w http.ResponseWriter, r *http.Request) {
	e.metricsMutex.RLock()
	syncStatus := e.metrics.SyncStatus
	e.metricsMutex.RUnlock()

	if syncStatus {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("not synchronized"))
	}
}