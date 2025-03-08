// Package ebpf provides functionality for managing eBPF programs and maps.
package ebpf

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MetricType represents the type of metric.
type MetricType string

const (
	// MetricTypeCounter represents a counter metric.
	MetricTypeCounter MetricType = "counter"
	// MetricTypeGauge represents a gauge metric.
	MetricTypeGauge MetricType = "gauge"
	// MetricTypeHistogram represents a histogram metric.
	MetricTypeHistogram MetricType = "histogram"
)

// Metric represents a metric value.
type Metric struct {
	Name        string
	Description string
	Type        MetricType
	Value       interface{}
	Labels      map[string]string
	Timestamp   time.Time
}

// MetricsCollector collects metrics from eBPF programs and maps.
type MetricsCollector struct {
	programManager *ProgramManager
	mapManager     *MapManager
	metrics        map[string]Metric
	metricsMu      sync.RWMutex
	interval       time.Duration
}

// NewMetricsCollector creates a new MetricsCollector.
func NewMetricsCollector(programManager *ProgramManager, mapManager *MapManager) *MetricsCollector {
	return &MetricsCollector{
		programManager: programManager,
		mapManager:     mapManager,
		metrics:        make(map[string]Metric),
		interval:       10 * time.Second, // Default collection interval
	}
}

// Start starts the metrics collector.
func (m *MetricsCollector) Start(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.collectMetrics(); err != nil {
				fmt.Printf("Error collecting metrics: %v\n", err)
			}
		}
	}
}

// collectMetrics collects metrics from eBPF programs and maps.
func (m *MetricsCollector) collectMetrics() error {
	// Collect program metrics
	programs, err := m.programManager.ListPrograms()
	if err != nil {
		return fmt.Errorf("failed to list programs: %w", err)
	}

	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()

	// Clear existing metrics
	m.metrics = make(map[string]Metric)

	// Collect metrics for each program
	for _, program := range programs {
		// Get program metrics
		programMetrics, err := m.programManager.GetProgramMetrics(program.Name)
		if err != nil {
			fmt.Printf("Failed to get metrics for program %s: %v\n", program.Name, err)
			continue
		}

		// Add program metrics
		for key, value := range programMetrics {
			metricName := fmt.Sprintf("ebpf_program_%s_%s", program.Name, key)
			m.metrics[metricName] = Metric{
				Name:        metricName,
				Description: fmt.Sprintf("Metric %s for program %s", key, program.Name),
				Type:        MetricTypeGauge,
				Value:       value,
				Labels: map[string]string{
					"program": program.Name,
					"type":    program.Type,
				},
				Timestamp: time.Now(),
			}
		}

		// Add program status metric
		statusValue := 0
		if program.Attached {
			statusValue = 1
		}
		metricName := fmt.Sprintf("ebpf_program_%s_attached", program.Name)
		m.metrics[metricName] = Metric{
			Name:        metricName,
			Description: fmt.Sprintf("Attachment status for program %s", program.Name),
			Type:        MetricTypeGauge,
			Value:       statusValue,
			Labels: map[string]string{
				"program": program.Name,
				"type":    program.Type,
			},
			Timestamp: time.Now(),
		}
	}

	// Collect map metrics
	maps, err := m.mapManager.ListMaps()
	if err != nil {
		return fmt.Errorf("failed to list maps: %w", err)
	}

	// Collect metrics for each map
	for _, mapObj := range maps {
		// Get map entry count
		entries, err := m.mapManager.DumpMap(mapObj.Name)
		if err != nil {
			fmt.Printf("Failed to dump map %s: %v\n", mapObj.Name, err)
			continue
		}

		// Add map entry count metric
		metricName := fmt.Sprintf("ebpf_map_%s_entries", mapObj.Name)
		m.metrics[metricName] = Metric{
			Name:        metricName,
			Description: fmt.Sprintf("Number of entries in map %s", mapObj.Name),
			Type:        MetricTypeGauge,
			Value:       len(entries),
			Labels: map[string]string{
				"map":  mapObj.Name,
				"type": string(mapObj.Type),
			},
			Timestamp: time.Now(),
		}
	}

	return nil
}

// GetMetrics gets all collected metrics.
func (m *MetricsCollector) GetMetrics() map[string]Metric {
	m.metricsMu.RLock()
	defer m.metricsMu.RUnlock()

	// Create a copy of the metrics
	metrics := make(map[string]Metric, len(m.metrics))
	for name, metric := range m.metrics {
		metrics[name] = metric
	}

	return metrics
}

// GetMetric gets a specific metric by name.
func (m *MetricsCollector) GetMetric(name string) (Metric, error) {
	m.metricsMu.RLock()
	defer m.metricsMu.RUnlock()

	// Check if metric exists
	metric, ok := m.metrics[name]
	if !ok {
		return Metric{}, fmt.Errorf("metric %s not found", name)
	}

	return metric, nil
}

// RegisterCustomMetric registers a custom metric.
func (m *MetricsCollector) RegisterCustomMetric(name, description string, metricType MetricType, value interface{}, labels map[string]string) error {
	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()

	// Create the metric
	m.metrics[name] = Metric{
		Name:        name,
		Description: description,
		Type:        metricType,
		Value:       value,
		Labels:      labels,
		Timestamp:   time.Now(),
	}

	return nil
}

// UpdateCustomMetric updates a custom metric.
func (m *MetricsCollector) UpdateCustomMetric(name string, value interface{}) error {
	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()

	// Check if metric exists
	metric, ok := m.metrics[name]
	if !ok {
		return fmt.Errorf("metric %s not found", name)
	}

	// Update the metric
	metric.Value = value
	metric.Timestamp = time.Now()
	m.metrics[name] = metric

	return nil
}

// DeleteCustomMetric deletes a custom metric.
func (m *MetricsCollector) DeleteCustomMetric(name string) error {
	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()

	// Check if metric exists
	if _, ok := m.metrics[name]; !ok {
		return fmt.Errorf("metric %s not found", name)
	}

	// Delete the metric
	delete(m.metrics, name)

	return nil
}
