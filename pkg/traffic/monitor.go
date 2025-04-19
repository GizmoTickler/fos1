package traffic

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

// Monitor represents a traffic monitor
type Monitor struct {
	mutex            sync.RWMutex
	trafficManager   Manager
	updateInterval   time.Duration
	stopCh           chan struct{}
	prometheusMetrics *prometheusMetrics
}

// prometheusMetrics represents Prometheus metrics for traffic monitoring
type prometheusMetrics struct {
	// Interface metrics
	interfaceRxBytes      *prometheus.GaugeVec
	interfaceTxBytes      *prometheus.GaugeVec
	interfaceRxPackets    *prometheus.GaugeVec
	interfaceTxPackets    *prometheus.GaugeVec
	interfaceRxDrops      *prometheus.GaugeVec
	interfaceTxDrops      *prometheus.GaugeVec
	interfaceRxErrors     *prometheus.GaugeVec
	interfaceTxErrors     *prometheus.GaugeVec
	interfaceRxRate       *prometheus.GaugeVec
	interfaceTxRate       *prometheus.GaugeVec
	interfaceRxUtilization *prometheus.GaugeVec
	interfaceTxUtilization *prometheus.GaugeVec

	// Class metrics
	classBytes      *prometheus.GaugeVec
	classPackets    *prometheus.GaugeVec
	classDrops      *prometheus.GaugeVec
	classRate       *prometheus.GaugeVec
	classUtilization *prometheus.GaugeVec
}

// NewMonitor creates a new traffic monitor
func NewMonitor(trafficManager Manager, updateInterval time.Duration) *Monitor {
	// Create Prometheus metrics
	metrics := &prometheusMetrics{
		// Interface metrics
		interfaceRxBytes: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_rx_bytes",
				Help: "Number of bytes received on the interface",
			},
			[]string{"interface"},
		),
		interfaceTxBytes: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_tx_bytes",
				Help: "Number of bytes transmitted on the interface",
			},
			[]string{"interface"},
		),
		interfaceRxPackets: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_rx_packets",
				Help: "Number of packets received on the interface",
			},
			[]string{"interface"},
		),
		interfaceTxPackets: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_tx_packets",
				Help: "Number of packets transmitted on the interface",
			},
			[]string{"interface"},
		),
		interfaceRxDrops: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_rx_drops",
				Help: "Number of received packets dropped on the interface",
			},
			[]string{"interface"},
		),
		interfaceTxDrops: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_tx_drops",
				Help: "Number of transmitted packets dropped on the interface",
			},
			[]string{"interface"},
		),
		interfaceRxErrors: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_rx_errors",
				Help: "Number of received packets with errors on the interface",
			},
			[]string{"interface"},
		),
		interfaceTxErrors: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_tx_errors",
				Help: "Number of transmitted packets with errors on the interface",
			},
			[]string{"interface"},
		),
		interfaceRxRate: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_rx_rate",
				Help: "Current receive rate in bits per second on the interface",
			},
			[]string{"interface"},
		),
		interfaceTxRate: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_tx_rate",
				Help: "Current transmit rate in bits per second on the interface",
			},
			[]string{"interface"},
		),
		interfaceRxUtilization: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_rx_utilization",
				Help: "Current receive utilization as a percentage on the interface",
			},
			[]string{"interface"},
		),
		interfaceTxUtilization: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_interface_tx_utilization",
				Help: "Current transmit utilization as a percentage on the interface",
			},
			[]string{"interface"},
		),

		// Class metrics
		classBytes: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_class_bytes",
				Help: "Number of bytes processed by the traffic class",
			},
			[]string{"interface", "class"},
		),
		classPackets: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_class_packets",
				Help: "Number of packets processed by the traffic class",
			},
			[]string{"interface", "class"},
		),
		classDrops: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_class_drops",
				Help: "Number of packets dropped by the traffic class",
			},
			[]string{"interface", "class"},
		),
		classRate: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_class_rate",
				Help: "Current rate in bits per second for the traffic class",
			},
			[]string{"interface", "class"},
		),
		classUtilization: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "traffic_class_utilization",
				Help: "Current utilization as a percentage for the traffic class",
			},
			[]string{"interface", "class"},
		),
	}

	// Register metrics with Prometheus
	prometheus.MustRegister(
		metrics.interfaceRxBytes,
		metrics.interfaceTxBytes,
		metrics.interfaceRxPackets,
		metrics.interfaceTxPackets,
		metrics.interfaceRxDrops,
		metrics.interfaceTxDrops,
		metrics.interfaceRxErrors,
		metrics.interfaceTxErrors,
		metrics.interfaceRxRate,
		metrics.interfaceTxRate,
		metrics.interfaceRxUtilization,
		metrics.interfaceTxUtilization,
		metrics.classBytes,
		metrics.classPackets,
		metrics.classDrops,
		metrics.classRate,
		metrics.classUtilization,
	)

	return &Monitor{
		trafficManager:   trafficManager,
		updateInterval:   updateInterval,
		stopCh:           make(chan struct{}),
		prometheusMetrics: metrics,
	}
}

// Start starts the traffic monitor
func (m *Monitor) Start() {
	klog.Info("Starting traffic monitor")

	// Start the update loop
	go m.updateLoop()
}

// Stop stops the traffic monitor
func (m *Monitor) Stop() {
	klog.Info("Stopping traffic monitor")

	// Stop the update loop
	close(m.stopCh)
}

// updateLoop periodically updates traffic statistics
func (m *Monitor) updateLoop() {
	ticker := time.NewTicker(m.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.updateStatistics(); err != nil {
				klog.Errorf("Failed to update traffic statistics: %v", err)
			}
		case <-m.stopCh:
			klog.Info("Traffic monitor stopped")
			return
		}
	}
}

// updateStatistics updates traffic statistics
func (m *Monitor) updateStatistics() error {
	// Get all configurations
	configs, err := m.trafficManager.ListConfigurations()
	if err != nil {
		return fmt.Errorf("failed to list configurations: %w", err)
	}

	// Update statistics for each configuration
	for _, config := range configs {
		// Get interface statistics
		ifStats, err := m.trafficManager.GetInterfaceStatistics(config.Interface)
		if err != nil {
			klog.Warningf("Failed to get interface statistics for %s: %v", config.Interface, err)
			continue
		}

		// Update interface metrics
		m.prometheusMetrics.interfaceRxBytes.WithLabelValues(config.Interface).Set(float64(ifStats.RxBytes))
		m.prometheusMetrics.interfaceTxBytes.WithLabelValues(config.Interface).Set(float64(ifStats.TxBytes))
		m.prometheusMetrics.interfaceRxPackets.WithLabelValues(config.Interface).Set(float64(ifStats.RxPackets))
		m.prometheusMetrics.interfaceTxPackets.WithLabelValues(config.Interface).Set(float64(ifStats.TxPackets))
		m.prometheusMetrics.interfaceRxDrops.WithLabelValues(config.Interface).Set(float64(ifStats.RxDrops))
		m.prometheusMetrics.interfaceTxDrops.WithLabelValues(config.Interface).Set(float64(ifStats.TxDrops))
		m.prometheusMetrics.interfaceRxErrors.WithLabelValues(config.Interface).Set(float64(ifStats.RxErrors))
		m.prometheusMetrics.interfaceTxErrors.WithLabelValues(config.Interface).Set(float64(ifStats.TxErrors))
		m.prometheusMetrics.interfaceRxRate.WithLabelValues(config.Interface).Set(float64(ifStats.RxRate))
		m.prometheusMetrics.interfaceTxRate.WithLabelValues(config.Interface).Set(float64(ifStats.TxRate))
		m.prometheusMetrics.interfaceRxUtilization.WithLabelValues(config.Interface).Set(ifStats.RxUtilization)
		m.prometheusMetrics.interfaceTxUtilization.WithLabelValues(config.Interface).Set(ifStats.TxUtilization)

		// Update class statistics
		for _, class := range config.Classes {
			classStats, err := m.trafficManager.GetClassStatistics(config.Interface, class.Name)
			if err != nil {
				klog.Warningf("Failed to get class statistics for %s on interface %s: %v", class.Name, config.Interface, err)
				continue
			}

			// Update class metrics
			m.prometheusMetrics.classBytes.WithLabelValues(config.Interface, class.Name).Set(float64(classStats.Bytes))
			m.prometheusMetrics.classPackets.WithLabelValues(config.Interface, class.Name).Set(float64(classStats.Packets))
			m.prometheusMetrics.classDrops.WithLabelValues(config.Interface, class.Name).Set(float64(classStats.Drops))
			m.prometheusMetrics.classRate.WithLabelValues(config.Interface, class.Name).Set(float64(classStats.Rate))
			m.prometheusMetrics.classUtilization.WithLabelValues(config.Interface, class.Name).Set(classStats.Utilization)
		}
	}

	return nil
}

// GetTopTalkers gets the top talkers
func (m *Monitor) GetTopTalkers(interfaceName string, count int) ([]TopTalker, error) {
	// Check if the interface exists
	if err := checkInterfaceExists(interfaceName); err != nil {
		return nil, fmt.Errorf("interface check failed: %w", err)
	}

	// Get top talkers using iftop
	cmd := exec.Command("iftop", "-t", "-s", "5", "-n", "-i", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get top talkers: %w", err)
	}

	// Parse the output
	topTalkers := make([]TopTalker, 0)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "=>") {
			// Extract source and destination
			parts := strings.Split(line, "=>")
			if len(parts) != 2 {
				continue
			}

			source := strings.TrimSpace(parts[0])
			destination := strings.TrimSpace(parts[1])

			// Extract rate
			rateRegex := regexp.MustCompile(`(\d+\.\d+)([KMG])bits?/s`)
			rateMatch := rateRegex.FindStringSubmatch(line)
			if rateMatch == nil {
				continue
			}

			rateValue, _ := strconv.ParseFloat(rateMatch[1], 64)
			rateUnit := rateMatch[2]

			// Convert to bits per second
			var rate float64
			switch rateUnit {
			case "K":
				rate = rateValue * 1000
			case "M":
				rate = rateValue * 1000000
			case "G":
				rate = rateValue * 1000000000
			default:
				rate = rateValue
			}

			// Add to top talkers
			topTalkers = append(topTalkers, TopTalker{
				Source:      source,
				Destination: destination,
				Rate:        rate,
			})

			// Stop if we have enough top talkers
			if len(topTalkers) >= count {
				break
			}
		}
	}

	return topTalkers, nil
}

// TopTalker represents a top talker
type TopTalker struct {
	// Source is the source IP address
	Source string

	// Destination is the destination IP address
	Destination string

	// Rate is the rate in bits per second
	Rate float64
}
