//go:build linux

package ebpf

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusCollector exports eBPF map statistics as Prometheus metrics.
type PrometheusCollector struct {
	statsCollector *StatsCollector

	// Metric descriptors
	blacklistSize    *prometheus.Desc
	rateLimitEntries *prometheus.Desc
	flowCount        *prometheus.Desc
	ipv6FlowCount    *prometheus.Desc
	mapEntries       *prometheus.Desc
}

// NewPrometheusCollector creates a new Prometheus collector for eBPF stats.
func NewPrometheusCollector(sc *StatsCollector) *PrometheusCollector {
	return &PrometheusCollector{
		statsCollector: sc,
		blacklistSize: prometheus.NewDesc(
			"ebpf_xdp_blacklist_entries",
			"Number of entries in the XDP IPv4 blacklist map",
			[]string{"program"}, nil,
		),
		rateLimitEntries: prometheus.NewDesc(
			"ebpf_xdp_ratelimit_entries",
			"Number of entries in the XDP rate limit map",
			[]string{"program"}, nil,
		),
		flowCount: prometheus.NewDesc(
			"ebpf_flow_count",
			"Number of tracked IPv4 flows",
			[]string{"program"}, nil,
		),
		ipv6FlowCount: prometheus.NewDesc(
			"ebpf_ipv6_flow_count",
			"Number of tracked IPv6 flows",
			[]string{"program"}, nil,
		),
		mapEntries: prometheus.NewDesc(
			"ebpf_map_entries",
			"Number of entries in an eBPF map",
			[]string{"map_name"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *PrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.blacklistSize
	ch <- c.rateLimitEntries
	ch <- c.flowCount
	ch <- c.ipv6FlowCount
	ch <- c.mapEntries
}

// Collect implements prometheus.Collector.
func (c *PrometheusCollector) Collect(ch chan<- prometheus.Metric) {
	allStats := c.statsCollector.GetAllStats()

	for name, stats := range allStats {
		if stats.XDP != nil {
			ch <- prometheus.MustNewConstMetric(
				c.blacklistSize, prometheus.GaugeValue,
				float64(stats.XDP.BlacklistSize), name,
			)
			ch <- prometheus.MustNewConstMetric(
				c.rateLimitEntries, prometheus.GaugeValue,
				float64(stats.XDP.RateLimitEntries), name,
			)
			ch <- prometheus.MustNewConstMetric(
				c.flowCount, prometheus.GaugeValue,
				float64(stats.XDP.FlowCount), name,
			)
			ch <- prometheus.MustNewConstMetric(
				c.ipv6FlowCount, prometheus.GaugeValue,
				float64(stats.XDP.IPv6FlowCount), name,
			)
		}
		if stats.TC != nil {
			ch <- prometheus.MustNewConstMetric(
				c.flowCount, prometheus.GaugeValue,
				float64(stats.TC.FlowCount), name,
			)
		}
	}
}
