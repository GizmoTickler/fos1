package nat

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ConntrackStats holds connection tracking statistics.
type ConntrackStats struct {
	TotalEntries int64
	TCPEntries   int64
	UDPEntries   int64
	ICMPEntries  int64
}

// GetConntrackStats reads connection tracking statistics from /proc/net/nf_conntrack.
func GetConntrackStats() (*ConntrackStats, error) {
	file, err := os.Open("/proc/net/nf_conntrack")
	if err != nil {
		// Try alternative path
		file, err = os.Open("/proc/net/ip_conntrack")
		if err != nil {
			return &ConntrackStats{}, nil // conntrack not available
		}
	}
	defer file.Close()

	stats := &ConntrackStats{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		stats.TotalEntries++

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			switch fields[2] {
			case "tcp":
				stats.TCPEntries++
			case "udp":
				stats.UDPEntries++
			case "icmp":
				stats.ICMPEntries++
			}
		}
	}

	return stats, scanner.Err()
}

// GetConntrackCount returns the total number of tracked connections.
func GetConntrackCount() (int64, error) {
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		return 0, fmt.Errorf("failed to read conntrack count: %w", err)
	}

	var count int64
	_, err = fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &count)
	return count, err
}

// GetConntrackMax returns the maximum number of tracked connections.
func GetConntrackMax() (int64, error) {
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return 0, fmt.Errorf("failed to read conntrack max: %w", err)
	}

	var max int64
	_, err = fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &max)
	return max, err
}
