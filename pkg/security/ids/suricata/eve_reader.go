package suricata

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// EveEvent represents a single event from the Suricata Eve JSON log.
type EveEvent struct {
	Timestamp string      `json:"timestamp"`
	EventType string      `json:"event_type"`
	SrcIP     string      `json:"src_ip"`
	SrcPort   int         `json:"src_port"`
	DestIP    string      `json:"dest_ip"`
	DestPort  int         `json:"dest_port"`
	Proto     string      `json:"proto"`
	InIface   string      `json:"in_iface"`
	Alert     *EveAlert   `json:"alert,omitempty"`
	Flow      *EveFlow    `json:"flow,omitempty"`
	Stats     *EveStats   `json:"stats,omitempty"`
}

// EveAlert is the alert sub-object within an Eve event.
type EveAlert struct {
	Action      string `json:"action"`
	GID         int    `json:"gid"`
	SignatureID int    `json:"signature_id"`
	Rev         int    `json:"rev"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

// EveFlow is the flow sub-object within an Eve event.
type EveFlow struct {
	PktsToServer  int64 `json:"pkts_toserver"`
	PktsToClient  int64 `json:"pkts_toclient"`
	BytesToServer int64 `json:"bytes_toserver"`
	BytesToClient int64 `json:"bytes_toclient"`
	Start         string `json:"start"`
	End           string `json:"end"`
}

// EveStats is the stats sub-object within an Eve event.
type EveStats struct {
	Uptime  int64 `json:"uptime"`
	Capture struct {
		KernelPackets int64 `json:"kernel_packets"`
		KernelDrops   int64 `json:"kernel_drops"`
	} `json:"capture"`
	Detect struct {
		Alerts int64 `json:"alerts"`
	} `json:"detect"`
}

// EveLogReader reads events from a Suricata Eve JSON log file.
type EveLogReader struct {
	path string
}

// NewEveLogReader creates a reader for the given Eve log file path.
func NewEveLogReader(path string) *EveLogReader {
	return &EveLogReader{path: path}
}

// ReadAlerts reads alert events from the Eve log, applying optional time and
// count filters. If since is non-zero, only alerts after that time are returned.
// If limit is > 0, at most limit alerts are returned (most recent first).
func (r *EveLogReader) ReadAlerts(since time.Time, limit int) ([]EveEvent, error) {
	f, err := os.Open(r.path)
	if err != nil {
		return nil, fmt.Errorf("open eve log %s: %w", r.path, err)
	}
	defer f.Close()

	var alerts []EveEvent
	scanner := bufio.NewScanner(f)
	// Increase buffer size for potentially large Eve JSON lines.
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		var event EveEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue // skip malformed lines
		}

		if event.EventType != "alert" || event.Alert == nil {
			continue
		}

		if !since.IsZero() {
			ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", event.Timestamp)
			if err == nil && ts.Before(since) {
				continue
			}
		}

		alerts = append(alerts, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read eve log %s: %w", r.path, err)
	}

	if limit > 0 && len(alerts) > limit {
		alerts = alerts[len(alerts)-limit:]
	}

	return alerts, nil
}

// SeverityString converts a numeric Suricata severity (1=highest, 4=lowest)
// to a human-readable string.
func SeverityString(severity int) string {
	switch severity {
	case 1:
		return "critical"
	case 2:
		return "high"
	case 3:
		return "medium"
	case 4:
		return "low"
	default:
		return "unknown(" + strconv.Itoa(severity) + ")"
	}
}
