// Package capture provides functionality for packet capture management.
package capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/varuntirumala1/fos1/pkg/hardware/types"
)

// Manager implements the types.CaptureManager interface.
type Manager struct {
	captures     map[string]*captureJob
	capturesMu   sync.RWMutex
	captureDir   string
	currentDir   string
}

// captureJob represents an active packet capture job.
type captureJob struct {
	ID          string
	Config      types.CaptureConfig
	Cmd         *exec.Cmd
	OutputFile  string
	StartTime   time.Time
	Status      string
	Error       string
	Size        int64
	PacketCount int64
	cancel      context.CancelFunc
}

// NewManager creates a new Capture Manager.
func NewManager() (*Manager, error) {
	// Create capture directory if it doesn't exist
	captureDir := "/var/lib/fos1/captures"
	if err := os.MkdirAll(captureDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create capture directory: %w", err)
	}

	// Get current directory for relative paths
	currentDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current directory: %w", err)
	}

	return &Manager{
		captures:     make(map[string]*captureJob),
		captureDir:   captureDir,
		currentDir:   currentDir,
	}, nil
}

// Initialize initializes the Capture Manager.
func (m *Manager) Initialize(ctx context.Context) error {
	// Check if tcpdump is installed
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return fmt.Errorf("tcpdump not found, required for packet capture: %w", err)
	}

	return nil
}

// Shutdown shuts down the Capture Manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	// Stop all active captures
	m.capturesMu.Lock()
	defer m.capturesMu.Unlock()

	for id, capture := range m.captures {
		if capture.Status == "running" {
			m.stopCaptureInternal(capture)
		}
		delete(m.captures, id)
	}

	return nil
}

// StartCapture starts a new packet capture.
func (m *Manager) StartCapture(config types.CaptureConfig) (string, error) {
	// Validate config
	if config.Interface == "" {
		return "", fmt.Errorf("interface is required")
	}

	// Generate unique ID
	id := uuid.New().String()

	// Create output file path
	filename := config.Filename
	if filename == "" {
		timestamp := time.Now().Format("20060102-150405")
		filename = fmt.Sprintf("%s_%s.pcap", config.Interface, timestamp)
	}
	outputFile := filepath.Join(m.captureDir, filename)

	// Parse max duration
	var durationArg []string
	if config.MaxDuration != "" {
		duration, err := parseDuration(config.MaxDuration)
		if err != nil {
			return "", fmt.Errorf("invalid max duration: %w", err)
		}
		durationArg = []string{"-G", strconv.Itoa(int(duration.Seconds()))}
	}

	// Parse max size
	var sizeArg []string
	if config.MaxSize != "" {
		size, err := parseSize(config.MaxSize)
		if err != nil {
			return "", fmt.Errorf("invalid max size: %w", err)
		}
		sizeArg = []string{"-C", strconv.Itoa(int(size / 1000000))} // Convert to MB
	}

	// Create context with cancel function
	ctx, cancel := context.WithCancel(context.Background())

	// Prepare tcpdump command
	args := []string{
		"-i", config.Interface,
		"-w", outputFile,
		"-Z", "root", // Drop privileges after opening interface
	}

	// Add filter if provided
	if config.Filter != "" {
		args = append(args, config.Filter)
	}

	// Add duration and size limits if provided
	args = append(args, durationArg...)
	args = append(args, sizeArg...)

	cmd := exec.CommandContext(ctx, "tcpdump", args...)

	// Start capture
	if err := cmd.Start(); err != nil {
		cancel()
		return "", fmt.Errorf("failed to start capture: %w", err)
	}

	// Create capture job
	job := &captureJob{
		ID:         id,
		Config:     config,
		Cmd:        cmd,
		OutputFile: outputFile,
		StartTime:  time.Now(),
		Status:     "running",
		cancel:     cancel,
	}

	// Store capture job
	m.capturesMu.Lock()
	m.captures[id] = job
	m.capturesMu.Unlock()

	// Monitor capture in background
	go m.monitorCapture(job)

	return id, nil
}

// StopCapture stops a packet capture.
func (m *Manager) StopCapture(captureID string) error {
	m.capturesMu.Lock()
	defer m.capturesMu.Unlock()

	capture, ok := m.captures[captureID]
	if !ok {
		return fmt.Errorf("capture %s not found", captureID)
	}

	if capture.Status != "running" {
		return fmt.Errorf("capture %s is not running", captureID)
	}

	return m.stopCaptureInternal(capture)
}

// GetCaptureStatus gets the status of a packet capture.
func (m *Manager) GetCaptureStatus(captureID string) (*types.CaptureStatus, error) {
	m.capturesMu.RLock()
	defer m.capturesMu.RUnlock()

	capture, ok := m.captures[captureID]
	if !ok {
		return nil, fmt.Errorf("capture %s not found", captureID)
	}

	// Update file size and packet count if file exists
	if capture.OutputFile != "" {
		if stat, err := os.Stat(capture.OutputFile); err == nil {
			capture.Size = stat.Size()
		}

		// Count packets using tcpdump if file exists and capture is not running
		if capture.Status != "running" && capture.PacketCount == 0 {
			if _, err := os.Stat(capture.OutputFile); err == nil {
				if packets, err := countPackets(capture.OutputFile); err == nil {
					capture.PacketCount = packets
				}
			}
		}
	}

	duration := time.Since(capture.StartTime)
	if capture.Status != "running" {
		// If not running, duration is from start to finish
		if capture.Cmd != nil && capture.Cmd.ProcessState != nil {
			duration = capture.Cmd.ProcessState.SystemTime() + capture.Cmd.ProcessState.UserTime()
		}
	}

	return &types.CaptureStatus{
		ID:          capture.ID,
		Interface:   capture.Config.Interface,
		Filter:      capture.Config.Filter,
		StartTime:   capture.StartTime.Format(time.RFC3339),
		Duration:    duration.String(),
		Size:        capture.Size,
		PacketCount: capture.PacketCount,
		Status:      capture.Status,
		Error:       capture.Error,
	}, nil
}

// ListCaptures lists all packet captures.
func (m *Manager) ListCaptures() ([]string, error) {
	m.capturesMu.RLock()
	defer m.capturesMu.RUnlock()

	captures := make([]string, 0, len(m.captures))
	for id := range m.captures {
		captures = append(captures, id)
	}

	return captures, nil
}

// GetCapturePath returns the path to a capture file.
func (m *Manager) GetCapturePath(captureID string) (string, error) {
	m.capturesMu.RLock()
	defer m.capturesMu.RUnlock()

	capture, ok := m.captures[captureID]
	if !ok {
		return "", fmt.Errorf("capture %s not found", captureID)
	}

	return capture.OutputFile, nil
}

// stopCaptureInternal stops a packet capture.
// Caller must hold the capturesMu lock.
func (m *Manager) stopCaptureInternal(capture *captureJob) error {
	// Cancel context to stop command
	if capture.cancel != nil {
		capture.cancel()
	}

	// Send SIGTERM to process
	if capture.Cmd != nil && capture.Cmd.Process != nil {
		if err := capture.Cmd.Process.Signal(os.Interrupt); err != nil {
			// If can't send signal, try to kill
			if err := capture.Cmd.Process.Kill(); err != nil {
				capture.Error = fmt.Sprintf("failed to kill process: %v", err)
				return fmt.Errorf("failed to kill process: %w", err)
			}
		}
	}

	// Wait for process to exit
	if capture.Cmd != nil {
		if err := capture.Cmd.Wait(); err != nil {
			// Ignore context canceled errors
			if !strings.Contains(err.Error(), "context canceled") {
				capture.Error = fmt.Sprintf("error waiting for process to exit: %v", err)
				return fmt.Errorf("error waiting for process to exit: %w", err)
			}
		}
	}

	capture.Status = "stopped"
	return nil
}

// monitorCapture monitors a packet capture job.
func (m *Manager) monitorCapture(capture *captureJob) {
	// Wait for process to exit
	err := capture.Cmd.Wait()

	m.capturesMu.Lock()
	defer m.capturesMu.Unlock()

	if err != nil {
		// Check if context was canceled
		if strings.Contains(err.Error(), "context canceled") {
			capture.Status = "stopped"
		} else {
			capture.Status = "error"
			capture.Error = err.Error()
		}
	} else {
		capture.Status = "completed"
	}

	// Update file size
	if stat, err := os.Stat(capture.OutputFile); err == nil {
		capture.Size = stat.Size()
	}

	// Count packets
	if packets, err := countPackets(capture.OutputFile); err == nil {
		capture.PacketCount = packets
	}
}

// parseDuration parses a duration string.
func parseDuration(s string) (time.Duration, error) {
	// Check if already in Go duration format
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Handle human-readable formats like "5m" or "1h"
	s = strings.ToLower(s)
	if strings.HasSuffix(s, "m") {
		minutes, err := strconv.Atoi(strings.TrimSuffix(s, "m"))
		if err != nil {
			return 0, fmt.Errorf("invalid minutes: %w", err)
		}
		return time.Duration(minutes) * time.Minute, nil
	} else if strings.HasSuffix(s, "h") {
		hours, err := strconv.Atoi(strings.TrimSuffix(s, "h"))
		if err != nil {
			return 0, fmt.Errorf("invalid hours: %w", err)
		}
		return time.Duration(hours) * time.Hour, nil
	} else if strings.HasSuffix(s, "s") {
		seconds, err := strconv.Atoi(strings.TrimSuffix(s, "s"))
		if err != nil {
			return 0, fmt.Errorf("invalid seconds: %w", err)
		}
		return time.Duration(seconds) * time.Second, nil
	}

	// Try to parse as seconds
	seconds, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration: %w", err)
	}
	return time.Duration(seconds) * time.Second, nil
}

// parseSize parses a size string.
func parseSize(s string) (int64, error) {
	s = strings.ToUpper(s)
	if strings.HasSuffix(s, "KB") {
		kb, err := strconv.ParseInt(strings.TrimSuffix(s, "KB"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid KB: %w", err)
		}
		return kb * 1024, nil
	} else if strings.HasSuffix(s, "MB") {
		mb, err := strconv.ParseInt(strings.TrimSuffix(s, "MB"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid MB: %w", err)
		}
		return mb * 1024 * 1024, nil
	} else if strings.HasSuffix(s, "GB") {
		gb, err := strconv.ParseInt(strings.TrimSuffix(s, "GB"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid GB: %w", err)
		}
		return gb * 1024 * 1024 * 1024, nil
	} else if strings.HasSuffix(s, "B") {
		b, err := strconv.ParseInt(strings.TrimSuffix(s, "B"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid bytes: %w", err)
		}
		return b, nil
	}

	// Try to parse as bytes
	bytes, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size: %w", err)
	}
	return bytes, nil
}

// countPackets counts the number of packets in a pcap file.
func countPackets(file string) (int64, error) {
	cmd := exec.Command("tcpdump", "-r", file, "-qn")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to run tcpdump: %w", err)
	}

	// Count number of lines in output
	lines := strings.Count(string(output), "\n")
	return int64(lines), nil
}
