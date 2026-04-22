//go:build linux

// Package capture provides functionality for packet capture management.
package capture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// Capture job states. Exported as plain strings to match the public
// CaptureStatus.Status contract.
const (
	statusRunning   = "running"
	statusStopped   = "stopped"
	statusCompleted = "completed"
	statusErrored   = "error"
)

// captureProcess is the subset of *exec.Cmd semantics the manager actually
// depends on. Splitting this out lets tests model process lifecycle (start /
// wait / kill) without spawning real binaries.
type captureProcess interface {
	Start() error
	Wait() error
	Kill() error
	Signal(os.Signal) error
	Pid() int
}

// captureExec is the seam around os/exec used by the manager. The real
// implementation shells out to tcpdump; tests swap it for a deterministic
// fake. The interface also lets us fail NewManager() fast with
// ErrTCPDumpNotAvailable when the binary is absent.
type captureExec interface {
	// LookPath checks that the capture binary exists on PATH.
	LookPath(name string) (string, error)
	// Command builds (but does not start) a capture process. Equivalent to
	// exec.CommandContext under the hood.
	Command(ctx context.Context, name string, args ...string) captureProcess
	// CountPackets counts packets in a pcap file by shelling out to the
	// capture binary in read mode.
	CountPackets(file string) (int64, error)
}

// realCaptureExec is the production implementation of captureExec backed by
// os/exec and a tcpdump binary. It is only compiled on Linux.
type realCaptureExec struct {
	binaryPath string
}

func (r *realCaptureExec) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (r *realCaptureExec) Command(ctx context.Context, name string, args ...string) captureProcess {
	cmd := exec.CommandContext(ctx, name, args...)
	return &realCaptureProcess{cmd: cmd}
}

func (r *realCaptureExec) CountPackets(file string) (int64, error) {
	binary := r.binaryPath
	if binary == "" {
		binary = "tcpdump"
	}
	cmd := exec.Command(binary, "-r", file, "-qn")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("count packets in %s: %w", file, err)
	}
	return int64(strings.Count(string(output), "\n")), nil
}

// realCaptureProcess wraps *exec.Cmd to satisfy the captureProcess seam.
type realCaptureProcess struct {
	cmd *exec.Cmd
}

func (p *realCaptureProcess) Start() error { return p.cmd.Start() }
func (p *realCaptureProcess) Wait() error  { return p.cmd.Wait() }
func (p *realCaptureProcess) Kill() error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Kill()
}
func (p *realCaptureProcess) Signal(sig os.Signal) error {
	if p.cmd.Process == nil {
		return fmt.Errorf("process not started")
	}
	return p.cmd.Process.Signal(sig)
}
func (p *realCaptureProcess) Pid() int {
	if p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// Manager implements the types.CaptureManager interface on Linux by shelling
// out to tcpdump. The implementation is routinely executed as root so it can
// drop privileges after opening the capture socket via tcpdump's `-Z` flag.
type Manager struct {
	captures    map[string]*captureJob
	capturesMu  sync.RWMutex
	captureDir  string
	currentDir  string
	exec        captureExec
	binaryPath  string
}

// captureJob represents an active packet capture job.
type captureJob struct {
	ID          string
	Config      types.CaptureConfig
	Proc        captureProcess
	OutputFile  string
	StartTime   time.Time
	EndTime     time.Time
	Status      string
	Error       string
	Size        int64
	PacketCount int64
	cancel      context.CancelFunc
}

// NewManager creates a new Capture Manager. It fails fast with
// ErrTCPDumpNotAvailable when the tcpdump binary is missing from PATH so the
// caller can log a clear "capture unsupported on this kernel/deployment"
// message rather than silently producing empty pcaps.
func NewManager() (*Manager, error) {
	execer := &realCaptureExec{}
	return newManagerWithExec(execer, "/var/lib/fos1/captures")
}

// newManagerWithExec is the testable constructor. It accepts a seam interface
// and the capture directory (which is created if missing). The returned
// manager has already verified that the capture binary is reachable.
func newManagerWithExec(execer captureExec, captureDir string) (*Manager, error) {
	if execer == nil {
		return nil, fmt.Errorf("capture exec seam is nil")
	}

	binaryPath, err := execer.LookPath("tcpdump")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTCPDumpNotAvailable, err)
	}

	if err := os.MkdirAll(captureDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create capture directory %s: %w", captureDir, err)
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current directory: %w", err)
	}

	// Propagate the resolved binary path onto the real exec so CountPackets
	// uses the same binary the caller discovered.
	if r, ok := execer.(*realCaptureExec); ok {
		r.binaryPath = binaryPath
	}

	return &Manager{
		captures:   make(map[string]*captureJob),
		captureDir: captureDir,
		currentDir: currentDir,
		exec:       execer,
		binaryPath: binaryPath,
	}, nil
}

// Initialize is retained for interface compatibility. The real availability
// check already happened in NewManager, but we re-run LookPath here so callers
// that construct the zero-value manager still get a clear error.
func (m *Manager) Initialize(ctx context.Context) error {
	if m.exec == nil {
		return fmt.Errorf("capture manager not initialized: %w", ErrCaptureUnsupported)
	}
	if _, err := m.exec.LookPath("tcpdump"); err != nil {
		return fmt.Errorf("%w: %v", ErrTCPDumpNotAvailable, err)
	}
	return nil
}

// Shutdown stops all active captures and releases resources.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.capturesMu.Lock()
	defer m.capturesMu.Unlock()

	var firstErr error
	for id, job := range m.captures {
		if job.Status == statusRunning {
			if err := m.stopCaptureInternal(job); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("stop capture %s on shutdown: %w", id, err)
			}
		}
		delete(m.captures, id)
	}
	return firstErr
}

// StartCapture starts a new packet capture.
func (m *Manager) StartCapture(config types.CaptureConfig) (string, error) {
	if config.Interface == "" {
		return "", fmt.Errorf("start capture: interface is required")
	}

	id := uuid.New().String()

	filename := config.Filename
	if filename == "" {
		timestamp := time.Now().Format("20060102-150405")
		filename = fmt.Sprintf("%s_%s.pcap", config.Interface, timestamp)
	}
	outputFile := filepath.Join(m.captureDir, filename)

	var durationArg []string
	if config.MaxDuration != "" {
		duration, err := parseDuration(config.MaxDuration)
		if err != nil {
			return "", fmt.Errorf("start capture %s interface=%s: invalid max duration: %w", id, config.Interface, err)
		}
		durationArg = []string{"-G", strconv.Itoa(int(duration.Seconds()))}
	}

	var sizeArg []string
	if config.MaxSize != "" {
		size, err := parseSize(config.MaxSize)
		if err != nil {
			return "", fmt.Errorf("start capture %s interface=%s: invalid max size: %w", id, config.Interface, err)
		}
		sizeArg = []string{"-C", strconv.Itoa(int(size / 1000000))} // MB
	}

	ctx, cancel := context.WithCancel(context.Background())

	args := []string{
		"-i", config.Interface,
		"-w", outputFile,
		"-Z", "root",
	}
	if config.Filter != "" {
		args = append(args, config.Filter)
	}
	args = append(args, durationArg...)
	args = append(args, sizeArg...)

	proc := m.exec.Command(ctx, m.binaryPath, args...)
	if err := proc.Start(); err != nil {
		cancel()
		return "", fmt.Errorf("start capture %s interface=%s: %w", id, config.Interface, err)
	}

	job := &captureJob{
		ID:         id,
		Config:     config,
		Proc:       proc,
		OutputFile: outputFile,
		StartTime:  time.Now(),
		Status:     statusRunning,
		cancel:     cancel,
	}

	m.capturesMu.Lock()
	m.captures[id] = job
	m.capturesMu.Unlock()

	go m.monitorCapture(job)

	return id, nil
}

// StopCapture stops a packet capture.
func (m *Manager) StopCapture(captureID string) error {
	m.capturesMu.Lock()
	defer m.capturesMu.Unlock()

	job, ok := m.captures[captureID]
	if !ok {
		return fmt.Errorf("stop capture %s: %w", captureID, ErrCaptureNotFound)
	}
	if job.Status != statusRunning {
		return fmt.Errorf("stop capture %s interface=%s: not running (status=%s)", captureID, job.Config.Interface, job.Status)
	}
	return m.stopCaptureInternal(job)
}

// GetCaptureStatus gets the status of a packet capture.
func (m *Manager) GetCaptureStatus(captureID string) (*types.CaptureStatus, error) {
	m.capturesMu.RLock()
	defer m.capturesMu.RUnlock()

	job, ok := m.captures[captureID]
	if !ok {
		return nil, fmt.Errorf("get status for capture %s: %w", captureID, ErrCaptureNotFound)
	}

	if job.OutputFile != "" {
		if stat, err := os.Stat(job.OutputFile); err == nil {
			job.Size = stat.Size()
		}
		if job.Status != statusRunning && job.PacketCount == 0 {
			if _, err := os.Stat(job.OutputFile); err == nil {
				if packets, err := m.exec.CountPackets(job.OutputFile); err == nil {
					job.PacketCount = packets
				}
			}
		}
	}

	duration := time.Since(job.StartTime)
	if job.Status != statusRunning && !job.EndTime.IsZero() {
		duration = job.EndTime.Sub(job.StartTime)
	}

	return &types.CaptureStatus{
		ID:          job.ID,
		Interface:   job.Config.Interface,
		Filter:      job.Config.Filter,
		StartTime:   job.StartTime.Format(time.RFC3339),
		Duration:    duration.String(),
		Size:        job.Size,
		PacketCount: job.PacketCount,
		Status:      job.Status,
		Error:       job.Error,
	}, nil
}

// ListCaptures lists all packet captures.
func (m *Manager) ListCaptures() ([]string, error) {
	m.capturesMu.RLock()
	defer m.capturesMu.RUnlock()

	ids := make([]string, 0, len(m.captures))
	for id := range m.captures {
		ids = append(ids, id)
	}
	return ids, nil
}

// GetCapturePath returns the path to a capture file.
func (m *Manager) GetCapturePath(captureID string) (string, error) {
	m.capturesMu.RLock()
	defer m.capturesMu.RUnlock()

	job, ok := m.captures[captureID]
	if !ok {
		return "", fmt.Errorf("get capture path for %s: %w", captureID, ErrCaptureNotFound)
	}
	return job.OutputFile, nil
}

// stopCaptureInternal stops a packet capture.
// Caller must hold m.capturesMu.
func (m *Manager) stopCaptureInternal(job *captureJob) error {
	if job.cancel != nil {
		job.cancel()
	}

	if job.Proc != nil {
		// Try a polite SIGINT first; fall back to SIGKILL if that fails.
		if err := job.Proc.Signal(os.Interrupt); err != nil {
			if killErr := job.Proc.Kill(); killErr != nil {
				job.Error = fmt.Sprintf("failed to kill capture %s process: %v", job.ID, killErr)
				return fmt.Errorf("stop capture %s interface=%s: kill process: %w", job.ID, job.Config.Interface, killErr)
			}
		}

		if err := job.Proc.Wait(); err != nil && !isExpectedExit(err) {
			job.Error = fmt.Sprintf("error waiting for capture %s process: %v", job.ID, err)
			return fmt.Errorf("stop capture %s interface=%s: wait process: %w", job.ID, job.Config.Interface, err)
		}
	}

	job.Status = statusStopped
	job.EndTime = time.Now()
	return nil
}

// monitorCapture watches a capture job for process exit and records terminal
// status. It runs in a goroutine spawned by StartCapture.
func (m *Manager) monitorCapture(job *captureJob) {
	err := job.Proc.Wait()

	m.capturesMu.Lock()
	defer m.capturesMu.Unlock()

	if err != nil {
		if isExpectedExit(err) {
			if job.Status != statusStopped {
				job.Status = statusStopped
			}
		} else {
			job.Status = statusErrored
			job.Error = err.Error()
		}
	} else if job.Status != statusStopped {
		job.Status = statusCompleted
	}

	job.EndTime = time.Now()

	if stat, err := os.Stat(job.OutputFile); err == nil {
		job.Size = stat.Size()
	}
	if packets, err := m.exec.CountPackets(job.OutputFile); err == nil {
		job.PacketCount = packets
	}
}

func isExpectedExit(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "context canceled") ||
		strings.Contains(msg, "signal: interrupt") ||
		strings.Contains(msg, "signal: killed") ||
		strings.Contains(msg, "process already finished")
}

// parseDuration parses a duration string.
func parseDuration(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	s = strings.ToLower(s)
	switch {
	case strings.HasSuffix(s, "m"):
		minutes, err := strconv.Atoi(strings.TrimSuffix(s, "m"))
		if err != nil {
			return 0, fmt.Errorf("invalid minutes: %w", err)
		}
		return time.Duration(minutes) * time.Minute, nil
	case strings.HasSuffix(s, "h"):
		hours, err := strconv.Atoi(strings.TrimSuffix(s, "h"))
		if err != nil {
			return 0, fmt.Errorf("invalid hours: %w", err)
		}
		return time.Duration(hours) * time.Hour, nil
	case strings.HasSuffix(s, "s"):
		seconds, err := strconv.Atoi(strings.TrimSuffix(s, "s"))
		if err != nil {
			return 0, fmt.Errorf("invalid seconds: %w", err)
		}
		return time.Duration(seconds) * time.Second, nil
	}

	seconds, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration: %w", err)
	}
	return time.Duration(seconds) * time.Second, nil
}

// parseSize parses a size string.
func parseSize(s string) (int64, error) {
	s = strings.ToUpper(s)
	switch {
	case strings.HasSuffix(s, "KB"):
		kb, err := strconv.ParseInt(strings.TrimSuffix(s, "KB"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid KB: %w", err)
		}
		return kb * 1024, nil
	case strings.HasSuffix(s, "MB"):
		mb, err := strconv.ParseInt(strings.TrimSuffix(s, "MB"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid MB: %w", err)
		}
		return mb * 1024 * 1024, nil
	case strings.HasSuffix(s, "GB"):
		gb, err := strconv.ParseInt(strings.TrimSuffix(s, "GB"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid GB: %w", err)
		}
		return gb * 1024 * 1024 * 1024, nil
	case strings.HasSuffix(s, "B"):
		b, err := strconv.ParseInt(strings.TrimSuffix(s, "B"), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid bytes: %w", err)
		}
		return b, nil
	}

	bytes, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size: %w", err)
	}
	return bytes, nil
}
