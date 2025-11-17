package frr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// Manager manages FRR daemon lifecycle
type Manager struct {
	client    *Client
	generator *ConfigGenerator
	mutex     sync.RWMutex
	config    *ClientConfig
}

// NewManager creates a new FRR manager
func NewManager(config *ClientConfig) *Manager {
	if config == nil {
		config = DefaultClientConfig()
	}

	return &Manager{
		client:    NewClientWithConfig(config),
		generator: NewConfigGenerator(config.ConfigPath),
		config:    config,
	}
}

// StartDaemon starts an FRR daemon
func (m *Manager) StartDaemon(ctx context.Context, daemon DaemonType) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	klog.V(2).Infof("Starting FRR daemon: %s", daemon)

	// Check if daemon is already running
	if m.isDaemonRunning(ctx, daemon) {
		klog.V(2).Infof("Daemon %s is already running", daemon)
		return nil
	}

	// Start the daemon using systemctl or service command
	cmd := exec.CommandContext(ctx, "systemctl", "start", fmt.Sprintf("frr@%s", daemon))
	if err := cmd.Run(); err != nil {
		// Try using service command as fallback
		cmd = exec.CommandContext(ctx, "service", string(daemon), "start")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to start daemon %s: %w", daemon, err)
		}
	}

	// Wait for daemon to start
	if err := m.waitForDaemon(ctx, daemon, 10*time.Second); err != nil {
		return fmt.Errorf("daemon %s failed to start: %w", daemon, err)
	}

	klog.V(2).Infof("Successfully started daemon: %s", daemon)
	return nil
}

// StopDaemon stops an FRR daemon
func (m *Manager) StopDaemon(ctx context.Context, daemon DaemonType) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	klog.V(2).Infof("Stopping FRR daemon: %s", daemon)

	// Don't stop zebra as it's the core routing manager
	if daemon == DaemonTypeZEBRA {
		return fmt.Errorf("cannot stop zebra daemon")
	}

	// Stop the daemon using systemctl or service command
	cmd := exec.CommandContext(ctx, "systemctl", "stop", fmt.Sprintf("frr@%s", daemon))
	if err := cmd.Run(); err != nil {
		// Try using service command as fallback
		cmd = exec.CommandContext(ctx, "service", string(daemon), "stop")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to stop daemon %s: %w", daemon, err)
		}
	}

	klog.V(2).Infof("Successfully stopped daemon: %s", daemon)
	return nil
}

// RestartDaemon restarts an FRR daemon
func (m *Manager) RestartDaemon(ctx context.Context, daemon DaemonType) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	klog.V(2).Infof("Restarting FRR daemon: %s", daemon)

	cmd := exec.CommandContext(ctx, "systemctl", "restart", fmt.Sprintf("frr@%s", daemon))
	if err := cmd.Run(); err != nil {
		// Try using service command as fallback
		cmd = exec.CommandContext(ctx, "service", string(daemon), "restart")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to restart daemon %s: %w", daemon, err)
		}
	}

	// Wait for daemon to start
	if err := m.waitForDaemon(ctx, daemon, 10*time.Second); err != nil {
		return fmt.Errorf("daemon %s failed to restart: %w", daemon, err)
	}

	klog.V(2).Infof("Successfully restarted daemon: %s", daemon)
	return nil
}

// ReloadDaemon reloads an FRR daemon configuration
func (m *Manager) ReloadDaemon(ctx context.Context, daemon DaemonType) error {
	klog.V(2).Infof("Reloading FRR daemon configuration: %s", daemon)

	// Send SIGHUP to reload configuration
	cmd := exec.CommandContext(ctx, "systemctl", "reload", fmt.Sprintf("frr@%s", daemon))
	if err := cmd.Run(); err != nil {
		// Try using kill -HUP as fallback
		pid, err := m.getDaemonPID(ctx, daemon)
		if err != nil {
			return fmt.Errorf("failed to get daemon PID: %w", err)
		}

		cmd = exec.CommandContext(ctx, "kill", "-HUP", strconv.Itoa(pid))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to reload daemon %s: %w", daemon, err)
		}
	}

	klog.V(2).Infof("Successfully reloaded daemon: %s", daemon)
	return nil
}

// EnableDaemon enables an FRR daemon to start on boot
func (m *Manager) EnableDaemon(ctx context.Context, daemon DaemonType) error {
	cmd := exec.CommandContext(ctx, "systemctl", "enable", fmt.Sprintf("frr@%s", daemon))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable daemon %s: %w", daemon, err)
	}

	klog.V(2).Infof("Successfully enabled daemon: %s", daemon)
	return nil
}

// DisableDaemon disables an FRR daemon from starting on boot
func (m *Manager) DisableDaemon(ctx context.Context, daemon DaemonType) error {
	// Don't disable zebra
	if daemon == DaemonTypeZEBRA {
		return fmt.Errorf("cannot disable zebra daemon")
	}

	cmd := exec.CommandContext(ctx, "systemctl", "disable", fmt.Sprintf("frr@%s", daemon))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to disable daemon %s: %w", daemon, err)
	}

	klog.V(2).Infof("Successfully disabled daemon: %s", daemon)
	return nil
}

// isDaemonRunning checks if a daemon is currently running
func (m *Manager) isDaemonRunning(ctx context.Context, daemon DaemonType) bool {
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", fmt.Sprintf("frr@%s", daemon))
	err := cmd.Run()
	return err == nil
}

// getDaemonPID gets the PID of a running daemon
func (m *Manager) getDaemonPID(ctx context.Context, daemon DaemonType) (int, error) {
	cmd := exec.CommandContext(ctx, "pidof", string(daemon))
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to get daemon PID: %w", err)
	}

	pidStr := strings.TrimSpace(string(output))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid PID: %s", pidStr)
	}

	return pid, nil
}

// waitForDaemon waits for a daemon to become available
func (m *Manager) waitForDaemon(ctx context.Context, daemon DaemonType, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if m.isDaemonRunning(ctx, daemon) {
			// Additional check: try to communicate with the daemon
			if err := m.client.HealthCheck(ctx); err == nil {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
			// Continue waiting
		}
	}

	return fmt.Errorf("timeout waiting for daemon %s to start", daemon)
}

// GetDaemonInfo gets detailed information about a daemon
func (m *Manager) GetDaemonInfo(ctx context.Context, daemon DaemonType) (*DaemonInfo, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	info := &DaemonInfo{
		Type:   daemon,
		Status: DaemonStatusUnknown,
	}

	// Check if running
	if m.isDaemonRunning(ctx, daemon) {
		info.Status = DaemonStatusRunning

		// Get PID
		if pid, err := m.getDaemonPID(ctx, daemon); err == nil {
			info.PID = pid
		}

		// Get version from vtysh (simplified)
		if output, err := m.client.ExecuteVtyshCommand(ctx, "show version"); err == nil {
			lines := strings.Split(output, "\n")
			if len(lines) > 0 {
				info.Version = strings.TrimSpace(lines[0])
			}
		}
	} else {
		info.Status = DaemonStatusStopped
	}

	return info, nil
}

// StartAllDaemons starts all enabled daemons
func (m *Manager) StartAllDaemons(ctx context.Context, enabledDaemons map[DaemonType]bool) error {
	klog.V(2).Info("Starting all enabled FRR daemons")

	// Always start zebra first
	if err := m.StartDaemon(ctx, DaemonTypeZEBRA); err != nil {
		return fmt.Errorf("failed to start zebra: %w", err)
	}

	// Start other enabled daemons
	for daemon, enabled := range enabledDaemons {
		if !enabled || daemon == DaemonTypeZEBRA {
			continue
		}

		if err := m.StartDaemon(ctx, daemon); err != nil {
			klog.Errorf("Failed to start daemon %s: %v", daemon, err)
			// Continue with other daemons
		}
	}

	return nil
}

// StopAllDaemons stops all running daemons except zebra
func (m *Manager) StopAllDaemons(ctx context.Context) error {
	klog.V(2).Info("Stopping all FRR daemons")

	daemons := []DaemonType{
		DaemonTypeBGPD,
		DaemonTypeOSPFD,
		DaemonTypeOSPF6D,
		DaemonTypeBFDD,
		DaemonTypeRIPD,
		DaemonTypeRIPNGD,
		DaemonTypeISISD,
		DaemonTypePIMD,
		DaemonTypeLDPD,
		DaemonTypeNHRPD,
		DaemonTypeFABRICD,
	}

	for _, daemon := range daemons {
		if m.isDaemonRunning(ctx, daemon) {
			if err := m.StopDaemon(ctx, daemon); err != nil {
				klog.Errorf("Failed to stop daemon %s: %v", daemon, err)
			}
		}
	}

	// Stop zebra last
	klog.V(2).Info("Stopping zebra daemon")
	cmd := exec.CommandContext(ctx, "systemctl", "stop", "frr@zebra")
	if err := cmd.Run(); err != nil {
		klog.Errorf("Failed to stop zebra: %v", err)
	}

	return nil
}

// ApplyConfiguration applies a new FRR configuration
func (m *Manager) ApplyConfiguration(ctx context.Context, config *Config, enabledDaemons map[DaemonType]bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	klog.V(2).Info("Applying FRR configuration")

	// Backup current configuration
	if err := m.generator.BackupConfig(); err != nil {
		klog.Warningf("Failed to backup configuration: %v", err)
	}

	// Generate daemons file
	if err := m.generator.GenerateDaemonsFile(enabledDaemons); err != nil {
		return fmt.Errorf("failed to generate daemons file: %w", err)
	}

	// Generate main configuration
	if err := m.generator.GenerateFRRConf(config); err != nil {
		return fmt.Errorf("failed to generate configuration: %w", err)
	}

	// Generate vtysh configuration
	if err := m.generator.GenerateVtyshConf(); err != nil {
		klog.Warningf("Failed to generate vtysh.conf: %v", err)
	}

	// Reload configuration for all running daemons
	for daemon, enabled := range enabledDaemons {
		if enabled && m.isDaemonRunning(ctx, daemon) {
			if err := m.ReloadDaemon(ctx, daemon); err != nil {
				klog.Errorf("Failed to reload daemon %s: %v", daemon, err)
			}
		}
	}

	klog.V(2).Info("Successfully applied FRR configuration")
	return nil
}

// GetClient returns the FRR client for direct command execution
func (m *Manager) GetClient() *Client {
	return m.client
}

// GetConfigGenerator returns the configuration generator
func (m *Manager) GetConfigGenerator() *ConfigGenerator {
	return m.generator
}

// MonitorDaemons starts monitoring daemon health and restarts failed daemons
func (m *Manager) MonitorDaemons(ctx context.Context, enabledDaemons map[DaemonType]bool, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			klog.V(2).Info("Stopping daemon monitoring")
			return
		case <-ticker.C:
			m.checkAndRestartDaemons(ctx, enabledDaemons)
		}
	}
}

// checkAndRestartDaemons checks daemon health and restarts if needed
func (m *Manager) checkAndRestartDaemons(ctx context.Context, enabledDaemons map[DaemonType]bool) {
	for daemon, enabled := range enabledDaemons {
		if !enabled {
			continue
		}

		if !m.isDaemonRunning(ctx, daemon) {
			klog.Warningf("Daemon %s is not running, attempting to restart", daemon)
			if err := m.StartDaemon(ctx, daemon); err != nil {
				klog.Errorf("Failed to restart daemon %s: %v", daemon, err)
			}
		}
	}
}

// ExportConfiguration exports the running configuration
func (m *Manager) ExportConfiguration(ctx context.Context) (string, error) {
	return m.client.GetRunningConfig(ctx)
}

// ImportConfiguration imports and applies a configuration
func (m *Manager) ImportConfiguration(ctx context.Context, configContent string) error {
	// Write configuration to file
	confPath := fmt.Sprintf("%s/frr.conf", m.config.ConfigPath)
	if err := os.WriteFile(confPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write configuration: %w", err)
	}

	// Reload all daemons
	return m.client.ReloadConfiguration(ctx)
}
