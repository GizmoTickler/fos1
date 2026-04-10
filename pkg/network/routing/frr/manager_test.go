package frr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyConfiguration_ValidationFailure_RollsBack(t *testing.T) {
	tmpDir := t.TempDir()

	// Write an initial config to serve as backup source
	originalContent := "! Original config\nhostname original\n!\n"
	confPath := filepath.Join(tmpDir, "frr.conf")
	if err := os.WriteFile(confPath, []byte(originalContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a mock executor that fails on validation (vtysh --dryrun)
	executor := &mockExecutor{
		runFunc: func(name string, args ...string) ([]byte, error) {
			for _, arg := range args {
				if arg == "--dryrun" {
					return []byte("% Error: bad config"), fmt.Errorf("exit status 1: bad config")
				}
			}
			return []byte(""), nil
		},
	}

	config := &ClientConfig{
		VTYSHPath:      "/usr/bin/vtysh",
		SocketPath:     "/var/run/frr",
		ConfigPath:     tmpDir,
		CommandTimeout: 30,
		MaxRetries:     1,
		RetryDelay:     0,
	}

	mgr := &Manager{
		client:    NewClientWithConfig(config),
		generator: NewConfigGeneratorWithExecutor(tmpDir, executor, "/usr/bin/vtysh"),
		config:    config,
	}

	newConfig := &Config{
		Hostname: "bad-router",
		Sections: []ConfigSection{},
	}

	enabledDaemons := map[DaemonType]bool{
		DaemonTypeZEBRA: true,
		DaemonTypeBGPD:  true,
	}

	err := mgr.ApplyConfiguration(context.Background(), newConfig, enabledDaemons)
	if err == nil {
		t.Fatal("expected error from ApplyConfiguration when validation fails, got nil")
	}

	if got := err.Error(); !containsSubstr(got, "validation failed") {
		t.Fatalf("expected 'validation failed' in error, got: %s", got)
	}

	// After rollback, the config should be restored to original content
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != originalContent {
		t.Fatalf("expected config to be rolled back to original, got: %s", string(data))
	}
}

func TestApplyConfiguration_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Write an initial config
	confPath := filepath.Join(tmpDir, "frr.conf")
	if err := os.WriteFile(confPath, []byte("! old config\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a mock executor that succeeds on validation
	executor := &mockExecutor{
		runFunc: func(name string, args ...string) ([]byte, error) {
			return []byte(""), nil
		},
	}

	config := &ClientConfig{
		VTYSHPath:      "/usr/bin/vtysh",
		SocketPath:     "/var/run/frr",
		ConfigPath:     tmpDir,
		CommandTimeout: 30,
		MaxRetries:     1,
		RetryDelay:     0,
	}

	mgr := &Manager{
		client:    NewClientWithConfig(config),
		generator: NewConfigGeneratorWithExecutor(tmpDir, executor, "/usr/bin/vtysh"),
		config:    config,
	}

	newConfig := &Config{
		Hostname: "good-router",
		Sections: []ConfigSection{},
	}

	// No enabled daemons running, so reload won't be attempted
	enabledDaemons := map[DaemonType]bool{}

	err := mgr.ApplyConfiguration(context.Background(), newConfig, enabledDaemons)
	if err != nil {
		t.Fatalf("expected no error from ApplyConfiguration, got: %v", err)
	}

	// The config file should now contain the new config
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if !containsSubstr(string(data), "hostname good-router") {
		t.Fatalf("expected new config to contain 'hostname good-router', got: %s", string(data))
	}
}

func TestApplyConfiguration_NoBackup_ValidationFailure_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()

	// Don't write an initial config - so no backup will be created

	executor := &mockExecutor{
		runFunc: func(name string, args ...string) ([]byte, error) {
			for _, arg := range args {
				if arg == "--dryrun" {
					return []byte("syntax error"), fmt.Errorf("exit status 1: syntax error")
				}
			}
			return []byte(""), nil
		},
	}

	config := &ClientConfig{
		VTYSHPath:      "/usr/bin/vtysh",
		SocketPath:     "/var/run/frr",
		ConfigPath:     tmpDir,
		CommandTimeout: 30,
		MaxRetries:     1,
		RetryDelay:     0,
	}

	mgr := &Manager{
		client:    NewClientWithConfig(config),
		generator: NewConfigGeneratorWithExecutor(tmpDir, executor, "/usr/bin/vtysh"),
		config:    config,
	}

	newConfig := &Config{
		Hostname: "bad-router",
		Sections: []ConfigSection{},
	}

	enabledDaemons := map[DaemonType]bool{}

	err := mgr.ApplyConfiguration(context.Background(), newConfig, enabledDaemons)
	if err == nil {
		t.Fatal("expected error when validation fails, got nil")
	}
}
