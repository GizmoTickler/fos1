package frr

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// mockExecutor is a test double for CommandExecutor
type mockExecutor struct {
	// runFunc is called when Run is invoked; if nil, returns success
	runFunc func(name string, args ...string) ([]byte, error)
	// calls records each invocation for assertions
	calls []mockCall
}

type mockCall struct {
	Name string
	Args []string
}

func (m *mockExecutor) Run(name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, mockCall{Name: name, Args: args})
	if m.runFunc != nil {
		return m.runFunc(name, args...)
	}
	return []byte(""), nil
}

func TestValidateConfig_FileDoesNotExist(t *testing.T) {
	tmpDir := t.TempDir()
	gen := NewConfigGeneratorWithExecutor(tmpDir, &mockExecutor{}, "/usr/bin/vtysh")

	err := gen.ValidateConfig()
	if err == nil {
		t.Fatal("expected error for missing config file, got nil")
	}
	if got := err.Error(); !contains(got, "does not exist") {
		t.Fatalf("expected 'does not exist' in error, got: %s", got)
	}
}

func TestValidateConfig_ValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "frr.conf")
	if err := os.WriteFile(confPath, []byte("hostname router1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	executor := &mockExecutor{
		runFunc: func(name string, args ...string) ([]byte, error) {
			// vtysh --dryrun succeeds
			return []byte(""), nil
		},
	}

	gen := NewConfigGeneratorWithExecutor(tmpDir, executor, "/usr/bin/vtysh")

	err := gen.ValidateConfig()
	if err != nil {
		t.Fatalf("expected no error for valid config, got: %v", err)
	}

	// Verify vtysh was called with correct arguments
	if len(executor.calls) != 1 {
		t.Fatalf("expected 1 call to executor, got %d", len(executor.calls))
	}
	call := executor.calls[0]
	if call.Name != "/usr/bin/vtysh" {
		t.Fatalf("expected vtysh call, got: %s", call.Name)
	}
	expectedArgs := []string{"-f", confPath, "--dryrun"}
	for i, arg := range expectedArgs {
		if i >= len(call.Args) || call.Args[i] != arg {
			t.Fatalf("expected arg %d to be %q, got %q", i, arg, call.Args)
		}
	}
}

func TestValidateConfig_InvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "frr.conf")
	if err := os.WriteFile(confPath, []byte("invalid config\n"), 0644); err != nil {
		t.Fatal(err)
	}

	executor := &mockExecutor{
		runFunc: func(name string, args ...string) ([]byte, error) {
			return []byte("% Unknown command: invalid"), fmt.Errorf("exit status 1: %s", "Unknown command: invalid")
		},
	}

	gen := NewConfigGeneratorWithExecutor(tmpDir, executor, "/usr/bin/vtysh")

	err := gen.ValidateConfig()
	if err == nil {
		t.Fatal("expected error for invalid config, got nil")
	}
	if got := err.Error(); !contains(got, "validation failed") {
		t.Fatalf("expected 'validation failed' in error, got: %s", got)
	}
}

func TestBackupAndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	gen := NewConfigGenerator(tmpDir)

	originalContent := "hostname original-router\n"
	confPath := filepath.Join(tmpDir, "frr.conf")
	if err := os.WriteFile(confPath, []byte(originalContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Backup
	if err := gen.BackupConfig(); err != nil {
		t.Fatalf("BackupConfig failed: %v", err)
	}

	// Find backup file
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	var backupPath string
	for _, entry := range entries {
		if entry.Name() != "frr.conf" {
			backupPath = filepath.Join(tmpDir, entry.Name())
			break
		}
	}
	if backupPath == "" {
		t.Fatal("no backup file found")
	}

	// Overwrite original
	newContent := "hostname new-router\n"
	if err := os.WriteFile(confPath, []byte(newContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Restore
	if err := gen.RestoreBackup(backupPath); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	// Verify restoration
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != originalContent {
		t.Fatalf("expected restored content %q, got %q", originalContent, string(data))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
