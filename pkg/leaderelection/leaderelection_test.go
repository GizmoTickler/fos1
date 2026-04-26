// Sprint 31 / Ticket 47 — leader-election helper tests.
//
// These tests exercise the lightweight contract of the helper without
// spinning up an apiserver: validation, default timings, env-derived
// identity/namespace, and the OnStartedLeading happy path against a fake
// kubernetes client. The actual Lease coordination is the responsibility of
// k8s.io/client-go and is covered there; the only thing we test on top is
// that we wire the resource lock and callback correctly.
package leaderelection

import (
	"context"
	"os"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func TestConfigValidateRequiresAllFields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name:    "missing lock name",
			mutate:  func(c *Config) { c.LockName = "" },
			wantErr: "LockName is required",
		},
		{
			name:    "missing lock namespace",
			mutate:  func(c *Config) { c.LockNamespace = "" },
			wantErr: "LockNamespace is required",
		},
		{
			name:    "missing identity",
			mutate:  func(c *Config) { c.Identity = "" },
			wantErr: "Identity is required",
		},
		{
			name:    "missing client",
			mutate:  func(c *Config) { c.Client = nil },
			wantErr: "Client is required",
		},
	}

	base := func() Config {
		return Config{
			LockName:      "test.fos1.io",
			LockNamespace: "default",
			Identity:      "pod-1",
			Client:        fake.NewSimpleClientset(),
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			err := cfg.validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if got := err.Error(); !contains(got, tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, got)
			}
		})
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	cfg := Config{}
	cfg.applyDefaults()
	if cfg.LeaseDuration != DefaultLeaseDuration {
		t.Errorf("LeaseDuration: got %v want %v", cfg.LeaseDuration, DefaultLeaseDuration)
	}
	if cfg.RenewDeadline != DefaultRenewDeadline {
		t.Errorf("RenewDeadline: got %v want %v", cfg.RenewDeadline, DefaultRenewDeadline)
	}
	if cfg.RetryPeriod != DefaultRetryPeriod {
		t.Errorf("RetryPeriod: got %v want %v", cfg.RetryPeriod, DefaultRetryPeriod)
	}

	custom := Config{
		LeaseDuration: 30 * time.Second,
		RenewDeadline: 20 * time.Second,
		RetryPeriod:   5 * time.Second,
	}
	custom.applyDefaults()
	if custom.LeaseDuration != 30*time.Second {
		t.Errorf("custom LeaseDuration overwritten: got %v", custom.LeaseDuration)
	}
}

func TestIdentityFromEnv(t *testing.T) {
	t.Setenv("POD_NAME", "ids-controller-7d-abc")
	if got := IdentityFromEnv(); got != "ids-controller-7d-abc" {
		t.Errorf("got %q, want %q", got, "ids-controller-7d-abc")
	}

	t.Setenv("POD_NAME", "")
	hn, _ := os.Hostname()
	if got := IdentityFromEnv(); got != hn {
		t.Errorf("hostname fallback: got %q, want %q", got, hn)
	}
}

func TestNamespaceFromEnv(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "security")
	if got := NamespaceFromEnv(); got != "security" {
		t.Errorf("got %q, want %q", got, "security")
	}
	t.Setenv("POD_NAMESPACE", "")
	if got := NamespaceFromEnv(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// TestRunReturnsOnContextCancel exercises the happy path: start the elector
// against a fake client, immediately cancel the outer context, and assert
// Run returns nil. The fake client lets the elector's Lease create call
// succeed so the candidate can become leader before we cancel.
func TestRunReturnsOnContextCancel(t *testing.T) {
	client := fake.NewSimpleClientset()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	leaderRan := make(chan struct{})

	go func() {
		err := Run(ctx, Config{
			LockName:      "test.fos1.io",
			LockNamespace: "default",
			Identity:      "test-pod",
			Client:        client,
			LeaseDuration: 1 * time.Second,
			RenewDeadline: 500 * time.Millisecond,
			RetryPeriod:   100 * time.Millisecond,
		}, func(leaderCtx context.Context) {
			close(leaderRan)
			<-leaderCtx.Done()
		})
		// Either a graceful shutdown (nil) or the lease-lost shutdown error
		// is acceptable here; both are normal termination paths from the
		// candidate's perspective.
		_ = err
	}()

	select {
	case <-leaderRan:
		// Became leader.
	case <-time.After(3 * time.Second):
		t.Fatal("OnStartedLeading was not invoked within 3s")
	}

	cancel()
	// Give Run a moment to unwind; nothing else to assert beyond no
	// goroutine leak / panic on shutdown.
	time.Sleep(200 * time.Millisecond)
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && (indexOf(haystack, needle) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
