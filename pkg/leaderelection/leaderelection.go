// Package leaderelection wraps k8s.io/client-go/tools/leaderelection so the
// repository's controller mains can opt in to active/standby HA without each
// pulling controller-runtime in just for the manager-level toggle.
//
// Sprint 31 / Ticket 47 introduced this helper. The wrapper enforces a single
// timing profile — LeaseDuration 15s / RenewDeadline 10s / RetryPeriod 2s —
// so every fos1 controller targets the same RTO ≤ 30s. Override the timings
// only when a controller has a documented reason; the defaults are correct
// for everything in tree.
//
// The standard usage from a controller main is:
//
//	cfg := leaderelection.Config{
//	    LockName:      "ids-controller.fos1.io",
//	    LockNamespace: os.Getenv("POD_NAMESPACE"),
//	    Identity:      os.Getenv("POD_NAME"),
//	    Client:        kubeClient,
//	}
//	if err := leaderelection.Run(ctx, cfg, func(leaderCtx context.Context) {
//	    runController(leaderCtx) // blocks until leaderCtx is cancelled
//	}); err != nil {
//	    klog.Fatalf("leader election: %v", err)
//	}
//
// The OnStartedLeading callback runs in the same goroutine as Run; Run blocks
// until the supplied context is cancelled. When the elector loses leadership
// the leaderCtx passed to the callback is cancelled and Run returns the
// outer context's error (if any).
package leaderelection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
)

// DefaultLeaseDuration is the lease the active leader holds before any peer
// is allowed to attempt acquisition. Sprint 31 / Ticket 47 fixed this at 15s
// to give every fos1 controller the same RTO ≤ 30s envelope.
const DefaultLeaseDuration = 15 * time.Second

// DefaultRenewDeadline is how long the active leader retries renewing the
// lease before giving up and stepping down. Must be < LeaseDuration.
const DefaultRenewDeadline = 10 * time.Second

// DefaultRetryPeriod is how often non-leaders check the lease.
const DefaultRetryPeriod = 2 * time.Second

// Config drives Run. LockName, LockNamespace, Identity, and Client are
// required; the timing fields and ReleaseOnCancel default to the
// fos1-standard values when zero.
type Config struct {
	// LockName is the Lease object's name. Convention: "<controller>.fos1.io".
	LockName string

	// LockNamespace is the namespace the Lease is created in. Pass the
	// POD_NAMESPACE env var (downward API) so each controller's lease lives
	// in its own namespace and the RBAC stays namespace-scoped.
	LockNamespace string

	// Identity is the unique identity of this candidate. Use POD_NAME
	// (downward API) so the lease's holderIdentity matches the active pod.
	Identity string

	// Client is the kube client used to read/write the Lease. The caller
	// owns its lifetime.
	Client kubernetes.Interface

	// LeaseDuration / RenewDeadline / RetryPeriod use the fos1 defaults
	// when zero. Override only with a documented reason.
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration

	// ReleaseOnCancel makes the elector release the lease on graceful
	// shutdown (Run's ctx cancellation). Defaults to true so a clean
	// SIGTERM lets the standby take over without waiting for the lease
	// to expire.
	ReleaseOnCancel *bool
}

// LeaderFunc is the work the elected leader runs. It must return promptly
// when leaderCtx is cancelled (either because the outer context was
// cancelled or because we lost the lease).
type LeaderFunc func(leaderCtx context.Context)

// Run blocks the caller in leader-election mode. The supplied LeaderFunc
// is invoked exactly when this candidate becomes leader and is given a
// context that is cancelled the moment leadership is lost.
//
// Run returns nil on graceful shutdown (the caller's ctx cancelled) and a
// non-nil error if the elector itself failed to construct or start.
func Run(ctx context.Context, cfg Config, fn LeaderFunc) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	cfg.applyDefaults()

	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		cfg.LockNamespace,
		cfg.LockName,
		cfg.Client.CoreV1(),
		cfg.Client.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity: cfg.Identity,
		},
	)
	if err != nil {
		return fmt.Errorf("build leases resource lock: %w", err)
	}

	leaderCtx, leaderCancel := context.WithCancel(ctx)
	defer leaderCancel()

	leCfg := leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   cfg.LeaseDuration,
		RenewDeadline:   cfg.RenewDeadline,
		RetryPeriod:     cfg.RetryPeriod,
		ReleaseOnCancel: derefBool(cfg.ReleaseOnCancel, true),
		Name:            cfg.LockName,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(callbackCtx context.Context) {
				klog.InfoS("acquired leadership",
					"lock", cfg.LockName,
					"namespace", cfg.LockNamespace,
					"identity", cfg.Identity)
				fn(callbackCtx)
			},
			OnStoppedLeading: func() {
				klog.InfoS("lost leadership",
					"lock", cfg.LockName,
					"namespace", cfg.LockNamespace,
					"identity", cfg.Identity)
				leaderCancel()
			},
			OnNewLeader: func(identity string) {
				if identity == cfg.Identity {
					return
				}
				klog.InfoS("observed new leader",
					"lock", cfg.LockName,
					"namespace", cfg.LockNamespace,
					"leader", identity)
			},
		},
	}

	elector, err := leaderelection.NewLeaderElector(leCfg)
	if err != nil {
		return fmt.Errorf("build leader elector: %w", err)
	}

	// Run blocks until leaderCtx is cancelled (either because the outer
	// ctx was cancelled, or because OnStoppedLeading was triggered).
	elector.Run(leaderCtx)

	if ctx.Err() != nil {
		// Outer ctx cancelled — graceful shutdown.
		return nil
	}
	// Inner cancel without outer cancel means we lost the lease. Treat as
	// shutdown so the caller can exit and a new pod takes over the lease.
	return errors.New("leader election ended; pod will exit and standby will take over")
}

// IdentityFromEnv returns the value of POD_NAME if set, falling back to the
// hostname. Controllers should pass POD_NAME from the downward API so the
// holderIdentity in the Lease object matches the active pod name.
func IdentityFromEnv() string {
	if name := os.Getenv("POD_NAME"); name != "" {
		return name
	}
	if hn, err := os.Hostname(); err == nil {
		return hn
	}
	return "unknown"
}

// NamespaceFromEnv returns POD_NAMESPACE; an empty string is returned if the
// env var is unset. Controllers should fail fast in main when this is empty,
// because a Lease cannot be created in the empty namespace.
func NamespaceFromEnv() string {
	return os.Getenv("POD_NAMESPACE")
}

func (c *Config) validate() error {
	if c.LockName == "" {
		return errors.New("leaderelection: LockName is required")
	}
	if c.LockNamespace == "" {
		return errors.New("leaderelection: LockNamespace is required (pass POD_NAMESPACE)")
	}
	if c.Identity == "" {
		return errors.New("leaderelection: Identity is required (pass POD_NAME)")
	}
	if c.Client == nil {
		return errors.New("leaderelection: Client is required")
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.LeaseDuration == 0 {
		c.LeaseDuration = DefaultLeaseDuration
	}
	if c.RenewDeadline == 0 {
		c.RenewDeadline = DefaultRenewDeadline
	}
	if c.RetryPeriod == 0 {
		c.RetryPeriod = DefaultRetryPeriod
	}
}

func derefBool(p *bool, fallback bool) bool {
	if p == nil {
		return fallback
	}
	return *p
}
