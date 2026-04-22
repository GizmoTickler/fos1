// Command api-server is the binary entrypoint for the read-only REST
// management API (v0) described at docs/design/api-server.md.
//
// It constructs a controller-runtime manager (for a cached client and
// informer that share its cache with other in-process controllers when
// run side-by-side) and hands the client to pkg/api.Server. The binary
// also owns TLS file paths, the allowlist configuration, and OS signal
// handling for graceful shutdown.
//
// v0 is READ-ONLY. There are no flags or environment toggles that turn on
// write paths; enabling writes is a deliberate follow-up ticket.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/GizmoTickler/fos1/pkg/api"
	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

// scheme is the runtime scheme used by the manager. We register the core
// Kubernetes types (for Secrets, ConfigMaps, Events etc. that the manager
// uses internally) and the FilterPolicy CRD.
var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(policy.AddToScheme(scheme))
}

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	addr := flag.String("address", api.DefaultListenAddress, "TCP address to listen on.")
	certFile := flag.String("server-cert", "/etc/fos1/api/tls.crt", "Path to the server TLS certificate (PEM).")
	keyFile := flag.String("server-key", "/etc/fos1/api/tls.key", "Path to the server TLS private key (PEM).")
	caFile := flag.String("client-ca", "/etc/fos1/api/ca.crt", "Path to the client-cert CA bundle (PEM).")
	allowlist := flag.String("allowlist", "", "Comma-separated list of authorized client-cert Subject CNs.")
	allowlistFile := flag.String("allowlist-file", "", "Optional path to a file containing one Subject CN per line. Overrides --allowlist if set.")
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig. If empty and --in-cluster is set, the in-cluster config is used.")
	inCluster := flag.Bool("in-cluster", false, "Use the pod's service-account token (in-cluster config).")
	metricsAddr := flag.String("metrics-addr", "0", "controller-runtime metrics bind address. '0' disables the endpoint.")
	readTimeout := flag.Duration("read-timeout", api.DefaultReadTimeout, "HTTP read timeout.")
	writeTimeout := flag.Duration("write-timeout", api.DefaultWriteTimeout, "HTTP write timeout.")

	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		klog.InfoS("signal received, shutting down", "signal", s)
		cancel()
	}()

	restConfig, err := loadRESTConfig(*kubeconfig, *inCluster)
	if err != nil {
		klog.ErrorS(err, "load kube config")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme: scheme,
		// Bind a metrics server lazily; the default "0" disables it. We
		// keep the manager minimal — no leader election, no webhooks.
		LeaderElection: false,
	})
	if err != nil {
		klog.ErrorS(err, "build controller-runtime manager")
		os.Exit(1)
	}

	allow, err := loadAllowlist(*allowlist, *allowlistFile)
	if err != nil {
		klog.ErrorS(err, "load allowlist")
		os.Exit(1)
	}

	cfg := api.ServerConfig{
		Address:        *addr,
		ServerCertFile: *certFile,
		ServerKeyFile:  *keyFile,
		ClientCAFile:   *caFile,
		Allowlist:      allow,
		ReadTimeout:    *readTimeout,
		WriteTimeout:   *writeTimeout,
	}

	// The manager's client is cached once the manager starts; the cache is
	// shared across anything running under the manager (including future
	// in-process controllers). Before Start() returns, the client is usable
	// but reads go direct to the apiserver. We accept that trade-off for
	// simplicity; the readyz handler will gate cache-sync for downstream
	// callers.
	srv, err := api.NewServer(mgr.GetClient(), cfg)
	if err != nil {
		klog.ErrorS(err, "build api server")
		os.Exit(1)
	}
	srv.Readiness = managerReadiness{mgr: mgr}

	// Start the manager in a goroutine; it owns the informer cache. The
	// API server runs in the main goroutine so a Serve error propagates
	// directly to exit code 1.
	go func() {
		if err := mgr.Start(ctx); err != nil {
			klog.ErrorS(err, "manager exited with error")
			cancel()
		}
	}()

	// Allow the cache to warm up before accepting traffic. We do not block
	// indefinitely — the readyz handler will report NotReady until the
	// cache syncs, which is the right signal for kube-proxy.
	warmupCtx, warmupCancel := context.WithTimeout(ctx, 30*time.Second)
	if ok := mgr.GetCache().WaitForCacheSync(warmupCtx); !ok {
		klog.Warning("informer cache did not sync within 30s; proceeding with 'not ready' until it does")
	}
	warmupCancel()

	klog.InfoS("starting read-only REST management API",
		"address", cfg.Address,
		"metricsAddr", *metricsAddr,
		"inCluster", *inCluster)

	if err := srv.Run(ctx); err != nil {
		klog.ErrorS(err, "api server run")
		os.Exit(1)
	}
}

// loadRESTConfig resolves a *rest.Config honoring the --in-cluster flag and
// the usual KUBECONFIG precedence when running out of cluster.
func loadRESTConfig(kubeconfigPath string, inCluster bool) (*rest.Config, error) {
	if inCluster {
		return ctrlconfig.GetConfig()
	}
	if kubeconfigPath != "" {
		loading := clientcmd.NewDefaultClientConfigLoadingRules()
		loading.ExplicitPath = kubeconfigPath
		cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{})
		return cc.ClientConfig()
	}
	return ctrlconfig.GetConfig()
}

// loadAllowlist returns the merged Subject-CN allowlist. If allowlistFile is
// non-empty it wins over the command-line --allowlist flag. One CN per line
// in the file; blank lines and lines starting with '#' are ignored.
func loadAllowlist(inline, path string) ([]string, error) {
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(raw), "\n")
		out := make([]string, 0, len(lines))
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			out = append(out, l)
		}
		return out, nil
	}
	if inline == "" {
		return nil, nil
	}
	parts := strings.Split(inline, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// managerReadiness adapts ctrl.Manager to api.Readiness. It reports ready
// once the cache has synced; before that, the readyz endpoint returns 503.
type managerReadiness struct {
	mgr ctrl.Manager
}

func (m managerReadiness) Ready(ctx context.Context) error {
	if m.mgr.GetCache().WaitForCacheSync(ctx) {
		return nil
	}
	return context.DeadlineExceeded
}
