// threatintel-controller is the entry point for the ThreatFeed reconciler.
// It watches ThreatFeed CRs, polls each feed on its RefreshInterval, and
// translates indicators into Cilium deny policies via the
// pkg/security/threatintel package.
//
// Supports URLhaus CSV (Sprint 30 Ticket 44) and MISP JSON (Sprint 31
// Ticket 53) feed formats. For MISP feeds the controller loads API keys
// from Kubernetes Secrets referenced by spec.authSecretRef via kubectl.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/leaderelection"
	"github.com/GizmoTickler/fos1/pkg/security/threatintel"
)

func main() {
	ciliumAPI := flag.String("cilium-api", "", "Cilium API endpoint (empty uses kubectl)")
	tick := flag.Duration("tick-interval", 15*time.Second, "Reconcile loop tick interval")
	httpTimeout := flag.Duration("http-timeout", 30*time.Second, "HTTP timeout for feed fetches")
	defaultSecretNS := flag.String("default-secret-namespace", "security", "Namespace used to resolve authSecretRef when the ThreatFeed does not set one")
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig (empty uses in-cluster or KUBECONFIG)")
	flag.Parse()

	ciliumClient := cilium.NewDefaultCiliumClient(*ciliumAPI, "")

	store, err := threatintel.NewKubectlFeedStore()
	if err != nil {
		log.Fatalf("threatintel-controller: build feed store: %v", err)
	}
	store.Kubeconfig = *kubeconfig

	ctrl := threatintel.NewController(store, ciliumClient)
	ctrl.TickInterval = *tick
	ctrl.HTTPClient = &http.Client{Timeout: *httpTimeout}
	ctrl.Secrets = &threatintel.KubectlSecretReader{Kubeconfig: *kubeconfig}
	ctrl.DefaultSecretNamespace = *defaultSecretNS

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		fmt.Printf("threatintel-controller: received %v, shutting down\n", sig)
		cancel()
	}()

	// Sprint 31 / Ticket 47: HA via client-go leader election. The
	// reconcile loop pushes Cilium policies; running two writers
	// concurrently would generate redundant API churn and racing status
	// updates. We build a typed kube client here only for the Lease;
	// the rest of the controller continues to use the kubectl shells.
	kubeClient, err := buildKubeClient(*kubeconfig)
	if err != nil {
		log.Fatalf("threatintel-controller: build kube client for leader election: %v", err)
	}
	leNamespace := leaderelection.NamespaceFromEnv()
	if leNamespace == "" {
		log.Fatal("threatintel-controller: POD_NAMESPACE must be set (downward API) for leader election")
	}

	log.Println("threatintel-controller: waiting for leader election")
	leErr := leaderelection.Run(ctx, leaderelection.Config{
		LockName:      "threatintel-controller.fos1.io",
		LockNamespace: leNamespace,
		Identity:      leaderelection.IdentityFromEnv(),
		Client:        kubeClient,
	}, func(leaderCtx context.Context) {
		log.Println("threatintel-controller: starting reconcile loop")
		if err := ctrl.Run(leaderCtx); err != nil && err != context.Canceled && leaderCtx.Err() == nil {
			log.Printf("threatintel-controller: run: %v", err)
		}
		log.Println("threatintel-controller: stopped")
	})
	if leErr != nil {
		log.Fatalf("threatintel-controller: leader election: %v", leErr)
	}
}

// buildKubeClient resolves a typed Kubernetes client used solely for the
// leader-election Lease. In-cluster takes precedence; falls back to the
// supplied kubeconfig path when running outside the cluster (developer
// laptop / KUBECONFIG).
func buildKubeClient(kubeconfig string) (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		// Out-of-cluster fallback. ClientConfig honours $KUBECONFIG when
		// kubeconfig is empty.
		loading := clientcmd.NewDefaultClientConfigLoadingRules()
		if kubeconfig != "" {
			loading.ExplicitPath = kubeconfig
		}
		cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{})
		cfg, err = cc.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("resolve kube config: %w", err)
		}
	}
	return kubernetes.NewForConfig(cfg)
}
