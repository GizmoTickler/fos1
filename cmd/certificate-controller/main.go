package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	certmanagerclientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/leaderelection"
	"github.com/GizmoTickler/fos1/pkg/security/certificates"
)

func main() {
	// Parse command line flags
	var (
		kubeconfig   string
		namespace    string
		resyncPeriod time.Duration
		workers      int
	)

	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	flag.StringVar(&namespace, "namespace", "cert-manager", "Namespace to watch for certificates and issuers")
	flag.DurationVar(&resyncPeriod, "resync-period", 10*time.Minute, "Resync period for informers")
	flag.IntVar(&workers, "workers", 2, "Number of workers for processing the queues")
	klog.InitFlags(nil)
	flag.Parse()

	// Create Kubernetes client
	var config *rest.Config
	var err error
	if kubeconfig == "" {
		klog.Info("Using in-cluster configuration")
		config, err = rest.InClusterConfig()
	} else {
		klog.Infof("Using configuration from %s", kubeconfig)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if err != nil {
		klog.Fatalf("Failed to create config: %v", err)
	}

	// Create Kubernetes client
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Create cert-manager client
	certClient, err := certmanagerclientset.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Failed to create cert-manager client: %v", err)
	}

	// Create certificate manager
	certManager, err := certificates.NewCertManager(
		kubeClient,
		certClient,
		&certificates.Config{
			DefaultNamespace:     namespace,
			DefaultIssuerName:    "selfsigned-issuer",
			DefaultIssuerKind:    "Issuer",
			DefaultIssuerGroup:   "cert-manager.io",
			RenewalCheckInterval: 24 * time.Hour,
			DefaultKeySize:       2048,
			DefaultKeyAlgorithm:  "RSA",
			DefaultKeyEncoding:   "PKCS1",
			DefaultDuration:      90 * 24 * time.Hour,
			DefaultRenewBefore:   30 * 24 * time.Hour,
		},
	)
	if err != nil {
		klog.Fatalf("Failed to create certificate manager: %v", err)
	}

	// Create controller
	controller, err := certificates.NewController(
		kubeClient,
		certClient,
		certManager,
		&certificates.ControllerConfig{
			Namespace:    namespace,
			ResyncPeriod: resyncPeriod,
			Workers:      workers,
		},
	)
	if err != nil {
		klog.Fatalf("Failed to create certificate controller: %v", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signalCh
		klog.Infof("Received signal %s, shutting down", sig)
		cancel()
	}()

	// Sprint 31 / Ticket 47: HA via client-go leader election. The standby
	// pod blocks here until it acquires the Lease, then runs the controller
	// loop. POD_NAMESPACE / POD_NAME come from the downward API on the
	// Deployment so the lease lives in the controller's own namespace.
	leNamespace := leaderelection.NamespaceFromEnv()
	if leNamespace == "" {
		klog.Fatal("POD_NAMESPACE must be set (downward API) for leader election")
	}

	leErr := leaderelection.Run(ctx, leaderelection.Config{
		LockName:      "certificate-controller.fos1.io",
		LockNamespace: leNamespace,
		Identity:      leaderelection.IdentityFromEnv(),
		Client:        kubeClient,
	}, func(leaderCtx context.Context) {
		// Initialize the certificate manager
		if err := certManager.Initialize(leaderCtx); err != nil {
			klog.Errorf("Failed to initialize certificate manager: %v", err)
			return
		}

		// Run the controller — blocks until leaderCtx is cancelled.
		if err := controller.Run(leaderCtx); err != nil && leaderCtx.Err() == nil {
			klog.Errorf("certificate controller exited: %v", err)
		}
	})
	if leErr != nil {
		klog.Fatalf("leader election: %v", leErr)
	}
}
