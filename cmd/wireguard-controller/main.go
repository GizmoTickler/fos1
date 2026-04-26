package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GizmoTickler/fos1/pkg/leaderelection"
	wgcontroller "github.com/GizmoTickler/fos1/pkg/vpn/controller"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

func main() {
	// Parse command line flags
	var (
		kubeconfig   string
		resyncPeriod time.Duration
		workers      int
		configDir    string
		wgBinary     string
	)

	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	flag.DurationVar(&resyncPeriod, "resync-period", 30*time.Minute, "Resync period for informers")
	flag.IntVar(&workers, "workers", 2, "Number of worker threads")
	flag.StringVar(&configDir, "config-dir", "/etc/wireguard", "Directory for WireGuard configuration files")
	flag.StringVar(&wgBinary, "wg-binary", "wg", "Path to WireGuard binary")
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

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Failed to create client: %v", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Failed to create dynamic client: %v", err)
	}

	gvr := schema.GroupVersionResource{
		Group:    "vpn.fos1.io",
		Version:  "v1alpha1",
		Resource: "wireguardinterfaces",
	}
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynamicClient, resyncPeriod, "", nil)
	informer := factory.ForResource(gvr).Informer()

	controller, err := wgcontroller.NewWireGuardController(
		kubeClient,
		informer,
		&wgcontroller.Config{
			ResyncPeriod: resyncPeriod,
			Workers:      workers,
			ConfigDir:    configDir,
			WGBinary:     wgBinary,
		},
	)
	if err != nil {
		klog.Fatalf("Failed to create WireGuard controller: %v", err)
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

	// Sprint 31 / Ticket 47: HA via client-go leader election. The
	// WireGuard controller mutates per-host wg interfaces / config files,
	// which must be driven by a single active leader to avoid two writers
	// fighting over the same kernel state.
	leNamespace := leaderelection.NamespaceFromEnv()
	if leNamespace == "" {
		klog.Fatal("POD_NAMESPACE must be set (downward API) for leader election")
	}

	klog.Info("WireGuard controller waiting for leader election")
	leErr := leaderelection.Run(ctx, leaderelection.Config{
		LockName:      "wireguard-controller.fos1.io",
		LockNamespace: leNamespace,
		Identity:      leaderelection.IdentityFromEnv(),
		Client:        kubeClient,
	}, func(leaderCtx context.Context) {
		klog.Info("Starting WireGuard controller")
		runErr := controller.Run(leaderCtx)
		if runErr != nil && leaderCtx.Err() == nil {
			klog.Errorf("WireGuard controller exited with error: %v", runErr)
		}
		klog.Info(fmt.Sprintf("Shutting down"))
	})
	if leErr != nil {
		klog.Fatalf("leader election: %v", leErr)
	}
}
