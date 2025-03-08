package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/cilium"
	"github.com/varuntirumala1/fos1/pkg/cilium/controllers"
)

func main() {
	// Configure logging
	klog.InitFlags(nil)
	defer klog.Flush()
	
	// Parse command line flags
	apiEndpoint := flag.String("api-endpoint", "http://localhost:9234", "Cilium API endpoint")
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig file for accessing k8s cluster")
	k8sContext := flag.String("k8s-context", "", "Kubernetes context to use")
	inCluster := flag.Bool("in-cluster", false, "Use in-cluster configuration (service account)")
	pollInterval := flag.Duration("poll-interval", 30*time.Second, "Poll interval for route synchronization")
	
	flag.Parse()

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signalCh
		klog.InfoS("Received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Create Kubernetes client
	var config *rest.Config
	var err error
	
	if *inCluster {
		klog.InfoS("Using in-cluster configuration")
		config, err = rest.InClusterConfig()
	} else {
		klog.InfoS("Using kubeconfig", "path", *kubeconfig, "context", *k8sContext)
		configLoadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		if *kubeconfig != "" {
			configLoadingRules.ExplicitPath = *kubeconfig
		}
		
		configOverrides := &clientcmd.ConfigOverrides{}
		if *k8sContext != "" {
			configOverrides.CurrentContext = *k8sContext
		}
		
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			configLoadingRules,
			configOverrides,
		)
		
		config, err = kubeConfig.ClientConfig()
	}
	
	if err != nil {
		klog.Fatalf("Failed to create Kubernetes client config: %v", err)
	}
	
	// Create dynamic client for CRDs
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Failed to create Kubernetes dynamic client: %v", err)
	}
	
	// Create Cilium client
	klog.InfoS("Creating Cilium client", "apiEndpoint", *apiEndpoint)
	ciliumClient := cilium.NewDefaultCiliumClient(*apiEndpoint, *k8sContext)
	
	// Create NetworkController
	networkController := cilium.NewNetworkController(ciliumClient)
	
	// Create RouteSynchronizer
	routeSynchronizer := cilium.NewRouteSynchronizer(ciliumClient, *pollInterval)
	
	// Create Controller Manager
	klog.InfoS("Creating controller manager")
	controllerManager := controllers.NewControllerManager(
		dynamicClient,
		ciliumClient,
		routeSynchronizer,
		networkController,
	)
	
	// Initialize controllers
	klog.InfoS("Initializing controllers")
	controllerManager.Initialize()
	
	// Start controllers
	klog.InfoS("Starting controllers")
	if err := controllerManager.Start(ctx); err != nil {
		klog.Fatalf("Failed to start controllers: %v", err)
	}
	
	// Example of direct NetworkController usage
	klog.InfoS("Configuring base network settings")
	
	// Configure NAT for a source network
	sourceNetwork := "192.168.1.0/24"
	outInterface := "eth0"
	if err := networkController.ConfigureNAT(ctx, sourceNetwork, outInterface, false); err != nil {
		klog.Warningf("Failed to configure NAT: %v", err)
	} else {
		klog.InfoS("Configured NAT", "sourceNetwork", sourceNetwork, "interface", outInterface)
	}
	
	// Configure NAT66 for an IPv6 network
	sourceNetworkV6 := "2001:db8::/64"
	if err := networkController.ConfigureNAT(ctx, sourceNetworkV6, outInterface, true); err != nil {
		klog.Warningf("Failed to configure NAT66: %v", err)
	} else {
		klog.InfoS("Configured NAT66", "sourceNetwork", sourceNetworkV6, "interface", outInterface)
	}
	
	// Configure inter-VLAN routing
	vlans := []uint16{10, 20, 30}
	if err := networkController.ConfigureInterVLANRouting(ctx, vlans, false); err != nil {
		klog.Warningf("Failed to configure inter-VLAN routing: %v", err)
	} else {
		klog.InfoS("Configured inter-VLAN routing", "vlans", vlans)
	}
	
	// Set up DPI integration
	appPolicies := map[string]cilium.AppPolicy{
		"http": {
			Application: "http",
			Action:      "allow",
			Priority:    1,
		},
		"ssh": {
			Application: "ssh",
			Action:      "allow",
			Priority:    2,
		},
	}
	if err := networkController.IntegrateDPI(ctx, appPolicies); err != nil {
		klog.Warningf("Failed to integrate DPI: %v", err)
	} else {
		klog.InfoS("Integrated DPI with policies")
	}
	
	// Run indefinitely until signal received
	klog.InfoS("Cilium controller manager running", "status", "ready")
	<-ctx.Done()
	
	// Graceful shutdown
	klog.InfoS("Shutting down controller manager")
	controllerManager.Stop()
	
	klog.InfoS("Cilium controller stopped")
}