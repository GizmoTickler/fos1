package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/security/ids"
)

func main() {
	// Parse command line flags
	var (
		kubeconfig string
		masterURL  string
	)

	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	flag.StringVar(&masterURL, "master", "", "URL of the Kubernetes API server")
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
		config, err = clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	}
	if err != nil {
		klog.Fatalf("Failed to create config: %v", err)
	}

	// Create Kubernetes client
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Create IDS/IPS manager
	idsManager, err := ids.NewIDSManager(kubeClient, config)
	if err != nil {
		klog.Fatalf("Failed to create IDS/IPS manager: %v", err)
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

	// Initialize the IDS/IPS manager
	if err := idsManager.Initialize(ctx); err != nil {
		klog.Fatalf("Failed to initialize IDS/IPS manager: %v", err)
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Shutdown the IDS/IPS manager
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := idsManager.Shutdown(shutdownCtx); err != nil {
		klog.Errorf("Failed to shutdown IDS/IPS manager: %v", err)
	}
}
