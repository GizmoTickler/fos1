package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/ntp/client"
	"github.com/GizmoTickler/fos1/pkg/ntp/controller"
)

func main() {
	var kubeconfig string
	var chronyConfigPath string
	var chronyKeysPath string
	var chronyCommand string
	var metricsEnabled bool
	var metricsPort int
	var metricsInterval time.Duration
	var integrationEnabled bool
	var workers int
	var resyncPeriod time.Duration
	var tlsCertDir string
	var mtlsAllowlist string

	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	flag.StringVar(&chronyConfigPath, "chrony-config", "/etc/chrony/chrony.conf", "Path to Chrony config file")
	flag.StringVar(&chronyKeysPath, "chrony-keys", "/etc/chrony/chrony.keys", "Path to Chrony keys file")
	flag.StringVar(&chronyCommand, "chrony-command", "chronyc", "Path to Chrony command")
	flag.BoolVar(&metricsEnabled, "metrics", true, "Enable Prometheus metrics")
	flag.IntVar(&metricsPort, "metrics-port", 9559, "Metrics server port")
	flag.DurationVar(&metricsInterval, "metrics-interval", 15*time.Second, "Metrics collection interval")
	flag.BoolVar(&integrationEnabled, "integration", true, "Enable DHCP and DNS integration")
	flag.IntVar(&workers, "workers", 2, "Number of worker threads")
	flag.DurationVar(&resyncPeriod, "resync-period", 30*time.Minute, "Informer resync period")
	// Sprint 31 / Ticket 49: directory containing tls.crt/tls.key/ca.crt
	// for HTTPS-served metrics + API endpoints. Empty preserves the
	// historical plaintext behavior.
	flag.StringVar(&tlsCertDir, "tls-cert-dir", "", "Directory with cert-manager-rotated TLS material (empty = plaintext)")
	flag.StringVar(&mtlsAllowlist, "mtls-allowlist", "", "Comma-separated client certificate Subject CNs allowed to call HTTPS endpoints")

	klog.InitFlags(nil)
	flag.Parse()

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		klog.Info("Received termination signal, shutting down...")
		cancel()
		// Give controller time to clean up
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	// Build config from kubeconfig path or in-cluster config
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		klog.Fatalf("Error building kubeconfig: %v", err)
	}

	// Create dynamic client
	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Error creating dynamic client: %v", err)
	}

	// Create Kubernetes typed client
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatalf("Error creating Kubernetes client: %v", err)
	}

	// Create informer factory
	ntpResource := schema.GroupVersionResource{
		Group:    "ntp.fos1.io",
		Version:  "v1alpha1",
		Resource: "ntpservices",
	}
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynClient, resyncPeriod, "", nil)
	informer := factory.ForResource(ntpResource).Informer()

	// Create NTP client
	ntpClient := client.NewClient()

	// Create controller config
	controllerConfig := &controller.Config{
		ResyncPeriod:        resyncPeriod,
		Workers:             workers,
		ChronyConfigPath:    chronyConfigPath,
		ChronyKeysPath:      chronyKeysPath,
		ChronyCommand:       chronyCommand,
		EnableIntegration:   integrationEnabled,
		EnableMetrics:       metricsEnabled,
		MetricsPort:         metricsPort,
		MetricsInterval:     metricsInterval,
		LeaderElection:      true,
		LeaderElectionID:    "ntp-controller",
		LeaderElectionNS:    "kube-system",
		TLSCertDir:          tlsCertDir,
		MTLSAllowedSubjects: splitCSV(mtlsAllowlist),
	}

	// Create and run controller
	ctrl, err := controller.NewController(kubeClient, ntpClient, informer, controllerConfig)
	if err != nil {
		klog.Fatalf("Error creating controller: %v", err)
	}

	if err := ctrl.Run(ctx); err != nil {
		klog.Fatalf("Error running controller: %v", err)
	}

	// Wait for context to be cancelled
	<-ctx.Done()
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
