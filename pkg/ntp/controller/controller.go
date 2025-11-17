package controller

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/ntp"
	"github.com/GizmoTickler/fos1/pkg/ntp/chrony"
	ntpclient "github.com/GizmoTickler/fos1/pkg/ntp/client"
	"github.com/GizmoTickler/fos1/pkg/ntp/manager"
)

// Controller watches NTP CRDs and manages the NTP service
type Controller struct {
	// Kubernetes clients
	kubeClient kubernetes.Interface
	ntpClient  ntpclient.Interface

	// Informers and listers
	ntpInformer cache.SharedIndexInformer
	ntpLister   ntpclient.NTPServiceLister

	// Work queue
	queue workqueue.RateLimitingInterface

	// Component managers
	chronyManager   *chrony.Manager
	configGenerator *chrony.ConfigGenerator
	ntpManager      *manager.Manager

	// Configuration
	resyncPeriod time.Duration
	workers      int
}

// Config holds controller configuration
type Config struct {
	ResyncPeriod       time.Duration
	Workers            int
	ChronyConfigPath   string
	ChronyKeysPath     string
	ChronyCommand      string
	EnableIntegration  bool
	EnableMetrics      bool
	MetricsPort        int
	MetricsInterval    time.Duration
	LeaderElection     bool
	LeaderElectionID   string
	LeaderElectionNS   string
}

// NewController creates a new NTP controller
func NewController(
	kubeClient kubernetes.Interface,
	ntpClient ntpclient.Interface,
	ntpInformer cache.SharedIndexInformer,
	config *Config) (*Controller, error) {

	if config == nil {
		config = &Config{
			ResyncPeriod:     30 * time.Minute,
			Workers:          2,
			ChronyConfigPath: "/etc/chrony/chrony.conf",
			ChronyKeysPath:   "/etc/chrony/chrony.keys",
			ChronyCommand:    "chronyc",
			EnableIntegration: true,
			EnableMetrics:    true,
			MetricsPort:      9559,
			MetricsInterval:  15 * time.Second,
			LeaderElection:   true,
			LeaderElectionID: "ntp-controller",
			LeaderElectionNS: "kube-system",
		}
	}

	// Create Chrony manager
	chronyManager := chrony.NewManager(
		config.ChronyConfigPath,
		config.ChronyKeysPath,
		config.ChronyCommand,
	)

	// Create config generator
	configGenerator := chrony.NewConfigGenerator()

	// Create NTP manager
	managerConfig := &manager.Config{
		EnableDHCPIntegration: config.EnableIntegration,
		EnableDNSIntegration:  config.EnableIntegration,
		MetricsEnabled:        config.EnableMetrics,
		APIEnabled:            true,
		ChronyConfigPath:      config.ChronyConfigPath,
		ChronyKeysPath:        config.ChronyKeysPath,
		ChronyCommand:         config.ChronyCommand,
		MetricsPort:           config.MetricsPort,
		MetricsInterval:       config.MetricsInterval,
	}

	ntpManager, err := manager.NewManager(kubeClient, managerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create NTP manager: %w", err)
	}

	controller := &Controller{
		kubeClient:       kubeClient,
		ntpClient:        ntpClient,
		ntpInformer:      ntpInformer,
		ntpLister:        ntpclient.NewNTPServiceLister(ntpInformer.GetIndexer()),
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ntpservice"),
		chronyManager:    chronyManager,
		configGenerator:  configGenerator,
		ntpManager:       ntpManager,
		resyncPeriod:     config.ResyncPeriod,
		workers:          config.Workers,
	}

	// Set up event handlers
	ntpInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueNTPService,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueNTPService(new)
		},
		DeleteFunc: controller.enqueueNTPService,
	})

	return controller, nil
}

// Run starts the controller
func (c *Controller) Run(ctx context.Context) error {
	defer c.queue.ShutDown()

	klog.Info("Starting NTP controller")

	// Start the informer
	go c.ntpInformer.Run(ctx.Done())

	// Wait for caches to sync
	klog.Info("Waiting for informer caches to sync")
	if !cache.WaitForCacheSync(ctx.Done(), c.ntpInformer.HasSynced) {
		return fmt.Errorf("failed to wait for informer caches to sync")
	}

	klog.Info("Starting NTP manager")
	if err := c.ntpManager.Start(); err != nil {
		return fmt.Errorf("failed to start NTP manager: %w", err)
	}

	// Start workers
	klog.Info("Starting workers")
	for i := 0; i < c.workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}

	klog.Info("NTP controller started successfully")
	<-ctx.Done()
	klog.Info("Shutting down NTP controller")

	// Stop NTP manager
	c.ntpManager.Stop()

	return nil
}

// runWorker processes items from the work queue
func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextItem(ctx) {
	}
}

// processNextItem processes the next item from the work queue
func (c *Controller) processNextItem(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncNTPService(ctx, key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	klog.Errorf("Error syncing NTP service %q: %v", key, err)
	c.queue.AddRateLimited(key)
	return true
}

// enqueueNTPService adds an NTP service to the work queue
func (c *Controller) enqueueNTPService(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	c.queue.Add(key)
}

// syncNTPService syncs the state for a single NTP service
func (c *Controller) syncNTPService(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid resource key: %s", key)
	}

	// Get the NTP service resource
	ntpService, err := c.ntpLister.NTPServices(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			klog.Infof("NTP service %s has been deleted", key)
			// If the service was deleted, we need to clean up resources
			// Currently there's no cleanup needed, but if there were, it would go here
			return nil
		}
		return fmt.Errorf("failed to get NTP service %s: %w", key, err)
	}

	// Convert CRD to internal representation
	internalService := convertToInternalNTPService(ntpService)

	// Update the NTP service configuration
	if err := c.ntpManager.UpdateNTPService(internalService); err != nil {
		return fmt.Errorf("failed to update NTP service: %w", err)
	}

	// Update firewall rules for VLANs
	if err := c.ntpManager.UpdateFirewallRules(internalService); err != nil {
		return fmt.Errorf("failed to update firewall rules: %w", err)
	}

	// Update status
	if err := c.updateNTPServiceStatus(ctx, ntpService); err != nil {
		return fmt.Errorf("failed to update NTP service status: %w", err)
	}

	klog.Infof("Successfully synced NTP service %s", key)
	return nil
}

// updateNTPServiceStatus updates the status of the NTP service resource
func (c *Controller) updateNTPServiceStatus(ctx context.Context, ntpService runtime.Object) error {
	// This would update the status in a real implementation
	// For simplicity, we're not implementing it in this placeholder
	return nil
}

// convertToInternalNTPService converts a CRD to our internal representation
func convertToInternalNTPService(crds runtime.Object) *ntp.NTPService {
	// In a real implementation, this would convert from the CRD types to internal types
	// For simplicity, we're just returning a placeholder here
	return &ntp.NTPService{
		Name:    "main-ntp",
		Enabled: true,
		Sources: ntp.Sources{
			Pools: []ntp.PoolSource{
				{
					Name:    "pool.ntp.org",
					Servers: 4,
					IBurst:  true,
					Prefer:  false,
				},
				{
					Name:    "time.cloudflare.com",
					Servers: 2,
					IBurst:  true,
					Prefer:  true,
				},
			},
			Servers: []ntp.ServerSource{
				{
					Address: "time.google.com",
					IBurst:  true,
					Prefer:  false,
					MinPoll: 6,
					MaxPoll: 10,
				},
			},
		},
		Server: ntp.ServerConfig{
			Stratum:   2,
			DriftFile: "/var/lib/chrony/drift",
			MakeStep: ntp.StepConfig{
				Threshold: 1.0,
				Limit:     3,
			},
			Local: ntp.LocalClockConfig{
				Enabled: true,
				Stratum: 10,
			},
		},
		Security: ntp.SecurityConfig{
			RateLimit: ntp.RateLimitConfig{
				Enabled:  true,
				Interval: 3,
				Burst:    8,
			},
			Access: []ntp.AccessRule{
				{
					Network:    "192.168.0.0/16",
					Permission: "allow",
				},
				{
					Network:    "10.0.0.0/8",
					Permission: "allow",
				},
				{
					Network:    "0.0.0.0/0",
					Permission: "deny",
				},
			},
		},
		VLANConfig: []ntp.VLANConfig{
			{
				VLANRef:     "vlan-10",
				Enabled:     true,
				Broadcast:   true,
				ClientsOnly: false,
			},
			{
				VLANRef:     "vlan-20",
				Enabled:     true,
				Broadcast:   false,
				ClientsOnly: true,
			},
		},
	}
}