package controller

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/vpn"
	"github.com/varuntirumala1/fos1/pkg/vpn/wireguard"
)

// WireGuardController is the controller for WireGuard VPNs
type WireGuardController struct {
	// Kubernetes client
	kubeClient kubernetes.Interface
	
	// WireGuard manager
	wgManager vpn.WireGuardManager
	
	// Informer and queue
	informer cache.SharedIndexInformer
	queue    workqueue.RateLimitingInterface
	
	// Configuration
	resyncPeriod time.Duration
	workers      int
}

// Config holds controller configuration
type Config struct {
	ResyncPeriod time.Duration
	Workers      int
	ConfigDir    string
	WGBinary     string
}

// NewWireGuardController creates a new WireGuard controller
func NewWireGuardController(
	kubeClient kubernetes.Interface,
	informer cache.SharedIndexInformer,
	config *Config) (*WireGuardController, error) {
	
	if kubeClient == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}
	
	if informer == nil {
		return nil, fmt.Errorf("informer is required")
	}
	
	if config == nil {
		config = &Config{
			ResyncPeriod: 30 * time.Minute,
			Workers:      2,
			ConfigDir:    "/etc/wireguard",
			WGBinary:     "wg",
		}
	}
	
	// Create WireGuard manager
	wgManager, err := wireguard.NewManager(&wireguard.Config{
		ConfigDir: config.ConfigDir,
		WGBinary:  config.WGBinary,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard manager: %w", err)
	}
	
	controller := &WireGuardController{
		kubeClient:   kubeClient,
		wgManager:    wgManager,
		informer:     informer,
		queue:        workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "wireguard-controller"),
		resyncPeriod: config.ResyncPeriod,
		workers:      config.Workers,
	}
	
	// Set up event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueWireGuardVPN,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueWireGuardVPN(new)
		},
		DeleteFunc: controller.enqueueWireGuardVPN,
	})
	
	return controller, nil
}

// Run starts the controller
func (c *WireGuardController) Run(ctx context.Context) error {
	defer c.queue.ShutDown()
	
	klog.Info("Starting WireGuard controller")
	
	// Start the informer
	go c.informer.Run(ctx.Done())
	
	// Wait for the caches to be synced
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		return fmt.Errorf("failed to sync caches")
	}
	
	klog.Info("WireGuard controller caches synced")
	
	// Start workers
	for i := 0; i < c.workers; i++ {
		go wait.UntilWithContext(ctx, c.worker, time.Second)
	}
	
	<-ctx.Done()
	klog.Info("Stopping WireGuard controller")
	return nil
}

// worker runs a worker thread that processes items from the queue
func (c *WireGuardController) worker(ctx context.Context) {
	for c.processNextItem(ctx) {
	}
}

// processNextItem processes the next item from the queue
func (c *WireGuardController) processNextItem(ctx context.Context) bool {
	// Get the next item from the queue
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Process the item
	err := func(key interface{}) error {
		defer c.queue.Done(key)
		
		// Process the item
		err := c.syncWireGuardVPN(ctx, key.(string))
		if err != nil {
			// If the error is transient, requeue the item
			c.queue.AddRateLimited(key)
			return fmt.Errorf("error syncing WireGuard VPN %q: %w", key, err)
		}
		
		// If no error, forget the item
		c.queue.Forget(key)
		return nil
	}(key)
	
	if err != nil {
		klog.Error(err)
	}
	
	return true
}

// enqueueWireGuardVPN adds a WireGuard VPN to the queue
func (c *WireGuardController) enqueueWireGuardVPN(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	c.queue.Add(key)
}

// syncWireGuardVPN syncs the WireGuard VPN with the WireGuard manager
func (c *WireGuardController) syncWireGuardVPN(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid resource key: %s", key)
	}
	
	// Get the WireGuard VPN resource
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("failed to get WireGuard VPN %s: %w", key, err)
	}
	
	if !exists {
		klog.Infof("WireGuard VPN %s has been deleted", key)
		// Delete the VPN
		if err := c.wgManager.DeleteVPN(name); err != nil {
			return fmt.Errorf("failed to delete VPN: %w", err)
		}
		return nil
	}
	
	// Convert to WireGuard VPN
	wgVPN, err := convertToInternalWireGuardVPN(obj)
	if err != nil {
		return fmt.Errorf("failed to convert object to WireGuard VPN: %w", err)
	}
	
	// Check if the VPN is enabled
	if !wgVPN.Enabled {
		klog.Infof("WireGuard VPN %s is disabled, deleting", key)
		// Delete the VPN
		if err := c.wgManager.DeleteVPN(name); err != nil {
			return fmt.Errorf("failed to delete VPN: %w", err)
		}
		return nil
	}
	
	// Create or update the VPN
	if err := c.wgManager.UpdateVPN(wgVPN); err != nil {
		return fmt.Errorf("failed to update VPN: %w", err)
	}
	
	// Update the status
	if err := c.updateStatus(ctx, namespace, name, wgVPN); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}
	
	klog.Infof("Successfully synced WireGuard VPN %s", key)
	return nil
}

// updateStatus updates the status of the WireGuard VPN
func (c *WireGuardController) updateStatus(ctx context.Context, namespace, name string, wgVPN *vpn.WireGuardVPN) error {
	// Get the current status
	status, err := c.wgManager.GetVPNStatus(name)
	if err != nil {
		return fmt.Errorf("failed to get VPN status: %w", err)
	}
	
	// In a real implementation, this would update the status of the WireGuard VPN resource
	// For this placeholder, we'll just log the status
	klog.Infof("WireGuard VPN %s/%s status: phase=%s, publicKey=%s, connectedPeers=%d",
		namespace, name, status.Phase, status.PublicKey, status.ConnectedPeers)
	
	return nil
}

// convertToInternalWireGuardVPN converts a CRD to our internal representation
func convertToInternalWireGuardVPN(obj interface{}) (*vpn.WireGuardVPN, error) {
	// In a real implementation, this would convert from the CRD types to internal types
	// For this placeholder, we'll just return a dummy VPN
	return &vpn.WireGuardVPN{
		Name:    "example-vpn",
		Enabled: true,
		Interface: vpn.InterfaceConfig{
			Name:       "wg0",
			PrivateKey: "private-key",
			ListenPort: 51820,
			Addresses:  []string{"10.10.10.1/24", "fd00:1234:5678:9abc::1/64"},
			MTU:        1420,
			Firewall:   true,
			Table:      51820,
			PostUp: []string{
				"iptables -A FORWARD -i %i -j ACCEPT",
				"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
			},
			PostDown: []string{
				"iptables -D FORWARD -i %i -j ACCEPT",
				"iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
			},
		},
		Peers: []vpn.PeerConfig{
			{
				PublicKey:          "public-key-1",
				PresharedKey:       "preshared-key-1",
				Endpoint:           "peer1.example.com:51820",
				PersistentKeepalive: 25,
				AllowedIPs:         []string{"10.10.10.2/32", "192.168.1.0/24"},
				Description:        "Remote Office 1",
			},
		},
		Routing: vpn.RoutingConfig{
			DefaultRoute: false,
			AllowedIPs:   []string{"192.168.1.0/24"},
			Metric:       100,
		},
		Security: vpn.SecurityConfig{
			KeyRotation: vpn.KeyRotationConfig{
				Enabled:  true,
				Interval: "30d",
			},
		},
		Monitoring: vpn.MonitoringConfig{
			Enabled:  true,
			Metrics:  true,
			Logging:  true,
			LogLevel: "info",
		},
	}, nil
}
