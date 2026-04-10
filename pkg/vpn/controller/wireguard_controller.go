package controller

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/vpn"
	"github.com/GizmoTickler/fos1/pkg/vpn/wireguard"
)

// WireGuardInterfaceResource is the API resource name for WireGuard CRDs.
const WireGuardInterfaceResource = "wiregaurdinterfaces.vpn.fos1.io"

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

	return NewWireGuardControllerWithManager(kubeClient, informer, wgManager, config)
}

// NewWireGuardControllerWithManager creates a new WireGuard controller with an
// injected WireGuardManager. This is useful for testing.
func NewWireGuardControllerWithManager(
	kubeClient kubernetes.Interface,
	informer cache.SharedIndexInformer,
	wgManager vpn.WireGuardManager,
	config *Config) (*WireGuardController, error) {

	if kubeClient == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}

	if informer == nil {
		return nil, fmt.Errorf("informer is required")
	}

	if wgManager == nil {
		return nil, fmt.Errorf("WireGuard manager is required")
	}

	if config == nil {
		config = &Config{
			ResyncPeriod: 30 * time.Minute,
			Workers:      2,
		}
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
			// If the VPN doesn't exist in the manager, that's fine
			klog.V(2).Infof("DeleteVPN for %s returned: %v", name, err)
		}
		return nil
	}

	// Convert to WireGuard VPN
	wgVPN, err := convertToInternalWireGuardVPN(obj)
	if err != nil {
		c.updateStatusDegraded(ctx, obj, namespace, name, fmt.Sprintf("failed to parse CRD spec: %v", err))
		return fmt.Errorf("failed to convert object to WireGuard VPN: %w", err)
	}

	// Check if the VPN is enabled
	if !wgVPN.Enabled {
		klog.Infof("WireGuard VPN %s is disabled, deleting", key)
		if err := c.wgManager.DeleteVPN(name); err != nil {
			klog.V(2).Infof("DeleteVPN for disabled %s returned: %v", name, err)
		}
		c.updateStatusInactive(ctx, obj, namespace, name)
		return nil
	}

	// Try to create the VPN first; if it already exists, update it.
	createErr := c.wgManager.CreateVPN(wgVPN)
	if createErr != nil {
		// VPN may already exist; attempt update.
		updateErr := c.wgManager.UpdateVPN(wgVPN)
		if updateErr != nil {
			c.updateStatusDegraded(ctx, obj, namespace, name, fmt.Sprintf("failed to apply VPN config: %v", updateErr))
			return fmt.Errorf("failed to create or update VPN: create=%v, update=%v", createErr, updateErr)
		}
	}

	// Update the status from the actual interface state
	if err := c.updateStatusFromInterface(ctx, obj, namespace, name); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	klog.Infof("Successfully synced WireGuard VPN %s", key)
	return nil
}

// updateStatusFromInterface queries the WireGuard manager for real interface
// state and writes it back to the CRD status subresource.
func (c *WireGuardController) updateStatusFromInterface(ctx context.Context, obj interface{}, namespace, name string) error {
	status, err := c.wgManager.GetVPNStatus(name)
	if err != nil {
		return fmt.Errorf("failed to get VPN status: %w", err)
	}

	statusMap := map[string]interface{}{
		"active":    true,
		"publicKey": status.PublicKey,
		"message":   fmt.Sprintf("Running with %d peer(s)", status.ConnectedPeers),
		"phase":     status.Phase,
		"connectedPeers": int64(status.ConnectedPeers),
		"transferRx":     status.TransferRx,
		"transferTx":     status.TransferTx,
		"lastUpdated":    time.Now().UTC().Format(time.RFC3339),
	}

	if !status.LastHandshake.IsZero() {
		statusMap["lastHandshake"] = status.LastHandshake.UTC().Format(time.RFC3339)
	}

	// Build peer status list
	if len(status.Conditions) > 0 {
		peerStatuses := make([]interface{}, 0, len(status.Conditions))
		for _, cond := range status.Conditions {
			if cond.Type == "Peer" {
				peerStatus := map[string]interface{}{
					"publicKey": cond.Reason,
					"message":   cond.Message,
					"status":    cond.Status,
				}
				if !cond.LastTransitionTime.IsZero() {
					peerStatus["lastHandshake"] = cond.LastTransitionTime.UTC().Format(time.RFC3339)
				}
				peerStatuses = append(peerStatuses, peerStatus)
			}
		}
		statusMap["peers"] = peerStatuses
	}

	return c.updateCRDStatus(obj, statusMap)
}

// updateStatusDegraded writes a degraded status to the CRD.
func (c *WireGuardController) updateStatusDegraded(ctx context.Context, obj interface{}, namespace, name, message string) {
	statusMap := map[string]interface{}{
		"active":      false,
		"phase":       "Degraded",
		"message":     message,
		"lastUpdated": time.Now().UTC().Format(time.RFC3339),
	}

	if err := c.updateCRDStatus(obj, statusMap); err != nil {
		klog.Errorf("Failed to update degraded status for %s/%s: %v", namespace, name, err)
	}
}

// updateStatusInactive writes an inactive status to the CRD.
func (c *WireGuardController) updateStatusInactive(ctx context.Context, obj interface{}, namespace, name string) {
	statusMap := map[string]interface{}{
		"active":      false,
		"phase":       "Inactive",
		"message":     "VPN is disabled",
		"lastUpdated": time.Now().UTC().Format(time.RFC3339),
	}

	if err := c.updateCRDStatus(obj, statusMap); err != nil {
		klog.Errorf("Failed to update inactive status for %s/%s: %v", namespace, name, err)
	}
}

// updateCRDStatus updates the status subresource of a WireGuard CRD.
func (c *WireGuardController) updateCRDStatus(obj interface{}, status map[string]interface{}) error {
	crd, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return fmt.Errorf("object is not an Unstructured type")
	}

	// Create a copy to avoid modifying the cache
	crdCopy := crd.DeepCopy()

	// Set the status field
	if err := unstructured.SetNestedField(crdCopy.Object, status, "status"); err != nil {
		return fmt.Errorf("failed to set status field: %w", err)
	}

	if c.kubeClient == nil {
		// No Kubernetes client available (e.g. unit tests); status was set on
		// the local copy but cannot be persisted.
		klog.V(2).Info("Skipping CRD status update: no Kubernetes client")
		return nil
	}

	// Update the CRD status via the Kubernetes API
	_, err := c.kubeClient.CoreV1().RESTClient().Put().
		Namespace(crdCopy.GetNamespace()).
		Resource(WireGuardInterfaceResource).
		Name(crdCopy.GetName()).
		SubResource("status").
		Body(crdCopy).
		Do(context.Background()).
		Get()

	if err != nil {
		return fmt.Errorf("failed to update CRD status: %w", err)
	}

	return nil
}

// convertToInternalWireGuardVPN converts a CRD (unstructured) object to the
// internal WireGuardVPN representation by parsing the actual spec fields.
func convertToInternalWireGuardVPN(obj interface{}) (*vpn.WireGuardVPN, error) {
	crd, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("object is not an Unstructured type")
	}

	spec, found, err := unstructured.NestedMap(crd.Object, "spec")
	if err != nil || !found {
		return nil, fmt.Errorf("spec not found in CRD: %v", err)
	}

	// Extract interface name (required)
	interfaceName, _ := spec["interfaceName"].(string)
	if interfaceName == "" {
		return nil, fmt.Errorf("spec.interfaceName is required")
	}

	// Extract address (required)
	address, _ := spec["address"].(string)
	if address == "" {
		return nil, fmt.Errorf("spec.address is required")
	}

	// Extract listen port
	listenPort := 0
	if lp, ok := spec["listenPort"].(float64); ok {
		listenPort = int(lp)
	} else if lp, ok := spec["listenPort"].(int64); ok {
		listenPort = int(lp)
	}

	// Extract private key from secret reference
	privateKey := ""
	if pkSecret, ok := spec["privateKeySecret"].(map[string]interface{}); ok {
		// In a real deployment the controller would read the secret from the
		// Kubernetes API. Here we store the secret reference so the manager
		// can resolve it. For now, we represent it as "secretName/key".
		secretName, _ := pkSecret["name"].(string)
		secretKey, _ := pkSecret["key"].(string)
		if secretName != "" && secretKey != "" {
			privateKey = fmt.Sprintf("secret:%s/%s", secretName, secretKey)
		}
	}
	// Allow a direct privateKey field (for testing / non-secret scenarios)
	if pk, ok := spec["privateKey"].(string); ok && pk != "" {
		privateKey = pk
	}

	// Extract enabled flag (defaults to true)
	enabled := true
	if e, ok := spec["enabled"].(bool); ok {
		enabled = e
	}

	// Extract MTU
	mtu := 0
	if m, ok := spec["mtu"].(float64); ok {
		mtu = int(m)
	} else if m, ok := spec["mtu"].(int64); ok {
		mtu = int(m)
	}

	// Extract postUp commands
	postUp := extractStringSlice(spec, "postUp")

	// Extract postDown commands
	postDown := extractStringSlice(spec, "postDown")

	// Extract peers
	var peers []vpn.PeerConfig
	if peersRaw, ok := spec["peers"].([]interface{}); ok {
		for _, peerRaw := range peersRaw {
			peerMap, ok := peerRaw.(map[string]interface{})
			if !ok {
				continue
			}
			peer, err := parsePeerConfig(peerMap)
			if err != nil {
				klog.Warningf("Skipping invalid peer in CRD %s: %v", crd.GetName(), err)
				continue
			}
			peers = append(peers, peer)
		}
	}

	result := &vpn.WireGuardVPN{
		Name:    crd.GetName(),
		Enabled: enabled,
		Interface: vpn.InterfaceConfig{
			Name:       interfaceName,
			PrivateKey: privateKey,
			ListenPort: listenPort,
			Addresses:  []string{address},
			MTU:        mtu,
			PostUp:     postUp,
			PostDown:   postDown,
		},
		Peers: peers,
	}

	// Extract routing config if present
	if routing, ok := spec["routing"].(map[string]interface{}); ok {
		if dr, ok := routing["defaultRoute"].(bool); ok {
			result.Routing.DefaultRoute = dr
		}
		result.Routing.AllowedIPs = extractStringSlice(routing, "allowedIPs")
		if m, ok := routing["metric"].(float64); ok {
			result.Routing.Metric = int(m)
		} else if m, ok := routing["metric"].(int64); ok {
			result.Routing.Metric = int(m)
		}
	}

	// Extract monitoring config if present
	if mon, ok := spec["monitoring"].(map[string]interface{}); ok {
		if e, ok := mon["enabled"].(bool); ok {
			result.Monitoring.Enabled = e
		}
		if m, ok := mon["metrics"].(bool); ok {
			result.Monitoring.Metrics = m
		}
		if l, ok := mon["logging"].(bool); ok {
			result.Monitoring.Logging = l
		}
		if ll, ok := mon["logLevel"].(string); ok {
			result.Monitoring.LogLevel = ll
		}
	}

	return result, nil
}

// parsePeerConfig parses a peer configuration from an unstructured map.
func parsePeerConfig(peerMap map[string]interface{}) (vpn.PeerConfig, error) {
	publicKey, _ := peerMap["publicKey"].(string)
	if publicKey == "" {
		return vpn.PeerConfig{}, fmt.Errorf("peer publicKey is required")
	}

	peer := vpn.PeerConfig{
		PublicKey:   publicKey,
		Description: stringFromMap(peerMap, "description"),
		Endpoint:    stringFromMap(peerMap, "endpoint"),
	}

	// Preshared key can come from a secret ref or directly
	if pskSecret, ok := peerMap["presharedKeySecret"].(map[string]interface{}); ok {
		secretName, _ := pskSecret["name"].(string)
		secretKey, _ := pskSecret["key"].(string)
		if secretName != "" && secretKey != "" {
			peer.PresharedKey = fmt.Sprintf("secret:%s/%s", secretName, secretKey)
		}
	}
	if psk, ok := peerMap["presharedKey"].(string); ok && psk != "" {
		peer.PresharedKey = psk
	}

	if ka, ok := peerMap["persistentKeepalive"].(float64); ok {
		peer.PersistentKeepalive = int(ka)
	} else if ka, ok := peerMap["persistentKeepalive"].(int64); ok {
		peer.PersistentKeepalive = int(ka)
	}

	peer.AllowedIPs = extractStringSlice(peerMap, "allowedIPs")

	return peer, nil
}

// extractStringSlice extracts a []string from an unstructured map field.
func extractStringSlice(m map[string]interface{}, key string) []string {
	raw, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// stringFromMap extracts a string from a map, returning "" if not found.
func stringFromMap(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}
