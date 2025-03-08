package vlan

import (
	"context"
	"fmt"
	"reflect"
	"time"
    "errors"
    "strconv"
    "net"
    "strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

// NetworkInterfaceResource is the resource name for the NetworkInterface CRD
const NetworkInterfaceResource = "networkinterfaces.network.fos1.io"

// VLANController watches for NetworkInterface CRDs with type "vlan" and manages VLAN interfaces
type VLANController struct {
	manager         VLANManager
	config          VLANControllerConfig
	eventHandlers   []VLANEventHandler
	stopCh          chan struct{}
	
	// Kubernetes client and other dependencies
	client          kubernetes.Interface
	informer        cache.SharedIndexInformer
	queue           workqueue.RateLimitingInterface
}

// NewVLANController creates a new VLAN controller
func NewVLANController(client kubernetes.Interface, manager VLANManager, config VLANControllerConfig) *VLANController {
	controller := &VLANController{
		client:        client,
		manager:       manager,
		config:        config,
		eventHandlers: make([]VLANEventHandler, 0),
		stopCh:        make(chan struct{}),
		queue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "vlan-controller"),
	}
	
	// Set up the NetworkInterface CRD informer
	controller.informer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				// Filter to only get NetworkInterfaces with type=vlan
				options.FieldSelector = "spec.type=vlan"
				return client.CoreV1().RESTClient().Get().
					Resource(NetworkInterfaceResource).
					VersionedParams(&options, metav1.ParameterCodec).
					Do(context.Background()).
					Get()
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				// Filter to only get NetworkInterfaces with type=vlan
				options.FieldSelector = "spec.type=vlan"
				return client.CoreV1().RESTClient().Get().
					Resource(NetworkInterfaceResource).
					VersionedParams(&options, metav1.ParameterCodec).
					Watch(context.Background())
			},
		},
		&unstructured.Unstructured{},
		time.Duration(config.ResyncInterval)*time.Second,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	
	// Add event handlers for the informer
	controller.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueNetworkInterface,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueNetworkInterface(new)
		},
		DeleteFunc: controller.enqueueNetworkInterface,
	})
	
	return controller
}

// Start starts the VLAN controller
func (c *VLANController) Start(ctx context.Context) error {
	klog.Info("Starting VLAN controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		return fmt.Errorf("timed out waiting for informer cache to sync")
	}
	
	// Start workers to process items from the queue
	for i := 0; i < c.config.MaxConcurrentReconciles; i++ {
		go wait.Until(c.runWorker, time.Second, c.stopCh)
	}
	
	// Start a goroutine to periodically check for orphaned VLANs
	go c.reconcileLoop(ctx)
	
	return nil
}

// Stop stops the VLAN controller
func (c *VLANController) Stop() {
	klog.Info("Stopping VLAN controller")
	close(c.stopCh)
	c.queue.ShutDown()
}

// AddEventHandler adds a handler for VLAN events
func (c *VLANController) AddEventHandler(handler VLANEventHandler) {
	c.eventHandlers = append(c.eventHandlers, handler)
}

// notifyEvent notifies all registered event handlers
func (c *VLANController) notifyEvent(event VLANEvent) {
	for _, handler := range c.eventHandlers {
		go handler(event)
	}
}

// reconcileLoop performs periodic reconciliation of VLAN interfaces
func (c *VLANController) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(c.config.ResyncInterval) * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			klog.V(2).Info("Running periodic reconciliation of VLAN interfaces")
			
			// Get a list of all VLAN interfaces from the manager
			vlans, err := c.manager.ListVLANs()
			if err != nil {
				klog.Errorf("Failed to list VLAN interfaces: %v", err)
				continue
			}
			
			// Get a list of all NetworkInterface CRDs with type=vlan
			crds, err := c.listVLANCRDs()
			if err != nil {
				klog.Errorf("Failed to list NetworkInterface CRDs: %v", err)
				continue
			}
			
			// Check for VLAN interfaces that don't have a corresponding CRD
			for _, vlan := range vlans {
				found := false
				for _, crd := range crds {
					if crd.GetName() == vlan.Name {
						found = true
						break
					}
				}
				
				if !found {
					// This VLAN doesn't have a CRD, it may be orphaned
					klog.Warningf("Found orphaned VLAN interface %s, considering for removal", vlan.Name)
					
					// Delete the orphaned VLAN interface
					if err := c.manager.DeleteVLAN(vlan.Name); err != nil {
						klog.Errorf("Failed to delete orphaned VLAN interface %s: %v", vlan.Name, err)
					} else {
						klog.Infof("Deleted orphaned VLAN interface %s", vlan.Name)
					}
				}
			}
			
			// Update the status of all VLAN interfaces
			for _, vlan := range vlans {
				if err := c.updateVLANStatus(vlan.Name); err != nil {
					klog.Warningf("Failed to update status for VLAN interface %s: %v", vlan.Name, err)
				}
			}
			
		case <-c.stopCh:
			klog.Info("Stopping VLAN controller reconcile loop")
			return
			
		case <-ctx.Done():
			klog.Info("Context cancelled, stopping VLAN controller reconcile loop")
			return
		}
	}
}

// handleVLANCreate handles creation of a new VLAN interface from a CRD
func (c *VLANController) handleVLANCreate(name string, parent string, vlanID int, config VLANConfig) error {
	// Create the VLAN interface
	vlan, err := c.manager.CreateVLAN(parent, vlanID, name, config)
	if err != nil {
		// Notify event handlers of the error
		c.notifyEvent(VLANEvent{
			Type:      VLANEventError,
			Interface: nil,
			Message:   fmt.Sprintf("Failed to create VLAN interface %s: %v", name, err),
		})
		return err
	}
	
	// Notify event handlers of the created VLAN
	c.notifyEvent(VLANEvent{
		Type:      VLANEventCreated,
		Interface: vlan,
		Message:   fmt.Sprintf("Created VLAN interface %s", name),
	})
	
	return nil
}

// handleVLANUpdate handles updates to an existing VLAN interface from a CRD
func (c *VLANController) handleVLANUpdate(name string, config VLANConfig) error {
	// Update the VLAN interface
	vlan, err := c.manager.UpdateVLAN(name, config)
	if err != nil {
		// Notify event handlers of the error
		c.notifyEvent(VLANEvent{
			Type:      VLANEventError,
			Interface: nil,
			Message:   fmt.Sprintf("Failed to update VLAN interface %s: %v", name, err),
		})
		return err
	}
	
	// Notify event handlers of the updated VLAN
	c.notifyEvent(VLANEvent{
		Type:      VLANEventUpdated,
		Interface: vlan,
		Message:   fmt.Sprintf("Updated VLAN interface %s", name),
	})
	
	return nil
}

// handleVLANDelete handles deletion of a VLAN interface from a CRD
func (c *VLANController) handleVLANDelete(name string) error {
	// Get the VLAN interface before deleting it
	vlan, err := c.manager.GetVLAN(name)
	if err != nil {
		// VLAN doesn't exist, nothing to do
		return nil
	}
	
	// Delete the VLAN interface
	err = c.manager.DeleteVLAN(name)
	if err != nil {
		// Notify event handlers of the error
		c.notifyEvent(VLANEvent{
			Type:      VLANEventError,
			Interface: vlan,
			Message:   fmt.Sprintf("Failed to delete VLAN interface %s: %v", name, err),
		})
		return err
	}
	
	// Notify event handlers of the deleted VLAN
	c.notifyEvent(VLANEvent{
		Type:      VLANEventDeleted,
		Interface: vlan,
		Message:   fmt.Sprintf("Deleted VLAN interface %s", name),
	})
	
	return nil
}

// updateVLANStatus updates the status of a VLAN interface in its CRD
func (c *VLANController) updateVLANStatus(name string) error {
	// Get the VLAN interface from the manager
	vlan, err := c.manager.GetVLAN(name)
	if err != nil {
		return fmt.Errorf("failed to get VLAN interface %s: %w", name, err)
	}
	
	// Get the corresponding NetworkInterface CRD
	obj, exists, err := c.informer.GetIndexer().GetByKey(name)
	if err != nil {
		return fmt.Errorf("failed to get NetworkInterface CRD %s: %w", name, err)
	}
	
	if !exists {
		return fmt.Errorf("NetworkInterface CRD %s does not exist", name)
	}
	
	crd := obj.(*unstructured.Unstructured)
	
	// Build the status object
	status := map[string]interface{}{
		"operationalState": vlan.OperationalState,
		"actualMtu":        vlan.ActualMTU,
		"parent":           vlan.Parent,
		"errorMessage":     vlan.ErrorMessage,
	}
	
	// Add statistics
	statistics := map[string]interface{}{
		"rxPackets": vlan.Statistics.RxPackets,
		"txPackets": vlan.Statistics.TxPackets,
		"rxBytes":   vlan.Statistics.RxBytes,
		"txBytes":   vlan.Statistics.TxBytes,
		"rxErrors":  vlan.Statistics.RxErrors,
		"txErrors":  vlan.Statistics.TxErrors,
		"rxDropped": vlan.Statistics.RxDropped,
		"txDropped": vlan.Statistics.TxDropped,
	}
	status["statistics"] = statistics
	
	// Add addresses
	addresses := make([]string, 0, len(vlan.Config.Addresses))
	for _, addr := range vlan.Config.Addresses {
		ipNet := &net.IPNet{
			IP:   addr.Address,
			Mask: net.CIDRMask(addr.Prefix, addr.Address.BitLen()),
		}
		addresses = append(addresses, ipNet.String())
	}
	status["addresses"] = addresses
	
	// Update the CRD's status
	if err := c.updateCRDStatus(crd, status); err != nil {
		return fmt.Errorf("failed to update status in NetworkInterface CRD %s: %w", name, err)
	}
	
	klog.V(2).Infof("Updated status of VLAN interface %s: %s", name, vlan.OperationalState)
	return nil
}

// updateCRDStatus updates the status of a NetworkInterface CRD
func (c *VLANController) updateCRDStatus(crd *unstructured.Unstructured, status map[string]interface{}) error {
	// Create a copy of the CRD to avoid modifying the cache
	copy := crd.DeepCopy()
	
	// Set the status field
	if err := unstructured.SetNestedField(copy.Object, status, "status"); err != nil {
		return fmt.Errorf("failed to set status field: %w", err)
	}
	
	// Update the CRD in the Kubernetes API
	_, err := c.client.CoreV1().RESTClient().Put().
		Namespace(copy.GetNamespace()).
		Resource(NetworkInterfaceResource).
		Name(copy.GetName()).
		Subresource("status").
		Body(copy).
		Do(context.Background()).
		Get()
		
	if err != nil {
		return fmt.Errorf("failed to update CRD status: %w", err)
	}
	
	return nil
}

// enqueueNetworkInterface adds a NetworkInterface object to the work queue
func (c *VLANController) enqueueNetworkInterface(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	c.queue.Add(key)
}

// runWorker is a long-running function that processes items from the work queue
func (c *VLANController) runWorker() {
	for c.processNextItem() {
		// Continue processing items until the queue is empty
	}
}

// processNextItem processes a single item from the work queue
func (c *VLANController) processNextItem() bool {
	// Get the next item from the queue
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcileVLAN(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about the key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error processing item %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		c.queue.Forget(key)
	}
	
	return true
}

// reconcileVLAN reconciles a single NetworkInterface
func (c *VLANController) reconcileVLAN(key string) error {
	// Get the NetworkInterface object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("failed to get NetworkInterface CRD %s: %w", key, err)
	}
	
	// If it's been deleted, ensure the VLAN is removed
	if !exists {
		// Extract the name from the key
		parts := strings.Split(key, "/")
		name := parts[len(parts)-1]
		
		// Delete the VLAN interface
		return c.handleVLANDelete(name)
	}
	
	// Get the VLAN details from the CRD
	crd := obj.(*unstructured.Unstructured)
	spec, found, err := unstructured.NestedMap(crd.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("error getting spec from CRD: %v", err)
	}
	
	// Extract the relevant fields
	name, _ := spec["name"].(string)
	parent, _ := spec["parent"].(string)
	vlanIDFloat, _ := spec["vlanId"].(float64)
	vlanID := int(vlanIDFloat)
	
	// Create the VLANConfig from the CRD spec
	config := VLANConfig{
		State: "up", // Default to up unless specified otherwise
	}
	
	// Extract MTU if present
	if mtu, ok := spec["mtu"].(float64); ok {
		config.MTU = int(mtu)
	}
	
	// Extract QoS priority if present
	if qos, ok := spec["qos"].(map[string]interface{}); ok {
		if priority, ok := qos["priority"].(float64); ok {
			config.QoSPriority = int(priority)
		}
		if dscp, ok := qos["dscp"].(float64); ok {
			config.DSCP = int(dscp)
		}
	}
	
	// Extract addresses if present
	if addresses, ok := spec["addresses"].([]interface{}); ok {
		config.Addresses = make([]IPConfig, 0, len(addresses))
		for _, addr := range addresses {
			addrStr, ok := addr.(string)
			if !ok {
				continue
			}
			
			// Parse the CIDR notation
			ip, ipNet, err := net.ParseCIDR(addrStr)
			if err != nil {
				klog.Warningf("Failed to parse address %s: %v", addrStr, err)
				continue
			}
			
			// Calculate the prefix length
			prefixSize, _ := ipNet.Mask.Size()
			
			// Add the IP configuration
			config.Addresses = append(config.Addresses, IPConfig{
				Address: ip,
				Prefix:  prefixSize,
			})
		}
	}
	
	// Check if the VLAN interface already exists
	existing, err := c.manager.GetVLAN(name)
	if err == nil {
		// VLAN exists, so update it
		return c.handleVLANUpdate(name, config)
	}
	
	// VLAN doesn't exist, so create it
	return c.handleVLANCreate(name, parent, vlanID, config)
}

// listVLANCRDs returns a list of all NetworkInterface CRDs with type=vlan
func (c *VLANController) listVLANCRDs() ([]metav1.Object, error) {
	// Get all objects from the informer's index
	list := c.informer.GetIndexer().List()
	result := make([]metav1.Object, 0, len(list))
	
	// Filter to only include NetworkInterfaces with type=vlan
	for _, obj := range list {
		crd, ok := obj.(metav1.Object)
		if !ok {
			continue
		}
		
		// Add to the result list
		result = append(result, crd)
	}
	
	return result, nil
}