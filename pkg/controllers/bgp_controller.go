package controllers

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/network/routing"
)

const (
	// BGPResyncPeriod is the resync period for BGP informers
	BGPResyncPeriod = 10 * time.Minute
)

// BGPController watches for BGPConfig CRDs and configures BGP accordingly
type BGPController struct {
	// dynamicClient is the client for interacting with CRDs
	dynamicClient dynamic.Interface
	
	// protocolManager is used to manage routing protocols
	protocolManager routing.ProtocolManager
	
	// informer is the informer for BGPConfig CRDs
	informer cache.SharedIndexInformer
	
	// queue is the workqueue for BGPConfig events
	queue workqueue.RateLimitingInterface
	
	// stopCh is used to signal the informer to stop
	stopCh chan struct{}
}

// NewBGPController creates a new controller for BGPConfig CRDs
func NewBGPController(
	dynamicClient dynamic.Interface,
	protocolManager routing.ProtocolManager,
) *BGPController {
	// Create a GVR for BGPConfig CRDs
	gvr := schema.GroupVersionResource{
		Group:    "networking.fos1.io",
		Version:  "v1alpha1",
		Resource: "bgpconfigs",
	}
	
	// Create a dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, BGPResyncPeriod)
	
	// Create an informer for BGPConfig CRDs
	informer := factory.ForResource(gvr).Informer()
	
	// Create a controller
	controller := &BGPController{
		dynamicClient:    dynamicClient,
		protocolManager:  protocolManager,
		informer:         informer,
		queue:            workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:           make(chan struct{}),
	}
	
	// Add event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueBGPConfig,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			
			// Skip if the objects are the same
			if reflect.DeepEqual(oldObj.GetSpec(), newObj.GetSpec()) {
				return
			}
			
			controller.enqueueBGPConfig(newObj)
		},
		DeleteFunc: controller.enqueueBGPConfig,
	})
	
	return controller
}

// Run starts the controller
func (c *BGPController) Run(workers int) {
	defer c.queue.ShutDown()
	
	klog.Info("Starting BGP controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		klog.Error("Failed to sync informer cache")
		return
	}
	
	klog.Info("BGP controller synced and ready")
	
	// Start workers
	for i := 0; i < workers; i++ {
		go c.runWorker()
	}
	
	// Wait for stop signal
	<-c.stopCh
	klog.Info("Stopping BGP controller")
}

// Stop stops the controller
func (c *BGPController) Stop() {
	close(c.stopCh)
}

// runWorker runs a worker thread
func (c *BGPController) runWorker() {
	for c.processNextItem() {
	}
}

// enqueueBGPConfig adds a BGPConfig to the queue
func (c *BGPController) enqueueBGPConfig(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	
	c.queue.Add(key)
}

// processNextItem processes the next item in the queue
func (c *BGPController) processNextItem() bool {
	// Get the next item
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcileBGPConfig(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about this key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error reconciling BGPConfig %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("Requeuing BGPConfig %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		klog.Infof("Dropping BGPConfig %s from queue after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
	}
	
	return true
}

// reconcileBGPConfig reconciles a BGPConfig CRD
func (c *BGPController) reconcileBGPConfig(key string) error {
	// Get the BGPConfig object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("error getting BGPConfig %s from cache: %w", key, err)
	}
	
	// If the object has been deleted, stop BGP
	if !exists {
		return c.handleBGPConfigDelete(key)
	}
	
	// Otherwise, create or update BGP
	return c.handleBGPConfigCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleBGPConfigDelete handles deletion of a BGPConfig CRD
func (c *BGPController) handleBGPConfigDelete(key string) error {
	// Extract namespace and name from the key
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key: %s", key)
	}
	
	klog.Infof("Handling deletion of BGPConfig %s/%s", namespace, name)
	
	// Stop BGP
	if err := c.protocolManager.StopProtocol("bgp"); err != nil {
		return fmt.Errorf("failed to stop BGP: %w", err)
	}
	
	klog.Infof("BGP stopped for %s/%s", namespace, name)
	return nil
}

// handleBGPConfigCreateOrUpdate handles creation or update of a BGPConfig CRD
func (c *BGPController) handleBGPConfigCreateOrUpdate(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	klog.Infof("Processing BGPConfig %s/%s", namespace, name)
	
	// Get the spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("spec not found in BGPConfig %s/%s: %w", namespace, name, err)
	}
	
	// Extract BGP configuration from the spec
	enabled, found, err := unstructured.NestedBool(spec, "enabled")
	if err != nil {
		return fmt.Errorf("error getting enabled from BGPConfig %s/%s: %w", namespace, name, err)
	}
	if found && !enabled {
		// If BGP is disabled, stop it
		if err := c.protocolManager.StopProtocol("bgp"); err != nil {
			return fmt.Errorf("failed to stop BGP: %w", err)
		}
		
		klog.Infof("BGP disabled for %s/%s", namespace, name)
		return nil
	}
	
	// Extract AS number
	asNumber, found, err := unstructured.NestedInt64(spec, "asNumber")
	if err != nil || !found {
		return fmt.Errorf("asNumber not found in BGPConfig %s/%s: %w", namespace, name, err)
	}
	
	// Extract router ID
	routerID, found, err := unstructured.NestedString(spec, "routerId")
	if err != nil || !found {
		return fmt.Errorf("routerId not found in BGPConfig %s/%s: %w", namespace, name, err)
	}
	
	// Extract neighbors
	neighborsUntyped, found, err := unstructured.NestedSlice(spec, "neighbors")
	if err != nil {
		return fmt.Errorf("error getting neighbors from BGPConfig %s/%s: %w", namespace, name, err)
	}
	
	// Convert neighbors to typed objects
	neighbors := make([]routing.BGPNeighbor, 0, len(neighborsUntyped))
	for _, neighborUntyped := range neighborsUntyped {
		neighborMap, ok := neighborUntyped.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid neighbor format in BGPConfig %s/%s", namespace, name)
		}
		
		address, found, err := unstructured.NestedString(neighborMap, "address")
		if err != nil || !found {
			return fmt.Errorf("address not found in neighbor of BGPConfig %s/%s: %w", namespace, name, err)
		}
		
		remoteASNumber, found, err := unstructured.NestedInt64(neighborMap, "remoteAsNumber")
		if err != nil || !found {
			return fmt.Errorf("remoteAsNumber not found in neighbor of BGPConfig %s/%s: %w", namespace, name, err)
		}
		
		description, _, _ := unstructured.NestedString(neighborMap, "description")
		keepaliveInterval, _, _ := unstructured.NestedInt64(neighborMap, "keepaliveInterval")
		holdTime, _, _ := unstructured.NestedInt64(neighborMap, "holdTime")
		connectRetryInterval, _, _ := unstructured.NestedInt64(neighborMap, "connectRetryInterval")
		bfdEnabled, _, _ := unstructured.NestedBool(neighborMap, "bfdEnabled")
		
		neighbors = append(neighbors, routing.BGPNeighbor{
			Address:              address,
			RemoteASNumber:       int(remoteASNumber),
			Description:          description,
			KeepaliveInterval:    int(keepaliveInterval),
			HoldTime:             int(holdTime),
			ConnectRetryInterval: int(connectRetryInterval),
			BFDEnabled:           bfdEnabled,
		})
	}
	
	// Extract address families
	addressFamiliesUntyped, found, err := unstructured.NestedSlice(spec, "addressFamilies")
	if err != nil {
		return fmt.Errorf("error getting addressFamilies from BGPConfig %s/%s: %w", namespace, name, err)
	}
	
	// Convert address families to typed objects
	addressFamilies := make([]routing.BGPAddressFamily, 0, len(addressFamiliesUntyped))
	for _, afUntyped := range addressFamiliesUntyped {
		afMap, ok := afUntyped.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid addressFamily format in BGPConfig %s/%s", namespace, name)
		}
		
		afType, found, err := unstructured.NestedString(afMap, "type")
		if err != nil || !found {
			return fmt.Errorf("type not found in addressFamily of BGPConfig %s/%s: %w", namespace, name, err)
		}
		
		enabled, _, _ := unstructured.NestedBool(afMap, "enabled")
		
		// Extract redistributions
		redistributionsUntyped, _, _ := unstructured.NestedSlice(afMap, "redistributions")
		redistributions := make([]routing.Redistribution, 0, len(redistributionsUntyped))
		for _, redistUntyped := range redistributionsUntyped {
			redistMap, ok := redistUntyped.(map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid redistribution format in BGPConfig %s/%s", namespace, name)
			}
			
			protocol, found, err := unstructured.NestedString(redistMap, "protocol")
			if err != nil || !found {
				return fmt.Errorf("protocol not found in redistribution of BGPConfig %s/%s: %w", namespace, name, err)
			}
			
			routeMapRef, _, _ := unstructured.NestedString(redistMap, "routeMapRef")
			
			redistributions = append(redistributions, routing.Redistribution{
				Protocol:    protocol,
				RouteMapRef: routeMapRef,
			})
		}
		
		// Extract networks
		networksUntyped, _, _ := unstructured.NestedSlice(afMap, "networks")
		networks := make([]string, 0, len(networksUntyped))
		for _, networkUntyped := range networksUntyped {
			network, ok := networkUntyped.(string)
			if !ok {
				return fmt.Errorf("invalid network format in BGPConfig %s/%s", namespace, name)
			}
			
			networks = append(networks, network)
		}
		
		addressFamilies = append(addressFamilies, routing.BGPAddressFamily{
			Type:           afType,
			Enabled:        enabled,
			Redistributions: redistributions,
			Networks:       networks,
		})
	}
	
	// Extract VRF
	vrf, _, _ := unstructured.NestedString(spec, "vrf")
	if vrf == "" {
		vrf = "main"
	}
	
	// Extract other BGP parameters
	ebgpMultihop, _, _ := unstructured.NestedInt64(spec, "ebgpMultihop")
	deterministicMED, _, _ := unstructured.NestedBool(spec, "deterministic-med")
	multipath, _, _ := unstructured.NestedBool(spec, "multipath")
	
	// Create BGP configuration
	bgpConfig := routing.BGPConfig{
		ASNumber:        int(asNumber),
		RouterID:        routerID,
		Neighbors:       neighbors,
		AddressFamilies: addressFamilies,
		VRF:             vrf,
		EBGPMultihop:    int(ebgpMultihop),
		DeterministicMED: deterministicMED,
		Multipath:       multipath,
	}
	
	// Start or update BGP
	if err := c.protocolManager.StartProtocol("bgp", bgpConfig); err != nil {
		return fmt.Errorf("failed to start BGP: %w", err)
	}
	
	// Update status
	if err := c.updateBGPConfigStatus(obj); err != nil {
		return fmt.Errorf("failed to update BGPConfig status: %w", err)
	}
	
	klog.Infof("BGP configured for %s/%s", namespace, name)
	return nil
}

// updateBGPConfigStatus updates the status of a BGPConfig CRD
func (c *BGPController) updateBGPConfigStatus(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	
	// Get the BGP status
	status, err := c.protocolManager.GetProtocolStatus("bgp")
	if err != nil {
		return fmt.Errorf("failed to get BGP status: %w", err)
	}
	
	// Create a copy of the object
	newObj := obj.DeepCopy()
	
	// Update the status
	if err := unstructured.SetNestedField(newObj.Object, status.State, "status", "state"); err != nil {
		return fmt.Errorf("failed to set status.state: %w", err)
	}
	
	if err := unstructured.SetNestedField(newObj.Object, status.Uptime.String(), "status", "uptime"); err != nil {
		return fmt.Errorf("failed to set status.uptime: %w", err)
	}
	
	// Convert neighbors to unstructured format
	neighborsUntyped := make([]interface{}, 0, len(status.Neighbors))
	for _, neighbor := range status.Neighbors {
		neighborMap := map[string]interface{}{
			"address":          neighbor.Address,
			"state":            neighbor.State,
			"uptime":           neighbor.Uptime.String(),
			"prefixesReceived": neighbor.PrefixesReceived,
			"prefixesSent":     neighbor.PrefixesSent,
		}
		
		neighborsUntyped = append(neighborsUntyped, neighborMap)
	}
	
	if err := unstructured.SetNestedSlice(newObj.Object, neighborsUntyped, "status", "neighbors"); err != nil {
		return fmt.Errorf("failed to set status.neighbors: %w", err)
	}
	
	// Update the object
	gvr := schema.GroupVersionResource{
		Group:    "networking.fos1.io",
		Version:  "v1alpha1",
		Resource: "bgpconfigs",
	}
	
	_, err = c.dynamicClient.Resource(gvr).Namespace(namespace).UpdateStatus(context.Background(), newObj, nil)
	if err != nil {
		return fmt.Errorf("failed to update BGPConfig status: %w", err)
	}
	
	return nil
}
