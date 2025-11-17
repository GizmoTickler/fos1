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

	"github.com/GizmoTickler/fos1/pkg/network/routing"
)

const (
	// OSPFResyncPeriod is the resync period for OSPF informers
	OSPFResyncPeriod = 10 * time.Minute
)

// OSPFController watches for OSPFConfig CRDs and configures OSPF accordingly
type OSPFController struct {
	// dynamicClient is the client for interacting with CRDs
	dynamicClient dynamic.Interface
	
	// protocolManager is used to manage routing protocols
	protocolManager routing.ProtocolManager
	
	// informer is the informer for OSPFConfig CRDs
	informer cache.SharedIndexInformer
	
	// queue is the workqueue for OSPFConfig events
	queue workqueue.RateLimitingInterface
	
	// stopCh is used to signal the informer to stop
	stopCh chan struct{}
}

// NewOSPFController creates a new controller for OSPFConfig CRDs
func NewOSPFController(
	dynamicClient dynamic.Interface,
	protocolManager routing.ProtocolManager,
) *OSPFController {
	// Create a GVR for OSPFConfig CRDs
	gvr := schema.GroupVersionResource{
		Group:    "networking.fos1.io",
		Version:  "v1alpha1",
		Resource: "ospfconfigs",
	}
	
	// Create a dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, OSPFResyncPeriod)
	
	// Create an informer for OSPFConfig CRDs
	informer := factory.ForResource(gvr).Informer()
	
	// Create a controller
	controller := &OSPFController{
		dynamicClient:    dynamicClient,
		protocolManager:  protocolManager,
		informer:         informer,
		queue:            workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:           make(chan struct{}),
	}
	
	// Add event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueOSPFConfig,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			
			// Skip if the objects are the same
			if reflect.DeepEqual(oldObj.GetSpec(), newObj.GetSpec()) {
				return
			}
			
			controller.enqueueOSPFConfig(newObj)
		},
		DeleteFunc: controller.enqueueOSPFConfig,
	})
	
	return controller
}

// Run starts the controller
func (c *OSPFController) Run(workers int) {
	defer c.queue.ShutDown()
	
	klog.Info("Starting OSPF controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		klog.Error("Failed to sync informer cache")
		return
	}
	
	klog.Info("OSPF controller synced and ready")
	
	// Start workers
	for i := 0; i < workers; i++ {
		go c.runWorker()
	}
	
	// Wait for stop signal
	<-c.stopCh
	klog.Info("Stopping OSPF controller")
}

// Stop stops the controller
func (c *OSPFController) Stop() {
	close(c.stopCh)
}

// runWorker runs a worker thread
func (c *OSPFController) runWorker() {
	for c.processNextItem() {
	}
}

// enqueueOSPFConfig adds an OSPFConfig to the queue
func (c *OSPFController) enqueueOSPFConfig(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	
	c.queue.Add(key)
}

// processNextItem processes the next item in the queue
func (c *OSPFController) processNextItem() bool {
	// Get the next item
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcileOSPFConfig(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about this key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error reconciling OSPFConfig %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("Requeuing OSPFConfig %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		klog.Infof("Dropping OSPFConfig %s from queue after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
	}
	
	return true
}

// reconcileOSPFConfig reconciles an OSPFConfig CRD
func (c *OSPFController) reconcileOSPFConfig(key string) error {
	// Get the OSPFConfig object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("error getting OSPFConfig %s from cache: %w", key, err)
	}
	
	// If the object has been deleted, stop OSPF
	if !exists {
		return c.handleOSPFConfigDelete(key)
	}
	
	// Otherwise, create or update OSPF
	return c.handleOSPFConfigCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleOSPFConfigDelete handles deletion of an OSPFConfig CRD
func (c *OSPFController) handleOSPFConfigDelete(key string) error {
	// Extract namespace and name from the key
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key: %s", key)
	}
	
	klog.Infof("Handling deletion of OSPFConfig %s/%s", namespace, name)
	
	// Stop OSPF
	if err := c.protocolManager.StopProtocol("ospf"); err != nil {
		return fmt.Errorf("failed to stop OSPF: %w", err)
	}
	
	klog.Infof("OSPF stopped for %s/%s", namespace, name)
	return nil
}

// handleOSPFConfigCreateOrUpdate handles creation or update of an OSPFConfig CRD
func (c *OSPFController) handleOSPFConfigCreateOrUpdate(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	klog.Infof("Processing OSPFConfig %s/%s", namespace, name)
	
	// Get the spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("spec not found in OSPFConfig %s/%s: %w", namespace, name, err)
	}
	
	// Extract router ID
	routerID, found, err := unstructured.NestedString(spec, "routerId")
	if err != nil || !found {
		return fmt.Errorf("routerId not found in OSPFConfig %s/%s: %w", namespace, name, err)
	}
	
	// Extract areas
	areasUntyped, found, err := unstructured.NestedSlice(spec, "areas")
	if err != nil {
		return fmt.Errorf("error getting areas from OSPFConfig %s/%s: %w", namespace, name, err)
	}
	
	// Convert areas to typed objects
	areas := make([]routing.OSPFArea, 0, len(areasUntyped))
	for _, areaUntyped := range areasUntyped {
		areaMap, ok := areaUntyped.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid area format in OSPFConfig %s/%s", namespace, name)
		}
		
		areaID, found, err := unstructured.NestedString(areaMap, "areaId")
		if err != nil || !found {
			return fmt.Errorf("areaId not found in area of OSPFConfig %s/%s: %w", namespace, name, err)
		}
		
		stubArea, _, _ := unstructured.NestedBool(areaMap, "stubArea")
		nssaArea, _, _ := unstructured.NestedBool(areaMap, "nssaArea")
		
		// Extract interfaces
		interfacesUntyped, _, _ := unstructured.NestedSlice(areaMap, "interfaces")
		interfaces := make([]routing.OSPFInterface, 0, len(interfacesUntyped))
		for _, intfUntyped := range interfacesUntyped {
			intfMap, ok := intfUntyped.(map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid interface format in OSPFConfig %s/%s", namespace, name)
			}
			
			intfName, found, err := unstructured.NestedString(intfMap, "name")
			if err != nil || !found {
				return fmt.Errorf("name not found in interface of OSPFConfig %s/%s: %w", namespace, name, err)
			}
			
			networkType, _, _ := unstructured.NestedString(intfMap, "networkType")
			priority, _, _ := unstructured.NestedInt64(intfMap, "priority")
			cost, _, _ := unstructured.NestedInt64(intfMap, "cost")
			
			// Extract authentication
			authMap, _, _ := unstructured.NestedMap(intfMap, "authentication")
			var auth routing.OSPFAuthentication
			if authMap != nil {
				authType, _, _ := unstructured.NestedString(authMap, "type")
				key, _, _ := unstructured.NestedString(authMap, "key")
				keyID, _, _ := unstructured.NestedInt64(authMap, "keyId")
				
				auth = routing.OSPFAuthentication{
					Type:  authType,
					Key:   key,
					KeyID: int(keyID),
				}
			}
			
			interfaces = append(interfaces, routing.OSPFInterface{
				Name:           intfName,
				NetworkType:    networkType,
				Priority:       int(priority),
				Cost:           int(cost),
				Authentication: auth,
			})
		}
		
		areas = append(areas, routing.OSPFArea{
			AreaID:     areaID,
			Interfaces: interfaces,
			StubArea:   stubArea,
			NSSAArea:   nssaArea,
		})
	}
	
	// Extract redistributions
	redistributionsUntyped, _, _ := unstructured.NestedSlice(spec, "redistributions")
	redistributions := make([]routing.Redistribution, 0, len(redistributionsUntyped))
	for _, redistUntyped := range redistributionsUntyped {
		redistMap, ok := redistUntyped.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid redistribution format in OSPFConfig %s/%s", namespace, name)
		}
		
		protocol, found, err := unstructured.NestedString(redistMap, "protocol")
		if err != nil || !found {
			return fmt.Errorf("protocol not found in redistribution of OSPFConfig %s/%s: %w", namespace, name, err)
		}
		
		routeMapRef, _, _ := unstructured.NestedString(redistMap, "routeMapRef")
		
		redistributions = append(redistributions, routing.Redistribution{
			Protocol:    protocol,
			RouteMapRef: routeMapRef,
		})
	}
	
	// Extract VRF
	vrf, _, _ := unstructured.NestedString(spec, "vrf")
	if vrf == "" {
		vrf = "main"
	}
	
	// Extract reference bandwidth
	referenceBandwidth, _, _ := unstructured.NestedInt64(spec, "referenceBandwidth")
	
	// Create OSPF configuration
	ospfConfig := routing.OSPFConfig{
		RouterID:           routerID,
		Areas:              areas,
		Redistributions:    redistributions,
		VRF:                vrf,
		ReferenceBandwidth: int(referenceBandwidth),
	}
	
	// Start or update OSPF
	if err := c.protocolManager.StartProtocol("ospf", ospfConfig); err != nil {
		return fmt.Errorf("failed to start OSPF: %w", err)
	}
	
	// Update status
	if err := c.updateOSPFConfigStatus(obj); err != nil {
		return fmt.Errorf("failed to update OSPFConfig status: %w", err)
	}
	
	klog.Infof("OSPF configured for %s/%s", namespace, name)
	return nil
}

// updateOSPFConfigStatus updates the status of an OSPFConfig CRD
func (c *OSPFController) updateOSPFConfigStatus(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	
	// Get the OSPF status
	status, err := c.protocolManager.GetProtocolStatus("ospf")
	if err != nil {
		return fmt.Errorf("failed to get OSPF status: %w", err)
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
		Resource: "ospfconfigs",
	}
	
	_, err = c.dynamicClient.Resource(gvr).Namespace(namespace).UpdateStatus(context.Background(), newObj, nil)
	if err != nil {
		return fmt.Errorf("failed to update OSPFConfig status: %w", err)
	}
	
	return nil
}
