package controllers

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/varuntirumala1/fos1/pkg/cilium"
)

const (
	// RouteResyncPeriod is the resync period for the routing controller
	RouteResyncPeriod = 30 * time.Second
	
	// RouteResource is the resource name for the Route CRD
	RouteResource = "routes.network.fos1.io"
)

// RoutingController watches for Route CRDs and translates them to Cilium route configurations
type RoutingController struct {
	// dynamicClient is the client for interacting with CRDs
	dynamicClient dynamic.Interface
	
	// routeSynchronizer is used to synchronize routes with Cilium
	routeSynchronizer *cilium.RouteSynchronizer
	
	// informer is the informer for Route CRDs
	informer cache.SharedIndexInformer
	
	// queue is the workqueue for Route events
	queue workqueue.RateLimitingInterface
	
	// stopCh is used to signal the informer to stop
	stopCh chan struct{}
}

// NewRoutingController creates a new controller for Route CRDs
func NewRoutingController(
	dynamicClient dynamic.Interface,
	routeSynchronizer *cilium.RouteSynchronizer,
) *RoutingController {
	// Create a GVR for Route CRDs
	gvr := schema.GroupVersionResource{
		Group:    "network.fos1.io",
		Version:  "v1alpha1",
		Resource: "routes",
	}
	
	// Create a dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, RouteResyncPeriod)
	
	// Create an informer for Route CRDs
	informer := factory.ForResource(gvr).Informer()
	
	// Create a controller
	controller := &RoutingController{
		dynamicClient:     dynamicClient,
		routeSynchronizer: routeSynchronizer,
		informer:          informer,
		queue:             workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:            make(chan struct{}),
	}
	
	// Add event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueRoute,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			
			// Skip if the objects are the same
			if reflect.DeepEqual(oldObj.GetSpec(), newObj.GetSpec()) {
				return
			}
			
			controller.enqueueRoute(newObj)
		},
		DeleteFunc: controller.enqueueRoute,
	})
	
	return controller
}

// Start starts the controller
func (c *RoutingController) Start(ctx context.Context) error {
	klog.Info("Starting Route controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		return fmt.Errorf("timed out waiting for Route informer cache to sync")
	}
	
	// Start workers to process items from the queue
	for i := 0; i < 2; i++ {
		go wait.Until(c.runWorker, time.Second, c.stopCh)
	}
	
	<-ctx.Done()
	return nil
}

// Stop stops the controller
func (c *RoutingController) Stop() {
	klog.Info("Stopping Route controller")
	close(c.stopCh)
	c.queue.ShutDown()
}

// runWorker is a long-running function that processes items from the work queue
func (c *RoutingController) runWorker() {
	for c.processNextItem() {
		// Continue processing items until the queue is empty
	}
}

// processNextItem processes a single item from the work queue
func (c *RoutingController) processNextItem() bool {
	// Get the next item from the queue
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcileRoute(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about this key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error reconciling Route %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("Requeuing Route %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		klog.Infof("Dropping Route %s from queue after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
	}
	
	return true
}

// enqueueRoute adds a Route object to the work queue
func (c *RoutingController) enqueueRoute(obj interface{}) {
	// Convert the object to a key
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Error creating key for object: %v", err)
		return
	}
	
	// Add the key to the queue
	c.queue.Add(key)
}

// reconcileRoute reconciles a Route CRD
func (c *RoutingController) reconcileRoute(key string) error {
	// Get the Route object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("error getting Route %s from cache: %w", key, err)
	}
	
	// If the object has been deleted, delete the corresponding Cilium route
	if !exists {
		return c.handleRouteDelete(key)
	}
	
	// Otherwise, create or update the Cilium route
	return c.handleRouteCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleRouteDelete handles deletion of a Route CRD
func (c *RoutingController) handleRouteDelete(key string) error {
	// The Route has been deleted, so remove any Cilium configuration
	
	// In a real implementation, we would use RouteSync to remove the route from Cilium
	
	klog.Infof("Route %s deleted", key)
	return nil
}

// handleRouteCreateOrUpdate handles creation or update of a Route CRD
func (c *RoutingController) handleRouteCreateOrUpdate(obj *unstructured.Unstructured) error {
	// Get the Route spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("error getting spec from Route: %v", err)
	}
	
	// Extract fields from the spec
	destination, found, err := unstructured.NestedString(spec, "destination")
	if err != nil || !found {
		return fmt.Errorf("error getting destination from Route: %v", err)
	}
	
	gatewayStr, found, err := unstructured.NestedString(spec, "gateway")
	if err != nil || !found {
		return fmt.Errorf("error getting gateway from Route: %v", err)
	}
	
	// Parse the gateway IP
	gateway := net.ParseIP(gatewayStr)
	if gateway == nil {
		return fmt.Errorf("invalid gateway IP: %s", gatewayStr)
	}
	
	// Get the interface
	iface, found, err := unstructured.NestedString(spec, "interface")
	if err != nil || !found {
		return fmt.Errorf("error getting interface from Route: %v", err)
	}
	
	// Get optional VRF
	vrf, found, err := unstructured.NestedString(spec, "vrf")
	if err != nil {
		vrf = ""
	}
	
	// Get optional metric
	metricFloat, found, err := unstructured.NestedFloat64(spec, "metric")
	if err != nil || !found {
		metricFloat = 0
	}
	metric := int(metricFloat)
	
	// Get optional table ID
	tableIDFloat, found, err := unstructured.NestedFloat64(spec, "tableId")
	if err != nil || !found {
		tableIDFloat = 0
	}
	tableID := int(tableIDFloat)
	
	// Get optional labels
	labelsUntyped, found, err := unstructured.NestedMap(spec, "labels")
	if err != nil {
		labelsUntyped = nil
	}
	
	// Convert labels to map[string]string
	labels := make(map[string]string)
	if labelsUntyped != nil {
		for k, v := range labelsUntyped {
			if strValue, ok := v.(string); ok {
				labels[k] = strValue
			}
		}
	}
	
	// Create a RouteSync object
	routeSync := &cilium.RouteSync{
		Destination: destination,
		Gateway:     gateway,
		Interface:   iface,
		VRF:         vrf,
		Metric:      metric,
		TableID:     tableID,
		Labels:      labels,
	}
	
	// Synchronize the route with Cilium
	// This will add or update the route in Cilium
	ctx := context.Background()
	if err := c.routeSynchronizer.SyncRoute(ctx, routeSync); err != nil {
		return fmt.Errorf("error synchronizing route with Cilium: %w", err)
	}
	
	klog.Infof("Successfully synchronized route %s with Cilium", destination)
	return nil
}

// GetCiliumRouteLabelForRoute generates a Cilium route label for a Route
func GetCiliumRouteLabelForRoute(namespace, name string) string {
	return fmt.Sprintf("route-%s-%s", namespace, name)
}
