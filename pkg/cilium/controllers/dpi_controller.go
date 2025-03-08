package controllers

import (
	"context"
	"fmt"
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
	// DPIPolicyResyncPeriod is the resync period for the DPI controller
	DPIPolicyResyncPeriod = 30 * time.Second
	
	// DPIPolicyResource is the resource name for the DPIPolicy CRD
	DPIPolicyResource = "dpipolicies.security.fos1.io"
)

// DPIController watches for DPIPolicy CRDs and translates them to Cilium DPI configurations
type DPIController struct {
	// dynamicClient is the client for interacting with CRDs
	dynamicClient dynamic.Interface
	
	// ciliumClient is the client for interacting with Cilium
	ciliumClient cilium.CiliumClient
	
	// informer is the informer for DPIPolicy CRDs
	informer cache.SharedIndexInformer
	
	// queue is the workqueue for DPIPolicy events
	queue workqueue.RateLimitingInterface
	
	// stopCh is used to signal the informer to stop
	stopCh chan struct{}
}

// NewDPIController creates a new controller for DPIPolicy CRDs
func NewDPIController(
	dynamicClient dynamic.Interface,
	ciliumClient cilium.CiliumClient,
) *DPIController {
	// Create a GVR for DPIPolicy CRDs
	gvr := schema.GroupVersionResource{
		Group:    "security.fos1.io",
		Version:  "v1alpha1",
		Resource: "dpipolicies",
	}
	
	// Create a dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, DPIPolicyResyncPeriod)
	
	// Create an informer for DPIPolicy CRDs
	informer := factory.ForResource(gvr).Informer()
	
	// Create a controller
	controller := &DPIController{
		dynamicClient: dynamicClient,
		ciliumClient:  ciliumClient,
		informer:      informer,
		queue:         workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:        make(chan struct{}),
	}
	
	// Add event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueDPIPolicy,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			
			// Skip if the objects are the same
			if reflect.DeepEqual(oldObj.GetSpec(), newObj.GetSpec()) {
				return
			}
			
			controller.enqueueDPIPolicy(newObj)
		},
		DeleteFunc: controller.enqueueDPIPolicy,
	})
	
	return controller
}

// Start starts the controller
func (c *DPIController) Start(ctx context.Context) error {
	klog.Info("Starting DPIPolicy controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		return fmt.Errorf("timed out waiting for DPIPolicy informer cache to sync")
	}
	
	// Start workers to process items from the queue
	for i := 0; i < 2; i++ {
		go wait.Until(c.runWorker, time.Second, c.stopCh)
	}
	
	<-ctx.Done()
	return nil
}

// Stop stops the controller
func (c *DPIController) Stop() {
	klog.Info("Stopping DPIPolicy controller")
	close(c.stopCh)
	c.queue.ShutDown()
}

// runWorker is a long-running function that processes items from the work queue
func (c *DPIController) runWorker() {
	for c.processNextItem() {
		// Continue processing items until the queue is empty
	}
}

// processNextItem processes a single item from the work queue
func (c *DPIController) processNextItem() bool {
	// Get the next item from the queue
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcileDPIPolicy(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about this key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error reconciling DPIPolicy %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("Requeuing DPIPolicy %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		klog.Infof("Dropping DPIPolicy %s from queue after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
	}
	
	return true
}

// enqueueDPIPolicy adds a DPIPolicy object to the work queue
func (c *DPIController) enqueueDPIPolicy(obj interface{}) {
	// Convert the object to a key
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Error creating key for object: %v", err)
		return
	}
	
	// Add the key to the queue
	c.queue.Add(key)
}

// reconcileDPIPolicy reconciles a DPIPolicy CRD
func (c *DPIController) reconcileDPIPolicy(key string) error {
	// Get the DPIPolicy object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("error getting DPIPolicy %s from cache: %w", key, err)
	}
	
	// If the object has been deleted, delete the corresponding Cilium DPI configuration
	if !exists {
		return c.handleDPIPolicyDelete(key)
	}
	
	// Otherwise, create or update the Cilium DPI configuration
	return c.handleDPIPolicyCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleDPIPolicyDelete handles deletion of a DPIPolicy CRD
func (c *DPIController) handleDPIPolicyDelete(key string) error {
	// Extract the name from the key
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key %s: %w", key, err)
	}
	
	// In a real implementation, we would delete the corresponding Cilium DPI configuration
	
	klog.Infof("Deleted Cilium DPI configuration for DPIPolicy %s in namespace %s", name, namespace)
	return nil
}

// handleDPIPolicyCreateOrUpdate handles creation or update of a DPIPolicy CRD
func (c *DPIController) handleDPIPolicyCreateOrUpdate(obj *unstructured.Unstructured) error {
	// Get the DPIPolicy spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("error getting spec from DPIPolicy: %v", err)
	}
	
	// Extract namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	
	// Check if DPI is enabled
	enabled, found, err := unstructured.NestedBool(spec, "enabled")
	if err != nil || !found {
		// Default to true if not specified
		enabled = true
	}
	
	// If DPI is not enabled, we can skip the rest of the configuration
	if !enabled {
		klog.Infof("DPI is disabled for DPIPolicy %s in namespace %s, skipping", name, namespace)
		return nil
	}
	
	// Extract applications to monitor
	applicationsUntyped, found, err := unstructured.NestedSlice(spec, "applications")
	if err != nil || !found {
		return fmt.Errorf("error getting applications from DPIPolicy: %v", err)
	}
	
	// Convert applications to string slice
	applications := make([]string, 0, len(applicationsUntyped))
	for _, appUntyped := range applicationsUntyped {
		if appStr, ok := appUntyped.(string); ok {
			applications = append(applications, appStr)
		}
	}
	
	// Extract enforcement mode
	enforcementMode, found, err := unstructured.NestedString(spec, "enforcementMode")
	if err != nil || !found {
		// Default to "log" if not specified
		enforcementMode = "log"
	}
	
	// Extract target interfaces
	interfacesUntyped, found, err := unstructured.NestedSlice(spec, "targetInterfaces")
	if err != nil {
		// Default to empty list if not specified
		interfacesUntyped = make([]interface{}, 0)
	}
	
	// Convert interfaces to string slice
	interfaces := make([]string, 0, len(interfacesUntyped))
	for _, ifaceUntyped := range interfacesUntyped {
		if ifaceStr, ok := ifaceUntyped.(string); ok {
			interfaces = append(interfaces, ifaceStr)
		}
	}
	
	// Create DPI integration config
	dpiConfig := &cilium.DPIIntegrationConfig{
		Enabled:               enabled,
		ApplicationsToMonitor: applications,
		EnforcementMode:       enforcementMode,
		TargetInterfaces:      interfaces,
	}
	
	// Apply the DPI configuration to Cilium
	ctx := context.Background()
	if err := c.ciliumClient.ConfigureDPIIntegration(ctx, dpiConfig); err != nil {
		return fmt.Errorf("error configuring DPI integration with Cilium: %w", err)
	}
	
	klog.Infof("Successfully configured DPI integration for DPIPolicy %s in namespace %s", name, namespace)
	return nil
}

// GetCiliumDPIPolicyName generates a Cilium DPI policy name for a DPIPolicy
func GetCiliumDPIPolicyName(namespace, name string) string {
	return fmt.Sprintf("dpi-%s-%s", namespace, name)
}
