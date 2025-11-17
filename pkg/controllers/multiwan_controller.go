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

	"github.com/GizmoTickler/fos1/pkg/network/routing/multiwan"
)

const (
	// MultiWANResyncPeriod is the resync period for MultiWAN informers
	MultiWANResyncPeriod = 10 * time.Minute
)

// MultiWANController watches for MultiWAN CRDs and configures multi-WAN accordingly
type MultiWANController struct {
	// dynamicClient is the client for interacting with CRDs
	dynamicClient dynamic.Interface
	
	// wanManager is used to manage WAN interfaces
	wanManager multiwan.Manager
	
	// informer is the informer for MultiWAN CRDs
	informer cache.SharedIndexInformer
	
	// queue is the workqueue for MultiWAN events
	queue workqueue.RateLimitingInterface
	
	// stopCh is used to signal the informer to stop
	stopCh chan struct{}
}

// NewMultiWANController creates a new controller for MultiWAN CRDs
func NewMultiWANController(
	dynamicClient dynamic.Interface,
	wanManager multiwan.Manager,
) *MultiWANController {
	// Create a GVR for MultiWAN CRDs
	gvr := schema.GroupVersionResource{
		Group:    "network.fos1.io",
		Version:  "v1alpha1",
		Resource: "multiwans",
	}
	
	// Create a dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, MultiWANResyncPeriod)
	
	// Create an informer for MultiWAN CRDs
	informer := factory.ForResource(gvr).Informer()
	
	// Create a controller
	controller := &MultiWANController{
		dynamicClient: dynamicClient,
		wanManager:    wanManager,
		informer:      informer,
		queue:         workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:        make(chan struct{}),
	}
	
	// Add event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueMultiWAN,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			
			// Skip if the objects are the same
			if reflect.DeepEqual(oldObj.GetSpec(), newObj.GetSpec()) {
				return
			}
			
			controller.enqueueMultiWAN(newObj)
		},
		DeleteFunc: controller.enqueueMultiWAN,
	})
	
	return controller
}

// Run starts the controller
func (c *MultiWANController) Run(workers int) {
	defer c.queue.ShutDown()
	
	klog.Info("Starting MultiWAN controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		klog.Error("Failed to sync informer cache")
		return
	}
	
	klog.Info("MultiWAN controller synced and ready")
	
	// Start workers
	for i := 0; i < workers; i++ {
		go c.runWorker()
	}
	
	// Wait for stop signal
	<-c.stopCh
	klog.Info("Stopping MultiWAN controller")
}

// Stop stops the controller
func (c *MultiWANController) Stop() {
	close(c.stopCh)
}

// runWorker runs a worker thread
func (c *MultiWANController) runWorker() {
	for c.processNextItem() {
	}
}

// enqueueMultiWAN adds a MultiWAN to the queue
func (c *MultiWANController) enqueueMultiWAN(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	
	c.queue.Add(key)
}

// processNextItem processes the next item in the queue
func (c *MultiWANController) processNextItem() bool {
	// Get the next item
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcileMultiWAN(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about this key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error reconciling MultiWAN %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("Requeuing MultiWAN %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		klog.Infof("Dropping MultiWAN %s from queue after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
	}
	
	return true
}

// reconcileMultiWAN reconciles a MultiWAN CRD
func (c *MultiWANController) reconcileMultiWAN(key string) error {
	// Get the MultiWAN object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("error getting MultiWAN %s from cache: %w", key, err)
	}
	
	// If the object has been deleted, remove the configuration
	if !exists {
		return c.handleMultiWANDelete(key)
	}
	
	// Otherwise, create or update the configuration
	return c.handleMultiWANCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleMultiWANDelete handles deletion of a MultiWAN CRD
func (c *MultiWANController) handleMultiWANDelete(key string) error {
	// Extract namespace and name from the key
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key: %s", key)
	}
	
	klog.Infof("Handling deletion of MultiWAN %s/%s", namespace, name)
	
	// Remove the configuration
	if err := c.wanManager.RemoveConfiguration(name); err != nil {
		return fmt.Errorf("failed to remove MultiWAN configuration: %w", err)
	}
	
	klog.Infof("MultiWAN %s/%s removed", namespace, name)
	return nil
}

// handleMultiWANCreateOrUpdate handles creation or update of a MultiWAN CRD
func (c *MultiWANController) handleMultiWANCreateOrUpdate(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	klog.Infof("Processing MultiWAN %s/%s", namespace, name)
	
	// Get the spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("spec not found in MultiWAN %s/%s: %w", namespace, name, err)
	}
	
	// Extract description
	description, _, _ := unstructured.NestedString(spec, "description")
	
	// Extract WAN interfaces
	wanInterfacesUntyped, found, err := unstructured.NestedSlice(spec, "wanInterfaces")
	if err != nil || !found {
		return fmt.Errorf("wanInterfaces not found in MultiWAN %s/%s: %w", namespace, name, err)
	}
	
	// Convert WAN interfaces to typed objects
	wanInterfaces := make([]multiwan.WANInterface, 0, len(wanInterfacesUntyped))
	for _, wanUntyped := range wanInterfacesUntyped {
		wanMap, ok := wanUntyped.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid wanInterface format in MultiWAN %s/%s", namespace, name)
		}
		
		wanName, found, err := unstructured.NestedString(wanMap, "name")
		if err != nil || !found {
			return fmt.Errorf("name not found in wanInterface of MultiWAN %s/%s: %w", namespace, name, err)
		}
		
		interfaceName, found, err := unstructured.NestedString(wanMap, "interface")
		if err != nil || !found {
			return fmt.Errorf("interface not found in wanInterface of MultiWAN %s/%s: %w", namespace, name, err)
		}
		
		weight, found, err := unstructured.NestedInt64(wanMap, "weight")
		if err != nil || !found {
			weight = 100 // Default weight
		}
		
		priority, found, err := unstructured.NestedInt64(wanMap, "priority")
		if err != nil || !found {
			priority = 100 // Default priority
		}
		
		wanDescription, _, _ := unstructured.NestedString(wanMap, "description")
		
		gateway, found, err := unstructured.NestedString(wanMap, "gateway")
		if err != nil || !found {
			return fmt.Errorf("gateway not found in wanInterface of MultiWAN %s/%s: %w", namespace, name, err)
		}
		
		// Extract monitoring configuration
		monitoringMap, found, _ := unstructured.NestedMap(wanMap, "monitoring")
		var monitoring multiwan.WANMonitoring
		if found {
			// Extract targets
			targetsUntyped, found, _ := unstructured.NestedSlice(monitoringMap, "targets")
			if found {
				targets := make([]string, 0, len(targetsUntyped))
				for _, targetUntyped := range targetsUntyped {
					target, ok := targetUntyped.(string)
					if ok {
						targets = append(targets, target)
					}
				}
				monitoring.Targets = targets
			}
			
			// Extract method
			method, found, _ := unstructured.NestedString(monitoringMap, "method")
			if found {
				monitoring.Method = method
			} else {
				monitoring.Method = "ping" // Default method
			}
			
			// Extract interval
			interval, found, _ := unstructured.NestedInt64(monitoringMap, "interval")
			if found {
				monitoring.Interval = int(interval)
			} else {
				monitoring.Interval = 5 // Default interval
			}
			
			// Extract timeout
			timeout, found, _ := unstructured.NestedInt64(monitoringMap, "timeout")
			if found {
				monitoring.Timeout = int(timeout)
			} else {
				monitoring.Timeout = 1 // Default timeout
			}
			
			// Extract fail threshold
			failThreshold, found, _ := unstructured.NestedInt64(monitoringMap, "failThreshold")
			if found {
				monitoring.FailThreshold = int(failThreshold)
			} else {
				monitoring.FailThreshold = 3 // Default fail threshold
			}
			
			// Extract success threshold
			successThreshold, found, _ := unstructured.NestedInt64(monitoringMap, "successThreshold")
			if found {
				monitoring.SuccessThreshold = int(successThreshold)
			} else {
				monitoring.SuccessThreshold = 2 // Default success threshold
			}
		}
		
		wanInterfaces = append(wanInterfaces, multiwan.WANInterface{
			Name:        wanName,
			Interface:   interfaceName,
			Weight:      int(weight),
			Priority:    int(priority),
			Description: wanDescription,
			Gateway:     gateway,
			Monitoring:  monitoring,
		})
	}
	
	// Extract load balancing configuration
	loadBalancingMap, found, _ := unstructured.NestedMap(spec, "loadBalancing")
	var loadBalancing multiwan.LoadBalancing
	if found {
		// Extract enabled
		enabled, found, _ := unstructured.NestedBool(loadBalancingMap, "enabled")
		if found {
			loadBalancing.Enabled = enabled
		}
		
		// Extract method
		method, found, _ := unstructured.NestedString(loadBalancingMap, "method")
		if found {
			loadBalancing.Method = method
		} else {
			loadBalancing.Method = "weighted" // Default method
		}
		
		// Extract sticky
		sticky, found, _ := unstructured.NestedBool(loadBalancingMap, "sticky")
		if found {
			loadBalancing.Sticky = sticky
		}
		
		// Extract sticky timeout
		stickyTimeout, found, _ := unstructured.NestedInt64(loadBalancingMap, "stickyTimeout")
		if found {
			loadBalancing.StickyTimeout = int(stickyTimeout)
		} else {
			loadBalancing.StickyTimeout = 300 // Default sticky timeout
		}
	}
	
	// Extract failover configuration
	failoverMap, found, _ := unstructured.NestedMap(spec, "failover")
	var failover multiwan.Failover
	if found {
		// Extract enabled
		enabled, found, _ := unstructured.NestedBool(failoverMap, "enabled")
		if found {
			failover.Enabled = enabled
		} else {
			failover.Enabled = true // Default enabled
		}
		
		// Extract preempt
		preempt, found, _ := unstructured.NestedBool(failoverMap, "preempt")
		if found {
			failover.Preempt = preempt
		}
		
		// Extract preempt delay
		preemptDelay, found, _ := unstructured.NestedInt64(failoverMap, "preemptDelay")
		if found {
			failover.PreemptDelay = int(preemptDelay)
		} else {
			failover.PreemptDelay = 60 // Default preempt delay
		}
	}
	
	// Extract default route metric
	defaultRouteMetric, found, _ := unstructured.NestedInt64(spec, "defaultRouteMetric")
	if !found {
		defaultRouteMetric = 100 // Default metric
	}
	
	// Create MultiWAN configuration
	config := multiwan.Configuration{
		Name:              name,
		Namespace:         namespace,
		Description:       description,
		WANInterfaces:     wanInterfaces,
		LoadBalancing:     loadBalancing,
		Failover:          failover,
		DefaultRouteMetric: int(defaultRouteMetric),
	}
	
	// Apply the configuration
	if err := c.wanManager.ApplyConfiguration(config); err != nil {
		return fmt.Errorf("failed to apply MultiWAN configuration: %w", err)
	}
	
	// Update status
	if err := c.updateMultiWANStatus(obj); err != nil {
		return fmt.Errorf("failed to update MultiWAN status: %w", err)
	}
	
	klog.Infof("MultiWAN %s/%s applied", namespace, name)
	return nil
}

// updateMultiWANStatus updates the status of a MultiWAN CRD
func (c *MultiWANController) updateMultiWANStatus(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	
	// Get the MultiWAN status
	status, err := c.wanManager.GetStatus(name)
	if err != nil {
		return fmt.Errorf("failed to get MultiWAN status: %w", err)
	}
	
	// Create a copy of the object
	newObj := obj.DeepCopy()
	
	// Update active WANs
	activeWANsUntyped := make([]interface{}, 0, len(status.ActiveWANs))
	for _, wan := range status.ActiveWANs {
		wanMap := map[string]interface{}{
			"name":       wan.Name,
			"state":      wan.State,
			"rtt":        wan.RTT,
			"packetLoss": wan.PacketLoss,
		}
		activeWANsUntyped = append(activeWANsUntyped, wanMap)
	}
	
	if err := unstructured.SetNestedSlice(newObj.Object, activeWANsUntyped, "status", "activeWANs"); err != nil {
		return fmt.Errorf("failed to set status.activeWANs: %w", err)
	}
	
	// Update current primary
	if err := unstructured.SetNestedField(newObj.Object, status.CurrentPrimary, "status", "currentPrimary"); err != nil {
		return fmt.Errorf("failed to set status.currentPrimary: %w", err)
	}
	
	// Update last state change
	if err := unstructured.SetNestedField(newObj.Object, status.LastStateChange, "status", "lastStateChange"); err != nil {
		return fmt.Errorf("failed to set status.lastStateChange: %w", err)
	}
	
	// Update the object
	gvr := schema.GroupVersionResource{
		Group:    "network.fos1.io",
		Version:  "v1alpha1",
		Resource: "multiwans",
	}
	
	_, err = c.dynamicClient.Resource(gvr).Namespace(namespace).UpdateStatus(context.Background(), newObj, nil)
	if err != nil {
		return fmt.Errorf("failed to update MultiWAN status: %w", err)
	}
	
	return nil
}
