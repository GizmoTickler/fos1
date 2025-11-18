package controllers

import (
	"context"
	"fmt"
	"time"
	"reflect"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

const (
	// NetworkInterfaceResyncPeriod is the resync period for the network interface controller
	NetworkInterfaceResyncPeriod = 30 * time.Second
	
	// NetworkInterfaceResource is the resource name for the NetworkInterface CRD
	NetworkInterfaceResource = "networkinterfaces.network.fos1.io"
)

// NetworkInterfaceController watches for NetworkInterface CRDs and translates them to Cilium configurations
type NetworkInterfaceController struct {
	// dynamicClient is the client for interacting with CRDs
	dynamicClient dynamic.Interface
	
	// networkController is the controller for managing Cilium network configuration
	networkController *cilium.NetworkController
	
	// informer is the informer for NetworkInterface CRDs
	informer cache.SharedIndexInformer
	
	// queue is the workqueue for NetworkInterface events
	queue workqueue.RateLimitingInterface
	
	// stopCh is used to signal the informer to stop
	stopCh chan struct{}
}

// NewNetworkInterfaceController creates a new controller for NetworkInterface CRDs
func NewNetworkInterfaceController(
	dynamicClient dynamic.Interface,
	networkController *cilium.NetworkController,
) *NetworkInterfaceController {
	// Create a GVR for NetworkInterface CRDs
	gvr := schema.GroupVersionResource{
		Group:    "network.fos1.io",
		Version:  "v1alpha1",
		Resource: "networkinterfaces",
	}
	
	// Create a dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, NetworkInterfaceResyncPeriod)
	
	// Create an informer for NetworkInterface CRDs
	informer := factory.ForResource(gvr).Informer()
	
	// Create a controller
	controller := &NetworkInterfaceController{
		dynamicClient:     dynamicClient,
		networkController: networkController,
		informer:          informer,
		queue:             workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:            make(chan struct{}),
	}
	
	// Add event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueNetworkInterface,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			
			// Skip if the objects are the same
			if reflect.DeepEqual(oldObj.GetSpec(), newObj.GetSpec()) {
				return
			}
			
			controller.enqueueNetworkInterface(newObj)
		},
		DeleteFunc: controller.enqueueNetworkInterface,
	})
	
	return controller
}

// Start starts the controller
func (c *NetworkInterfaceController) Start(ctx context.Context) error {
	klog.Info("Starting NetworkInterface controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		return fmt.Errorf("timed out waiting for NetworkInterface informer cache to sync")
	}
	
	// Start workers to process items from the queue
	for i := 0; i < 2; i++ {
		go wait.Until(c.runWorker, time.Second, c.stopCh)
	}
	
	<-ctx.Done()
	return nil
}

// Stop stops the controller
func (c *NetworkInterfaceController) Stop() {
	klog.Info("Stopping NetworkInterface controller")
	close(c.stopCh)
	c.queue.ShutDown()
}

// runWorker is a long-running function that processes items from the work queue
func (c *NetworkInterfaceController) runWorker() {
	for c.processNextItem() {
		// Continue processing items until the queue is empty
	}
}

// processNextItem processes a single item from the work queue
func (c *NetworkInterfaceController) processNextItem() bool {
	// Get the next item from the queue
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcileNetworkInterface(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about this key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error reconciling NetworkInterface %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("Requeuing NetworkInterface %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		klog.Infof("Dropping NetworkInterface %s from queue after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
	}
	
	return true
}

// enqueueNetworkInterface adds a NetworkInterface object to the work queue
func (c *NetworkInterfaceController) enqueueNetworkInterface(obj interface{}) {
	// Convert the object to a key
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Error creating key for object: %v", err)
		return
	}
	
	// Add the key to the queue
	c.queue.Add(key)
}

// reconcileNetworkInterface reconciles a NetworkInterface CRD
func (c *NetworkInterfaceController) reconcileNetworkInterface(key string) error {
	// Get the NetworkInterface object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("error getting NetworkInterface %s from cache: %w", key, err)
	}
	
	// If the object has been deleted, delete the corresponding Cilium configuration
	if !exists {
		return c.handleNetworkInterfaceDelete(key)
	}
	
	// Otherwise, create or update the Cilium configuration
	return c.handleNetworkInterfaceCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleNetworkInterfaceDelete handles deletion of a NetworkInterface CRD
func (c *NetworkInterfaceController) handleNetworkInterfaceDelete(key string) error {
	// The NetworkInterface has been deleted, so remove any Cilium configuration
	
	// In a real implementation, we would identify and delete the corresponding Cilium resources
	
	klog.Infof("NetworkInterface %s deleted", key)
	return nil
}

// handleNetworkInterfaceCreateOrUpdate handles creation or update of a NetworkInterface CRD
func (c *NetworkInterfaceController) handleNetworkInterfaceCreateOrUpdate(obj *unstructured.Unstructured) error {
	// Get the NetworkInterface spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("error getting spec from NetworkInterface: %v", err)
	}
	
	// Get the type of the interface
	interfaceType, found, err := unstructured.NestedString(spec, "type")
	if err != nil || !found {
		return fmt.Errorf("error getting interface type from NetworkInterface: %v", err)
	}
	
	// Get the name of the interface
	name, found, err := unstructured.NestedString(spec, "name")
	if err != nil || !found {
		return fmt.Errorf("error getting name from NetworkInterface: %v", err)
	}
	
	// Handle different interface types
	switch interfaceType {
	case "physical":
		return c.handlePhysicalInterface(name, spec)
	case "vlan":
		return c.handleVLANInterface(name, spec)
	case "bridge":
		return c.handleBridgeInterface(name, spec)
	case "bond":
		return c.handleBondInterface(name, spec)
	default:
		return fmt.Errorf("unsupported interface type: %s", interfaceType)
	}
}

// handlePhysicalInterface handles a physical network interface
func (c *NetworkInterfaceController) handlePhysicalInterface(name string, spec map[string]interface{}) error {
	// Get the device name
	device, found, err := unstructured.NestedString(spec, "device")
	if err != nil || !found {
		return fmt.Errorf("error getting device from NetworkInterface: %v", err)
	}
	
	// In a real implementation, we would create Cilium policies for this physical interface
	// For example, configuring Cilium to manage traffic on this interface
	
	klog.Infof("Configuring physical interface %s (device: %s) with Cilium", name, device)
	return nil
}

// handleVLANInterface handles a VLAN network interface
func (c *NetworkInterfaceController) handleVLANInterface(name string, spec map[string]interface{}) error {
	// Get the parent interface
	parent, found, err := unstructured.NestedString(spec, "parent")
	if err != nil || !found {
		return fmt.Errorf("error getting parent from VLAN interface: %v", err)
	}
	
	// Get the VLAN ID
	vlanIDFloat, found, err := unstructured.NestedFloat64(spec, "vlanId")
	if err != nil || !found {
		return fmt.Errorf("error getting VLAN ID from VLAN interface: %v", err)
	}
	vlanID := uint16(vlanIDFloat)
	
	// In a real implementation, we would create Cilium configuration for this VLAN interface
	// This might involve applying labels to identify traffic for this VLAN
	
	klog.Infof("Configuring VLAN interface %s (parent: %s, ID: %d) with Cilium", name, parent, vlanID)
	return nil
}

// handleBridgeInterface handles a bridge network interface
func (c *NetworkInterfaceController) handleBridgeInterface(name string, spec map[string]interface{}) error {
	// Get the member interfaces
	bridge, found, err := unstructured.NestedMap(spec, "bridge")
	if err != nil || !found {
		return fmt.Errorf("error getting bridge config from interface: %v", err)
	}
	
	interfaces, found, err := unstructured.NestedStringSlice(bridge, "interfaces")
	if err != nil || !found {
		return fmt.Errorf("error getting interfaces from bridge: %v", err)
	}
	
	// In a real implementation, we would create Cilium configuration for this bridge interface
	// This might involve applying policies that allow traffic between the bridged interfaces
	
	klog.Infof("Configuring bridge interface %s with interfaces %v with Cilium", name, interfaces)
	return nil
}

// handleBondInterface handles a bond network interface
func (c *NetworkInterfaceController) handleBondInterface(name string, spec map[string]interface{}) error {
	// Get the bond configuration
	bond, found, err := unstructured.NestedMap(spec, "bond")
	if err != nil || !found {
		return fmt.Errorf("error getting bond config from interface: %v", err)
	}
	
	// Get the member interfaces
	interfaces, found, err := unstructured.NestedStringSlice(bond, "interfaces")
	if err != nil || !found {
		return fmt.Errorf("error getting interfaces from bond: %v", err)
	}
	
	// Get the bond mode
	mode, found, err := unstructured.NestedString(bond, "mode")
	if err != nil || !found {
		return fmt.Errorf("error getting mode from bond: %v", err)
	}
	
	// In a real implementation, we would create Cilium configuration for this bond interface
	// This might involve applying policies that handle traffic from bonded interfaces
	
	klog.Infof("Configuring bond interface %s (mode: %s, interfaces: %v) with Cilium", name, mode, interfaces)
	return nil
}
