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

	"github.com/varuntirumala1/fos1/pkg/network/nat"
)

const (
	// NATResyncPeriod is the resync period for NAT informers
	NATResyncPeriod = 10 * time.Minute
)

// NATController watches for EBPFNATPolicy CRDs and configures NAT accordingly
type NATController struct {
	// dynamicClient is the client for interacting with CRDs
	dynamicClient dynamic.Interface
	
	// natManager is used to manage NAT configurations
	natManager nat.Manager
	
	// informer is the informer for EBPFNATPolicy CRDs
	informer cache.SharedIndexInformer
	
	// queue is the workqueue for EBPFNATPolicy events
	queue workqueue.RateLimitingInterface
	
	// stopCh is used to signal the informer to stop
	stopCh chan struct{}
}

// NewNATController creates a new controller for EBPFNATPolicy CRDs
func NewNATController(
	dynamicClient dynamic.Interface,
	natManager nat.Manager,
) *NATController {
	// Create a GVR for EBPFNATPolicy CRDs
	gvr := schema.GroupVersionResource{
		Group:    "networking.fos1.io",
		Version:  "v1alpha1",
		Resource: "ebpfnatpolicies",
	}
	
	// Create a dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, NATResyncPeriod)
	
	// Create an informer for EBPFNATPolicy CRDs
	informer := factory.ForResource(gvr).Informer()
	
	// Create a controller
	controller := &NATController{
		dynamicClient: dynamicClient,
		natManager:    natManager,
		informer:      informer,
		queue:         workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:        make(chan struct{}),
	}
	
	// Add event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueNATPolicy,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			
			// Skip if the objects are the same
			if reflect.DeepEqual(oldObj.GetSpec(), newObj.GetSpec()) {
				return
			}
			
			controller.enqueueNATPolicy(newObj)
		},
		DeleteFunc: controller.enqueueNATPolicy,
	})
	
	return controller
}

// Run starts the controller
func (c *NATController) Run(workers int) {
	defer c.queue.ShutDown()
	
	klog.Info("Starting NAT controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		klog.Error("Failed to sync informer cache")
		return
	}
	
	klog.Info("NAT controller synced and ready")
	
	// Start workers
	for i := 0; i < workers; i++ {
		go c.runWorker()
	}
	
	// Wait for stop signal
	<-c.stopCh
	klog.Info("Stopping NAT controller")
}

// Stop stops the controller
func (c *NATController) Stop() {
	close(c.stopCh)
}

// runWorker runs a worker thread
func (c *NATController) runWorker() {
	for c.processNextItem() {
	}
}

// enqueueNATPolicy adds a NATPolicy to the queue
func (c *NATController) enqueueNATPolicy(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	
	c.queue.Add(key)
}

// processNextItem processes the next item in the queue
func (c *NATController) processNextItem() bool {
	// Get the next item
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcileNATPolicy(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about this key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error reconciling NATPolicy %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("Requeuing NATPolicy %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		klog.Infof("Dropping NATPolicy %s from queue after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
	}
	
	return true
}

// reconcileNATPolicy reconciles a NATPolicy CRD
func (c *NATController) reconcileNATPolicy(key string) error {
	// Get the NATPolicy object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("error getting NATPolicy %s from cache: %w", key, err)
	}
	
	// If the object has been deleted, remove the NAT configuration
	if !exists {
		return c.handleNATPolicyDelete(key)
	}
	
	// Otherwise, create or update the NAT configuration
	return c.handleNATPolicyCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleNATPolicyDelete handles deletion of a NATPolicy CRD
func (c *NATController) handleNATPolicyDelete(key string) error {
	// Extract namespace and name from the key
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key: %s", key)
	}
	
	klog.Infof("Handling deletion of NATPolicy %s/%s", namespace, name)
	
	// Remove the NAT configuration
	if err := c.natManager.RemoveNATPolicy(name, namespace); err != nil {
		return fmt.Errorf("failed to remove NAT policy: %w", err)
	}
	
	klog.Infof("NAT policy %s/%s removed", namespace, name)
	return nil
}

// handleNATPolicyCreateOrUpdate handles creation or update of a NATPolicy CRD
func (c *NATController) handleNATPolicyCreateOrUpdate(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	klog.Infof("Processing NATPolicy %s/%s", namespace, name)
	
	// Get the spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("spec not found in NATPolicy %s/%s: %w", namespace, name, err)
	}
	
	// Extract NAT type
	natType, found, err := unstructured.NestedString(spec, "type")
	if err != nil || !found {
		return fmt.Errorf("type not found in NATPolicy %s/%s: %w", namespace, name, err)
	}
	
	// Extract interface
	iface, found, err := unstructured.NestedString(spec, "interface")
	if err != nil || !found {
		return fmt.Errorf("interface not found in NATPolicy %s/%s: %w", namespace, name, err)
	}
	
	// Create NAT configuration based on type
	var config nat.Config
	
	switch natType {
	case "snat":
		config, err = c.extractSNATConfig(spec, name, namespace, iface)
	case "dnat":
		config, err = c.extractDNATConfig(spec, name, namespace, iface)
	case "masquerade":
		config, err = c.extractMasqueradeConfig(spec, name, namespace, iface)
	case "full":
		config, err = c.extractFullNATConfig(spec, name, namespace, iface)
	default:
		return fmt.Errorf("unsupported NAT type: %s", natType)
	}
	
	if err != nil {
		return fmt.Errorf("failed to extract NAT configuration: %w", err)
	}
	
	// Apply the NAT configuration
	if err := c.natManager.ApplyNATPolicy(config); err != nil {
		return fmt.Errorf("failed to apply NAT policy: %w", err)
	}
	
	// Update status
	if err := c.updateNATPolicyStatus(obj); err != nil {
		return fmt.Errorf("failed to update NATPolicy status: %w", err)
	}
	
	klog.Infof("NAT policy %s/%s applied", namespace, name)
	return nil
}

// extractSNATConfig extracts SNAT configuration from the spec
func (c *NATController) extractSNATConfig(spec map[string]interface{}, name, namespace, iface string) (nat.Config, error) {
	// Extract external IP
	externalIP, found, err := unstructured.NestedString(spec, "externalIP")
	if err != nil || !found {
		return nat.Config{}, fmt.Errorf("externalIP not found in SNAT policy: %w", err)
	}
	
	// Extract source addresses
	sourceAddressesUntyped, found, err := unstructured.NestedSlice(spec, "sourceAddresses")
	if err != nil {
		return nat.Config{}, fmt.Errorf("error getting sourceAddresses: %w", err)
	}
	
	sourceAddresses := make([]string, 0, len(sourceAddressesUntyped))
	for _, addrUntyped := range sourceAddressesUntyped {
		addr, ok := addrUntyped.(string)
		if !ok {
			return nat.Config{}, fmt.Errorf("invalid sourceAddress format")
		}
		sourceAddresses = append(sourceAddresses, addr)
	}
	
	// Extract enable tracking
	enableTracking, _, _ := unstructured.NestedBool(spec, "enableTracking")
	
	// Create SNAT configuration
	config := nat.Config{
		Name:            name,
		Namespace:       namespace,
		Type:            nat.TypeSNAT,
		Interface:       iface,
		ExternalIP:      externalIP,
		SourceAddresses: sourceAddresses,
		EnableTracking:  enableTracking,
	}
	
	return config, nil
}

// extractDNATConfig extracts DNAT configuration from the spec
func (c *NATController) extractDNATConfig(spec map[string]interface{}, name, namespace, iface string) (nat.Config, error) {
	// Extract external IP
	externalIP, found, err := unstructured.NestedString(spec, "externalIP")
	if err != nil || !found {
		return nat.Config{}, fmt.Errorf("externalIP not found in DNAT policy: %w", err)
	}
	
	// Extract port mappings
	portMappingsUntyped, found, err := unstructured.NestedSlice(spec, "portMappings")
	if err != nil {
		return nat.Config{}, fmt.Errorf("error getting portMappings: %w", err)
	}
	
	portMappings := make([]nat.PortMapping, 0, len(portMappingsUntyped))
	for _, mappingUntyped := range portMappingsUntyped {
		mappingMap, ok := mappingUntyped.(map[string]interface{})
		if !ok {
			return nat.Config{}, fmt.Errorf("invalid portMapping format")
		}
		
		protocol, found, err := unstructured.NestedString(mappingMap, "protocol")
		if err != nil || !found {
			return nat.Config{}, fmt.Errorf("protocol not found in portMapping: %w", err)
		}
		
		externalPort, found, err := unstructured.NestedInt64(mappingMap, "externalPort")
		if err != nil || !found {
			return nat.Config{}, fmt.Errorf("externalPort not found in portMapping: %w", err)
		}
		
		internalIP, found, err := unstructured.NestedString(mappingMap, "internalIP")
		if err != nil || !found {
			return nat.Config{}, fmt.Errorf("internalIP not found in portMapping: %w", err)
		}
		
		internalPort, found, err := unstructured.NestedInt64(mappingMap, "internalPort")
		if err != nil || !found {
			return nat.Config{}, fmt.Errorf("internalPort not found in portMapping: %w", err)
		}
		
		description, _, _ := unstructured.NestedString(mappingMap, "description")
		
		portMappings = append(portMappings, nat.PortMapping{
			Protocol:     protocol,
			ExternalPort: int(externalPort),
			InternalIP:   internalIP,
			InternalPort: int(internalPort),
			Description:  description,
		})
	}
	
	// Extract enable tracking
	enableTracking, _, _ := unstructured.NestedBool(spec, "enableTracking")
	
	// Create DNAT configuration
	config := nat.Config{
		Name:           name,
		Namespace:      namespace,
		Type:           nat.TypeDNAT,
		Interface:      iface,
		ExternalIP:     externalIP,
		PortMappings:   portMappings,
		EnableTracking: enableTracking,
	}
	
	return config, nil
}

// extractMasqueradeConfig extracts masquerade configuration from the spec
func (c *NATController) extractMasqueradeConfig(spec map[string]interface{}, name, namespace, iface string) (nat.Config, error) {
	// Extract source addresses
	sourceAddressesUntyped, found, err := unstructured.NestedSlice(spec, "sourceAddresses")
	if err != nil {
		return nat.Config{}, fmt.Errorf("error getting sourceAddresses: %w", err)
	}
	
	sourceAddresses := make([]string, 0, len(sourceAddressesUntyped))
	for _, addrUntyped := range sourceAddressesUntyped {
		addr, ok := addrUntyped.(string)
		if !ok {
			return nat.Config{}, fmt.Errorf("invalid sourceAddress format")
		}
		sourceAddresses = append(sourceAddresses, addr)
	}
	
	// Extract enable tracking
	enableTracking, _, _ := unstructured.NestedBool(spec, "enableTracking")
	
	// Create masquerade configuration
	config := nat.Config{
		Name:            name,
		Namespace:       namespace,
		Type:            nat.TypeMasquerade,
		Interface:       iface,
		SourceAddresses: sourceAddresses,
		EnableTracking:  enableTracking,
	}
	
	return config, nil
}

// extractFullNATConfig extracts full NAT configuration from the spec
func (c *NATController) extractFullNATConfig(spec map[string]interface{}, name, namespace, iface string) (nat.Config, error) {
	// Extract external IP
	externalIP, found, err := unstructured.NestedString(spec, "externalIP")
	if err != nil || !found {
		return nat.Config{}, fmt.Errorf("externalIP not found in full NAT policy: %w", err)
	}
	
	// Extract source addresses
	sourceAddressesUntyped, found, err := unstructured.NestedSlice(spec, "sourceAddresses")
	if err != nil {
		return nat.Config{}, fmt.Errorf("error getting sourceAddresses: %w", err)
	}
	
	sourceAddresses := make([]string, 0, len(sourceAddressesUntyped))
	for _, addrUntyped := range sourceAddressesUntyped {
		addr, ok := addrUntyped.(string)
		if !ok {
			return nat.Config{}, fmt.Errorf("invalid sourceAddress format")
		}
		sourceAddresses = append(sourceAddresses, addr)
	}
	
	// Extract port mappings
	portMappingsUntyped, found, err := unstructured.NestedSlice(spec, "portMappings")
	if err != nil {
		return nat.Config{}, fmt.Errorf("error getting portMappings: %w", err)
	}
	
	portMappings := make([]nat.PortMapping, 0, len(portMappingsUntyped))
	for _, mappingUntyped := range portMappingsUntyped {
		mappingMap, ok := mappingUntyped.(map[string]interface{})
		if !ok {
			return nat.Config{}, fmt.Errorf("invalid portMapping format")
		}
		
		protocol, found, err := unstructured.NestedString(mappingMap, "protocol")
		if err != nil || !found {
			return nat.Config{}, fmt.Errorf("protocol not found in portMapping: %w", err)
		}
		
		externalPort, found, err := unstructured.NestedInt64(mappingMap, "externalPort")
		if err != nil || !found {
			return nat.Config{}, fmt.Errorf("externalPort not found in portMapping: %w", err)
		}
		
		internalIP, found, err := unstructured.NestedString(mappingMap, "internalIP")
		if err != nil || !found {
			return nat.Config{}, fmt.Errorf("internalIP not found in portMapping: %w", err)
		}
		
		internalPort, found, err := unstructured.NestedInt64(mappingMap, "internalPort")
		if err != nil || !found {
			return nat.Config{}, fmt.Errorf("internalPort not found in portMapping: %w", err)
		}
		
		description, _, _ := unstructured.NestedString(mappingMap, "description")
		
		portMappings = append(portMappings, nat.PortMapping{
			Protocol:     protocol,
			ExternalPort: int(externalPort),
			InternalIP:   internalIP,
			InternalPort: int(internalPort),
			Description:  description,
		})
	}
	
	// Extract enable tracking
	enableTracking, _, _ := unstructured.NestedBool(spec, "enableTracking")
	
	// Create full NAT configuration
	config := nat.Config{
		Name:            name,
		Namespace:       namespace,
		Type:            nat.TypeFull,
		Interface:       iface,
		ExternalIP:      externalIP,
		SourceAddresses: sourceAddresses,
		PortMappings:    portMappings,
		EnableTracking:  enableTracking,
	}
	
	return config, nil
}

// updateNATPolicyStatus updates the status of a NATPolicy CRD
func (c *NATController) updateNATPolicyStatus(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	
	// Get the NAT policy status
	status, err := c.natManager.GetNATPolicyStatus(name, namespace)
	if err != nil {
		return fmt.Errorf("failed to get NAT policy status: %w", err)
	}
	
	// Create a copy of the object
	newObj := obj.DeepCopy()
	
	// Update the status
	if err := unstructured.SetNestedField(newObj.Object, status.ActiveConnections, "status", "activeConnections"); err != nil {
		return fmt.Errorf("failed to set status.activeConnections: %w", err)
	}
	
	// Update metrics
	metrics := map[string]interface{}{
		"packets":      status.Metrics.Packets,
		"bytes":        status.Metrics.Bytes,
		"translations": status.Metrics.Translations,
	}
	
	if err := unstructured.SetNestedMap(newObj.Object, metrics, "status", "metrics"); err != nil {
		return fmt.Errorf("failed to set status.metrics: %w", err)
	}
	
	// Update conditions
	conditions := make([]interface{}, 0, len(status.Conditions))
	for _, condition := range status.Conditions {
		conditionMap := map[string]interface{}{
			"type":               condition.Type,
			"status":             condition.Status,
			"lastTransitionTime": condition.LastTransitionTime.Format(time.RFC3339),
			"reason":             condition.Reason,
			"message":            condition.Message,
		}
		
		conditions = append(conditions, conditionMap)
	}
	
	if err := unstructured.SetNestedSlice(newObj.Object, conditions, "status", "conditions"); err != nil {
		return fmt.Errorf("failed to set status.conditions: %w", err)
	}
	
	// Update the object
	gvr := schema.GroupVersionResource{
		Group:    "networking.fos1.io",
		Version:  "v1alpha1",
		Resource: "ebpfnatpolicies",
	}
	
	_, err = c.dynamicClient.Resource(gvr).Namespace(namespace).UpdateStatus(context.Background(), newObj, nil)
	if err != nil {
		return fmt.Errorf("failed to update NATPolicy status: %w", err)
	}
	
	return nil
}
