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

	"github.com/GizmoTickler/fos1/pkg/security/qos"
	"github.com/GizmoTickler/fos1/pkg/traffic"
)

const (
	// QoSResyncPeriod is the resync period for QoS informers
	QoSResyncPeriod = 10 * time.Minute
)

// QoSController watches for QoSProfile CRDs and configures traffic management accordingly
type QoSController struct {
	// dynamicClient is the client for interacting with CRDs
	dynamicClient dynamic.Interface
	
	// qosManager is used to manage QoS profiles
	qosManager *qos.QoSManager
	
	// trafficManager is used to manage traffic
	trafficManager traffic.Manager
	
	// informer is the informer for QoSProfile CRDs
	informer cache.SharedIndexInformer
	
	// queue is the workqueue for QoSProfile events
	queue workqueue.RateLimitingInterface
	
	// stopCh is used to signal the informer to stop
	stopCh chan struct{}
}

// NewQoSController creates a new controller for QoSProfile CRDs
func NewQoSController(
	dynamicClient dynamic.Interface,
	qosManager *qos.QoSManager,
	trafficManager traffic.Manager,
) *QoSController {
	// Create a GVR for QoSProfile CRDs
	gvr := schema.GroupVersionResource{
		Group:    "network.fos1.io",
		Version:  "v1alpha1",
		Resource: "qosprofiles",
	}
	
	// Create a dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, QoSResyncPeriod)
	
	// Create an informer for QoSProfile CRDs
	informer := factory.ForResource(gvr).Informer()
	
	// Create a controller
	controller := &QoSController{
		dynamicClient:  dynamicClient,
		qosManager:     qosManager,
		trafficManager: trafficManager,
		informer:       informer,
		queue:          workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:         make(chan struct{}),
	}
	
	// Add event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueQoSProfile,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			
			// Skip if the objects are the same
			if reflect.DeepEqual(oldObj.GetSpec(), newObj.GetSpec()) {
				return
			}
			
			controller.enqueueQoSProfile(newObj)
		},
		DeleteFunc: controller.enqueueQoSProfile,
	})
	
	return controller
}

// Run starts the controller
func (c *QoSController) Run(workers int) {
	defer c.queue.ShutDown()
	
	klog.Info("Starting QoS controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		klog.Error("Failed to sync informer cache")
		return
	}
	
	klog.Info("QoS controller synced and ready")
	
	// Start workers
	for i := 0; i < workers; i++ {
		go c.runWorker()
	}
	
	// Wait for stop signal
	<-c.stopCh
	klog.Info("Stopping QoS controller")
}

// Stop stops the controller
func (c *QoSController) Stop() {
	close(c.stopCh)
}

// runWorker runs a worker thread
func (c *QoSController) runWorker() {
	for c.processNextItem() {
	}
}

// enqueueQoSProfile adds a QoSProfile to the queue
func (c *QoSController) enqueueQoSProfile(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	
	c.queue.Add(key)
}

// processNextItem processes the next item in the queue
func (c *QoSController) processNextItem() bool {
	// Get the next item
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcileQoSProfile(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about this key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error reconciling QoSProfile %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("Requeuing QoSProfile %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		klog.Infof("Dropping QoSProfile %s from queue after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
	}
	
	return true
}

// reconcileQoSProfile reconciles a QoSProfile CRD
func (c *QoSController) reconcileQoSProfile(key string) error {
	// Get the QoSProfile object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("error getting QoSProfile %s from cache: %w", key, err)
	}
	
	// If the object has been deleted, remove the QoS profile
	if !exists {
		return c.handleQoSProfileDelete(key)
	}
	
	// Otherwise, create or update the QoS profile
	return c.handleQoSProfileCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleQoSProfileDelete handles deletion of a QoSProfile CRD
func (c *QoSController) handleQoSProfileDelete(key string) error {
	// Extract namespace and name from the key
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key: %s", key)
	}
	
	klog.Infof("Handling deletion of QoSProfile %s/%s", namespace, name)
	
	// Get the interface name from the key
	// In a real implementation, we would store a mapping of QoSProfile names to interface names
	// For now, we'll assume the name is the interface name
	interfaceName := name
	
	// Delete the QoS profile
	if err := c.qosManager.DeleteProfile(interfaceName); err != nil {
		return fmt.Errorf("failed to delete QoS profile: %w", err)
	}
	
	// Delete the traffic configuration
	if err := c.trafficManager.DeleteConfiguration(interfaceName); err != nil {
		return fmt.Errorf("failed to delete traffic configuration: %w", err)
	}
	
	klog.Infof("QoSProfile %s/%s removed", namespace, name)
	return nil
}

// handleQoSProfileCreateOrUpdate handles creation or update of a QoSProfile CRD
func (c *QoSController) handleQoSProfileCreateOrUpdate(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	klog.Infof("Processing QoSProfile %s/%s", namespace, name)
	
	// Get the spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("spec not found in QoSProfile %s/%s: %w", namespace, name, err)
	}
	
	// Extract interface
	interfaceName, found, err := unstructured.NestedString(spec, "interface")
	if err != nil || !found {
		return fmt.Errorf("interface not found in QoSProfile %s/%s: %w", namespace, name, err)
	}
	
	// Extract upload bandwidth
	uploadBandwidth, found, err := unstructured.NestedString(spec, "uploadBandwidth")
	if err != nil || !found {
		return fmt.Errorf("uploadBandwidth not found in QoSProfile %s/%s: %w", namespace, name, err)
	}
	
	// Extract download bandwidth
	downloadBandwidth, found, err := unstructured.NestedString(spec, "downloadBandwidth")
	if err != nil || !found {
		return fmt.Errorf("downloadBandwidth not found in QoSProfile %s/%s: %w", namespace, name, err)
	}
	
	// Extract default class
	defaultClass, _, _ := unstructured.NestedString(spec, "defaultClass")
	
	// Extract classes
	classesUntyped, found, err := unstructured.NestedSlice(spec, "classes")
	if err != nil || !found {
		return fmt.Errorf("classes not found in QoSProfile %s/%s: %w", namespace, name, err)
	}
	
	// Convert classes to QoS traffic classes
	trafficClasses := make([]qos.TrafficClass, 0, len(classesUntyped))
	for _, classUntyped := range classesUntyped {
		classMap, ok := classUntyped.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid class format in QoSProfile %s/%s", namespace, name)
		}
		
		className, found, err := unstructured.NestedString(classMap, "name")
		if err != nil || !found {
			return fmt.Errorf("name not found in class of QoSProfile %s/%s: %w", namespace, name, err)
		}
		
		priority, found, err := unstructured.NestedInt64(classMap, "priority")
		if err != nil || !found {
			return fmt.Errorf("priority not found in class of QoSProfile %s/%s: %w", namespace, name, err)
		}
		
		minBandwidth, _, _ := unstructured.NestedString(classMap, "minBandwidth")
		maxBandwidth, _, _ := unstructured.NestedString(classMap, "maxBandwidth")
		burst, _, _ := unstructured.NestedString(classMap, "burst")
		
		dscp, _, _ := unstructured.NestedInt64(classMap, "dscp")
		
		// Extract applications
		applicationsUntyped, _, _ := unstructured.NestedSlice(classMap, "applications")
		applications := make([]string, 0, len(applicationsUntyped))
		for _, appUntyped := range applicationsUntyped {
			app, ok := appUntyped.(string)
			if ok {
				applications = append(applications, app)
			}
		}
		
		// Extract application categories
		categoriesUntyped, _, _ := unstructured.NestedSlice(classMap, "applicationCategories")
		categories := make([]string, 0, len(categoriesUntyped))
		for _, catUntyped := range categoriesUntyped {
			cat, ok := catUntyped.(string)
			if ok {
				categories = append(categories, cat)
			}
		}
		
		// Extract source addresses
		sourceAddressesUntyped, _, _ := unstructured.NestedSlice(classMap, "sourceAddresses")
		sourceAddresses := make([]string, 0, len(sourceAddressesUntyped))
		for _, addrUntyped := range sourceAddressesUntyped {
			addr, ok := addrUntyped.(string)
			if ok {
				sourceAddresses = append(sourceAddresses, addr)
			}
		}
		
		// Extract destination addresses
		destAddressesUntyped, _, _ := unstructured.NestedSlice(classMap, "destinationAddresses")
		destAddresses := make([]string, 0, len(destAddressesUntyped))
		for _, addrUntyped := range destAddressesUntyped {
			addr, ok := addrUntyped.(string)
			if ok {
				destAddresses = append(destAddresses, addr)
			}
		}
		
		sourcePort, _, _ := unstructured.NestedString(classMap, "sourcePort")
		destinationPort, _, _ := unstructured.NestedString(classMap, "destinationPort")
		protocol, _, _ := unstructured.NestedString(classMap, "protocol")
		
		trafficClasses = append(trafficClasses, qos.TrafficClass{
			Name:                 className,
			Priority:             int(priority),
			MinBandwidth:         minBandwidth,
			MaxBandwidth:         maxBandwidth,
			Burst:                burst,
			DSCP:                 int(dscp),
			Applications:         applications,
			ApplicationCategories: categories,
			SourceAddresses:      sourceAddresses,
			DestinationAddresses: destAddresses,
			SourcePort:           sourcePort,
			DestinationPort:      destinationPort,
			Protocol:             protocol,
		})
	}
	
	// Create QoS profile
	profile := &qos.QoSProfile{
		Interface:         interfaceName,
		UploadBandwidth:   uploadBandwidth,
		DownloadBandwidth: downloadBandwidth,
		DefaultClass:      defaultClass,
		Classes:           trafficClasses,
	}
	
	// Apply the QoS profile
	var profileErr error
	if existingProfile, err := c.qosManager.GetProfile(interfaceName); err != nil {
		// Profile doesn't exist, create it
		profileErr = c.qosManager.AddProfile(profile)
	} else {
		// Profile exists, update it
		profileErr = c.qosManager.UpdateProfile(profile)
	}
	
	if profileErr != nil {
		return fmt.Errorf("failed to apply QoS profile: %w", profileErr)
	}
	
	// Create traffic configuration
	trafficConfig := &traffic.Configuration{
		Interface:         interfaceName,
		UploadBandwidth:   uploadBandwidth,
		DownloadBandwidth: downloadBandwidth,
		DefaultClass:      defaultClass,
	}
	
	// Convert QoS traffic classes to traffic manager classes
	for _, class := range trafficClasses {
		trafficClass := traffic.Class{
			Name:                 class.Name,
			Priority:             class.Priority,
			MinBandwidth:         class.MinBandwidth,
			MaxBandwidth:         class.MaxBandwidth,
			Burst:                class.Burst,
			DSCP:                 class.DSCP,
			Applications:         class.Applications,
			ApplicationCategories: class.ApplicationCategories,
			SourceAddresses:      class.SourceAddresses,
			DestinationAddresses: class.DestinationAddresses,
			SourcePort:           class.SourcePort,
			DestinationPort:      class.DestinationPort,
			Protocol:             class.Protocol,
		}
		
		trafficConfig.Classes = append(trafficConfig.Classes, trafficClass)
	}
	
	// Apply the traffic configuration
	if err := c.trafficManager.ApplyConfiguration(trafficConfig); err != nil {
		return fmt.Errorf("failed to apply traffic configuration: %w", err)
	}
	
	// Update status
	if err := c.updateQoSProfileStatus(obj); err != nil {
		return fmt.Errorf("failed to update QoSProfile status: %w", err)
	}
	
	klog.Infof("QoSProfile %s/%s applied", namespace, name)
	return nil
}

// updateQoSProfileStatus updates the status of a QoSProfile CRD
func (c *QoSController) updateQoSProfileStatus(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	
	// Get the interface name from the spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("spec not found in QoSProfile %s/%s: %w", namespace, name, err)
	}
	
	interfaceName, found, err := unstructured.NestedString(spec, "interface")
	if err != nil || !found {
		return fmt.Errorf("interface not found in QoSProfile %s/%s: %w", namespace, name, err)
	}
	
	// Get the QoS profile
	profile, err := c.qosManager.GetProfile(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get QoS profile: %w", err)
	}
	
	// Create a copy of the object
	newObj := obj.DeepCopy()
	
	// Update the status
	status := make(map[string]interface{})
	status["actualUploadBandwidth"] = profile.UploadBandwidth
	status["actualDownloadBandwidth"] = profile.DownloadBandwidth
	
	// Update class statistics
	classStats := make(map[string]interface{})
	for _, class := range profile.Classes {
		stats, err := c.qosManager.GetClassStatistics(interfaceName, class.Name)
		if err != nil {
			continue
		}
		
		classStats[class.Name] = map[string]interface{}{
			"packets": stats.Packets,
			"bytes":   stats.Bytes,
			"drops":   stats.Drops,
		}
	}
	
	status["classStatistics"] = classStats
	status["lastUpdated"] = time.Now().Format(time.RFC3339)
	
	if err := unstructured.SetNestedMap(newObj.Object, status, "status"); err != nil {
		return fmt.Errorf("failed to set status: %w", err)
	}
	
	// Update the object
	gvr := schema.GroupVersionResource{
		Group:    "network.fos1.io",
		Version:  "v1alpha1",
		Resource: "qosprofiles",
	}
	
	_, err = c.dynamicClient.Resource(gvr).Namespace(namespace).UpdateStatus(context.Background(), newObj, nil)
	if err != nil {
		return fmt.Errorf("failed to update QoSProfile status: %w", err)
	}
	
	return nil
}
