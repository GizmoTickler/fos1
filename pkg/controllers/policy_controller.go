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
	"github.com/GizmoTickler/fos1/pkg/network/routing/policy"
)

const (
	// PolicyResyncPeriod is the resync period for policy informers
	PolicyResyncPeriod = 10 * time.Minute
)

// PolicyController watches for RoutingPolicy CRDs and configures policy-based routing accordingly
type PolicyController struct {
	// dynamicClient is the client for interacting with CRDs
	dynamicClient dynamic.Interface
	
	// policyManager is used to manage routing policies
	policyManager policy.Manager
	
	// informer is the informer for RoutingPolicy CRDs
	informer cache.SharedIndexInformer
	
	// queue is the workqueue for RoutingPolicy events
	queue workqueue.RateLimitingInterface
	
	// stopCh is used to signal the informer to stop
	stopCh chan struct{}
}

// NewPolicyController creates a new controller for RoutingPolicy CRDs
func NewPolicyController(
	dynamicClient dynamic.Interface,
	policyManager policy.Manager,
) *PolicyController {
	// Create a GVR for RoutingPolicy CRDs
	gvr := schema.GroupVersionResource{
		Group:    "network.fos1.io",
		Version:  "v1alpha1",
		Resource: "routingpolicies",
	}
	
	// Create a dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, PolicyResyncPeriod)
	
	// Create an informer for RoutingPolicy CRDs
	informer := factory.ForResource(gvr).Informer()
	
	// Create a controller
	controller := &PolicyController{
		dynamicClient: dynamicClient,
		policyManager: policyManager,
		informer:      informer,
		queue:         workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:        make(chan struct{}),
	}
	
	// Add event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueuePolicy,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			
			// Skip if the objects are the same
			if reflect.DeepEqual(oldObj.GetSpec(), newObj.GetSpec()) {
				return
			}
			
			controller.enqueuePolicy(newObj)
		},
		DeleteFunc: controller.enqueuePolicy,
	})
	
	return controller
}

// Run starts the controller
func (c *PolicyController) Run(workers int) {
	defer c.queue.ShutDown()
	
	klog.Info("Starting policy controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		klog.Error("Failed to sync informer cache")
		return
	}
	
	klog.Info("Policy controller synced and ready")
	
	// Start workers
	for i := 0; i < workers; i++ {
		go c.runWorker()
	}
	
	// Wait for stop signal
	<-c.stopCh
	klog.Info("Stopping policy controller")
}

// Stop stops the controller
func (c *PolicyController) Stop() {
	close(c.stopCh)
}

// runWorker runs a worker thread
func (c *PolicyController) runWorker() {
	for c.processNextItem() {
	}
}

// enqueuePolicy adds a RoutingPolicy to the queue
func (c *PolicyController) enqueuePolicy(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	
	c.queue.Add(key)
}

// processNextItem processes the next item in the queue
func (c *PolicyController) processNextItem() bool {
	// Get the next item
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcilePolicy(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about this key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error reconciling RoutingPolicy %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("Requeuing RoutingPolicy %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		klog.Infof("Dropping RoutingPolicy %s from queue after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
	}
	
	return true
}

// reconcilePolicy reconciles a RoutingPolicy CRD
func (c *PolicyController) reconcilePolicy(key string) error {
	// Get the RoutingPolicy object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("error getting RoutingPolicy %s from cache: %w", key, err)
	}
	
	// If the object has been deleted, remove the policy
	if !exists {
		return c.handlePolicyDelete(key)
	}
	
	// Otherwise, create or update the policy
	return c.handlePolicyCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handlePolicyDelete handles deletion of a RoutingPolicy CRD
func (c *PolicyController) handlePolicyDelete(key string) error {
	// Extract namespace and name from the key
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key: %s", key)
	}
	
	klog.Infof("Handling deletion of RoutingPolicy %s/%s", namespace, name)
	
	// Remove the policy
	if err := c.policyManager.RemovePolicy(name, namespace); err != nil {
		return fmt.Errorf("failed to remove policy: %w", err)
	}
	
	klog.Infof("RoutingPolicy %s/%s removed", namespace, name)
	return nil
}

// handlePolicyCreateOrUpdate handles creation or update of a RoutingPolicy CRD
func (c *PolicyController) handlePolicyCreateOrUpdate(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	klog.Infof("Processing RoutingPolicy %s/%s", namespace, name)
	
	// Get the spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("spec not found in RoutingPolicy %s/%s: %w", namespace, name, err)
	}
	
	// Extract description
	description, _, _ := unstructured.NestedString(spec, "description")
	
	// Extract priority
	priority, found, err := unstructured.NestedInt64(spec, "priority")
	if err != nil || !found {
		return fmt.Errorf("priority not found in RoutingPolicy %s/%s: %w", namespace, name, err)
	}
	
	// Extract match criteria
	matchMap, found, err := unstructured.NestedMap(spec, "match")
	if err != nil || !found {
		return fmt.Errorf("match not found in RoutingPolicy %s/%s: %w", namespace, name, err)
	}
	
	// Extract source match
	sourceMap, found, _ := unstructured.NestedMap(matchMap, "source")
	var sourceMatch policy.SourceMatch
	if found {
		// Extract source networks
		networksUntyped, found, _ := unstructured.NestedSlice(sourceMap, "networks")
		if found {
			networks := make([]string, 0, len(networksUntyped))
			for _, networkUntyped := range networksUntyped {
				network, ok := networkUntyped.(string)
				if ok {
					networks = append(networks, network)
				}
			}
			sourceMatch.Networks = networks
		}
		
		// Extract source interfaces
		interfacesUntyped, found, _ := unstructured.NestedSlice(sourceMap, "interfaces")
		if found {
			interfaces := make([]string, 0, len(interfacesUntyped))
			for _, interfaceUntyped := range interfacesUntyped {
				iface, ok := interfaceUntyped.(string)
				if ok {
					interfaces = append(interfaces, iface)
				}
			}
			sourceMatch.Interfaces = interfaces
		}
	}
	
	// Extract destination match
	destMap, found, _ := unstructured.NestedMap(matchMap, "destination")
	var destMatch policy.DestinationMatch
	if found {
		// Extract destination networks
		networksUntyped, found, _ := unstructured.NestedSlice(destMap, "networks")
		if found {
			networks := make([]string, 0, len(networksUntyped))
			for _, networkUntyped := range networksUntyped {
				network, ok := networkUntyped.(string)
				if ok {
					networks = append(networks, network)
				}
			}
			destMatch.Networks = networks
		}
	}
	
	// Extract protocol
	protocol, _, _ := unstructured.NestedString(matchMap, "protocol")
	
	// Extract ports
	portsUntyped, found, _ := unstructured.NestedSlice(matchMap, "ports")
	var ports []policy.PortRange
	if found {
		ports = make([]policy.PortRange, 0, len(portsUntyped))
		for _, portUntyped := range portsUntyped {
			portMap, ok := portUntyped.(map[string]interface{})
			if !ok {
				continue
			}
			
			start, found, _ := unstructured.NestedInt64(portMap, "start")
			if !found {
				continue
			}
			
			end, found, _ := unstructured.NestedInt64(portMap, "end")
			if !found {
				end = start
			}
			
			ports = append(ports, policy.PortRange{
				Start: int(start),
				End:   int(end),
			})
		}
	}
	
	// Extract applications
	applicationsUntyped, found, _ := unstructured.NestedSlice(matchMap, "applications")
	var applications []string
	if found {
		applications = make([]string, 0, len(applicationsUntyped))
		for _, appUntyped := range applicationsUntyped {
			app, ok := appUntyped.(string)
			if ok {
				applications = append(applications, app)
			}
		}
	}
	
	// Extract traffic types
	trafficTypesUntyped, found, _ := unstructured.NestedSlice(matchMap, "trafficType")
	var trafficTypes []string
	if found {
		trafficTypes = make([]string, 0, len(trafficTypesUntyped))
		for _, typeUntyped := range trafficTypesUntyped {
			trafficType, ok := typeUntyped.(string)
			if ok {
				trafficTypes = append(trafficTypes, trafficType)
			}
		}
	}
	
	// Extract time match
	timeMap, found, _ := unstructured.NestedMap(matchMap, "time")
	var timeMatch policy.TimeMatch
	if found {
		// Extract days of week
		daysUntyped, found, _ := unstructured.NestedSlice(timeMap, "daysOfWeek")
		if found {
			days := make([]string, 0, len(daysUntyped))
			for _, dayUntyped := range daysUntyped {
				day, ok := dayUntyped.(string)
				if ok {
					days = append(days, day)
				}
			}
			timeMatch.DaysOfWeek = days
		}
		
		// Extract time of day
		timeOfDayUntyped, found, _ := unstructured.NestedSlice(timeMap, "timeOfDay")
		if found {
			timeOfDay := make([]policy.TimeOfDay, 0, len(timeOfDayUntyped))
			for _, todUntyped := range timeOfDayUntyped {
				todMap, ok := todUntyped.(map[string]interface{})
				if !ok {
					continue
				}
				
				start, found, _ := unstructured.NestedString(todMap, "start")
				if !found {
					continue
				}
				
				end, found, _ := unstructured.NestedString(todMap, "end")
				if !found {
					continue
				}
				
				timeOfDay = append(timeOfDay, policy.TimeOfDay{
					Start: start,
					End:   end,
				})
			}
			timeMatch.TimeOfDay = timeOfDay
		}
	}
	
	// Extract action
	actionMap, found, err := unstructured.NestedMap(spec, "action")
	if err != nil || !found {
		return fmt.Errorf("action not found in RoutingPolicy %s/%s: %w", namespace, name, err)
	}
	
	// Extract action type
	actionType, found, err := unstructured.NestedString(actionMap, "type")
	if err != nil || !found {
		return fmt.Errorf("action type not found in RoutingPolicy %s/%s: %w", namespace, name, err)
	}
	
	// Extract next hop
	nextHop, _, _ := unstructured.NestedString(actionMap, "nextHop")
	
	// Extract table
	table, _, _ := unstructured.NestedString(actionMap, "table")
	
	// Extract mark
	mark, _, _ := unstructured.NestedInt64(actionMap, "mark")
	
	// Extract DSCP
	dscp, _, _ := unstructured.NestedInt64(actionMap, "dscp")
	
	// Extract VRF
	vrf, _, _ := unstructured.NestedString(spec, "vrf")
	if vrf == "" {
		vrf = "main"
	}
	
	// Create policy match
	policyMatch := policy.PolicyMatch{
		Source:       sourceMatch,
		Destination:  destMatch,
		Protocol:     protocol,
		Ports:        ports,
		Applications: applications,
		TrafficType:  trafficTypes,
		Time:         timeMatch,
	}
	
	// Create policy action
	policyAction := policy.PolicyAction{
		Type:    actionType,
		NextHop: nextHop,
		Table:   table,
		Mark:    int(mark),
		DSCP:    int(dscp),
	}
	
	// Create routing policy
	routingPolicy := policy.RoutingPolicy{
		Name:        name,
		Namespace:   namespace,
		Description: description,
		Priority:    int(priority),
		Match:       policyMatch,
		Action:      policyAction,
		VRF:         vrf,
	}
	
	// Apply the policy
	if err := c.policyManager.ApplyPolicy(routingPolicy); err != nil {
		return fmt.Errorf("failed to apply policy: %w", err)
	}
	
	// Update status
	if err := c.updatePolicyStatus(obj); err != nil {
		return fmt.Errorf("failed to update RoutingPolicy status: %w", err)
	}
	
	klog.Infof("RoutingPolicy %s/%s applied", namespace, name)
	return nil
}

// updatePolicyStatus updates the status of a RoutingPolicy CRD
func (c *PolicyController) updatePolicyStatus(obj *unstructured.Unstructured) error {
	// Get the namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	
	// Get the policy status
	status, err := c.policyManager.GetPolicyStatus(name, namespace)
	if err != nil {
		return fmt.Errorf("failed to get policy status: %w", err)
	}
	
	// Create a copy of the object
	newObj := obj.DeepCopy()
	
	// Update the status
	if err := unstructured.SetNestedField(newObj.Object, status.Active, "status", "active"); err != nil {
		return fmt.Errorf("failed to set status.active: %w", err)
	}
	
	if err := unstructured.SetNestedField(newObj.Object, status.MatchCount, "status", "matchCount"); err != nil {
		return fmt.Errorf("failed to set status.matchCount: %w", err)
	}
	
	if err := unstructured.SetNestedField(newObj.Object, status.LastMatched.Format(time.RFC3339), "status", "lastMatched"); err != nil {
		return fmt.Errorf("failed to set status.lastMatched: %w", err)
	}
	
	// Update the object
	gvr := schema.GroupVersionResource{
		Group:    "network.fos1.io",
		Version:  "v1alpha1",
		Resource: "routingpolicies",
	}
	
	_, err = c.dynamicClient.Resource(gvr).Namespace(namespace).UpdateStatus(context.Background(), newObj, nil)
	if err != nil {
		return fmt.Errorf("failed to update RoutingPolicy status: %w", err)
	}
	
	return nil
}
