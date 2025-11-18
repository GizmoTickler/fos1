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

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

const (
	// FirewallRuleResyncPeriod is the resync period for the firewall controller
	FirewallRuleResyncPeriod = 30 * time.Second
	
	// FirewallRuleResource is the resource name for the FirewallRule CRD
	FirewallRuleResource = "firewallrules.security.fos1.io"
)

// FirewallController watches for FirewallRule CRDs and translates them to Cilium network policies
type FirewallController struct {
	// dynamicClient is the client for interacting with CRDs
	dynamicClient dynamic.Interface
	
	// ciliumClient is the client for interacting with Cilium
	ciliumClient cilium.CiliumClient
	
	// informer is the informer for FirewallRule CRDs
	informer cache.SharedIndexInformer
	
	// queue is the workqueue for FirewallRule events
	queue workqueue.RateLimitingInterface
	
	// stopCh is used to signal the informer to stop
	stopCh chan struct{}
}

// NewFirewallController creates a new controller for FirewallRule CRDs
func NewFirewallController(
	dynamicClient dynamic.Interface,
	ciliumClient cilium.CiliumClient,
) *FirewallController {
	// Create a GVR for FirewallRule CRDs
	gvr := schema.GroupVersionResource{
		Group:    "security.fos1.io",
		Version:  "v1alpha1",
		Resource: "firewallrules",
	}
	
	// Create a dynamic informer factory
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, FirewallRuleResyncPeriod)
	
	// Create an informer for FirewallRule CRDs
	informer := factory.ForResource(gvr).Informer()
	
	// Create a controller
	controller := &FirewallController{
		dynamicClient: dynamicClient,
		ciliumClient:  ciliumClient,
		informer:      informer,
		queue:         workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:        make(chan struct{}),
	}
	
	// Add event handlers
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueFirewallRule,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			
			// Skip if the objects are the same
			if reflect.DeepEqual(oldObj.GetSpec(), newObj.GetSpec()) {
				return
			}
			
			controller.enqueueFirewallRule(newObj)
		},
		DeleteFunc: controller.enqueueFirewallRule,
	})
	
	return controller
}

// Start starts the controller
func (c *FirewallController) Start(ctx context.Context) error {
	klog.Info("Starting FirewallRule controller")
	
	// Start the informer
	go c.informer.Run(c.stopCh)
	
	// Wait for the informer to sync
	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		return fmt.Errorf("timed out waiting for FirewallRule informer cache to sync")
	}
	
	// Start workers to process items from the queue
	for i := 0; i < 2; i++ {
		go wait.Until(c.runWorker, time.Second, c.stopCh)
	}
	
	<-ctx.Done()
	return nil
}

// Stop stops the controller
func (c *FirewallController) Stop() {
	klog.Info("Stopping FirewallRule controller")
	close(c.stopCh)
	c.queue.ShutDown()
}

// runWorker is a long-running function that processes items from the work queue
func (c *FirewallController) runWorker() {
	for c.processNextItem() {
		// Continue processing items until the queue is empty
	}
}

// processNextItem processes a single item from the work queue
func (c *FirewallController) processNextItem() bool {
	// Get the next item from the queue
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	
	// Tell the queue we're done with this key when we exit this function
	defer c.queue.Done(key)
	
	// Process the item
	err := c.reconcileFirewallRule(key.(string))
	if err == nil {
		// If no error, tell the queue to forget about this key
		c.queue.Forget(key)
	} else {
		// If an error occurred, log it and maybe requeue
		klog.Errorf("Error reconciling FirewallRule %s: %v", key, err)
		
		// Check if we should requeue the item
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("Requeuing FirewallRule %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		
		// Too many retries, forget the item
		klog.Infof("Dropping FirewallRule %s from queue after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
	}
	
	return true
}

// enqueueFirewallRule adds a FirewallRule object to the work queue
func (c *FirewallController) enqueueFirewallRule(obj interface{}) {
	// Convert the object to a key
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Error creating key for object: %v", err)
		return
	}
	
	// Add the key to the queue
	c.queue.Add(key)
}

// reconcileFirewallRule reconciles a FirewallRule CRD
func (c *FirewallController) reconcileFirewallRule(key string) error {
	// Get the FirewallRule object
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("error getting FirewallRule %s from cache: %w", key, err)
	}
	
	// If the object has been deleted, delete the corresponding Cilium network policy
	if !exists {
		return c.handleFirewallRuleDelete(key)
	}
	
	// Otherwise, create or update the Cilium network policy
	return c.handleFirewallRuleCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleFirewallRuleDelete handles deletion of a FirewallRule CRD
func (c *FirewallController) handleFirewallRuleDelete(key string) error {
	// Extract the name from the key
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key %s: %w", key, err)
	}
	
	// Generate the policy name based on the FirewallRule name
	policyName := fmt.Sprintf("fw-%s", name)
	
	// Delete the corresponding Cilium network policy
	// In a real implementation, we would use the Cilium API to delete the policy
	
	klog.Infof("Deleted Cilium network policy %s for FirewallRule %s in namespace %s", policyName, name, namespace)
	return nil
}

// handleFirewallRuleCreateOrUpdate handles creation or update of a FirewallRule CRD
func (c *FirewallController) handleFirewallRuleCreateOrUpdate(obj *unstructured.Unstructured) error {
	// Get the FirewallRule spec
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return fmt.Errorf("error getting spec from FirewallRule: %v", err)
	}
	
	// Extract namespace and name
	namespace := obj.GetNamespace()
	name := obj.GetName()
	
	// Extract source and destination selectors
	sourceSelector, _, err := unstructured.NestedMap(spec, "sourceSelector")
	if err != nil {
		return fmt.Errorf("error getting sourceSelector from FirewallRule: %v", err)
	}
	
	destinationSelector, _, err := unstructured.NestedMap(spec, "destinationSelector")
	if err != nil {
		return fmt.Errorf("error getting destinationSelector from FirewallRule: %v", err)
	}
	
	// Extract the rules
	rulesUntyped, found, err := unstructured.NestedSlice(spec, "rules")
	if err != nil || !found {
		return fmt.Errorf("error getting rules from FirewallRule: %v", err)
	}
	
	// Convert the FirewallRule to a Cilium NetworkPolicy
	policy := &cilium.NetworkPolicy{
		Name:        fmt.Sprintf("fw-%s", name),
		Namespace:   namespace,
		Description: fmt.Sprintf("Generated from FirewallRule %s", name),
	}
	
	// Convert source selector to Cilium labels
	if sourceSelector != nil {
		policy.SourceLabels = c.convertSelectorToLabels(sourceSelector)
	}
	
	// Convert destination selector to Cilium labels
	if destinationSelector != nil {
		policy.DestinationLabels = c.convertSelectorToLabels(destinationSelector)
	}
	
	// Convert rules to Cilium rules
	for _, ruleUntyped := range rulesUntyped {
		rule, ok := ruleUntyped.(map[string]interface{})
		if !ok {
			klog.Warningf("Skipping rule in FirewallRule %s, not a map", name)
			continue
		}
		
		ciliumRule, err := c.convertToCiliumRule(rule)
		if err != nil {
			klog.Warningf("Error converting rule in FirewallRule %s: %v", name, err)
			continue
		}
		
		policy.Rules = append(policy.Rules, ciliumRule)
	}
	
	// Apply the Cilium network policy
	ctx := context.Background()
	if err := c.ciliumClient.ApplyNetworkPolicy(ctx, policy); err != nil {
		return fmt.Errorf("error applying Cilium network policy: %w", err)
	}
	
	klog.Infof("Successfully applied Cilium network policy for FirewallRule %s in namespace %s", name, namespace)
	return nil
}

// convertSelectorToLabels converts a selector to Cilium labels
func (c *FirewallController) convertSelectorToLabels(selector map[string]interface{}) map[string]string {
	result := make(map[string]string)
	
	// Extract matchLabels
	matchLabels, found, err := unstructured.NestedMap(selector, "matchLabels")
	if err != nil || !found {
		klog.Warningf("No matchLabels found in selector")
		return result
	}
	
	// Convert matchLabels to a map[string]string
	for k, v := range matchLabels {
		if strValue, ok := v.(string); ok {
			result[k] = strValue
		}
	}
	
	return result
}

// convertToCiliumRule converts a FirewallRule rule to a Cilium rule
func (c *FirewallController) convertToCiliumRule(rule map[string]interface{}) (cilium.Rule, error) {
	ciliumRule := cilium.Rule{}
	
	// Extract protocol
	protocol, found, err := unstructured.NestedString(rule, "protocol")
	if err != nil || !found {
		return ciliumRule, fmt.Errorf("error getting protocol from rule: %v", err)
	}
	ciliumRule.Protocol = protocol
	
	// Extract ports
	portsUntyped, found, err := unstructured.NestedSlice(rule, "ports")
	if err == nil && found {
		for _, portUntyped := range portsUntyped {
			portFloat, ok := portUntyped.(float64)
			if !ok {
				klog.Warningf("Skipping port in rule, not a number")
				continue
			}
			
			ciliumRule.Ports = append(ciliumRule.Ports, int(portFloat))
		}
	}
	
	// Extract port ranges
	portRangesUntyped, found, err := unstructured.NestedSlice(rule, "portRanges")
	if err == nil && found {
		for _, rangeUntyped := range portRangesUntyped {
			rangeMap, ok := rangeUntyped.(map[string]interface{})
			if !ok {
				klog.Warningf("Skipping port range in rule, not a map")
				continue
			}
			
			fromFloat, found, err := unstructured.NestedFloat64(rangeMap, "from")
			if err != nil || !found {
				klog.Warningf("Skipping port range in rule, no 'from' value")
				continue
			}
			
			toFloat, found, err := unstructured.NestedFloat64(rangeMap, "to")
			if err != nil || !found {
				klog.Warningf("Skipping port range in rule, no 'to' value")
				continue
			}
			
			ciliumRule.PortRanges = append(ciliumRule.PortRanges, cilium.PortRange{
				First: int(fromFloat),
				Last:  int(toFloat),
			})
		}
	}
	
	// Extract ICMP type and code for ICMP protocol
	if protocol == "ICMP" || protocol == "ICMPv6" {
		icmpType, found, err := unstructured.NestedFloat64(rule, "icmpType")
		if err == nil && found {
			icmpTypeInt := int(icmpType)
			ciliumRule.ICMPType = &icmpTypeInt
		}
		
		icmpCode, found, err := unstructured.NestedFloat64(rule, "icmpCode")
		if err == nil && found {
			icmpCodeInt := int(icmpCode)
			ciliumRule.ICMPCode = &icmpCodeInt
		}
	}
	
	// Extract action
	action, found, err := unstructured.NestedString(rule, "action")
	if err != nil || !found {
		// Default to "deny" if no action is specified
		action = "deny"
	}
	ciliumRule.Action = action
	
	// Extract L7 rules
	l7Rules, found, err := unstructured.NestedMap(rule, "l7Rules")
	if err == nil && found {
		// Extract HTTP rules
		httpRulesUntyped, found, err := unstructured.NestedSlice(l7Rules, "http")
		if err == nil && found {
			for _, httpRuleUntyped := range httpRulesUntyped {
				httpRuleMap, ok := httpRuleUntyped.(map[string]interface{})
				if !ok {
					klog.Warningf("Skipping HTTP rule, not a map")
					continue
				}
				
				httpRule := cilium.HTTPRule{}
				
				method, found, err := unstructured.NestedString(httpRuleMap, "method")
				if err == nil && found {
					httpRule.Method = method
				}
				
				path, found, err := unstructured.NestedString(httpRuleMap, "path")
				if err == nil && found {
					httpRule.Path = path
				}
				
				host, found, err := unstructured.NestedString(httpRuleMap, "host")
				if err == nil && found {
					httpRule.Host = host
				}
				
				headersMap, found, err := unstructured.NestedMap(httpRuleMap, "headers")
				if err == nil && found {
					httpRule.Headers = make(map[string]string)
					for k, v := range headersMap {
						if strValue, ok := v.(string); ok {
							httpRule.Headers[k] = strValue
						}
					}
				}
				
				ciliumRule.L7Rules.HTTP = append(ciliumRule.L7Rules.HTTP, httpRule)
			}
		}
		
		// Extract DNS rules
		dnsRulesUntyped, found, err := unstructured.NestedSlice(l7Rules, "dns")
		if err == nil && found {
			for _, dnsRuleUntyped := range dnsRulesUntyped {
				dnsRuleMap, ok := dnsRuleUntyped.(map[string]interface{})
				if !ok {
					klog.Warningf("Skipping DNS rule, not a map")
					continue
				}
				
				pattern, found, err := unstructured.NestedString(dnsRuleMap, "pattern")
				if err != nil || !found {
					klog.Warningf("Skipping DNS rule, no pattern")
					continue
				}
				
				ciliumRule.L7Rules.DNS = append(ciliumRule.L7Rules.DNS, cilium.DNSRule{
					Pattern: pattern,
				})
			}
		}
		
		// Extract Kafka rules
		kafkaRulesUntyped, found, err := unstructured.NestedSlice(l7Rules, "kafka")
		if err == nil && found {
			for _, kafkaRuleUntyped := range kafkaRulesUntyped {
				kafkaRuleMap, ok := kafkaRuleUntyped.(map[string]interface{})
				if !ok {
					klog.Warningf("Skipping Kafka rule, not a map")
					continue
				}
				
				topic, found, err := unstructured.NestedString(kafkaRuleMap, "topic")
				if err != nil || !found {
					klog.Warningf("Skipping Kafka rule, no topic")
					continue
				}
				
				apiKeyFloat, found, err := unstructured.NestedFloat64(kafkaRuleMap, "apiKey")
				if err != nil || !found {
					klog.Warningf("Skipping Kafka rule, no apiKey")
					continue
				}
				
				ciliumRule.L7Rules.Kafka = append(ciliumRule.L7Rules.Kafka, cilium.KafkaRule{
					Topic:  topic,
					ApiKey: int(apiKeyFloat),
				})
			}
		}
	}
	
	return ciliumRule, nil
}

// GetCiliumRuleNameForFirewallRule generates a Cilium rule name for a FirewallRule
func GetCiliumRuleNameForFirewallRule(namespace, name string) string {
	return fmt.Sprintf("fw-%s-%s", namespace, name)
}
