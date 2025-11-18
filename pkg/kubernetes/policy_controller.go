package kubernetes

import (
	"context"
	"fmt"
	"log"
	"time"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumclientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"

	"github.com/GizmoTickler/fos1/pkg/security/dpi"
)

// PolicyController manages Cilium network policies based on DPI events
type PolicyController struct {
	client  *Client
	cilium  ciliumclientset.Interface
	manager *dpi.DPIManager
	queue   workqueue.RateLimitingInterface
}

// NewPolicyController creates a new policy controller
func NewPolicyController(client *Client, manager *dpi.DPIManager) *PolicyController {
	// Create Cilium clientset
	ciliumClient, err := ciliumclientset.NewForConfig(client.Config)
	if err != nil {
		log.Fatalf("Failed to create Cilium clientset: %v", err)
	}

	controller := &PolicyController{
		client:  client,
		cilium:  ciliumClient,
		manager: manager,
		queue:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "dpi-policies"),
	}

	// Register event handler to queue policy creation/updates
	manager.RegisterEventHandler(func(event dpi.DPIEvent) {
		if event.EventType == "alert" && event.Severity >= 3 {
			// High severity alerts trigger policy creation
			controller.queue.Add(event)
		}
	})

	return controller
}

// Run starts the policy controller
func (c *PolicyController) Run(ctx context.Context) {
	defer c.queue.ShutDown()

	log.Println("Starting policy controller")

	// Start workers to process the queue
	go wait.UntilWithContext(ctx, c.runWorker, time.Second)

	<-ctx.Done()
	log.Println("Shutting down policy controller")
}

// runWorker processes items from the queue
func (c *PolicyController) runWorker(ctx context.Context) {
	for c.processNextItem(ctx) {
	}
}

// processNextItem processes the next item from the queue
func (c *PolicyController) processNextItem(ctx context.Context) bool {
	// Get the next item from the queue
	obj, shutdown := c.queue.Get()
	if shutdown {
		return false
	}

	// Process the item
	err := func(obj interface{}) error {
		defer c.queue.Done(obj)

		// Type assertion
		event, ok := obj.(dpi.DPIEvent)
		if !ok {
			c.queue.Forget(obj)
			return fmt.Errorf("expected DPIEvent in queue but got %#v", obj)
		}

		// Process the event
		if err := c.createCiliumPolicy(ctx, event); err != nil {
			c.queue.AddRateLimited(obj)
			return fmt.Errorf("error processing event: %w", err)
		}

		c.queue.Forget(obj)
		return nil
	}(obj)

	if err != nil {
		log.Printf("Error processing item: %v", err)
	}

	return true
}

// createCiliumPolicy creates a Cilium network policy based on a DPI event
func (c *PolicyController) createCiliumPolicy(ctx context.Context, event dpi.DPIEvent) error {
	// Get namespace from environment or use default
	namespace := "default"
	if ns := os.Getenv("KUBERNETES_NAMESPACE"); ns != "" {
		namespace = ns
	}

	// Create policy name
	policyName := fmt.Sprintf("dpi-block-%s-%s", event.EventType, normalizeString(event.Signature))

	// Create Cilium network policy
	policy := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyName,
			Namespace: namespace,
			Labels: map[string]string{
				"app":       "dpi",
				"event":     event.EventType,
				"signature": normalizeString(event.Signature),
				"severity":  fmt.Sprintf("%d", event.Severity),
			},
		},
		Spec: &ciliumv2.NetworkPolicySpec{},
	}

	// Add ingress rules if source IP is available
	if event.SourceIP != "" {
		policy.Spec.Ingress = []ciliumv2.IngressRule{
			{
				FromCIDR: []ciliumv2.CIDR{
					ciliumv2.CIDR(event.SourceIP + "/32"),
				},
			},
		}
	}

	// Add egress rules if destination IP is available
	if event.DestIP != "" {
		policy.Spec.Egress = []ciliumv2.EgressRule{
			{
				ToCIDR: []ciliumv2.CIDR{
					ciliumv2.CIDR(event.DestIP + "/32"),
				},
			},
		}
	}

	// Create or update the policy
	_, err := c.cilium.CiliumV2().CiliumNetworkPolicies(namespace).Create(
		ctx, policy, metav1.CreateOptions{},
	)
	if err != nil {
		// If policy already exists, update it
		if k8serrors.IsAlreadyExists(err) {
			_, err = c.cilium.CiliumV2().CiliumNetworkPolicies(namespace).Update(
				ctx, policy, metav1.UpdateOptions{},
			)
			if err != nil {
				return fmt.Errorf("failed to update Cilium policy: %w", err)
			}
			log.Printf("Updated Cilium policy %s for %s", policyName, event.Signature)
			return nil
		}
		return fmt.Errorf("failed to create Cilium policy: %w", err)
	}

	log.Printf("Created Cilium policy %s for %s", policyName, event.Signature)
	return nil
}

// normalizeString normalizes a string for use in policy names
func normalizeString(s string) string {
	// Replace spaces and special characters with hyphens
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	
	// Convert to lowercase
	s = strings.ToLower(s)
	
	return s
}
