package kubernetes

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
)

// PolicyController manages network policies based on DPI events
type PolicyController struct {
	client  *Client
	queue   workqueue.RateLimitingInterface
	eventHandler func(DPIEvent)
}

// NewPolicyController creates a new policy controller
func NewPolicyController(client *Client) *PolicyController {
	controller := &PolicyController{
		client:  client,
		queue:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "dpi-policies"),
	}

	// Set up the event handler function
	controller.eventHandler = func(event DPIEvent) {
		if event.EventType == "alert" && event.Severity >= 3 {
			// High severity alerts trigger policy creation
			controller.queue.Add(event)
		}
	}

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
		event, ok := obj.(DPIEvent)
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

// createCiliumPolicy creates a network policy based on a DPI event
func (c *PolicyController) createCiliumPolicy(ctx context.Context, event DPIEvent) error {
	// Get namespace from environment or use default
	namespace := "default"
	if ns := os.Getenv("KUBERNETES_NAMESPACE"); ns != "" {
		namespace = ns
	}

	// Create policy name
	policyName := fmt.Sprintf("dpi-block-%s-%s", event.EventType, normalizeString(event.Signature))

	// Log the policy creation
	log.Printf("Would create policy %s in namespace %s for event: %s",
		policyName, namespace, event.Description)
	log.Printf("Source IP: %s, Destination IP: %s", event.SourceIP, event.DestIP)

	// In a real implementation, we would create the policy here
	// For now, just log the intent

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

// HandleDPIEvent handles a DPI event
func (c *PolicyController) HandleDPIEvent(event DPIEvent) {
	// Call the event handler function
	if c.eventHandler != nil {
		c.eventHandler(event)
	}
}
