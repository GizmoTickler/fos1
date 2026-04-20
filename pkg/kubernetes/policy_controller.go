package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumpolicyapi "github.com/cilium/cilium/pkg/policy/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
)

// PolicyController manages network policies based on DPI events
type PolicyController struct {
	client       *Client
	queue        workqueue.RateLimitingInterface
	eventHandler func(DPIEvent)
}

// NewPolicyController creates a new policy controller
func NewPolicyController(client *Client) *PolicyController {
	controller := &PolicyController{
		client: client,
		queue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "dpi-policies"),
	}

	// Set up the event handler function
	controller.eventHandler = func(event DPIEvent) {
		if event.EventType == "alert" && event.Severity >= 3 {
			// High severity alerts trigger policy creation
			eventCopy := event
			controller.queue.Add(&eventCopy)
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

		event, err := queuedDPIEvent(obj)
		if err != nil {
			c.queue.Forget(obj)
			return err
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
	if c.client == nil {
		return fmt.Errorf("kubernetes client is nil")
	}

	namespace := policyNamespace()
	policy, err := buildCiliumPolicy(namespace, event)
	if err != nil {
		return err
	}
	if err := c.client.ApplyCiliumNetworkPolicy(ctx, namespace, policy); err != nil {
		return fmt.Errorf("apply Cilium policy %s/%s: %w", namespace, policy.Name, err)
	}

	log.Printf("Applied Cilium policy %s in namespace %s for event: %s", policy.Name, namespace, event.Description)
	return nil
}

// normalizeString normalizes a string for use in policy names
func normalizeString(s string) string {
	var builder strings.Builder
	builder.Grow(len(s))

	lastHyphen := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			builder.WriteRune(r)
			lastHyphen = false
		case !lastHyphen:
			builder.WriteByte('-')
			lastHyphen = true
		}
	}

	return strings.Trim(builder.String(), "-")
}

// HandleDPIEvent handles a DPI event
func (c *PolicyController) HandleDPIEvent(event DPIEvent) {
	// Call the event handler function
	if c.eventHandler != nil {
		c.eventHandler(event)
	}
}

func queuedDPIEvent(obj interface{}) (DPIEvent, error) {
	switch event := obj.(type) {
	case DPIEvent:
		return event, nil
	case *DPIEvent:
		if event == nil {
			return DPIEvent{}, fmt.Errorf("expected non-nil *DPIEvent in queue")
		}
		return *event, nil
	default:
		return DPIEvent{}, fmt.Errorf("expected DPIEvent in queue but got %#v", obj)
	}
}

func policyNamespace() string {
	if ns := os.Getenv("KUBERNETES_NAMESPACE"); ns != "" {
		return ns
	}
	return "default"
}

func buildCiliumPolicy(namespace string, event DPIEvent) (*ciliumv2.CiliumNetworkPolicy, error) {
	sourceCIDR, err := eventSourceCIDR(event)
	if err != nil {
		return nil, err
	}

	name := policyNameForEvent(event)
	return &ciliumv2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"fos1.io/managed-by": "dpi-policy-controller",
				"fos1.io/event-type": labelValue(event.EventType),
				"fos1.io/severity":   labelValue(fmt.Sprintf("%d", event.Severity)),
				"fos1.io/signature":  labelValue(event.Signature),
			},
		},
		Spec: &ciliumpolicyapi.Rule{
			Description:      fmt.Sprintf("Auto-generated from DPI event: %s", event.Description),
			EndpointSelector: ciliumpolicyapi.WildcardEndpointSelector,
			IngressDeny: []ciliumpolicyapi.IngressDenyRule{{
				IngressCommonRule: ciliumpolicyapi.IngressCommonRule{
					FromCIDR: []ciliumpolicyapi.CIDR{ciliumpolicyapi.CIDR(sourceCIDR)},
				},
			}},
		},
	}, nil
}

func eventSourceCIDR(event DPIEvent) (string, error) {
	if event.SourceIP != "" {
		return ipOrCIDR(event.SourceIP)
	}
	if event.DestIP != "" {
		return ipOrCIDR(event.DestIP)
	}
	return "", fmt.Errorf("dpi event does not contain a source or destination IP")
}

func ipOrCIDR(value string) (string, error) {
	if strings.Contains(value, "/") {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return "", fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		return value, nil
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address %q", value)
	}
	if ip.To4() != nil {
		return value + "/32", nil
	}
	return value + "/128", nil
}

func policyNameForEvent(event DPIEvent) string {
	parts := []string{"dpi"}
	if value := normalizeString(event.EventType); value != "" {
		parts = append(parts, value)
	}
	if value := normalizeString(firstNonEmpty(event.Signature, event.Description, event.SessionID)); value != "" {
		parts = append(parts, value)
	}
	if value := normalizeString(firstNonEmpty(event.SourceIP, event.DestIP)); value != "" {
		parts = append(parts, value)
	}

	name := strings.Join(parts, "-")
	name = strings.Trim(name, "-")
	if name == "" {
		name = "dpi-event"
	}
	if len(name) <= 63 {
		return name
	}

	sum := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(sum[:])[:10]
	prefix := strings.Trim(name[:63-len(suffix)-1], "-")
	if prefix == "" {
		prefix = "dpi"
	}

	return prefix + "-" + suffix
}

func labelValue(value string) string {
	value = normalizeString(value)
	if value == "" {
		return "unknown"
	}
	if len(value) > 63 {
		return value[:63]
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
