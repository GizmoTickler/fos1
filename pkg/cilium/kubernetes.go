package cilium

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumclientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8s "github.com/GizmoTickler/fos1/pkg/kubernetes"
)

// KubernetesCiliumClient implements the CiliumClient interface using Kubernetes
type KubernetesCiliumClient struct {
	k8sClient *k8s.Client
	cilium    ciliumclientset.Interface
	namespace string
}

// NewKubernetesCiliumClient creates a new Kubernetes-based Cilium client
func NewKubernetesCiliumClient(client *k8s.Client) *KubernetesCiliumClient {
	// Create Cilium clientset
	ciliumClient, err := ciliumclientset.NewForConfig(client.Config)
	if err != nil {
		log.Fatalf("Failed to create Cilium clientset: %v", err)
	}

	// Get namespace from environment or use default
	namespace := "default"
	if ns := os.Getenv("KUBERNETES_NAMESPACE"); ns != "" {
		namespace = ns
	}

	return &KubernetesCiliumClient{
		k8sClient: client,
		cilium:    ciliumClient,
		namespace: namespace,
	}
}

// ConfigureDPIIntegration configures Cilium for DPI integration
func (c *KubernetesCiliumClient) ConfigureDPIIntegration(ctx context.Context, config *CiliumDPIIntegrationConfig) error {
	// In Kubernetes, this would typically be done through CRDs or ConfigMaps
	// For now, we'll just log the configuration
	log.Printf("Configuring Cilium DPI integration: %+v", config)
	return nil
}

// CreateNAT creates NAT rules using Cilium's capabilities
func (c *KubernetesCiliumClient) CreateNAT(ctx context.Context, config *CiliumNATConfig) error {
	log.Printf("Creating NAT rules: %+v", config)
	return nil
}

// RemoveNAT removes NAT rules
func (c *KubernetesCiliumClient) RemoveNAT(ctx context.Context, config *CiliumNATConfig) error {
	log.Printf("Removing NAT rules: %+v", config)
	return nil
}

// CreateNAT64 creates NAT64 rules
func (c *KubernetesCiliumClient) CreateNAT64(ctx context.Context, config *NAT64Config) error {
	log.Printf("Creating NAT64 rules: %+v", config)
	return nil
}

// RemoveNAT64 removes NAT64 rules
func (c *KubernetesCiliumClient) RemoveNAT64(ctx context.Context, config *NAT64Config) error {
	log.Printf("Removing NAT64 rules: %+v", config)
	return nil
}

// CreatePortForward creates port forwarding rules
func (c *KubernetesCiliumClient) CreatePortForward(ctx context.Context, config *PortForwardConfig) error {
	log.Printf("Creating port forward: %+v", config)
	return nil
}

// RemovePortForward removes port forwarding rules
func (c *KubernetesCiliumClient) RemovePortForward(ctx context.Context, config *PortForwardConfig) error {
	log.Printf("Removing port forward: %+v", config)
	return nil
}

// ConfigureVLANRouting configures routing between VLANs
func (c *KubernetesCiliumClient) ConfigureVLANRouting(ctx context.Context, config *CiliumVLANRoutingConfig) error {
	log.Printf("Configuring VLAN routing: %+v", config)
	return nil
}

// ApplyNetworkPolicy applies a network policy to Cilium
func (c *KubernetesCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *CiliumPolicy) error {
	// Convert our NetworkPolicy to a CiliumNetworkPolicy
	// Create a simplified CiliumNetworkPolicy
	ciliumPolicy := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.Name,
			Namespace: c.namespace,
			Labels:    policy.Labels,
		},
	}

	// Add rules
	// This is a simplified implementation - in a real implementation, we would
	// convert the rules to Cilium's format
	log.Printf("Converting %d rules to Cilium format", len(policy.Rules))

	// Note: We're now using a single Rules field for both ingress and egress

	// Create or update the policy
	_, err := c.cilium.CiliumV2().CiliumNetworkPolicies(c.namespace).Create(
		ctx, ciliumPolicy, metav1.CreateOptions{},
	)
	if err != nil {
		// If policy already exists, update it
		if k8serrors.IsAlreadyExists(err) {
			_, err = c.cilium.CiliumV2().CiliumNetworkPolicies(c.namespace).Update(
				ctx, ciliumPolicy, metav1.UpdateOptions{},
			)
			if err != nil {
				return fmt.Errorf("failed to update Cilium policy: %w", err)
			}
			log.Printf("Updated Cilium policy %s", policy.Name)
			return nil
		}
		return fmt.Errorf("failed to create Cilium policy: %w", err)
	}

	log.Printf("Created Cilium policy %s", policy.Name)
	return nil
}

// DeleteNetworkPolicy removes a Cilium network policy by name
func (c *KubernetesCiliumClient) DeleteNetworkPolicy(ctx context.Context, policyName string) error {
	err := c.cilium.CiliumV2().CiliumNetworkPolicies(c.namespace).Delete(
		ctx, policyName, metav1.DeleteOptions{},
	)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			log.Printf("Cilium policy %s not found, nothing to delete", policyName)
			return nil
		}
		return fmt.Errorf("failed to delete Cilium policy %s: %w", policyName, err)
	}
	log.Printf("Deleted Cilium policy %s", policyName)
	return nil
}

// ListRoutes returns routes from the CRD store.
func (c *KubernetesCiliumClient) ListRoutes(ctx context.Context) ([]Route, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "routes.networking.fos1.io", "-A", "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w\nOutput: %s", err, string(output))
	}
	return routesFromKubectlJSON(output)
}

// ListVRFRoutes returns routes for a specific VRF.
func (c *KubernetesCiliumClient) ListVRFRoutes(ctx context.Context, vrfID int) ([]Route, error) {
	routes, err := c.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	vrfName := fmt.Sprintf("vrf-%d", vrfID)
	filtered := make([]Route, 0)
	for _, route := range routes {
		if route.VRF == vrfName {
			filtered = append(filtered, route)
		}
	}
	return filtered, nil
}

// AddRoute applies a route through the Kubernetes-backed client.
func (c *KubernetesCiliumClient) AddRoute(route Route) error {
	return applyRouteManifest(route, "upsert")
}

// DeleteRoute removes a route through the Kubernetes-backed client.
func (c *KubernetesCiliumClient) DeleteRoute(route Route) error {
	return deleteRouteManifest(route)
}

// AddVRFRoute applies a route in a VRF through the Kubernetes-backed client.
func (c *KubernetesCiliumClient) AddVRFRoute(route Route, vrfID int) error {
	route.VRF = fmt.Sprintf("vrf-%d", vrfID)
	return applyRouteManifest(route, "upsert")
}

// DeleteVRFRoute removes a route in a VRF through the Kubernetes-backed client.
func (c *KubernetesCiliumClient) DeleteVRFRoute(route Route, vrfID int) error {
	route.VRF = fmt.Sprintf("vrf-%d", vrfID)
	return deleteRouteManifest(route)
}
