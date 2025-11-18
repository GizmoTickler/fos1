package cilium

import (
	"context"
	"fmt"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumclientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/GizmoTickler/fos1/pkg/kubernetes"
)

// KubernetesCiliumClient implements the CiliumClient interface using Kubernetes
type KubernetesCiliumClient struct {
	k8sClient *kubernetes.Client
	cilium    ciliumclientset.Interface
	namespace string
}

// NewKubernetesCiliumClient creates a new Kubernetes-based Cilium client
func NewKubernetesCiliumClient(client *kubernetes.Client) *KubernetesCiliumClient {
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
func (c *KubernetesCiliumClient) ConfigureDPIIntegration(ctx context.Context, config *DPIIntegrationConfig) error {
	// In Kubernetes, this would typically be done through CRDs or ConfigMaps
	// For now, we'll just log the configuration
	log.Printf("Configuring Cilium DPI integration: %+v", config)
	return nil
}

// ApplyNetworkPolicy applies a network policy to Cilium
func (c *KubernetesCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *NetworkPolicy) error {
	// Convert our NetworkPolicy to a CiliumNetworkPolicy
	ciliumPolicy := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.Name,
			Namespace: c.namespace,
			Labels:    policy.Labels,
		},
		Spec: &ciliumv2.NetworkPolicySpec{},
	}

	// Add ingress rules
	for _, rule := range policy.Ingress {
		ingressRule := ciliumv2.IngressRule{}

		// Add CIDR rules
		if len(rule.FromCIDRs) > 0 {
			cidrRules := make([]ciliumv2.CIDR, 0, len(rule.FromCIDRs))
			for _, cidr := range rule.FromCIDRs {
				cidrRules = append(cidrRules, ciliumv2.CIDR(cidr))
			}
			ingressRule.FromCIDR = cidrRules
		}

		// Add port rules
		if len(rule.ToPorts) > 0 {
			portRules := make([]ciliumv2.PortRule, 0, len(rule.ToPorts))
			for _, portRule := range rule.ToPorts {
				ports := make([]ciliumv2.PortProtocol, 0, len(portRule.Ports))
				for _, port := range portRule.Ports {
					ports = append(ports, ciliumv2.PortProtocol{
						Port:     fmt.Sprintf("%d", port.Port),
						Protocol: port.Protocol,
					})
				}
				portRules = append(portRules, ciliumv2.PortRule{
					Ports: ports,
				})
			}
			ingressRule.ToPorts = portRules
		}

		ciliumPolicy.Spec.Ingress = append(ciliumPolicy.Spec.Ingress, ingressRule)
	}

	// Add egress rules
	for _, rule := range policy.Egress {
		egressRule := ciliumv2.EgressRule{}

		// Add CIDR rules
		if len(rule.ToCIDRs) > 0 {
			cidrRules := make([]ciliumv2.CIDR, 0, len(rule.ToCIDRs))
			for _, cidr := range rule.ToCIDRs {
				cidrRules = append(cidrRules, ciliumv2.CIDR(cidr))
			}
			egressRule.ToCIDR = cidrRules
		}

		// Add port rules
		if len(rule.ToPorts) > 0 {
			portRules := make([]ciliumv2.PortRule, 0, len(rule.ToPorts))
			for _, portRule := range rule.ToPorts {
				ports := make([]ciliumv2.PortProtocol, 0, len(portRule.Ports))
				for _, port := range portRule.Ports {
					ports = append(ports, ciliumv2.PortProtocol{
						Port:     fmt.Sprintf("%d", port.Port),
						Protocol: port.Protocol,
					})
				}
				portRules = append(portRules, ciliumv2.PortRule{
					Ports: ports,
				})
			}
			egressRule.ToPorts = portRules
		}

		ciliumPolicy.Spec.Egress = append(ciliumPolicy.Spec.Egress, egressRule)
	}

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
