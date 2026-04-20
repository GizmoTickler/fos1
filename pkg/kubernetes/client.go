package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumclientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// CiliumPolicyClient applies namespace-scoped Cilium network policies.
type CiliumPolicyClient interface {
	ApplyNetworkPolicy(ctx context.Context, namespace string, policy *ciliumv2.CiliumNetworkPolicy) error
}

// Client represents a Kubernetes client
type Client struct {
	Clientset          kubernetes.Interface
	Config             *rest.Config
	ciliumPolicyClient CiliumPolicyClient
}

// NewClient creates a new Kubernetes client
func NewClient(kubeconfig string) (*Client, error) {
	var config *rest.Config
	var err error

	// Try to use in-cluster config if no kubeconfig is provided
	if kubeconfig == "" {
		config, err = rest.InClusterConfig()
		if err != nil {
			// If running locally, try to use the default kubeconfig
			homeDir, _ := os.UserHomeDir()
			defaultKubeconfig := filepath.Join(homeDir, ".kube", "config")
			if _, err := os.Stat(defaultKubeconfig); err == nil {
				config, err = clientcmd.BuildConfigFromFlags("", defaultKubeconfig)
				if err != nil {
					return nil, fmt.Errorf("failed to create Kubernetes client config: %w", err)
				}
			} else {
				return nil, fmt.Errorf("failed to create in-cluster config: %w", err)
			}
		}
	} else {
		// Use the provided kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kubernetes client config: %w", err)
		}
	}

	// Create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	ciliumPolicyClient, err := newCiliumPolicyClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cilium policy client: %w", err)
	}

	return &Client{
		Clientset:          clientset,
		Config:             config,
		ciliumPolicyClient: ciliumPolicyClient,
	}, nil
}

// ApplyCiliumNetworkPolicy applies a namespace-scoped Cilium network policy through the configured client.
func (c *Client) ApplyCiliumNetworkPolicy(ctx context.Context, namespace string, policy *ciliumv2.CiliumNetworkPolicy) error {
	if c == nil {
		return fmt.Errorf("kubernetes client is nil")
	}
	if c.ciliumPolicyClient == nil {
		return fmt.Errorf("cilium policy client is not configured")
	}
	if policy == nil {
		return fmt.Errorf("cilium policy must not be nil")
	}
	if namespace == "" {
		namespace = policy.Namespace
	}
	if namespace == "" {
		namespace = "default"
	}

	return c.ciliumPolicyClient.ApplyNetworkPolicy(ctx, namespace, policy)
}

type kubeCiliumPolicyClient struct {
	clientset ciliumclientset.Interface
}

func newCiliumPolicyClient(config *rest.Config) (*kubeCiliumPolicyClient, error) {
	clientset, err := ciliumclientset.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &kubeCiliumPolicyClient{clientset: clientset}, nil
}

func (c *kubeCiliumPolicyClient) ApplyNetworkPolicy(ctx context.Context, namespace string, policy *ciliumv2.CiliumNetworkPolicy) error {
	if policy == nil {
		return fmt.Errorf("cilium policy must not be nil")
	}
	if policy.Name == "" {
		return fmt.Errorf("cilium policy name must not be empty")
	}

	desired := policy.DeepCopy()
	desired.Namespace = namespace

	_, err := c.clientset.CiliumV2().CiliumNetworkPolicies(namespace).Create(ctx, desired, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("create Cilium policy %s/%s: %w", namespace, desired.Name, err)
	}

	existing, getErr := c.clientset.CiliumV2().CiliumNetworkPolicies(namespace).Get(ctx, desired.Name, metav1.GetOptions{})
	if getErr != nil {
		return fmt.Errorf("get existing Cilium policy %s/%s: %w", namespace, desired.Name, getErr)
	}
	desired.ResourceVersion = existing.ResourceVersion

	if _, err := c.clientset.CiliumV2().CiliumNetworkPolicies(namespace).Update(ctx, desired, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update Cilium policy %s/%s: %w", namespace, desired.Name, err)
	}

	return nil
}
