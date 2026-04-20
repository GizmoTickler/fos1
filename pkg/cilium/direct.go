package cilium

import (
	"context"
	"fmt"
	"os/exec"
)

// DirectCiliumClient implements the CiliumClient interface for direct API calls
type DirectCiliumClient struct {
	// Configuration
	apiEndpoint string
	apiKey      string
}

// NewDirectCiliumClient creates a new direct Cilium client
func NewDirectCiliumClient(apiEndpoint, apiKey string) *DirectCiliumClient {
	if apiEndpoint == "" {
		apiEndpoint = "http://localhost:9876/api"
	}

	return &DirectCiliumClient{
		apiEndpoint: apiEndpoint,
		apiKey:      apiKey,
	}
}

func (c *DirectCiliumClient) defaultClient() *DefaultCiliumClient {
	return NewDefaultCiliumClient(c.apiEndpoint, "")
}

// ConfigureDPIIntegration configures Cilium for DPI integration
func (c *DirectCiliumClient) ConfigureDPIIntegration(ctx context.Context, config *CiliumDPIIntegrationConfig) error {
	return c.defaultClient().ConfigureDPIIntegration(ctx, config)
}

// CreateNAT creates NAT rules using Cilium's capabilities
func (c *DirectCiliumClient) CreateNAT(ctx context.Context, config *CiliumNATConfig) error {
	return c.defaultClient().CreateNAT(ctx, config)
}

// RemoveNAT removes NAT rules
func (c *DirectCiliumClient) RemoveNAT(ctx context.Context, config *CiliumNATConfig) error {
	return c.defaultClient().RemoveNAT(ctx, config)
}

// CreateNAT64 creates NAT64 rules
func (c *DirectCiliumClient) CreateNAT64(ctx context.Context, config *NAT64Config) error {
	return c.defaultClient().CreateNAT64(ctx, config)
}

// RemoveNAT64 removes NAT64 rules
func (c *DirectCiliumClient) RemoveNAT64(ctx context.Context, config *NAT64Config) error {
	return c.defaultClient().RemoveNAT64(ctx, config)
}

// CreatePortForward creates port forwarding rules
func (c *DirectCiliumClient) CreatePortForward(ctx context.Context, config *PortForwardConfig) error {
	return c.defaultClient().CreatePortForward(ctx, config)
}

// RemovePortForward removes port forwarding rules
func (c *DirectCiliumClient) RemovePortForward(ctx context.Context, config *PortForwardConfig) error {
	return c.defaultClient().RemovePortForward(ctx, config)
}

// ConfigureVLANRouting configures routing between VLANs
func (c *DirectCiliumClient) ConfigureVLANRouting(ctx context.Context, config *CiliumVLANRoutingConfig) error {
	return c.defaultClient().ConfigureVLANRouting(ctx, config)
}

// DeleteNetworkPolicy removes a Cilium network policy by name
func (c *DirectCiliumClient) DeleteNetworkPolicy(ctx context.Context, policyName string) error {
	return c.defaultClient().DeleteNetworkPolicy(ctx, policyName)
}

// ApplyNetworkPolicy applies a network policy to Cilium
func (c *DirectCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *CiliumPolicy) error {
	return c.defaultClient().ApplyNetworkPolicy(ctx, policy)
}

// ListRoutes returns routes from the CRD store.
func (c *DirectCiliumClient) ListRoutes(ctx context.Context) ([]Route, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "routes.networking.fos1.io", "-A", "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w\nOutput: %s", err, string(output))
	}
	return routesFromKubectlJSON(output)
}

// ListVRFRoutes returns routes for a specific VRF.
func (c *DirectCiliumClient) ListVRFRoutes(ctx context.Context, vrfID int) ([]Route, error) {
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

// AddRoute applies a route through the direct client.
func (c *DirectCiliumClient) AddRoute(route Route) error {
	return applyRouteManifest(route, "upsert")
}

// DeleteRoute removes a route through the direct client.
func (c *DirectCiliumClient) DeleteRoute(route Route) error {
	return deleteRouteManifest(route)
}

// AddVRFRoute applies a route in a VRF through the direct client.
func (c *DirectCiliumClient) AddVRFRoute(route Route, vrfID int) error {
	route.VRF = fmt.Sprintf("vrf-%d", vrfID)
	return applyRouteManifest(route, "upsert")
}

// DeleteVRFRoute removes a route in a VRF through the direct client.
func (c *DirectCiliumClient) DeleteVRFRoute(route Route, vrfID int) error {
	route.VRF = fmt.Sprintf("vrf-%d", vrfID)
	return deleteRouteManifest(route)
}
