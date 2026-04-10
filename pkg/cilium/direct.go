package cilium

import (
	"context"
	"fmt"
	"log"
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

// ConfigureDPIIntegration configures Cilium for DPI integration
func (c *DirectCiliumClient) ConfigureDPIIntegration(ctx context.Context, config *CiliumDPIIntegrationConfig) error {
	log.Printf("Configuring Cilium DPI integration: %+v", config)

	// In a real implementation, this would make API calls to Cilium
	// For now, just log the configuration
	return nil
}

// CreateNAT creates NAT rules using Cilium's capabilities
func (c *DirectCiliumClient) CreateNAT(ctx context.Context, config *CiliumNATConfig) error {
	log.Printf("Creating NAT rules: %+v", config)
	return nil
}

// RemoveNAT removes NAT rules
func (c *DirectCiliumClient) RemoveNAT(ctx context.Context, config *CiliumNATConfig) error {
	log.Printf("Removing NAT rules: %+v", config)
	return nil
}

// CreateNAT64 creates NAT64 rules
func (c *DirectCiliumClient) CreateNAT64(ctx context.Context, config *NAT64Config) error {
	log.Printf("Creating NAT64 rules: %+v", config)
	return nil
}

// RemoveNAT64 removes NAT64 rules
func (c *DirectCiliumClient) RemoveNAT64(ctx context.Context, config *NAT64Config) error {
	log.Printf("Removing NAT64 rules: %+v", config)
	return nil
}

// CreatePortForward creates port forwarding rules
func (c *DirectCiliumClient) CreatePortForward(ctx context.Context, config *PortForwardConfig) error {
	log.Printf("Creating port forward: %+v", config)
	return nil
}

// RemovePortForward removes port forwarding rules
func (c *DirectCiliumClient) RemovePortForward(ctx context.Context, config *PortForwardConfig) error {
	log.Printf("Removing port forward: %+v", config)
	return nil
}

// ConfigureVLANRouting configures routing between VLANs
func (c *DirectCiliumClient) ConfigureVLANRouting(ctx context.Context, config *CiliumVLANRoutingConfig) error {
	log.Printf("Configuring VLAN routing: %+v", config)
	return nil
}

// ApplyNetworkPolicy applies a network policy to Cilium
func (c *DirectCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *CiliumPolicy) error {
	log.Printf("Applying network policy: %s", policy.Name)

	// In a real implementation, this would make API calls to Cilium
	// For now, just log the policy
	fmt.Printf("Policy: %+v\n", policy)

	return nil
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
