// Package ebpf provides functionality for managing eBPF programs and maps.
package ebpf

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ConfigTranslator translates CRD configurations to eBPF program configurations.
type ConfigTranslator interface {
	// TranslateEBPFProgram translates an EBPFProgram CRD to a Program.
	TranslateEBPFProgram(config interface{}) (Program, error)
	// TranslateTrafficControl translates a TrafficControl CRD to a Program.
	TranslateTrafficControl(config interface{}) (Program, error)
	// TranslateNATConfig translates a NATConfig CRD to a Program.
	TranslateNATConfig(config interface{}) (Program, error)
}

// CiliumNetworkPolicy represents a Cilium network policy
type CiliumNetworkPolicy struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   CiliumPolicyMetadata   `json:"metadata"`
	Spec       CiliumPolicySpec       `json:"spec"`
}

// CiliumPolicyMetadata contains metadata for a Cilium policy
type CiliumPolicyMetadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// CiliumPolicySpec contains the specification of a Cilium policy
type CiliumPolicySpec struct {
	Description     string                 `json:"description,omitempty"`
	EndpointSelector map[string]interface{} `json:"endpointSelector"`
	Ingress         []interface{}          `json:"ingress,omitempty"`
	Egress          []interface{}          `json:"egress,omitempty"`
	NodeSelector    map[string]interface{} `json:"nodeSelector,omitempty"`
	// Options for hardware acceleration
	Options         map[string]string      `json:"options,omitempty"`
}

// HardwareAccelerationOptions contains options for hardware acceleration
type HardwareAccelerationOptions struct {
	Enabled       bool   `json:"enabled"`
	XDPAccel      bool   `json:"xdpAccel"`      // XDP acceleration
	XDPHWOffload  bool   `json:"xdpHWOffload"`  // XDP hardware offload
	SmartNIC      bool   `json:"smartNIC"`      // SmartNIC offload
	DPDKEnabled   bool   `json:"dpdkEnabled"`   // DPDK integration
	HardwareType  string `json:"hardwareType"`  // Type of hardware
	OffloadDevice string `json:"offloadDevice"` // Device for offload
}

// CiliumIntegration provides integration with Cilium.
type CiliumIntegration interface {
	// GetCiliumMaps gets maps managed by Cilium.
	GetCiliumMaps() ([]*Map, error)
	// GetCiliumPrograms gets programs managed by Cilium.
	GetCiliumPrograms() ([]*LoadedProgram, error)
	// RegisterWithCilium registers a custom program with Cilium.
	RegisterWithCilium(program Program) error
	// UnregisterFromCilium unregisters a custom program from Cilium.
	UnregisterFromCilium(programName string) error
	// GetCiliumEndpoints gets Cilium endpoint information.
	GetCiliumEndpoints() ([]interface{}, error)
	// GetCiliumNetworkPolicies retrieves all Cilium network policies.
	GetCiliumNetworkPolicies(ctx context.Context) ([]CiliumNetworkPolicy, error)
	// ApplyCiliumNetworkPolicy applies a new Cilium network policy.
	ApplyCiliumNetworkPolicy(ctx context.Context, policy CiliumNetworkPolicy) error
	// SyncCiliumConfiguration synchronizes configuration with Cilium.
	SyncCiliumConfiguration() error
}

// Controller manages eBPF programs and maps based on configuration.
// The authoritative lifecycle path is via Cilium network policies (ApplyCiliumNetworkPolicy).
// Direct eBPF program management methods (ApplyEBPFProgramConfig, etc.) have been removed
// per ADR-0001 to enforce the Cilium-first contract.
type Controller struct {
	programManager    *ProgramManager
	mapManager        *MapManager
	ciliumIntegration CiliumIntegration
	configTranslator  ConfigTranslator
	metrics           *MetricsCollector

	programConfigs    map[string]interface{}
	ciliumPolicies    map[string]CiliumNetworkPolicy
	configsMu         sync.RWMutex

	ctx               context.Context
	cancel            context.CancelFunc
}

// NewController creates a new eBPF Controller.
func NewController(
	programManager *ProgramManager,
	mapManager *MapManager,
	ciliumIntegration CiliumIntegration,
	configTranslator ConfigTranslator,
) *Controller {
	ctx, cancel := context.WithCancel(context.Background())
	return &Controller{
		programManager:    programManager,
		mapManager:        mapManager,
		ciliumIntegration: ciliumIntegration,
		configTranslator:  configTranslator,
		metrics:           NewMetricsCollector(programManager, mapManager),
		programConfigs:    make(map[string]interface{}),
		ciliumPolicies:    make(map[string]CiliumNetworkPolicy),
		ctx:               ctx,
		cancel:            cancel,
	}
}

// Start starts the controller.
func (c *Controller) Start() error {
	// Start metrics collector
	go c.metrics.Start(c.ctx)

	// Sync with Cilium configuration if available
	if c.ciliumIntegration != nil {
		go func() {
			// Initial sync - log errors but do not pretend success
			if err := c.ciliumIntegration.SyncCiliumConfiguration(); err != nil {
				fmt.Printf("Failed to sync with Cilium configuration: %v\n", err)
			}

			// Periodic sync
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					if err := c.ciliumIntegration.SyncCiliumConfiguration(); err != nil {
						fmt.Printf("Failed to sync with Cilium configuration: %v\n", err)
					}
				case <-c.ctx.Done():
					return
				}
			}
		}()
	}

	fmt.Printf("eBPF Controller started\n")

	return nil
}

// Stop stops the controller.
func (c *Controller) Stop() error {
	// Cancel context to stop metrics collector
	c.cancel()
	
	// In a real implementation, we would stop watchers for CRDs here
	fmt.Printf("eBPF Controller stopped\n")

	return nil
}

// ApplyEBPFProgramConfig is removed. Use ApplyCiliumNetworkPolicy instead.
// This method was deprecated per ADR-0001 because it bypassed the Cilium-first
// control-plane contract by loading eBPF programs directly.
//
// Callers should migrate to ApplyCiliumNetworkPolicy which goes through the
// authoritative Cilium enforcement path.

// ApplyTrafficControlConfig is removed. Use ApplyCiliumNetworkPolicy instead.
// This method was deprecated per ADR-0001 because it bypassed the Cilium-first
// control-plane contract.

// ApplyNATConfig is removed. Use ApplyCiliumNetworkPolicy instead.
// This method was deprecated per ADR-0001. NAT enforcement goes through
// Cilium policies exclusively.

// DeleteConfig deletes a configuration.
func (c *Controller) DeleteConfig(name string) error {
	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	// Check if the configuration exists
	if _, ok := c.programConfigs[name]; !ok {
		return fmt.Errorf("configuration %s not found", name)
	}

	// Delete the configuration
	delete(c.programConfigs, name)

	// Check if the program exists
	_, err := c.programManager.GetProgram(name)
	if err != nil {
		return nil // Program doesn't exist, nothing to do
	}

	// Unload the program
	if err := c.programManager.UnloadProgram(name); err != nil {
		return fmt.Errorf("failed to unload program: %w", err)
	}

	return nil
}

// GetConfig gets a configuration.
func (c *Controller) GetConfig(name string) (interface{}, error) {
	c.configsMu.RLock()
	defer c.configsMu.RUnlock()

	// Check if the configuration exists
	config, ok := c.programConfigs[name]
	if !ok {
		return nil, fmt.Errorf("configuration %s not found", name)
	}

	return config, nil
}

// ListConfigs lists all configurations.
func (c *Controller) ListConfigs() (map[string]interface{}, error) {
	c.configsMu.RLock()
	defer c.configsMu.RUnlock()

	// Create a copy of the configurations
	configs := make(map[string]interface{}, len(c.programConfigs))
	for name, config := range c.programConfigs {
		configs[name] = config
	}

	return configs, nil
}

// GetMetrics gets metrics for all programs.
func (c *Controller) GetMetrics() (map[string]map[string]interface{}, error) {
	// Get a list of all programs
	programs, err := c.programManager.ListPrograms()
	if err != nil {
		return nil, fmt.Errorf("failed to list programs: %w", err)
	}

	// Create a map to store metrics
	metrics := make(map[string]map[string]interface{}, len(programs))

	// Collect metrics for each program
	for _, program := range programs {
		programMetrics, err := c.programManager.GetProgramMetrics(program.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get metrics for program %s: %w", program.Name, err)
		}
		metrics[program.Name] = programMetrics
	}

	return metrics, nil
}

// RegisterWithCilium registers a program with Cilium.
func (c *Controller) RegisterWithCilium(programName string) error {
	// Check if program exists
	program, err := c.programManager.GetProgram(programName)
	if err != nil {
		return fmt.Errorf("program %s not found: %w", programName, err)
	}

	// Create a Program object from the LoadedProgram
	progConfig := Program{
		Name:      program.Name,
		Type:      program.Type,
		Interface: program.Interface,
		Priority:  program.Priority,
		Maps:      program.Maps,
	}

	// Register with Cilium
	if err := c.ciliumIntegration.RegisterWithCilium(progConfig); err != nil {
		return fmt.Errorf("failed to register program with Cilium: %w", err)
	}

	return nil
}

// UnregisterFromCilium unregisters a program from Cilium.
func (c *Controller) UnregisterFromCilium(programName string) error {
	// Unregister from Cilium
	if err := c.ciliumIntegration.UnregisterFromCilium(programName); err != nil {
		return fmt.Errorf("failed to unregister program from Cilium: %w", err)
	}

	return nil
}

// loadCiliumNetworkPolicies loads policies from the live Cilium agent.
// Returns an error if the Cilium agent is not reachable; does not
// return placeholder/simulated data.
func (c *Controller) loadCiliumNetworkPolicies() error {
	if c.ciliumIntegration == nil {
		return fmt.Errorf("cilium integration not configured")
	}

	policies, err := c.ciliumIntegration.GetCiliumNetworkPolicies(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to get Cilium network policies: %w", err)
	}

	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	c.ciliumPolicies = make(map[string]CiliumNetworkPolicy)

	for _, policy := range policies {
		policyName := policy.Metadata.Name
		if policy.Metadata.Namespace != "" {
			policyName = fmt.Sprintf("%s/%s", policy.Metadata.Namespace, policyName)
		}
		c.ciliumPolicies[policyName] = policy
	}

	return nil
}

// ApplyCiliumNetworkPolicy applies a Cilium network policy via the Cilium agent.
// This is the authoritative path for policy enforcement per ADR-0001.
func (c *Controller) ApplyCiliumNetworkPolicy(name string, policy CiliumNetworkPolicy) error {
	if c.ciliumIntegration == nil {
		return fmt.Errorf("cilium integration not configured")
	}

	// Apply the policy via the real Cilium agent API
	if err := c.ciliumIntegration.ApplyCiliumNetworkPolicy(c.ctx, policy); err != nil {
		return fmt.Errorf("failed to apply Cilium network policy: %w", err)
	}

	// Store the policy only after successful application
	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	policyName := policy.Metadata.Name
	if policy.Metadata.Namespace != "" {
		policyName = fmt.Sprintf("%s/%s", policy.Metadata.Namespace, policyName)
	}
	c.ciliumPolicies[policyName] = policy

	return nil
}

// GetCiliumNetworkPolicy gets a Cilium network policy.
func (c *Controller) GetCiliumNetworkPolicy(name string) (CiliumNetworkPolicy, error) {
	c.configsMu.RLock()
	defer c.configsMu.RUnlock()

	// Check if the policy exists
	policy, ok := c.ciliumPolicies[name]
	if !ok {
		return CiliumNetworkPolicy{}, fmt.Errorf("cilium network policy %s not found", name)
	}

	return policy, nil
}

// ListCiliumNetworkPolicies lists all Cilium network policies.
func (c *Controller) ListCiliumNetworkPolicies() (map[string]CiliumNetworkPolicy, error) {
	c.configsMu.RLock()
	defer c.configsMu.RUnlock()

	// Create a copy of the policies
	policies := make(map[string]CiliumNetworkPolicy, len(c.ciliumPolicies))
	for name, policy := range c.ciliumPolicies {
		policies[name] = policy
	}

	return policies, nil
}

// DeleteCiliumNetworkPolicy deletes a Cilium network policy from the local cache.
// Note: actual deletion from Cilium requires a separate API call not yet implemented.
func (c *Controller) DeleteCiliumNetworkPolicy(name string) error {
	if c.ciliumIntegration == nil {
		return fmt.Errorf("cilium integration not configured")
	}

	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	if _, ok := c.ciliumPolicies[name]; !ok {
		return fmt.Errorf("cilium network policy %s not found", name)
	}

	delete(c.ciliumPolicies, name)

	return nil
}
