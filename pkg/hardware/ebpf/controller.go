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
type Controller struct {
	programManager    *ProgramManager
	mapManager        *MapManager
	ciliumIntegration CiliumIntegration
	configTranslator  ConfigTranslator
	metrics           *MetricsCollector
	
	programConfigs    map[string]interface{}
	ciliumPolicies    map[string]CiliumNetworkPolicy
	hwAccelOptions    HardwareAccelerationOptions
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
		hwAccelOptions:    HardwareAccelerationOptions{Enabled: false},
		ctx:               ctx,
		cancel:            cancel,
	}
}

// Start starts the controller.
func (c *Controller) Start() error {
	// Start metrics collector
	go c.metrics.Start(c.ctx)

	// Sync with Cilium configuration
	if c.ciliumIntegration != nil {
		go func() {
			// Initial sync
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

		// Load existing Cilium network policies
		go func() {
			if err := c.loadCiliumNetworkPolicies(); err != nil {
				fmt.Printf("Failed to load Cilium network policies: %v\n", err)
			}
		}()
	}

	// In a real implementation, we would start watchers for CRDs here
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

// ApplyEBPFProgramConfig applies an eBPF program configuration.
// Deprecated: This method is being replaced by native Cilium network policies.
// DO NOT USE: All code should use ApplyCiliumNetworkPolicy instead.
func (c *Controller) ApplyEBPFProgramConfig(name string, config interface{}) error {
	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	// Store the configuration
	c.programConfigs[name] = config

	// Translate the configuration to a program
	program, err := c.configTranslator.TranslateEBPFProgram(config)
	if err != nil {
		return fmt.Errorf("failed to translate eBPF program configuration: %w", err)
	}

	// Set the program name to match the config name
	program.Name = name

	// Check if this is an update
	_, err = c.programManager.GetProgram(name)
	if err == nil {
		// Program exists, unload it first
		if err := c.programManager.UnloadProgram(name); err != nil {
			return fmt.Errorf("failed to unload existing program: %w", err)
		}
	}

	// Load the program
	if err := c.programManager.LoadProgram(program); err != nil {
		return fmt.Errorf("failed to load eBPF program: %w", err)
	}

	// Attach the program to the specified hook
	hookName := program.Type
	if err := c.programManager.AttachProgram(name, hookName); err != nil {
		// If attach fails, try to unload the program
		_ = c.programManager.UnloadProgram(name)
		return fmt.Errorf("failed to attach eBPF program: %w", err)
	}

	return nil
}

// ApplyTrafficControlConfig applies a traffic control configuration.
// Deprecated: This method is being replaced by native Cilium network policies.
// DO NOT USE: All code should use ApplyCiliumNetworkPolicy instead.
func (c *Controller) ApplyTrafficControlConfig(name string, config interface{}) error {
	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	// Store the configuration
	c.programConfigs[name] = config

	// Translate the configuration to a program
	program, err := c.configTranslator.TranslateTrafficControl(config)
	if err != nil {
		return fmt.Errorf("failed to translate traffic control configuration: %w", err)
	}

	// Set the program name to match the config name
	program.Name = name

	// Check if this is an update
	_, err = c.programManager.GetProgram(name)
	if err == nil {
		// Program exists, unload it first
		if err := c.programManager.UnloadProgram(name); err != nil {
			return fmt.Errorf("failed to unload existing program: %w", err)
		}
	}

	// Load the program
	if err := c.programManager.LoadProgram(program); err != nil {
		return fmt.Errorf("failed to load traffic control program: %w", err)
	}

	// Determine the hook name based on the program type
	var hookName string
	if program.Type == "tc-ingress" {
		hookName = string(HookTypeTCIngress)
	} else if program.Type == "tc-egress" {
		hookName = string(HookTypeTCEgress)
	} else {
		return fmt.Errorf("invalid program type for traffic control: %s", program.Type)
	}

	// Attach the program to the specified hook
	if err := c.programManager.AttachProgram(name, hookName); err != nil {
		// If attach fails, try to unload the program
		_ = c.programManager.UnloadProgram(name)
		return fmt.Errorf("failed to attach traffic control program: %w", err)
	}

	return nil
}

// ApplyNATConfig applies a NAT configuration.
// Deprecated: This method is being replaced by native Cilium network policies.
// DO NOT USE: All code should use ApplyCiliumNetworkPolicy instead.
func (c *Controller) ApplyNATConfig(name string, config interface{}) error {
	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	// Store the configuration
	c.programConfigs[name] = config

	// Translate the configuration to a program
	program, err := c.configTranslator.TranslateNATConfig(config)
	if err != nil {
		return fmt.Errorf("failed to translate NAT configuration: %w", err)
	}

	// Set the program name to match the config name
	program.Name = name

	// Check if this is an update
	_, err = c.programManager.GetProgram(name)
	if err == nil {
		// Program exists, unload it first
		if err := c.programManager.UnloadProgram(name); err != nil {
			return fmt.Errorf("failed to unload existing program: %w", err)
		}
	}

	// Load the program
	if err := c.programManager.LoadProgram(program); err != nil {
		return fmt.Errorf("failed to load NAT program: %w", err)
	}

	// NAT programs typically use TC hooks
	hookName := string(HookTypeTCIngress)

	// Attach the program to the specified hook
	if err := c.programManager.AttachProgram(name, hookName); err != nil {
		// If attach fails, try to unload the program
		_ = c.programManager.UnloadProgram(name)
		return fmt.Errorf("failed to attach NAT program: %w", err)
	}

	return nil
}

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

// loadCiliumNetworkPolicies loads existing Cilium network policies.
func (c *Controller) loadCiliumNetworkPolicies() error {
	// Check if Cilium integration is available
	if c.ciliumIntegration == nil {
		return fmt.Errorf("cilium integration not available")
	}

	// Get the current policies from Cilium
	policies, err := c.ciliumIntegration.GetCiliumNetworkPolicies(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to get Cilium network policies: %w", err)
	}

	// Store the policies
	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	// Clear existing policies
	c.ciliumPolicies = make(map[string]CiliumNetworkPolicy)

	// Add the new policies
	for _, policy := range policies {
		policyName := policy.Metadata.Name
		if policy.Metadata.Namespace != "" {
			policyName = fmt.Sprintf("%s/%s", policy.Metadata.Namespace, policyName)
		}
		c.ciliumPolicies[policyName] = policy

		// Check for hardware acceleration in policy options
		if policy.Spec.Options != nil {
			if _, hasXDP := policy.Spec.Options["xdp"]; hasXDP {
				// Enable XDP acceleration
				c.hwAccelOptions.Enabled = true
				c.hwAccelOptions.XDPAccel = true
			}

			if _, hasXDPOffload := policy.Spec.Options["xdpOffload"]; hasXDPOffload {
				// Enable XDP hardware offload
				c.hwAccelOptions.Enabled = true
				c.hwAccelOptions.XDPHWOffload = true
			}

			if _, hasSmartNIC := policy.Spec.Options["smartNIC"]; hasSmartNIC {
				// Enable SmartNIC offload
				c.hwAccelOptions.Enabled = true
				c.hwAccelOptions.SmartNIC = true
			}

			if device, hasDPDK := policy.Spec.Options["dpdk"]; hasDPDK {
				// Enable DPDK integration
				c.hwAccelOptions.Enabled = true
				c.hwAccelOptions.DPDKEnabled = true
				if device != "" {
					c.hwAccelOptions.OffloadDevice = device
				}
			}

			if hwType, hasHWType := policy.Spec.Options["hardwareType"]; hasHWType {
				// Set hardware type
				c.hwAccelOptions.HardwareType = hwType
			}
		}
	}

	fmt.Printf("Loaded %d Cilium network policies\n", len(policies))

	// Apply hardware acceleration changes if needed
	if c.hwAccelOptions.Enabled {
		fmt.Printf("Hardware acceleration enabled: XDP=%v, XDP-HW=%v, SmartNIC=%v, DPDK=%v\n",
			c.hwAccelOptions.XDPAccel, c.hwAccelOptions.XDPHWOffload,
			c.hwAccelOptions.SmartNIC, c.hwAccelOptions.DPDKEnabled)
		if err := c.applyHardwareAccelerationOptions(); err != nil {
			fmt.Printf("Failed to apply hardware acceleration options: %v\n", err)
		}
	}

	return nil
}

// ApplyCiliumNetworkPolicy applies a Cilium network policy.
func (c *Controller) ApplyCiliumNetworkPolicy(name string, policy CiliumNetworkPolicy) error {
	// Check if Cilium integration is available
	if c.ciliumIntegration == nil {
		return fmt.Errorf("cilium integration not available")
	}

	// Apply the policy via Cilium integration
	if err := c.ciliumIntegration.ApplyCiliumNetworkPolicy(c.ctx, policy); err != nil {
		return fmt.Errorf("failed to apply Cilium network policy: %w", err)
	}

	// Store the policy
	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	policyName := policy.Metadata.Name
	if policy.Metadata.Namespace != "" {
		policyName = fmt.Sprintf("%s/%s", policy.Metadata.Namespace, policyName)
	}
	c.ciliumPolicies[policyName] = policy

	// Check for hardware acceleration options
	if policy.Spec.Options != nil {
		hardwareChanged := false

		if _, hasXDP := policy.Spec.Options["xdp"]; hasXDP && !c.hwAccelOptions.XDPAccel {
			c.hwAccelOptions.Enabled = true
			c.hwAccelOptions.XDPAccel = true
			hardwareChanged = true
		}

		if _, hasXDPOffload := policy.Spec.Options["xdpOffload"]; hasXDPOffload && !c.hwAccelOptions.XDPHWOffload {
			c.hwAccelOptions.Enabled = true
			c.hwAccelOptions.XDPHWOffload = true
			hardwareChanged = true
		}

		if _, hasSmartNIC := policy.Spec.Options["smartNIC"]; hasSmartNIC && !c.hwAccelOptions.SmartNIC {
			c.hwAccelOptions.Enabled = true
			c.hwAccelOptions.SmartNIC = true
			hardwareChanged = true
		}

		if device, hasDPDK := policy.Spec.Options["dpdk"]; hasDPDK && !c.hwAccelOptions.DPDKEnabled {
			c.hwAccelOptions.Enabled = true
			c.hwAccelOptions.DPDKEnabled = true
			if device != "" {
				c.hwAccelOptions.OffloadDevice = device
			}
			hardwareChanged = true
		}

		if hwType, hasHWType := policy.Spec.Options["hardwareType"]; hasHWType && c.hwAccelOptions.HardwareType != hwType {
			c.hwAccelOptions.HardwareType = hwType
			hardwareChanged = true
		}

		// Apply hardware acceleration changes if needed
		if hardwareChanged {
			fmt.Printf("Hardware acceleration options changed: XDP=%v, XDP-HW=%v, SmartNIC=%v, DPDK=%v\n",
				c.hwAccelOptions.XDPAccel, c.hwAccelOptions.XDPHWOffload,
				c.hwAccelOptions.SmartNIC, c.hwAccelOptions.DPDKEnabled)
			if err := c.applyHardwareAccelerationOptions(); err != nil {
				fmt.Printf("Failed to apply hardware acceleration options: %v\n", err)
			}
		}
	}

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

// DeleteCiliumNetworkPolicy deletes a Cilium network policy.
func (c *Controller) DeleteCiliumNetworkPolicy(name string) error {
	// Check if Cilium integration is available
	if c.ciliumIntegration == nil {
		return fmt.Errorf("cilium integration not available")
	}

	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	// Check if the policy exists
	if _, ok := c.ciliumPolicies[name]; !ok {
		return fmt.Errorf("cilium network policy %s not found", name)
	}

	// Delete the policy
	delete(c.ciliumPolicies, name)

	// Note: In a real implementation, we would also delete the policy from Cilium
	// This would require adding a DeleteCiliumNetworkPolicy method to the CiliumIntegration interface

	return nil
}

// applyHardwareAccelerationOptions applies hardware acceleration options to all relevant programs.
func (c *Controller) applyHardwareAccelerationOptions() error {
	// This would apply hardware acceleration options to all relevant programs
	// For example, for XDP programs with hardware offload enabled:
	if c.hwAccelOptions.XDPHWOffload {
		// List all XDP programs
		programs, err := c.programManager.ListPrograms()
		if err != nil {
			return fmt.Errorf("failed to list programs: %w", err)
		}

		// Apply offload option to all XDP programs
		for _, program := range programs {
			if program.Type == "xdp" {
				fmt.Printf("Enabling XDP hardware offload for program %s\n", program.Name)
				// In a real implementation, we would modify the program's configuration
				// and potentially reload it with hardware offload enabled
			}
		}
	}

	return nil
}

// SetHardwareAccelerationOptions sets hardware acceleration options.
func (c *Controller) SetHardwareAccelerationOptions(options HardwareAccelerationOptions) error {
	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	// Store the options
	c.hwAccelOptions = options

	// Apply the options
	if options.Enabled {
		fmt.Printf("Setting hardware acceleration options: XDP=%v, XDP-HW=%v, SmartNIC=%v, DPDK=%v\n",
			options.XDPAccel, options.XDPHWOffload, options.SmartNIC, options.DPDKEnabled)
		if err := c.applyHardwareAccelerationOptions(); err != nil {
			return fmt.Errorf("failed to apply hardware acceleration options: %w", err)
		}
	}

	return nil
}

// GetHardwareAccelerationOptions gets the current hardware acceleration options.
func (c *Controller) GetHardwareAccelerationOptions() HardwareAccelerationOptions {
	c.configsMu.RLock()
	defer c.configsMu.RUnlock()

	return c.hwAccelOptions
}



// startCiliumSync starts a goroutine to periodically sync with Cilium.
func (c *Controller) startCiliumSync() {
	ticker := time.NewTicker(30 * time.Second) // Sync every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.syncWithCilium(); err != nil {
				fmt.Printf("Failed to sync with Cilium: %v\n", err)
			}
		}
	}
}

// syncWithCilium synchronizes the controller state with Cilium.
func (c *Controller) syncWithCilium() error {
	// Sync Cilium configuration
	if err := c.ciliumIntegration.SyncCiliumConfiguration(); err != nil {
		return fmt.Errorf("failed to sync Cilium configuration: %w", err)
	}

	// Get the latest Cilium network policies
	policies, err := c.ciliumIntegration.GetCiliumNetworkPolicies(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to get Cilium network policies: %w", err)
	}

	c.configsMu.Lock()
	defer c.configsMu.Unlock()

	// Track new and modified policies
	newPolicies := make(map[string]struct{})
	hardwareChanged := false

	// Process all policies
	for _, policy := range policies {
		policyName := policy.Metadata.Name
		if policy.Metadata.Namespace != "" {
			policyName = fmt.Sprintf("%s/%s", policy.Metadata.Namespace, policyName)
		}

		newPolicies[policyName] = struct{}{}

		// Check if policy is new or modified
		existingPolicy, exists := c.ciliumPolicies[policyName]
		if !exists || !reflect.DeepEqual(existingPolicy, policy) {
			// Update or add the policy
			c.ciliumPolicies[policyName] = policy

			// Check for hardware acceleration options
			if policy.Spec.Options != nil {
				oldXDP := c.hwAccelOptions.XDPAccel
				oldXDPHW := c.hwAccelOptions.XDPHWOffload
				oldSmartNIC := c.hwAccelOptions.SmartNIC
				oldDPDK := c.hwAccelOptions.DPDKEnabled
				oldHWType := c.hwAccelOptions.HardwareType

				// Update hardware acceleration options as needed
				if _, hasXDP := policy.Spec.Options["xdp"]; hasXDP && !c.hwAccelOptions.XDPAccel {
					c.hwAccelOptions.Enabled = true
					c.hwAccelOptions.XDPAccel = true
				}

				if _, hasXDPOffload := policy.Spec.Options["xdpOffload"]; hasXDPOffload && !c.hwAccelOptions.XDPHWOffload {
					c.hwAccelOptions.Enabled = true
					c.hwAccelOptions.XDPHWOffload = true
				}

				if _, hasSmartNIC := policy.Spec.Options["smartNIC"]; hasSmartNIC && !c.hwAccelOptions.SmartNIC {
					c.hwAccelOptions.Enabled = true
					c.hwAccelOptions.SmartNIC = true
				}

				if device, hasDPDK := policy.Spec.Options["dpdk"]; hasDPDK && !c.hwAccelOptions.DPDKEnabled {
					c.hwAccelOptions.Enabled = true
					c.hwAccelOptions.DPDKEnabled = true
					if device != "" {
						c.hwAccelOptions.OffloadDevice = device
					}
				}

				if hwType, hasHWType := policy.Spec.Options["hardwareType"]; hasHWType && c.hwAccelOptions.HardwareType != hwType {
					c.hwAccelOptions.HardwareType = hwType
				}

				// Check if any hardware options changed
				if oldXDP != c.hwAccelOptions.XDPAccel ||
					oldXDPHW != c.hwAccelOptions.XDPHWOffload ||
					oldSmartNIC != c.hwAccelOptions.SmartNIC ||
					oldDPDK != c.hwAccelOptions.DPDKEnabled ||
					oldHWType != c.hwAccelOptions.HardwareType {
					hardwareChanged = true
				}
			}
		}
	}

	// Find and remove deleted policies
	for name := range c.ciliumPolicies {
		if _, exists := newPolicies[name]; !exists {
			delete(c.ciliumPolicies, name)
		}
	}

	// Apply hardware acceleration changes if needed
	if hardwareChanged {
		fmt.Printf("Hardware acceleration options changed: XDP=%v, XDP-HW=%v, SmartNIC=%v, DPDK=%v\n",
			c.hwAccelOptions.XDPAccel, c.hwAccelOptions.XDPHWOffload,
			c.hwAccelOptions.SmartNIC, c.hwAccelOptions.DPDKEnabled)
		
		if err := c.applyHardwareAccelerationOptions(); err != nil {
			fmt.Printf("Failed to apply hardware acceleration options: %v\n", err)
		}
	}

	return nil
}
