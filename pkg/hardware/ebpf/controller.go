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
}

// Controller manages eBPF programs and maps based on configuration.
type Controller struct {
	programManager    *ProgramManager
	mapManager        *MapManager
	ciliumIntegration CiliumIntegration
	configTranslator  ConfigTranslator
	metrics           *MetricsCollector
	
	programConfigs    map[string]interface{}
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
		ctx:               ctx,
		cancel:            cancel,
	}
}

// Start starts the controller.
func (c *Controller) Start() error {
	// Start metrics collector
	go c.metrics.Start(c.ctx)

	// In a real implementation, we would start watchers for CRDs here
	// For now, we'll just log a message
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
