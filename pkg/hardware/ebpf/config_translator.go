// Package ebpf provides functionality for managing eBPF programs and maps.
package ebpf

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// EBPFProgramConfig represents an EBPFProgram CRD configuration.
type EBPFProgramConfig struct {
	Name        string
	Description string
	Type        string
	Interface   string
	Priority    int
	Settings    map[string]interface{}
}

// TrafficControlConfig represents a TrafficControl CRD configuration.
type TrafficControlConfig struct {
	Name                string
	Description         string
	Interface           string
	Direction           string
	Priority            int
	QueueingDiscipline  string
	Classes             []TrafficClass
}

// TrafficClass represents a traffic class in a TrafficControl configuration.
type TrafficClass struct {
	Name     string
	Priority int
	Rate     string
	Ceiling  string
	Match    map[string]interface{}
}

// NATConfig represents a NATConfig CRD configuration.
type NATConfig struct {
	Name         string
	Description  string
	Interfaces   map[string]string
	Type         string
	IPVersion    string
	PortMappings []PortMapping
	SourceCIDRs  []string
	ExcludeCIDRs []string
}

// PortMapping represents a port mapping in a NAT configuration.
type PortMapping struct {
	Protocol     string
	InternalIP   string
	InternalPort int
	ExternalPort int
}

// ConfigTranslatorImpl implements the ConfigTranslator interface.
type ConfigTranslatorImpl struct {
	programTemplatesPath string
}

// NewConfigTranslator creates a new ConfigTranslatorImpl.
func NewConfigTranslator(programTemplatesPath string) (*ConfigTranslatorImpl, error) {
	// Create the program templates directory if it doesn't exist
	if err := os.MkdirAll(programTemplatesPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create program templates directory: %w", err)
	}

	return &ConfigTranslatorImpl{
		programTemplatesPath: programTemplatesPath,
	}, nil
}

// TranslateEBPFProgram translates an EBPFProgram CRD to a Program.
func (c *ConfigTranslatorImpl) TranslateEBPFProgram(config interface{}) (Program, error) {
	// Convert config to EBPFProgramConfig
	progConfig, ok := config.(EBPFProgramConfig)
	if !ok {
		return Program{}, fmt.Errorf("invalid config type: %T", config)
	}

	// Validate config
	if progConfig.Name == "" {
		return Program{}, fmt.Errorf("program name is required")
	}
	if progConfig.Type == "" {
		return Program{}, fmt.Errorf("program type is required")
	}

	// Get the template file based on program type
	templateFile := fmt.Sprintf("%s_template.o", progConfig.Type)
	templatePath := filepath.Join(c.programTemplatesPath, templateFile)

	// Check if template file exists
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		return Program{}, fmt.Errorf("template file %s not found", templateFile)
	}

	// Read the template file
	code, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return Program{}, fmt.Errorf("failed to read template file: %w", err)
	}

	// Create the program
	program := Program{
		Name:      progConfig.Name,
		Type:      progConfig.Type,
		Code:      code,
		Interface: progConfig.Interface,
		Priority:  progConfig.Priority,
		Maps:      []string{}, // Would be determined based on program type and settings
	}

	// Determine required maps based on program type and settings
	switch progConfig.Type {
	case "xdp":
		// Add maps for XDP programs
		if rateLimiting, ok := progConfig.Settings["rateLimiting"].(map[string]interface{}); ok {
			if enabled, ok := rateLimiting["enabled"].(bool); ok && enabled {
				program.Maps = append(program.Maps, fmt.Sprintf("%s_ratelimit", progConfig.Name))
			}
		}
		if blacklist, ok := progConfig.Settings["blacklist"].(map[string]interface{}); ok {
			if enabled, ok := blacklist["enabled"].(bool); ok && enabled {
				program.Maps = append(program.Maps, fmt.Sprintf("%s_blacklist", progConfig.Name))
			}
		}
		if stateful, ok := progConfig.Settings["stateful"].(bool); ok && stateful {
			program.Maps = append(program.Maps, fmt.Sprintf("%s_state", progConfig.Name))
		}
	case "tc-ingress", "tc-egress":
		// Add maps for TC programs
		program.Maps = append(program.Maps, fmt.Sprintf("%s_config", progConfig.Name))
		program.Maps = append(program.Maps, fmt.Sprintf("%s_rules", progConfig.Name))
	case "sockops":
		// Add maps for socket operations programs
		program.Maps = append(program.Maps, fmt.Sprintf("%s_sockets", progConfig.Name))
	case "cgroup":
		// Add maps for cgroup programs
		program.Maps = append(program.Maps, fmt.Sprintf("%s_cgroup", progConfig.Name))
	}

	return program, nil
}

// TranslateTrafficControl translates a TrafficControl CRD to a Program.
func (c *ConfigTranslatorImpl) TranslateTrafficControl(config interface{}) (Program, error) {
	// Convert config to TrafficControlConfig
	tcConfig, ok := config.(TrafficControlConfig)
	if !ok {
		return Program{}, fmt.Errorf("invalid config type: %T", config)
	}

	// Validate config
	if tcConfig.Name == "" {
		return Program{}, fmt.Errorf("traffic control name is required")
	}
	if tcConfig.Interface == "" {
		return Program{}, fmt.Errorf("interface is required")
	}
	if tcConfig.Direction == "" {
		return Program{}, fmt.Errorf("direction is required")
	}

	// Determine program type based on direction
	programType := "tc-ingress"
	if strings.ToLower(tcConfig.Direction) == "egress" {
		programType = "tc-egress"
	}

	// Get the template file based on program type and queueing discipline
	templateFile := fmt.Sprintf("tc_%s_%s_template.o", strings.ToLower(tcConfig.Direction), 
		strings.ToLower(tcConfig.QueueingDiscipline))
	templatePath := filepath.Join(c.programTemplatesPath, templateFile)

	// Check if template file exists, if not, use a default template
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		templateFile = fmt.Sprintf("tc_%s_default_template.o", strings.ToLower(tcConfig.Direction))
		templatePath = filepath.Join(c.programTemplatesPath, templateFile)
		if _, err := os.Stat(templatePath); os.IsNotExist(err) {
			return Program{}, fmt.Errorf("template file %s not found", templateFile)
		}
	}

	// Read the template file
	code, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return Program{}, fmt.Errorf("failed to read template file: %w", err)
	}

	// Create the program
	program := Program{
		Name:      tcConfig.Name,
		Type:      programType,
		Code:      code,
		Interface: tcConfig.Interface,
		Priority:  tcConfig.Priority,
		Maps: []string{
			fmt.Sprintf("%s_config", tcConfig.Name),
			fmt.Sprintf("%s_classes", tcConfig.Name),
			fmt.Sprintf("%s_filters", tcConfig.Name),
		},
	}

	return program, nil
}

// TranslateNATConfig translates a NATConfig CRD to a Program.
func (c *ConfigTranslatorImpl) TranslateNATConfig(config interface{}) (Program, error) {
	// Convert config to NATConfig
	natConfig, ok := config.(NATConfig)
	if !ok {
		return Program{}, fmt.Errorf("invalid config type: %T", config)
	}

	// Validate config
	if natConfig.Name == "" {
		return Program{}, fmt.Errorf("NAT config name is required")
	}
	if len(natConfig.Interfaces) == 0 {
		return Program{}, fmt.Errorf("at least one interface is required")
	}
	if natConfig.Type == "" {
		return Program{}, fmt.Errorf("NAT type is required")
	}

	// Get the source interface
	srcInterface, ok := natConfig.Interfaces["source"]
	if !ok {
		return Program{}, fmt.Errorf("source interface is required")
	}

	// Get the template file based on NAT type and IP version
	templateFile := fmt.Sprintf("nat_%s_%s_template.o", strings.ToLower(natConfig.Type), 
		strings.ToLower(natConfig.IPVersion))
	templatePath := filepath.Join(c.programTemplatesPath, templateFile)

	// Check if template file exists, if not, use a default template
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		templateFile = fmt.Sprintf("nat_%s_default_template.o", strings.ToLower(natConfig.Type))
		templatePath = filepath.Join(c.programTemplatesPath, templateFile)
		if _, err := os.Stat(templatePath); os.IsNotExist(err) {
			return Program{}, fmt.Errorf("template file %s not found", templateFile)
		}
	}

	// Read the template file
	code, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return Program{}, fmt.Errorf("failed to read template file: %w", err)
	}

	// Create the program
	program := Program{
		Name:      natConfig.Name,
		Type:      "tc-ingress", // NAT programs typically use TC hooks
		Code:      code,
		Interface: srcInterface,
		Priority:  10, // Default priority
		Maps: []string{
			fmt.Sprintf("%s_config", natConfig.Name),
			fmt.Sprintf("%s_translations", natConfig.Name),
			fmt.Sprintf("%s_portmap", natConfig.Name),
		},
	}

	return program, nil
}
