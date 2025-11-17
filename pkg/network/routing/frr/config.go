package frr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// ConfigGenerator generates FRR configuration files
type ConfigGenerator struct {
	configPath string
}

// NewConfigGenerator creates a new configuration generator
func NewConfigGenerator(configPath string) *ConfigGenerator {
	return &ConfigGenerator{
		configPath: configPath,
	}
}

// GenerateDaemonsFile generates the daemons configuration file
// This file controls which FRR daemons are enabled
func (g *ConfigGenerator) GenerateDaemonsFile(enabledDaemons map[DaemonType]bool) error {
	daemonsPath := filepath.Join(g.configPath, "daemons")

	content := strings.Builder{}
	content.WriteString("# FRR daemons configuration file\n")
	content.WriteString("# This file tells the frr package which daemons to start.\n\n")

	// Define all daemons with their defaults
	allDaemons := map[DaemonType]string{
		DaemonTypeZEBRA:    "zebra",
		DaemonTypeBGPD:     "bgpd",
		DaemonTypeOSPFD:    "ospfd",
		DaemonTypeOSPF6D:   "ospf6d",
		DaemonTypeRIPD:     "ripd",
		DaemonTypeRIPNGD:   "ripngd",
		DaemonTypeISISD:    "isisd",
		DaemonTypePIMD:     "pimd",
		DaemonTypeLDPD:     "ldpd",
		DaemonTypeNHRPD:    "nhrpd",
		DaemonTypeBFDD:     "bfdd",
		DaemonTypeFABRICD:  "fabricd",
	}

	// Zebra is always enabled
	content.WriteString("zebra=yes\n")

	// Write enabled status for each daemon
	for daemon, name := range allDaemons {
		if daemon == DaemonTypeZEBRA {
			continue // Already written
		}
		enabled := "no"
		if enabledDaemons[daemon] {
			enabled = "yes"
		}
		content.WriteString(fmt.Sprintf("%s=%s\n", name, enabled))
	}

	// Add vtysh configuration
	content.WriteString("\n# Enable integrated vtysh config\n")
	content.WriteString("vtysh_enable=yes\n")
	content.WriteString("zebra_options=\"  -A 127.0.0.1 -s 90000000\"\n")
	content.WriteString("bgpd_options=\"   -A 127.0.0.1\"\n")
	content.WriteString("ospfd_options=\"  -A 127.0.0.1\"\n")
	content.WriteString("ospf6d_options=\" -A ::1\"\n")
	content.WriteString("ripd_options=\"   -A 127.0.0.1\"\n")
	content.WriteString("ripngd_options=\" -A ::1\"\n")
	content.WriteString("isisd_options=\"  -A 127.0.0.1\"\n")
	content.WriteString("pimd_options=\"   -A 127.0.0.1\"\n")
	content.WriteString("ldpd_options=\"   -A 127.0.0.1\"\n")
	content.WriteString("nhrpd_options=\"  -A 127.0.0.1\"\n")
	content.WriteString("bfdd_options=\"   -A 127.0.0.1\"\n")
	content.WriteString("fabricd_options=\"-A 127.0.0.1\"\n")

	// Write to file
	if err := os.WriteFile(daemonsPath, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write daemons file: %w", err)
	}

	klog.V(2).Infof("Generated daemons configuration file: %s", daemonsPath)
	return nil
}

// GenerateFRRConf generates the main frr.conf configuration file
func (g *ConfigGenerator) GenerateFRRConf(config *Config) error {
	confPath := filepath.Join(g.configPath, "frr.conf")

	content := strings.Builder{}

	// Write header
	content.WriteString("!\n")
	content.WriteString("! FRRouting configuration file\n")
	content.WriteString("!\n")

	// Write hostname
	if config.Hostname != "" {
		content.WriteString(fmt.Sprintf("hostname %s\n", config.Hostname))
	}

	// Write passwords
	if config.Password != "" {
		content.WriteString(fmt.Sprintf("password %s\n", config.Password))
	}
	if config.EnablePassword != "" {
		content.WriteString(fmt.Sprintf("enable password %s\n", config.EnablePassword))
	}

	// Write logging configuration
	if config.LogFile != "" {
		content.WriteString(fmt.Sprintf("log file %s\n", config.LogFile))
	}
	if config.LogLevel != "" {
		content.WriteString(fmt.Sprintf("log %s\n", config.LogLevel))
	}

	content.WriteString("!\n")

	// Write configuration sections
	for _, section := range config.Sections {
		g.writeConfigSection(&content, &section, 0)
	}

	// Write footer
	content.WriteString("!\n")
	content.WriteString("line vty\n")
	content.WriteString("!\n")

	// Write to file
	if err := os.WriteFile(confPath, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write frr.conf: %w", err)
	}

	klog.V(2).Infof("Generated FRR configuration file: %s", confPath)
	return nil
}

// writeConfigSection writes a configuration section recursively
func (g *ConfigGenerator) writeConfigSection(sb *strings.Builder, section *ConfigSection, indent int) {
	indentStr := strings.Repeat(" ", indent)

	// Write section header
	sb.WriteString(fmt.Sprintf("%s%s\n", indentStr, section.Name))

	// Write commands
	for _, cmd := range section.Commands {
		sb.WriteString(fmt.Sprintf("%s %s\n", indentStr, cmd))
	}

	// Write subsections
	for _, subsection := range section.Subsections {
		g.writeConfigSection(sb, &subsection, indent+1)
	}

	// Write section footer if needed
	if indent > 0 {
		sb.WriteString(fmt.Sprintf("%sexit\n", indentStr))
	}
	sb.WriteString("!\n")
}

// GenerateBGPConfig generates BGP configuration section
func (g *ConfigGenerator) GenerateBGPConfig(asn uint32, routerID string, neighbors []BGPNeighbor, addressFamilies []BGPAddressFamily) *ConfigSection {
	section := &ConfigSection{
		Name:     fmt.Sprintf("router bgp %d", asn),
		Commands: []string{},
	}

	// Add router ID
	section.Commands = append(section.Commands, fmt.Sprintf("bgp router-id %s", routerID))

	// Add neighbors
	for _, neighbor := range neighbors {
		section.Commands = append(section.Commands,
			fmt.Sprintf("neighbor %s remote-as %d", neighbor.Address, neighbor.RemoteASNumber))

		if neighbor.Description != "" {
			section.Commands = append(section.Commands,
				fmt.Sprintf("neighbor %s description %s", neighbor.Address, neighbor.Description))
		}

		if neighbor.KeepaliveInterval > 0 && neighbor.HoldTime > 0 {
			section.Commands = append(section.Commands,
				fmt.Sprintf("neighbor %s timers %d %d", neighbor.Address, neighbor.KeepaliveInterval, neighbor.HoldTime))
		}

		if neighbor.BFDEnabled {
			section.Commands = append(section.Commands,
				fmt.Sprintf("neighbor %s bfd", neighbor.Address))
		}

		if neighbor.RouteMapIn != "" {
			section.Commands = append(section.Commands,
				fmt.Sprintf("neighbor %s route-map %s in", neighbor.Address, neighbor.RouteMapIn))
		}

		if neighbor.RouteMapOut != "" {
			section.Commands = append(section.Commands,
				fmt.Sprintf("neighbor %s route-map %s out", neighbor.Address, neighbor.RouteMapOut))
		}
	}

	// Add address families
	for _, af := range addressFamilies {
		if !af.Enabled {
			continue
		}

		afSection := ConfigSection{
			Name:     fmt.Sprintf("address-family %s", af.Type),
			Commands: []string{},
		}

		// Add networks
		for _, network := range af.Networks {
			afSection.Commands = append(afSection.Commands, fmt.Sprintf("network %s", network))
		}

		// Add redistributions
		for _, redist := range af.Redistributions {
			if redist.RouteMapRef != "" {
				afSection.Commands = append(afSection.Commands,
					fmt.Sprintf("redistribute %s route-map %s", redist.Protocol, redist.RouteMapRef))
			} else {
				afSection.Commands = append(afSection.Commands,
					fmt.Sprintf("redistribute %s", redist.Protocol))
			}
		}

		// Activate neighbors
		for _, neighbor := range neighbors {
			afSection.Commands = append(afSection.Commands,
				fmt.Sprintf("neighbor %s activate", neighbor.Address))
		}

		afSection.Commands = append(afSection.Commands, "exit-address-family")
		section.Subsections = append(section.Subsections, afSection)
	}

	return section
}

// GenerateOSPFConfig generates OSPF configuration section
func (g *ConfigGenerator) GenerateOSPFConfig(routerID string, areas []OSPFArea, redistributions []Redistribution) *ConfigSection {
	section := &ConfigSection{
		Name:     "router ospf",
		Commands: []string{},
	}

	// Add router ID
	section.Commands = append(section.Commands, fmt.Sprintf("ospf router-id %s", routerID))

	// Add networks
	for _, area := range areas {
		for _, intf := range area.Interfaces {
			if intf.Network != "" {
				section.Commands = append(section.Commands,
					fmt.Sprintf("network %s area %s", intf.Network, area.AreaID))
			}
		}

		// Add area properties
		if area.StubArea {
			section.Commands = append(section.Commands, fmt.Sprintf("area %s stub", area.AreaID))
		}
		if area.NSSAArea {
			section.Commands = append(section.Commands, fmt.Sprintf("area %s nssa", area.AreaID))
		}
	}

	// Add redistributions
	for _, redist := range redistributions {
		if redist.RouteMapRef != "" {
			section.Commands = append(section.Commands,
				fmt.Sprintf("redistribute %s route-map %s", redist.Protocol, redist.RouteMapRef))
		} else {
			section.Commands = append(section.Commands,
				fmt.Sprintf("redistribute %s", redist.Protocol))
		}
	}

	return section
}

// GenerateRouteMapConfig generates route-map configuration section
func (g *ConfigGenerator) GenerateRouteMapConfig(routeMap *RouteMap) []ConfigSection {
	sections := []ConfigSection{}

	for _, entry := range routeMap.Entries {
		section := ConfigSection{
			Name:     fmt.Sprintf("route-map %s %s %d", routeMap.Name, entry.Action, entry.Sequence),
			Commands: []string{},
		}

		// Add match conditions
		if entry.Match.Prefix != "" {
			section.Commands = append(section.Commands, fmt.Sprintf("match ip address prefix-list %s", entry.Match.Prefix))
		}
		if entry.Match.Protocol != "" {
			section.Commands = append(section.Commands, fmt.Sprintf("match source-protocol %s", entry.Match.Protocol))
		}
		if entry.Match.Community != "" {
			section.Commands = append(section.Commands, fmt.Sprintf("match community %s", entry.Match.Community))
		}
		if entry.Match.ASPath != "" {
			section.Commands = append(section.Commands, fmt.Sprintf("match as-path %s", entry.Match.ASPath))
		}

		// Add set actions
		if entry.Set.Metric > 0 {
			section.Commands = append(section.Commands, fmt.Sprintf("set metric %d", entry.Set.Metric))
		}
		if entry.Set.LocalPreference > 0 {
			section.Commands = append(section.Commands, fmt.Sprintf("set local-preference %d", entry.Set.LocalPreference))
		}
		if entry.Set.Community != "" {
			section.Commands = append(section.Commands, fmt.Sprintf("set community %s", entry.Set.Community))
		}
		if entry.Set.NextHop != "" {
			section.Commands = append(section.Commands, fmt.Sprintf("set ip next-hop %s", entry.Set.NextHop))
		}
		if entry.Set.Weight > 0 {
			section.Commands = append(section.Commands, fmt.Sprintf("set weight %d", entry.Set.Weight))
		}
		if entry.Set.ASPathPrepend != "" {
			section.Commands = append(section.Commands, fmt.Sprintf("set as-path prepend %s", entry.Set.ASPathPrepend))
		}

		sections = append(sections, section)
	}

	return sections
}

// GenerateInterfaceConfig generates interface configuration
func (g *ConfigGenerator) GenerateInterfaceConfig(interfaceName string, commands []string) *ConfigSection {
	return &ConfigSection{
		Name:     fmt.Sprintf("interface %s", interfaceName),
		Commands: commands,
	}
}

// BackupConfig backs up the current configuration
func (g *ConfigGenerator) BackupConfig() error {
	confPath := filepath.Join(g.configPath, "frr.conf")
	backupPath := filepath.Join(g.configPath, fmt.Sprintf("frr.conf.backup.%d", time.Now().Unix()))

	data, err := os.ReadFile(confPath)
	if err != nil {
		if os.IsNotExist(err) {
			klog.V(2).Info("No existing configuration to backup")
			return nil
		}
		return fmt.Errorf("failed to read config for backup: %w", err)
	}

	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	klog.V(2).Infof("Backed up configuration to: %s", backupPath)
	return nil
}

// ValidateConfig validates the configuration syntax
func (g *ConfigGenerator) ValidateConfig() error {
	// Use vtysh to validate the configuration
	confPath := filepath.Join(g.configPath, "frr.conf")

	// Check if file exists
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file does not exist: %s", confPath)
	}

	// TODO: Add actual validation using vtysh --check or similar
	klog.V(2).Info("Configuration validation not yet implemented")
	return nil
}

// RestoreBackup restores a backup configuration
func (g *ConfigGenerator) RestoreBackup(backupPath string) error {
	confPath := filepath.Join(g.configPath, "frr.conf")

	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	if err := os.WriteFile(confPath, data, 0644); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	klog.V(2).Infof("Restored configuration from: %s", backupPath)
	return nil
}

// GenerateVtyshConf generates the vtysh.conf file
func (g *ConfigGenerator) GenerateVtyshConf() error {
	vtyshPath := filepath.Join(g.configPath, "vtysh.conf")

	content := `! vtysh configuration file
!
service integrated-vtysh-config
!
`

	if err := os.WriteFile(vtyshPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write vtysh.conf: %w", err)
	}

	klog.V(2).Infof("Generated vtysh configuration file: %s", vtyshPath)
	return nil
}
