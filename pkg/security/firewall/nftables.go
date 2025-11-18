package firewall

// DEPRECATED: Use Cilium's eBPF-based firewall through the pkg/cilium package instead.
// This file is kept for reference but should not be used in new code.

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// NFTablesFirewall implements firewall functionality using nftables
type NFTablesFirewall struct {
	// Dependencies could be injected here
}

// NewNFTablesFirewall creates a new NFTables firewall instance
func NewNFTablesFirewall() *NFTablesFirewall {
	return &NFTablesFirewall{}
}

// InitializeFirewall sets up the basic nftables structure
func (f *NFTablesFirewall) InitializeFirewall() error {
	// Create the base tables
	if err := f.setupBaseTables(); err != nil {
		return fmt.Errorf("failed to set up base tables: %w", err)
	}

	// Create standard chains
	if err := f.setupStandardChains(); err != nil {
		return fmt.Errorf("failed to set up standard chains: %w", err)
	}

	// Set up base policies
	if err := f.setupBasePolicies(); err != nil {
		return fmt.Errorf("failed to set up base policies: %w", err)
	}

	return nil
}

// AddRule adds a firewall rule
func (f *NFTablesFirewall) AddRule(rule FirewallRule) error {
	// Convert the rule to an nftables command
	cmd, err := f.buildRuleCommand(rule)
	if err != nil {
		return fmt.Errorf("failed to build rule command: %w", err)
	}

	// Execute the nftables command
	if err := exec.Command("nft", cmd...).Run(); err != nil {
		return fmt.Errorf("failed to add rule: %w", err)
	}

	return nil
}

// DeleteRule deletes a firewall rule by handle
func (f *NFTablesFirewall) DeleteRule(family, table, chain string, handle int) error {
	cmd := exec.Command("nft", "delete", "rule", family, table, chain, "handle", strconv.Itoa(handle))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	return nil
}

// ListRules lists all firewall rules
func (f *NFTablesFirewall) ListRules() ([]string, error) {
	cmd := exec.Command("nft", "list", "ruleset")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	// Parse the output
	var rules []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "ip") || strings.Contains(line, "ip6") {
			rules = append(rules, strings.TrimSpace(line))
		}
	}

	return rules, nil
}

// CreateIPSet creates a new IP set
func (f *NFTablesFirewall) CreateIPSet(name string, ipVersion string, entries []string) error {
	// Determine the appropriate family
	family := "ip"
	if ipVersion == "ipv6" {
		family = "ip6"
	}

	// Create the set
	createSet := exec.Command("nft", "add", "set", family, "filter", name, "{ type ipv4_addr; }")
	if ipVersion == "ipv6" {
		createSet = exec.Command("nft", "add", "set", family, "filter", name, "{ type ipv6_addr; }")
	}

	if err := createSet.Run(); err != nil {
		return fmt.Errorf("failed to create IP set: %w", err)
	}

	// Add entries to the set
	for _, entry := range entries {
		addEntry := exec.Command("nft", "add", "element", family, "filter", name, "{ "+entry+" }")
		if err := addEntry.Run(); err != nil {
			return fmt.Errorf("failed to add entry to IP set: %w", err)
		}
	}

	return nil
}

// DeleteIPSet deletes an IP set
func (f *NFTablesFirewall) DeleteIPSet(name string, ipVersion string) error {
	// Determine the appropriate family
	family := "ip"
	if ipVersion == "ipv6" {
		family = "ip6"
	}

	// Delete the set
	deleteSet := exec.Command("nft", "delete", "set", family, "filter", name)
	if err := deleteSet.Run(); err != nil {
		return fmt.Errorf("failed to delete IP set: %w", err)
	}

	return nil
}

// AddIPToSet adds an IP address to an existing set
func (f *NFTablesFirewall) AddIPToSet(name string, ipVersion string, ip string) error {
	// Determine the appropriate family
	family := "ip"
	if ipVersion == "ipv6" {
		family = "ip6"
	}

	// Add the IP to the set
	addIP := exec.Command("nft", "add", "element", family, "filter", name, "{ "+ip+" }")
	if err := addIP.Run(); err != nil {
		return fmt.Errorf("failed to add IP to set: %w", err)
	}

	return nil
}

// RemoveIPFromSet removes an IP address from an existing set
func (f *NFTablesFirewall) RemoveIPFromSet(name string, ipVersion string, ip string) error {
	// Determine the appropriate family
	family := "ip"
	if ipVersion == "ipv6" {
		family = "ip6"
	}

	// Delete the IP from the set
	deleteIP := exec.Command("nft", "delete", "element", family, "filter", name, "{ "+ip+" }")
	if err := deleteIP.Run(); err != nil {
		return fmt.Errorf("failed to remove IP from set: %w", err)
	}

	return nil
}

// CreateZone creates a new zone
func (f *NFTablesFirewall) CreateZone(name string, interfaces []string, defaultAction string) error {
	// Create a chain for forward and input for this zone
	for _, family := range []string{"ip", "ip6"} {
		// Create input chain
		createInputChain := exec.Command("nft", "add", "chain", family, "filter", fmt.Sprintf("input_%s", name), "{ type filter hook input priority 0; }")
		if err := createInputChain.Run(); err != nil {
			return fmt.Errorf("failed to create input chain for zone: %w", err)
		}

		// Create forward chain
		createForwardChain := exec.Command("nft", "add", "chain", family, "filter", fmt.Sprintf("forward_%s", name), "{ type filter hook forward priority 0; }")
		if err := createForwardChain.Run(); err != nil {
			return fmt.Errorf("failed to create forward chain for zone: %w", err)
		}

		// Add default action
		defaultRule := exec.Command("nft", "add", "rule", family, "filter", fmt.Sprintf("forward_%s", name), fmt.Sprintf("counter %s", defaultAction))
		if err := defaultRule.Run(); err != nil {
			return fmt.Errorf("failed to set default action for zone: %w", err)
		}
	}

	// Associate interfaces with the zone
	for _, iface := range interfaces {
		for _, family := range []string{"ip", "ip6"} {
			// Add input rule for interface
			inputRule := exec.Command("nft", "add", "rule", family, "filter", "input", fmt.Sprintf("iifname %s jump input_%s", iface, name))
			if err := inputRule.Run(); err != nil {
				return fmt.Errorf("failed to add input rule for interface: %w", err)
			}

			// Add forward rule for interface
			forwardRule := exec.Command("nft", "add", "rule", family, "filter", "forward", fmt.Sprintf("iifname %s jump forward_%s", iface, name))
			if err := forwardRule.Run(); err != nil {
				return fmt.Errorf("failed to add forward rule for interface: %w", err)
			}
		}
	}

	return nil
}

// DeleteZone deletes a zone
func (f *NFTablesFirewall) DeleteZone(name string) error {
	// Delete the chains for this zone
	for _, family := range []string{"ip", "ip6"} {
		// Delete input chain
		deleteInputChain := exec.Command("nft", "delete", "chain", family, "filter", fmt.Sprintf("input_%s", name))
		if err := deleteInputChain.Run(); err != nil {
			return fmt.Errorf("failed to delete input chain for zone: %w", err)
		}

		// Delete forward chain
		deleteForwardChain := exec.Command("nft", "delete", "chain", family, "filter", fmt.Sprintf("forward_%s", name))
		if err := deleteForwardChain.Run(); err != nil {
			return fmt.Errorf("failed to delete forward chain for zone: %w", err)
		}
	}

	return nil
}

// AddInterfaceToZone adds an interface to a zone
func (f *NFTablesFirewall) AddInterfaceToZone(zone, iface string) error {
	for _, family := range []string{"ip", "ip6"} {
		// Add input rule for interface
		inputRule := exec.Command("nft", "add", "rule", family, "filter", "input", fmt.Sprintf("iifname %s jump input_%s", iface, zone))
		if err := inputRule.Run(); err != nil {
			return fmt.Errorf("failed to add input rule for interface: %w", err)
		}

		// Add forward rule for interface
		forwardRule := exec.Command("nft", "add", "rule", family, "filter", "forward", fmt.Sprintf("iifname %s jump forward_%s", iface, zone))
		if err := forwardRule.Run(); err != nil {
			return fmt.Errorf("failed to add forward rule for interface: %w", err)
		}
	}

	return nil
}

// RemoveInterfaceFromZone removes an interface from a zone
func (f *NFTablesFirewall) RemoveInterfaceFromZone(zone, iface string) error {
	// Find and delete the rules for this interface
	for _, family := range []string{"ip", "ip6"} {
		// Get the ruleset
		cmd := exec.Command("nft", "-a", "list", "ruleset")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to list ruleset: %w", err)
		}

		// Find input rules for this interface and zone
		inputRegex := regexp.MustCompile(fmt.Sprintf(`iifname "%s" jump input_%s # handle ([0-9]+)`, regexp.QuoteMeta(iface), regexp.QuoteMeta(zone)))
		inputMatches := inputRegex.FindStringSubmatch(string(output))
		if len(inputMatches) >= 2 {
			handle := inputMatches[1]
			deleteRule := exec.Command("nft", "delete", "rule", family, "filter", "input", "handle", handle)
			if err := deleteRule.Run(); err != nil {
				return fmt.Errorf("failed to delete input rule: %w", err)
			}
		}

		// Find forward rules for this interface and zone
		forwardRegex := regexp.MustCompile(fmt.Sprintf(`iifname "%s" jump forward_%s # handle ([0-9]+)`, regexp.QuoteMeta(iface), regexp.QuoteMeta(zone)))
		forwardMatches := forwardRegex.FindStringSubmatch(string(output))
		if len(forwardMatches) >= 2 {
			handle := forwardMatches[1]
			deleteRule := exec.Command("nft", "delete", "rule", family, "filter", "forward", "handle", handle)
			if err := deleteRule.Run(); err != nil {
				return fmt.Errorf("failed to delete forward rule: %w", err)
			}
		}
	}

	return nil
}

// setupBaseTables sets up the base tables for nftables
func (f *NFTablesFirewall) setupBaseTables() error {
	// Create filter table for IPv4
	createIPTable := exec.Command("nft", "add", "table", "ip", "filter")
	if err := createIPTable.Run(); err != nil {
		return fmt.Errorf("failed to create IPv4 filter table: %w", err)
	}

	// Create filter table for IPv6
	createIP6Table := exec.Command("nft", "add", "table", "ip6", "filter")
	if err := createIP6Table.Run(); err != nil {
		return fmt.Errorf("failed to create IPv6 filter table: %w", err)
	}

	// Create nat table for IPv4
	createNatTable := exec.Command("nft", "add", "table", "ip", "nat")
	if err := createNatTable.Run(); err != nil {
		return fmt.Errorf("failed to create IPv4 nat table: %w", err)
	}

	// Create nat table for IPv6
	createNat6Table := exec.Command("nft", "add", "table", "ip6", "nat")
	if err := createNat6Table.Run(); err != nil {
		return fmt.Errorf("failed to create IPv6 nat table: %w", err)
	}

	return nil
}

// setupStandardChains sets up the standard chains for nftables
func (f *NFTablesFirewall) setupStandardChains() error {
	// Create chains for IPv4 filter
	chains := []struct {
		family   string
		table    string
		chain    string
		hookType string
		priority int
	}{
		{"ip", "filter", "input", "input", 0},
		{"ip", "filter", "forward", "forward", 0},
		{"ip", "filter", "output", "output", 0},
		{"ip6", "filter", "input", "input", 0},
		{"ip6", "filter", "forward", "forward", 0},
		{"ip6", "filter", "output", "output", 0},
		{"ip", "nat", "prerouting", "prerouting", 0},
		{"ip", "nat", "postrouting", "postrouting", 100},
		{"ip6", "nat", "prerouting", "prerouting", 0},
		{"ip6", "nat", "postrouting", "postrouting", 100},
	}

	for _, c := range chains {
		createChain := exec.Command("nft", "add", "chain", c.family, c.table, c.chain,
			fmt.Sprintf("{ type filter hook %s priority %d; }", c.hookType, c.priority))
		if err := createChain.Run(); err != nil {
			return fmt.Errorf("failed to create chain %s: %w", c.chain, err)
		}
	}

	return nil
}

// setupBasePolicies sets up the base policies for nftables
func (f *NFTablesFirewall) setupBasePolicies() error {
	// Set up connection tracking rules for IPv4
	conntrackRules := []struct {
		family string
		table  string
		chain  string
		rule   string
	}{
		{"ip", "filter", "input", "ct state established,related accept"},
		{"ip", "filter", "input", "ct state invalid drop"},
		{"ip", "filter", "forward", "ct state established,related accept"},
		{"ip", "filter", "forward", "ct state invalid drop"},
		{"ip6", "filter", "input", "ct state established,related accept"},
		{"ip6", "filter", "input", "ct state invalid drop"},
		{"ip6", "filter", "forward", "ct state established,related accept"},
		{"ip6", "filter", "forward", "ct state invalid drop"},
	}

	for _, rule := range conntrackRules {
		cmd := exec.Command("nft", "add", "rule", rule.family, rule.table, rule.chain, rule.rule)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add rule: %w", err)
		}
	}

	return nil
}

// buildRuleCommand builds an nftables command from a firewall rule
func (f *NFTablesFirewall) buildRuleCommand(rule FirewallRule) ([]string, error) {
	// Determine the family
	family := "ip"
	if rule.IPVersion == "ipv6" {
		family = "ip6"
	} else if rule.IPVersion == "both" {
		// For "both", we'll need to create two rules - for now, just handle IPv4
		// In a real implementation, you'd create rules for both IPv4 and IPv6
	}

	// Determine the chain
	chain := "forward" // default to forward
	if rule.SourceType == "zone" && rule.DestinationType == "zone" {
		// Inter-zone traffic
		chain = fmt.Sprintf("forward_%s", rule.Source)
	}

	// Start building the command
	cmd := []string{"add", "rule", family, "filter", chain}

	// Add source matching if specified
	if rule.SourceType != "any" && rule.Source != "" {
		switch rule.SourceType {
		case "interface":
			cmd = append(cmd, fmt.Sprintf("iifname %s", rule.Source))
		case "zone":
			// Already handled in chain selection
		case "network":
			cmd = append(cmd, fmt.Sprintf("ip saddr %s", rule.Source))
		case "ipset":
			cmd = append(cmd, fmt.Sprintf("ip saddr @%s", rule.Source))
		}
	}

	// Add source port if specified
	if rule.SourcePort != "" {
		if rule.Protocol == "tcp" || rule.Protocol == "udp" {
			cmd = append(cmd, fmt.Sprintf("%s sport %s", rule.Protocol, rule.SourcePort))
		} else {
			return nil, fmt.Errorf("source port specified without tcp/udp protocol")
		}
	}

	// Add destination matching if specified
	if rule.DestinationType != "any" && rule.Destination != "" {
		switch rule.DestinationType {
		case "interface":
			cmd = append(cmd, fmt.Sprintf("oifname %s", rule.Destination))
		case "zone":
			// For zone-to-zone, we'd need more complex logic
			// This is simplified for the example
		case "network":
			cmd = append(cmd, fmt.Sprintf("ip daddr %s", rule.Destination))
		case "ipset":
			cmd = append(cmd, fmt.Sprintf("ip daddr @%s", rule.Destination))
		}
	}

	// Add destination port if specified
	if rule.DestinationPort != "" {
		if rule.Protocol == "tcp" || rule.Protocol == "udp" {
			cmd = append(cmd, fmt.Sprintf("%s dport %s", rule.Protocol, rule.DestinationPort))
		} else {
			return nil, fmt.Errorf("destination port specified without tcp/udp protocol")
		}
	}

	// Add protocol if specified and not already added by port rules
	if rule.Protocol != "any" && rule.SourcePort == "" && rule.DestinationPort == "" {
		cmd = append(cmd, fmt.Sprintf("meta l4proto %s", rule.Protocol))
	}

	// Add connection tracking state if specified
	if rule.State != nil {
		states := []string{}
		if rule.State.New {
			states = append(states, "new")
		}
		if rule.State.Established {
			states = append(states, "established")
		}
		if rule.State.Related {
			states = append(states, "related")
		}
		if rule.State.Invalid {
			states = append(states, "invalid")
		}
		if len(states) > 0 {
			cmd = append(cmd, fmt.Sprintf("ct state %s", strings.Join(states, ",")))
		}
	}

	// Add logging if enabled
	if rule.Logging {
		cmd = append(cmd, "log prefix", fmt.Sprintf("\"rule-%s: \"", rule.Name))
	}

	// Add counter
	cmd = append(cmd, "counter")

	// Add action
	cmd = append(cmd, rule.Action)

	return cmd, nil
}

// FirewallRule represents a firewall rule
type FirewallRule struct {
	Name                string
	Description         string
	Enabled             bool
	Action              string // accept, drop, reject, log
	Protocol            string // tcp, udp, icmp, icmpv6, any
	SourceType          string // interface, zone, network, ipset, any
	Source              string
	SourcePort          string
	DestinationType     string // interface, zone, network, ipset, any
	Destination         string
	DestinationPort     string
	IPVersion           string // ipv4, ipv6, both
	State               *ConnectionState
	Application         string // DPI-based application match
	ApplicationCategory string // DPI-based application category match
	DSCP                int
	Logging             bool
	Priority            int
	TimeSchedule        string
}

// ConnectionState represents connection tracking states
type ConnectionState struct {
	New         bool
	Established bool
	Related     bool
	Invalid     bool
}
