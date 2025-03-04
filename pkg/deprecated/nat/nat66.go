package nat

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// NAT66Manager handles IPv6 Network Address Translation
type NAT66Manager struct {
	// Dependencies could be injected here
}

// NewNAT66Manager creates a new NAT66 manager
func NewNAT66Manager() *NAT66Manager {
	return &NAT66Manager{}
}

// EnableNAT66 enables NAT66 for a source network to a destination interface
func (m *NAT66Manager) EnableNAT66(sourceNetwork, outInterface string) error {
	// Validate the source network
	if !isValidIPv6Network(sourceNetwork) {
		return fmt.Errorf("invalid IPv6 network: %s", sourceNetwork)
	}

	// Check if the interface exists
	if err := m.checkInterfaceExists(outInterface); err != nil {
		return fmt.Errorf("interface check failed: %w", err)
	}

	// Enable IPv6 forwarding
	if err := m.enableIPv6Forwarding(); err != nil {
		return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
	}

	// Create NAT66 rule with nftables
	err := m.createNFTNAT66Rule(sourceNetwork, outInterface)
	if err != nil {
		return fmt.Errorf("failed to create NFT NAT66 rule: %w", err)
	}

	return nil
}

// DisableNAT66 disables NAT66 for a source network to a destination interface
func (m *NAT66Manager) DisableNAT66(sourceNetwork, outInterface string) error {
	// Remove NFT NAT66 rule
	err := m.removeNFTNAT66Rule(sourceNetwork, outInterface)
	if err != nil {
		return fmt.Errorf("failed to remove NFT NAT66 rule: %w", err)
	}

	return nil
}

// ListNAT66Rules lists all NAT66 rules
func (m *NAT66Manager) ListNAT66Rules() ([]string, error) {
	// List NFT NAT66 rules
	cmd := exec.Command("nft", "list", "table", "ip6", "nat")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list NAT66 rules: %w", err)
	}

	// Parse the output
	var rules []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "masquerade") {
			rules = append(rules, strings.TrimSpace(line))
		}
	}

	return rules, nil
}

// enableIPv6Forwarding enables IPv6 forwarding
func (m *NAT66Manager) enableIPv6Forwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
	}
	return nil
}

// checkInterfaceExists checks if an interface exists
func (m *NAT66Manager) checkInterfaceExists(name string) error {
	cmd := exec.Command("ip", "link", "show", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("interface %s does not exist", name)
	}
	return nil
}

// createNFTNAT66Rule creates a NAT66 rule with nftables
func (m *NAT66Manager) createNFTNAT66Rule(sourceNetwork, outInterface string) error {
	// Create NAT table if it doesn't exist
	createTable := exec.Command("nft", "add", "table", "ip6", "nat")
	_ = createTable.Run() // Ignore error if table already exists

	// Create postrouting chain if it doesn't exist
	createChain := exec.Command("nft", "add", "chain", "ip6", "nat", "postrouting", "{ type nat hook postrouting priority 100; }")
	_ = createChain.Run() // Ignore error if chain already exists

	// Add masquerade rule
	addRule := exec.Command("nft", "add", "rule", "ip6", "nat", "postrouting", 
		fmt.Sprintf("ip6 saddr %s oif %s counter masquerade", sourceNetwork, outInterface))
	
	if err := addRule.Run(); err != nil {
		return fmt.Errorf("failed to add NFT masquerade rule: %w", err)
	}

	return nil
}

// removeNFTNAT66Rule removes a NAT66 rule with nftables
func (m *NAT66Manager) removeNFTNAT66Rule(sourceNetwork, outInterface string) error {
	// First try to find the rule handle
	listCmd := exec.Command("nft", "-a", "list", "table", "ip6", "nat")
	output, err := listCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list NAT66 rules: %w", err)
	}

	// Parse output to find the rule handle
	rulePattern := fmt.Sprintf("ip6 saddr %s oif %s counter masquerade # handle ([0-9]+)", 
		regexp.QuoteMeta(sourceNetwork), regexp.QuoteMeta(outInterface))
	re := regexp.MustCompile(rulePattern)
	matches := re.FindStringSubmatch(string(output))

	if len(matches) < 2 {
		return fmt.Errorf("failed to find NAT66 rule for %s via %s", sourceNetwork, outInterface)
	}

	handle := matches[1]

	// Delete the rule
	delRule := exec.Command("nft", "delete", "rule", "ip6", "nat", "postrouting", "handle", handle)
	if err := delRule.Run(); err != nil {
		return fmt.Errorf("failed to delete NFT masquerade rule: %w", err)
	}

	return nil
}

// isValidIPv6Network validates an IPv6 network
func isValidIPv6Network(network string) bool {
	// Very basic validation - in a real implementation, use a proper IPv6 CIDR validator
	return strings.Contains(network, ":")
}