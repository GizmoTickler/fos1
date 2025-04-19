package traffic

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"k8s.io/klog/v2"
)

// classifier implements the Classifier interface
type classifier struct {
	mutex sync.RWMutex
	rules map[string]ClassificationRule // key: rule name
}

// NewClassifier creates a new traffic classifier
func NewClassifier() Classifier {
	return &classifier{
		rules: make(map[string]ClassificationRule),
	}
}

// ClassifyPacket classifies a packet
func (c *classifier) ClassifyPacket(packet PacketInfo) (string, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Get all rules
	rules := make([]ClassificationRule, 0, len(c.rules))
	for _, rule := range c.rules {
		rules = append(rules, rule)
	}

	// Sort rules by priority
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	// Check each rule
	for _, rule := range rules {
		if c.matchesRule(packet, rule) {
			return rule.ClassName, nil
		}
	}

	// No matching rule
	return "", nil
}

// AddClassificationRule adds a classification rule
func (c *classifier) AddClassificationRule(rule ClassificationRule) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if the rule already exists
	if _, exists := c.rules[rule.Name]; exists {
		// Update the rule
		c.rules[rule.Name] = rule
		return nil
	}

	// Add the rule
	c.rules[rule.Name] = rule
	return nil
}

// RemoveClassificationRule removes a classification rule
func (c *classifier) RemoveClassificationRule(ruleName string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if the rule exists
	if _, exists := c.rules[ruleName]; !exists {
		return fmt.Errorf("classification rule %s does not exist", ruleName)
	}

	// Remove the rule
	delete(c.rules, ruleName)
	return nil
}

// ListClassificationRules lists all classification rules
func (c *classifier) ListClassificationRules() ([]ClassificationRule, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	rules := make([]ClassificationRule, 0, len(c.rules))
	for _, rule := range c.rules {
		rules = append(rules, rule)
	}

	return rules, nil
}

// matchesRule checks if a packet matches a rule
func (c *classifier) matchesRule(packet PacketInfo, rule ClassificationRule) bool {
	// Check source addresses
	if len(rule.SourceAddresses) > 0 {
		matched := false
		for _, addr := range rule.SourceAddresses {
			if c.ipInNetwork(packet.SourceIP, addr) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check destination addresses
	if len(rule.DestinationAddresses) > 0 {
		matched := false
		for _, addr := range rule.DestinationAddresses {
			if c.ipInNetwork(packet.DestinationIP, addr) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check protocol
	if rule.Protocol != "" && rule.Protocol != "any" && !strings.EqualFold(packet.Protocol, rule.Protocol) {
		return false
	}

	// Check source ports
	if len(rule.SourcePorts) > 0 {
		matched := false
		for _, portRange := range rule.SourcePorts {
			if c.portInRange(packet.SourcePort, portRange) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check destination ports
	if len(rule.DestinationPorts) > 0 {
		matched := false
		for _, portRange := range rule.DestinationPorts {
			if c.portInRange(packet.DestinationPort, portRange) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check applications
	if len(rule.Applications) > 0 {
		if packet.Application == "" {
			return false
		}

		matched := false
		for _, app := range rule.Applications {
			if strings.EqualFold(packet.Application, app) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check application categories
	if len(rule.ApplicationCategories) > 0 {
		if packet.ApplicationCategory == "" {
			return false
		}

		matched := false
		for _, category := range rule.ApplicationCategories {
			if strings.EqualFold(packet.ApplicationCategory, category) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check DSCP
	if rule.DSCP > 0 && packet.DSCP != rule.DSCP {
		return false
	}

	// All checks passed
	return true
}

// ipInNetwork checks if an IP address is in a network
func (c *classifier) ipInNetwork(ipStr, networkStr string) bool {
	// Parse IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Parse network
	_, network, err := net.ParseCIDR(networkStr)
	if err != nil {
		// Try as a single IP
		networkIP := net.ParseIP(networkStr)
		if networkIP == nil {
			return false
		}
		return ip.Equal(networkIP)
	}

	// Check if IP is in network
	return network.Contains(ip)
}

// portInRange checks if a port is in a port range
func (c *classifier) portInRange(port int, portRange string) bool {
	// Check if it's a single port
	if !strings.Contains(portRange, "-") {
		rangePort, err := strconv.Atoi(portRange)
		if err != nil {
			return false
		}
		return port == rangePort
	}

	// Parse port range
	parts := strings.Split(portRange, "-")
	if len(parts) != 2 {
		return false
	}

	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}

	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	// Check if port is in range
	return port >= start && port <= end
}
