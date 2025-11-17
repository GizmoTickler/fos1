package nat

import (
	"fmt"
	"sync"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// PortForwardingManager manages port forwarding rules
type PortForwardingManager struct {
	mutex         sync.RWMutex
	rules         map[string]PortForwardingRule // key: externalIP:externalPort:protocol
	ciliumClient  cilium.Client
}

// PortForwardingRule represents a port forwarding rule
type PortForwardingRule struct {
	// ExternalIP is the external IP address
	ExternalIP string
	
	// ExternalPort is the external port
	ExternalPort int
	
	// Protocol is the protocol (tcp, udp)
	Protocol string
	
	// InternalIP is the internal IP address
	InternalIP string
	
	// InternalPort is the internal port
	InternalPort int
	
	// Description is an optional description
	Description string
	
	// Enabled indicates whether the rule is enabled
	Enabled bool
}

// NewPortForwardingManager creates a new port forwarding manager
func NewPortForwardingManager(ciliumClient cilium.Client) *PortForwardingManager {
	return &PortForwardingManager{
		rules:        make(map[string]PortForwardingRule),
		ciliumClient: ciliumClient,
	}
}

// AddRule adds a port forwarding rule
func (m *PortForwardingManager) AddRule(rule PortForwardingRule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Create a key for the rule
	key := fmt.Sprintf("%s:%d:%s", rule.ExternalIP, rule.ExternalPort, rule.Protocol)
	
	// Check if the rule already exists
	if _, exists := m.rules[key]; exists {
		return fmt.Errorf("port forwarding rule already exists: %s", key)
	}
	
	// Store the rule
	m.rules[key] = rule
	
	// Apply the rule if it's enabled
	if rule.Enabled {
		if err := m.applyRule(rule); err != nil {
			delete(m.rules, key)
			return fmt.Errorf("failed to apply port forwarding rule: %w", err)
		}
	}
	
	klog.Infof("Added port forwarding rule: %s -> %s:%d", key, rule.InternalIP, rule.InternalPort)
	return nil
}

// UpdateRule updates a port forwarding rule
func (m *PortForwardingManager) UpdateRule(rule PortForwardingRule) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Create a key for the rule
	key := fmt.Sprintf("%s:%d:%s", rule.ExternalIP, rule.ExternalPort, rule.Protocol)
	
	// Check if the rule exists
	oldRule, exists := m.rules[key]
	if !exists {
		return fmt.Errorf("port forwarding rule does not exist: %s", key)
	}
	
	// Remove the old rule if it was enabled
	if oldRule.Enabled {
		if err := m.removeRule(oldRule); err != nil {
			return fmt.Errorf("failed to remove old port forwarding rule: %w", err)
		}
	}
	
	// Store the new rule
	m.rules[key] = rule
	
	// Apply the new rule if it's enabled
	if rule.Enabled {
		if err := m.applyRule(rule); err != nil {
			// Restore the old rule
			m.rules[key] = oldRule
			if oldRule.Enabled {
				_ = m.applyRule(oldRule)
			}
			return fmt.Errorf("failed to apply port forwarding rule: %w", err)
		}
	}
	
	klog.Infof("Updated port forwarding rule: %s -> %s:%d", key, rule.InternalIP, rule.InternalPort)
	return nil
}

// RemoveRule removes a port forwarding rule
func (m *PortForwardingManager) RemoveRule(externalIP string, externalPort int, protocol string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Create a key for the rule
	key := fmt.Sprintf("%s:%d:%s", externalIP, externalPort, protocol)
	
	// Check if the rule exists
	rule, exists := m.rules[key]
	if !exists {
		return fmt.Errorf("port forwarding rule does not exist: %s", key)
	}
	
	// Remove the rule if it was enabled
	if rule.Enabled {
		if err := m.removeRule(rule); err != nil {
			return fmt.Errorf("failed to remove port forwarding rule: %w", err)
		}
	}
	
	// Remove the rule from the map
	delete(m.rules, key)
	
	klog.Infof("Removed port forwarding rule: %s", key)
	return nil
}

// GetRule gets a port forwarding rule
func (m *PortForwardingManager) GetRule(externalIP string, externalPort int, protocol string) (*PortForwardingRule, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Create a key for the rule
	key := fmt.Sprintf("%s:%d:%s", externalIP, externalPort, protocol)
	
	// Check if the rule exists
	rule, exists := m.rules[key]
	if !exists {
		return nil, fmt.Errorf("port forwarding rule does not exist: %s", key)
	}
	
	// Return a copy of the rule
	ruleCopy := rule
	return &ruleCopy, nil
}

// ListRules lists all port forwarding rules
func (m *PortForwardingManager) ListRules() []PortForwardingRule {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Create a list of rules
	rules := make([]PortForwardingRule, 0, len(m.rules))
	for _, rule := range m.rules {
		rules = append(rules, rule)
	}
	
	return rules
}

// EnableRule enables a port forwarding rule
func (m *PortForwardingManager) EnableRule(externalIP string, externalPort int, protocol string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Create a key for the rule
	key := fmt.Sprintf("%s:%d:%s", externalIP, externalPort, protocol)
	
	// Check if the rule exists
	rule, exists := m.rules[key]
	if !exists {
		return fmt.Errorf("port forwarding rule does not exist: %s", key)
	}
	
	// Check if the rule is already enabled
	if rule.Enabled {
		return nil
	}
	
	// Enable the rule
	rule.Enabled = true
	
	// Apply the rule
	if err := m.applyRule(rule); err != nil {
		rule.Enabled = false
		m.rules[key] = rule
		return fmt.Errorf("failed to apply port forwarding rule: %w", err)
	}
	
	// Store the updated rule
	m.rules[key] = rule
	
	klog.Infof("Enabled port forwarding rule: %s", key)
	return nil
}

// DisableRule disables a port forwarding rule
func (m *PortForwardingManager) DisableRule(externalIP string, externalPort int, protocol string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Create a key for the rule
	key := fmt.Sprintf("%s:%d:%s", externalIP, externalPort, protocol)
	
	// Check if the rule exists
	rule, exists := m.rules[key]
	if !exists {
		return fmt.Errorf("port forwarding rule does not exist: %s", key)
	}
	
	// Check if the rule is already disabled
	if !rule.Enabled {
		return nil
	}
	
	// Disable the rule
	rule.Enabled = false
	
	// Remove the rule
	if err := m.removeRule(rule); err != nil {
		rule.Enabled = true
		m.rules[key] = rule
		return fmt.Errorf("failed to remove port forwarding rule: %w", err)
	}
	
	// Store the updated rule
	m.rules[key] = rule
	
	klog.Infof("Disabled port forwarding rule: %s", key)
	return nil
}

// applyRule applies a port forwarding rule
func (m *PortForwardingManager) applyRule(rule PortForwardingRule) error {
	// Create a Cilium port forwarding configuration
	config := &cilium.PortForwardConfig{
		ExternalIP:   rule.ExternalIP,
		ExternalPort: rule.ExternalPort,
		Protocol:     rule.Protocol,
		InternalIP:   rule.InternalIP,
		InternalPort: rule.InternalPort,
		Description:  rule.Description,
	}
	
	// Apply the port forwarding configuration using Cilium
	return m.ciliumClient.CreatePortForward(nil, config)
}

// removeRule removes a port forwarding rule
func (m *PortForwardingManager) removeRule(rule PortForwardingRule) error {
	// Create a Cilium port forwarding configuration
	config := &cilium.PortForwardConfig{
		ExternalIP:   rule.ExternalIP,
		ExternalPort: rule.ExternalPort,
		Protocol:     rule.Protocol,
		InternalIP:   rule.InternalIP,
		InternalPort: rule.InternalPort,
	}
	
	// Remove the port forwarding configuration using Cilium
	return m.ciliumClient.RemovePortForward(nil, config)
}
