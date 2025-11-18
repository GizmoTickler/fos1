package nat

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// manager implements the Manager interface
type manager struct {
	mutex      sync.RWMutex
	policies   map[string]Config // key: namespace/name
	statuses   map[string]*Status
	ciliumClient cilium.Client
}

// NewManager creates a new NAT manager
func NewManager(ciliumClient cilium.Client) Manager {
	return &manager{
		policies:     make(map[string]Config),
		statuses:     make(map[string]*Status),
		ciliumClient: ciliumClient,
	}
}

// ApplyNATPolicy applies a NAT policy
func (m *manager) ApplyNATPolicy(config Config) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := fmt.Sprintf("%s/%s", config.Namespace, config.Name)
	klog.Infof("Applying NAT policy %s", key)

	// Store the policy
	m.policies[key] = config

	// Initialize or update status
	status, exists := m.statuses[key]
	if !exists {
		status = &Status{
			ActiveConnections: 0,
			Metrics: Metrics{
				Packets:      0,
				Bytes:        0,
				Translations: 0,
			},
			Conditions: []Condition{
				{
					Type:               "Ready",
					Status:             "True",
					LastTransitionTime: time.Now(),
					Reason:             "PolicyApplied",
					Message:            "NAT policy has been applied",
				},
			},
		}
		m.statuses[key] = status
	} else {
		// Update the Ready condition
		found := false
		for i, condition := range status.Conditions {
			if condition.Type == "Ready" {
				status.Conditions[i] = Condition{
					Type:               "Ready",
					Status:             "True",
					LastTransitionTime: time.Now(),
					Reason:             "PolicyApplied",
					Message:            "NAT policy has been applied",
				}
				found = true
				break
			}
		}

		if !found {
			status.Conditions = append(status.Conditions, Condition{
				Type:               "Ready",
				Status:             "True",
				LastTransitionTime: time.Now(),
				Reason:             "PolicyApplied",
				Message:            "NAT policy has been applied",
			})
		}
	}

	// Apply the policy based on its type
	switch config.Type {
	case TypeSNAT:
		return m.applySNAT(config)
	case TypeDNAT:
		return m.applyDNAT(config)
	case TypeMasquerade:
		return m.applyMasquerade(config)
	case TypeFull:
		return m.applyFullNAT(config)
	case TypeNAT66:
		return m.applyNAT66(config)
	case TypeNAT64:
		return m.applyNAT64(config)
	default:
		return fmt.Errorf("unsupported NAT type: %s", config.Type)
	}
}

// RemoveNATPolicy removes a NAT policy
func (m *manager) RemoveNATPolicy(name, namespace string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := fmt.Sprintf("%s/%s", namespace, name)
	klog.Infof("Removing NAT policy %s", key)

	// Check if the policy exists
	config, exists := m.policies[key]
	if !exists {
		return fmt.Errorf("NAT policy %s does not exist", key)
	}

	// Remove the policy based on its type
	var err error
	switch config.Type {
	case TypeSNAT:
		err = m.removeSNAT(config)
	case TypeDNAT:
		err = m.removeDNAT(config)
	case TypeMasquerade:
		err = m.removeMasquerade(config)
	case TypeFull:
		err = m.removeFullNAT(config)
	case TypeNAT66:
		err = m.removeNAT66(config)
	case TypeNAT64:
		err = m.removeNAT64(config)
	default:
		err = fmt.Errorf("unsupported NAT type: %s", config.Type)
	}

	if err != nil {
		return err
	}

	// Remove the policy and status
	delete(m.policies, key)
	delete(m.statuses, key)

	return nil
}

// GetNATPolicyStatus gets the status of a NAT policy
func (m *manager) GetNATPolicyStatus(name, namespace string) (*Status, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	key := fmt.Sprintf("%s/%s", namespace, name)
	status, exists := m.statuses[key]
	if !exists {
		return nil, fmt.Errorf("NAT policy %s does not exist", key)
	}

	return status, nil
}

// ListNATPolicies lists all NAT policies
func (m *manager) ListNATPolicies() ([]Config, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	policies := make([]Config, 0, len(m.policies))
	for _, policy := range m.policies {
		policies = append(policies, policy)
	}

	return policies, nil
}

// applySNAT applies a Source NAT policy
func (m *manager) applySNAT(config Config) error {
	klog.Infof("Applying SNAT policy %s/%s", config.Namespace, config.Name)

	// Create a Cilium NAT configuration
	natConfig := &cilium.NATConfig{
		SourceNetwork:    config.SourceAddresses[0], // Use the first source address
		DestinationIface: config.Interface,
		IPv6:             config.IPv6,
	}

	// Apply the NAT configuration using Cilium
	return m.ciliumClient.CreateNAT(nil, natConfig)
}

// applyDNAT applies a Destination NAT policy
func (m *manager) applyDNAT(config Config) error {
	klog.Infof("Applying DNAT policy %s/%s", config.Namespace, config.Name)

	// For each port mapping, create a port forwarding rule
	for _, mapping := range config.PortMappings {
		// Create a port forwarding configuration
		portForwardConfig := &cilium.PortForwardConfig{
			ExternalIP:   config.ExternalIP,
			ExternalPort: mapping.ExternalPort,
			Protocol:     mapping.Protocol,
			InternalIP:   mapping.InternalIP,
			InternalPort: mapping.InternalPort,
			Description:  mapping.Description,
		}

		// Apply the port forwarding configuration using Cilium
		if err := m.ciliumClient.CreatePortForward(nil, portForwardConfig); err != nil {
			return fmt.Errorf("failed to create port forwarding: %w", err)
		}
	}

	return nil
}

// applyMasquerade applies a Masquerade NAT policy
func (m *manager) applyMasquerade(config Config) error {
	klog.Infof("Applying Masquerade policy %s/%s", config.Namespace, config.Name)

	// Create a Cilium NAT configuration with masquerade
	natConfig := &cilium.NATConfig{
		SourceNetwork:    config.SourceAddresses[0], // Use the first source address
		DestinationIface: config.Interface,
		IPv6:             config.IPv6,
	}

	// Apply the NAT configuration using Cilium
	return m.ciliumClient.CreateNAT(nil, natConfig)
}

// applyFullNAT applies a Full NAT policy (both SNAT and DNAT)
func (m *manager) applyFullNAT(config Config) error {
	klog.Infof("Applying Full NAT policy %s/%s", config.Namespace, config.Name)

	// Apply SNAT
	if err := m.applySNAT(config); err != nil {
		return fmt.Errorf("failed to apply SNAT: %w", err)
	}

	// Apply DNAT
	if err := m.applyDNAT(config); err != nil {
		return fmt.Errorf("failed to apply DNAT: %w", err)
	}

	return nil
}

// applyNAT66 applies a NAT66 policy (IPv6 to IPv6)
func (m *manager) applyNAT66(config Config) error {
	klog.Infof("Applying NAT66 policy %s/%s", config.Namespace, config.Name)

	// Create a Cilium NAT configuration with IPv6
	natConfig := &cilium.NATConfig{
		SourceNetwork:    config.SourceAddresses[0], // Use the first source address
		DestinationIface: config.Interface,
		IPv6:             true,
	}

	// Apply the NAT configuration using Cilium
	return m.ciliumClient.CreateNAT(nil, natConfig)
}

// applyNAT64 applies a NAT64 policy (IPv6 to IPv4)
func (m *manager) applyNAT64(config Config) error {
	klog.Infof("Applying NAT64 policy %s/%s", config.Namespace, config.Name)

	// Create a Cilium NAT64 configuration
	nat64Config := &cilium.NAT64Config{
		SourceNetwork:    config.SourceAddresses[0], // Use the first source address
		DestinationIface: config.Interface,
	}

	// Apply the NAT64 configuration using Cilium
	return m.ciliumClient.CreateNAT64(nil, nat64Config)
}

// removeSNAT removes a Source NAT policy
func (m *manager) removeSNAT(config Config) error {
	klog.Infof("Removing SNAT policy %s/%s", config.Namespace, config.Name)

	// Create a Cilium NAT configuration
	natConfig := &cilium.NATConfig{
		SourceNetwork:    config.SourceAddresses[0], // Use the first source address
		DestinationIface: config.Interface,
		IPv6:             config.IPv6,
	}

	// Remove the NAT configuration using Cilium
	return m.ciliumClient.RemoveNAT(nil, natConfig)
}

// removeDNAT removes a Destination NAT policy
func (m *manager) removeDNAT(config Config) error {
	klog.Infof("Removing DNAT policy %s/%s", config.Namespace, config.Name)

	// For each port mapping, remove the port forwarding rule
	for _, mapping := range config.PortMappings {
		// Create a port forwarding configuration
		portForwardConfig := &cilium.PortForwardConfig{
			ExternalIP:   config.ExternalIP,
			ExternalPort: mapping.ExternalPort,
			Protocol:     mapping.Protocol,
			InternalIP:   mapping.InternalIP,
			InternalPort: mapping.InternalPort,
		}

		// Remove the port forwarding configuration using Cilium
		if err := m.ciliumClient.RemovePortForward(nil, portForwardConfig); err != nil {
			return fmt.Errorf("failed to remove port forwarding: %w", err)
		}
	}

	return nil
}

// removeMasquerade removes a Masquerade NAT policy
func (m *manager) removeMasquerade(config Config) error {
	klog.Infof("Removing Masquerade policy %s/%s", config.Namespace, config.Name)

	// Create a Cilium NAT configuration with masquerade
	natConfig := &cilium.NATConfig{
		SourceNetwork:    config.SourceAddresses[0], // Use the first source address
		DestinationIface: config.Interface,
		IPv6:             config.IPv6,
	}

	// Remove the NAT configuration using Cilium
	return m.ciliumClient.RemoveNAT(nil, natConfig)
}

// removeFullNAT removes a Full NAT policy (both SNAT and DNAT)
func (m *manager) removeFullNAT(config Config) error {
	klog.Infof("Removing Full NAT policy %s/%s", config.Namespace, config.Name)

	// Remove SNAT
	if err := m.removeSNAT(config); err != nil {
		return fmt.Errorf("failed to remove SNAT: %w", err)
	}

	// Remove DNAT
	if err := m.removeDNAT(config); err != nil {
		return fmt.Errorf("failed to remove DNAT: %w", err)
	}

	return nil
}

// removeNAT66 removes a NAT66 policy (IPv6 to IPv6)
func (m *manager) removeNAT66(config Config) error {
	klog.Infof("Removing NAT66 policy %s/%s", config.Namespace, config.Name)

	// Create a Cilium NAT configuration with IPv6
	natConfig := &cilium.NATConfig{
		SourceNetwork:    config.SourceAddresses[0], // Use the first source address
		DestinationIface: config.Interface,
		IPv6:             true,
	}

	// Remove the NAT configuration using Cilium
	return m.ciliumClient.RemoveNAT(nil, natConfig)
}

// removeNAT64 removes a NAT64 policy (IPv6 to IPv4)
func (m *manager) removeNAT64(config Config) error {
	klog.Infof("Removing NAT64 policy %s/%s", config.Namespace, config.Name)

	// Create a Cilium NAT64 configuration
	nat64Config := &cilium.NAT64Config{
		SourceNetwork:    config.SourceAddresses[0], // Use the first source address
		DestinationIface: config.Interface,
	}

	// Remove the NAT64 configuration using Cilium
	return m.ciliumClient.RemoveNAT64(nil, nat64Config)
}
