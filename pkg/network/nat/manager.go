package nat

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// manager implements the Manager interface
type manager struct {
	mutex        sync.RWMutex
	policies     map[string]Config // key: namespace/name
	statuses     map[string]*Status
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

// validateConfig validates a NAT configuration before applying it.
// It rejects bad address family combinations and missing required fields.
func validateConfig(config Config) error {
	if config.Name == "" {
		return fmt.Errorf("NAT policy name is required")
	}
	if config.Namespace == "" {
		return fmt.Errorf("NAT policy namespace is required")
	}

	switch config.Type {
	case TypeSNAT, TypeMasquerade:
		if len(config.SourceAddresses) == 0 {
			return fmt.Errorf("source addresses are required for %s", config.Type)
		}
		if config.Interface == "" {
			return fmt.Errorf("interface is required for %s", config.Type)
		}
	case TypeDNAT:
		if config.ExternalIP == "" {
			return fmt.Errorf("external IP is required for DNAT")
		}
		if len(config.PortMappings) == 0 {
			return fmt.Errorf("port mappings are required for DNAT")
		}
		for _, pm := range config.PortMappings {
			if pm.InternalIP == "" {
				return fmt.Errorf("internal IP is required in port mapping")
			}
			if pm.ExternalPort <= 0 || pm.ExternalPort > 65535 {
				return fmt.Errorf("external port must be between 1 and 65535, got %d", pm.ExternalPort)
			}
			if pm.InternalPort <= 0 || pm.InternalPort > 65535 {
				return fmt.Errorf("internal port must be between 1 and 65535, got %d", pm.InternalPort)
			}
		}
	case TypeFull:
		if len(config.SourceAddresses) == 0 {
			return fmt.Errorf("source addresses are required for full NAT")
		}
		if config.Interface == "" {
			return fmt.Errorf("interface is required for full NAT")
		}
	case TypeNAT66:
		if len(config.SourceAddresses) == 0 {
			return fmt.Errorf("source addresses are required for NAT66")
		}
		if config.Interface == "" {
			return fmt.Errorf("interface is required for NAT66")
		}
		// Validate that source addresses are IPv6
		for _, addr := range config.SourceAddresses {
			if !isIPv6CIDR(addr) {
				return fmt.Errorf("NAT66 requires IPv6 source addresses, got %q", addr)
			}
		}
		// NAT66 must not have IPv6 set to false explicitly when addresses are IPv6
		// (IPv6 flag is forced true in applyNAT66)
	case TypeNAT64:
		if len(config.SourceAddresses) == 0 {
			return fmt.Errorf("source addresses are required for NAT64")
		}
		if config.Interface == "" {
			return fmt.Errorf("interface is required for NAT64")
		}
		// Validate that source addresses are IPv6 (NAT64 translates from IPv6 to IPv4)
		for _, addr := range config.SourceAddresses {
			if !isIPv6CIDR(addr) {
				return fmt.Errorf("NAT64 requires IPv6 source addresses, got %q", addr)
			}
		}
	default:
		return fmt.Errorf("unsupported NAT type: %s", config.Type)
	}

	// Validate address family consistency for SNAT/Masquerade
	if config.Type == TypeSNAT || config.Type == TypeMasquerade {
		for _, addr := range config.SourceAddresses {
			addrIsV6 := isIPv6CIDR(addr)
			if config.IPv6 && !addrIsV6 {
				return fmt.Errorf("IPv6 mode enabled but source address %q is IPv4", addr)
			}
			if !config.IPv6 && addrIsV6 {
				return fmt.Errorf("IPv4 mode enabled but source address %q is IPv6", addr)
			}
		}
	}

	return nil
}

// isIPv6CIDR returns true if the given CIDR or IP string is IPv6
func isIPv6CIDR(cidr string) bool {
	// Try parsing as CIDR first
	if strings.Contains(cidr, "/") {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return false
		}
		return ip.To4() == nil
	}
	// Try parsing as plain IP
	ip := net.ParseIP(cidr)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// setStatus sets the status for a policy key. It updates existing Ready
// conditions or appends a new one.
func (m *manager) setStatus(key string, ready bool, reason, message string) {
	status, exists := m.statuses[key]
	if !exists {
		status = &Status{
			ActiveConnections: 0,
			Metrics: Metrics{
				Packets:      0,
				Bytes:        0,
				Translations: 0,
			},
		}
		m.statuses[key] = status
	}

	readyStr := "True"
	if !ready {
		readyStr = "False"
	}

	condition := Condition{
		Type:               "Ready",
		Status:             readyStr,
		LastTransitionTime: time.Now(),
		Reason:             reason,
		Message:            message,
	}

	found := false
	for i, c := range status.Conditions {
		if c.Type == "Ready" {
			status.Conditions[i] = condition
			found = true
			break
		}
	}
	if !found {
		status.Conditions = append(status.Conditions, condition)
	}
}

// ApplyNATPolicy applies a NAT policy
func (m *manager) ApplyNATPolicy(config Config) error {
	// Validate before acquiring the lock for expensive Cilium calls
	if err := validateConfig(config); err != nil {
		return fmt.Errorf("invalid NAT policy: %w", err)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := fmt.Sprintf("%s/%s", config.Namespace, config.Name)
	klog.Infof("Applying NAT policy %s (type=%s)", key, config.Type)

	// Store the policy
	m.policies[key] = config

	// Apply the policy through the Cilium control plane
	var err error
	switch config.Type {
	case TypeSNAT:
		err = m.applySNAT(config)
	case TypeDNAT:
		err = m.applyDNAT(config)
	case TypeMasquerade:
		err = m.applyMasquerade(config)
	case TypeFull:
		err = m.applyFullNAT(config)
	case TypeNAT66:
		err = m.applyNAT66(config)
	case TypeNAT64:
		err = m.applyNAT64(config)
	default:
		// Already caught by validateConfig, but defensive
		delete(m.policies, key)
		return fmt.Errorf("unsupported NAT type: %s", config.Type)
	}

	// Set status based on Cilium enforcement result
	if err != nil {
		// Remove the policy and status since the Cilium enforcement failed
		delete(m.policies, key)
		delete(m.statuses, key)
		return fmt.Errorf("failed to enforce NAT policy %s via Cilium: %w", key, err)
	}

	m.setStatus(key, true, "PolicyApplied", "NAT policy has been applied via Cilium")
	return nil
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
		m.setStatus(key, false, "CiliumRemovalFailed", fmt.Sprintf("Failed to remove NAT policy via Cilium: %v", err))
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

	natConfig := &cilium.CiliumNATConfig{
		SourceNetwork:    config.SourceAddresses[0],
		DestinationIface: config.Interface,
		IPv6:             config.IPv6,
	}

	return m.ciliumClient.CreateNAT(nil, natConfig)
}

// applyDNAT applies a Destination NAT policy
func (m *manager) applyDNAT(config Config) error {
	klog.Infof("Applying DNAT policy %s/%s", config.Namespace, config.Name)

	for _, mapping := range config.PortMappings {
		portForwardConfig := &cilium.PortForwardConfig{
			ExternalIP:   config.ExternalIP,
			ExternalPort: mapping.ExternalPort,
			Protocol:     mapping.Protocol,
			InternalIP:   mapping.InternalIP,
			InternalPort: mapping.InternalPort,
			Description:  mapping.Description,
		}

		if err := m.ciliumClient.CreatePortForward(nil, portForwardConfig); err != nil {
			return fmt.Errorf("failed to create port forwarding for %s:%d: %w",
				config.ExternalIP, mapping.ExternalPort, err)
		}
	}

	return nil
}

// applyMasquerade applies a Masquerade NAT policy
func (m *manager) applyMasquerade(config Config) error {
	klog.Infof("Applying Masquerade policy %s/%s", config.Namespace, config.Name)

	natConfig := &cilium.CiliumNATConfig{
		SourceNetwork:     config.SourceAddresses[0],
		DestinationIface:  config.Interface,
		IPv6:              config.IPv6,
		MasqueradeEnabled: true,
	}

	return m.ciliumClient.CreateNAT(nil, natConfig)
}

// applyFullNAT applies a Full NAT policy (both SNAT and DNAT)
func (m *manager) applyFullNAT(config Config) error {
	klog.Infof("Applying Full NAT policy %s/%s", config.Namespace, config.Name)

	if err := m.applySNAT(config); err != nil {
		return fmt.Errorf("failed to apply SNAT component: %w", err)
	}

	if len(config.PortMappings) > 0 {
		if err := m.applyDNAT(config); err != nil {
			return fmt.Errorf("failed to apply DNAT component: %w", err)
		}
	}

	return nil
}

// applyNAT66 applies a NAT66 policy (IPv6 to IPv6)
func (m *manager) applyNAT66(config Config) error {
	klog.Infof("Applying NAT66 policy %s/%s", config.Namespace, config.Name)

	natConfig := &cilium.CiliumNATConfig{
		SourceNetwork:    config.SourceAddresses[0],
		DestinationIface: config.Interface,
		IPv6:             true, // NAT66 is always IPv6
	}

	return m.ciliumClient.CreateNAT(nil, natConfig)
}

// applyNAT64 applies a NAT64 policy (IPv6 to IPv4)
func (m *manager) applyNAT64(config Config) error {
	klog.Infof("Applying NAT64 policy %s/%s", config.Namespace, config.Name)

	nat64Config := &cilium.NAT64Config{
		SourceNetwork:    config.SourceAddresses[0],
		DestinationIface: config.Interface,
		Prefix64:         cilium.DefaultNAT64Prefix,
	}

	return m.ciliumClient.CreateNAT64(nil, nat64Config)
}

// removeSNAT removes a Source NAT policy
func (m *manager) removeSNAT(config Config) error {
	klog.Infof("Removing SNAT policy %s/%s", config.Namespace, config.Name)

	natConfig := &cilium.CiliumNATConfig{
		SourceNetwork:    config.SourceAddresses[0],
		DestinationIface: config.Interface,
		IPv6:             config.IPv6,
	}

	return m.ciliumClient.RemoveNAT(nil, natConfig)
}

// removeDNAT removes a Destination NAT policy
func (m *manager) removeDNAT(config Config) error {
	klog.Infof("Removing DNAT policy %s/%s", config.Namespace, config.Name)

	for _, mapping := range config.PortMappings {
		portForwardConfig := &cilium.PortForwardConfig{
			ExternalIP:   config.ExternalIP,
			ExternalPort: mapping.ExternalPort,
			Protocol:     mapping.Protocol,
			InternalIP:   mapping.InternalIP,
			InternalPort: mapping.InternalPort,
		}

		if err := m.ciliumClient.RemovePortForward(nil, portForwardConfig); err != nil {
			return fmt.Errorf("failed to remove port forwarding: %w", err)
		}
	}

	return nil
}

// removeMasquerade removes a Masquerade NAT policy
func (m *manager) removeMasquerade(config Config) error {
	klog.Infof("Removing Masquerade policy %s/%s", config.Namespace, config.Name)

	natConfig := &cilium.CiliumNATConfig{
		SourceNetwork:     config.SourceAddresses[0],
		DestinationIface:  config.Interface,
		IPv6:              config.IPv6,
		MasqueradeEnabled: true,
	}

	return m.ciliumClient.RemoveNAT(nil, natConfig)
}

// removeFullNAT removes a Full NAT policy (both SNAT and DNAT)
func (m *manager) removeFullNAT(config Config) error {
	klog.Infof("Removing Full NAT policy %s/%s", config.Namespace, config.Name)

	if err := m.removeSNAT(config); err != nil {
		return fmt.Errorf("failed to remove SNAT: %w", err)
	}

	if len(config.PortMappings) > 0 {
		if err := m.removeDNAT(config); err != nil {
			return fmt.Errorf("failed to remove DNAT: %w", err)
		}
	}

	return nil
}

// removeNAT66 removes a NAT66 policy (IPv6 to IPv6)
func (m *manager) removeNAT66(config Config) error {
	klog.Infof("Removing NAT66 policy %s/%s", config.Namespace, config.Name)

	natConfig := &cilium.CiliumNATConfig{
		SourceNetwork:    config.SourceAddresses[0],
		DestinationIface: config.Interface,
		IPv6:             true,
	}

	return m.ciliumClient.RemoveNAT(nil, natConfig)
}

// removeNAT64 removes a NAT64 policy (IPv6 to IPv4)
func (m *manager) removeNAT64(config Config) error {
	klog.Infof("Removing NAT64 policy %s/%s", config.Namespace, config.Name)

	nat64Config := &cilium.NAT64Config{
		SourceNetwork:    config.SourceAddresses[0],
		DestinationIface: config.Interface,
		Prefix64:         cilium.DefaultNAT64Prefix,
	}

	return m.ciliumClient.RemoveNAT64(nil, nat64Config)
}
