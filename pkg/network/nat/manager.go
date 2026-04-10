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
	mutex        sync.RWMutex
	policies     map[string]Config  // key: namespace/name
	statuses     map[string]*Status // key: namespace/name
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

// policyKey returns the map key for a given namespace/name
func policyKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

// setCondition updates or appends a condition, only changing the transition time
// if the condition status actually changed.
func setCondition(status *Status, condType, condStatus, reason, message string) {
	now := time.Now()
	for i, c := range status.Conditions {
		if c.Type == condType {
			if c.Status != condStatus {
				status.Conditions[i].LastTransitionTime = now
			}
			status.Conditions[i].Status = condStatus
			status.Conditions[i].Reason = reason
			status.Conditions[i].Message = message
			return
		}
	}
	status.Conditions = append(status.Conditions, Condition{
		Type:               condType,
		Status:             condStatus,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	})
}

// ApplyNATPolicy applies a NAT policy. It is idempotent: if the config hash matches
// the last applied hash, it skips Cilium calls and returns Applied=false.
func (m *manager) ApplyNATPolicy(config Config) (*ApplyResult, error) {
	// Validate config before acquiring lock
	if err := ValidateConfig(config); err != nil {
		// Store invalid status so the controller can report it
		m.mutex.Lock()
		key := policyKey(config.Namespace, config.Name)
		status := m.getOrCreateStatus(key)
		setCondition(status, ConditionInvalid, ConditionStatusTrue, "ValidationFailed", err.Error())
		setCondition(status, ConditionApplied, ConditionStatusFalse, "ValidationFailed", "config failed validation")
		// Clear degraded on validation failure
		setCondition(status, ConditionDegraded, ConditionStatusFalse, "ValidationFailed", "")
		m.mutex.Unlock()
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := policyKey(config.Namespace, config.Name)
	specHash := config.SpecHash()

	// Idempotency: if the hash matches, skip Cilium calls
	if existing, exists := m.statuses[key]; exists && existing.LastAppliedHash == specHash {
		klog.Infof("NAT policy %s spec unchanged (hash=%s), skipping apply", key, specHash[:12])
		return &ApplyResult{Applied: false}, nil
	}

	klog.Infof("Applying NAT policy %s (hash=%s)", key, specHash[:12])

	// Store the policy
	m.policies[key] = config

	// Get or create status
	status := m.getOrCreateStatus(key)

	// Clear Invalid condition since we passed validation
	setCondition(status, ConditionInvalid, ConditionStatusFalse, "Valid", "config passed validation")

	// Apply the policy based on its type
	var applyErr error
	switch config.Type {
	case TypeSNAT:
		applyErr = m.applySNAT(config)
	case TypeDNAT:
		applyErr = m.applyDNAT(config)
	case TypeMasquerade:
		applyErr = m.applyMasquerade(config)
	case TypeFull:
		applyErr = m.applyFullNAT(config)
	case TypeNAT66:
		applyErr = m.applyNAT66(config)
	case TypeNAT64:
		applyErr = m.applyNAT64(config)
	default:
		applyErr = fmt.Errorf("unsupported NAT type: %s", config.Type)
	}

	now := time.Now()

	if applyErr != nil {
		// Check if this is a partial failure (for Full NAT where SNAT succeeded but DNAT failed)
		// For full NAT, applyFullNAT reports partial errors with "failed to apply DNAT" prefix
		if config.Type == TypeFull && isDNATPartialFailure(applyErr) {
			setCondition(status, ConditionApplied, ConditionStatusFalse, "PartialApply", "SNAT applied but DNAT failed")
			setCondition(status, ConditionDegraded, ConditionStatusTrue, "PartialFailure", applyErr.Error())
			status.LastAppliedHash = "" // Force re-apply on next reconciliation
			status.LastAppliedTime = now
			return &ApplyResult{Applied: true, Degraded: true, Error: applyErr.Error()}, nil
		}

		setCondition(status, ConditionApplied, ConditionStatusFalse, "ApplyFailed", applyErr.Error())
		setCondition(status, ConditionDegraded, ConditionStatusFalse, "ApplyFailed", "")
		status.LastAppliedHash = "" // Force re-apply on next reconciliation
		return nil, fmt.Errorf("failed to apply NAT policy: %w", applyErr)
	}

	// Success
	setCondition(status, ConditionApplied, ConditionStatusTrue, "PolicyApplied", "NAT policy has been enforced via Cilium")
	setCondition(status, ConditionDegraded, ConditionStatusFalse, "FullyApplied", "all rules applied successfully")
	status.LastAppliedHash = specHash
	status.LastAppliedTime = now

	return &ApplyResult{Applied: true}, nil
}

// isDNATPartialFailure checks if an error from applyFullNAT is a DNAT-specific failure
// (meaning SNAT succeeded but DNAT failed)
func isDNATPartialFailure(err error) bool {
	return err != nil && len(err.Error()) > 0 &&
		(err.Error()[:len("failed to apply DNAT")] == "failed to apply DNAT")
}

// getOrCreateStatus returns an existing status or creates a new one
func (m *manager) getOrCreateStatus(key string) *Status {
	status, exists := m.statuses[key]
	if !exists {
		status = &Status{
			ActiveConnections: 0,
			Metrics: Metrics{
				Packets:      0,
				Bytes:        0,
				Translations: 0,
			},
			Conditions: []Condition{},
		}
		m.statuses[key] = status
	}
	return status
}

// RemoveNATPolicy removes a NAT policy
func (m *manager) RemoveNATPolicy(name, namespace string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := policyKey(namespace, name)
	klog.Infof("Removing NAT policy %s", key)

	// Check if the policy exists
	config, exists := m.policies[key]
	if !exists {
		// Already removed, idempotent
		return nil
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
		// Set Removed condition to False since cleanup failed
		status := m.getOrCreateStatus(key)
		setCondition(status, ConditionRemoved, ConditionStatusFalse, "RemovalFailed", err.Error())
		return fmt.Errorf("failed to remove NAT policy: %w", err)
	}

	// Set Removed condition before deleting
	status := m.getOrCreateStatus(key)
	setCondition(status, ConditionRemoved, ConditionStatusTrue, "CleanupComplete", "NAT policy removed from Cilium")
	setCondition(status, ConditionApplied, ConditionStatusFalse, "Removed", "policy has been removed")

	// Remove the policy and status
	delete(m.policies, key)
	delete(m.statuses, key)

	return nil
}

// GetNATPolicyStatus gets the status of a NAT policy
func (m *manager) GetNATPolicyStatus(name, namespace string) (*Status, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	key := policyKey(namespace, name)
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
				mapping.Protocol, mapping.ExternalPort, err)
		}
	}

	return nil
}

// applyMasquerade applies a Masquerade NAT policy
func (m *manager) applyMasquerade(config Config) error {
	klog.Infof("Applying Masquerade policy %s/%s", config.Namespace, config.Name)

	natConfig := &cilium.CiliumNATConfig{
		SourceNetwork:    config.SourceAddresses[0],
		DestinationIface: config.Interface,
		IPv6:             config.IPv6,
	}

	return m.ciliumClient.CreateNAT(nil, natConfig)
}

// applyFullNAT applies a Full NAT policy (both SNAT and DNAT)
func (m *manager) applyFullNAT(config Config) error {
	klog.Infof("Applying Full NAT policy %s/%s", config.Namespace, config.Name)

	if err := m.applySNAT(config); err != nil {
		return fmt.Errorf("failed to apply SNAT: %w", err)
	}

	if err := m.applyDNAT(config); err != nil {
		return fmt.Errorf("failed to apply DNAT: %w", err)
	}

	return nil
}

// applyNAT66 applies a NAT66 policy (IPv6 to IPv6)
func (m *manager) applyNAT66(config Config) error {
	klog.Infof("Applying NAT66 policy %s/%s", config.Namespace, config.Name)

	natConfig := &cilium.CiliumNATConfig{
		SourceNetwork:    config.SourceAddresses[0],
		DestinationIface: config.Interface,
		IPv6:             true,
	}

	return m.ciliumClient.CreateNAT(nil, natConfig)
}

// applyNAT64 applies a NAT64 policy (IPv6 to IPv4)
func (m *manager) applyNAT64(config Config) error {
	klog.Infof("Applying NAT64 policy %s/%s", config.Namespace, config.Name)

	nat64Config := &cilium.NAT64Config{
		SourceNetwork:    config.SourceAddresses[0],
		DestinationIface: config.Interface,
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
		SourceNetwork:    config.SourceAddresses[0],
		DestinationIface: config.Interface,
		IPv6:             config.IPv6,
	}

	return m.ciliumClient.RemoveNAT(nil, natConfig)
}

// removeFullNAT removes a Full NAT policy (both SNAT and DNAT)
func (m *manager) removeFullNAT(config Config) error {
	klog.Infof("Removing Full NAT policy %s/%s", config.Namespace, config.Name)

	if err := m.removeSNAT(config); err != nil {
		return fmt.Errorf("failed to remove SNAT: %w", err)
	}

	if err := m.removeDNAT(config); err != nil {
		return fmt.Errorf("failed to remove DNAT: %w", err)
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
	}

	return m.ciliumClient.RemoveNAT64(nil, nat64Config)
}
