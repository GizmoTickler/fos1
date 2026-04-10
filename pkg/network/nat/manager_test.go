package nat

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// mockCiliumClient implements cilium.Client for testing
type mockCiliumClient struct {
	createNATCalls         int
	removeNATCalls         int
	createPortForwardCalls int
	removePortForwardCalls int
	createNAT64Calls       int
	removeNAT64Calls       int

	// errors to inject
	createNATErr         error
	createPortForwardErr error
	removeNATErr         error
	removePortForwardErr error
	createNAT64Err       error
	removeNAT64Err       error

	// failAfterN causes CreatePortForward to fail after N successful calls
	failPortForwardAfterN int
}

func (m *mockCiliumClient) ApplyNetworkPolicy(_ context.Context, _ *cilium.CiliumPolicy) error {
	return nil
}

func (m *mockCiliumClient) CreateNAT(_ context.Context, _ *cilium.CiliumNATConfig) error {
	m.createNATCalls++
	return m.createNATErr
}

func (m *mockCiliumClient) RemoveNAT(_ context.Context, _ *cilium.CiliumNATConfig) error {
	m.removeNATCalls++
	return m.removeNATErr
}

func (m *mockCiliumClient) CreateNAT64(_ context.Context, _ *cilium.NAT64Config) error {
	m.createNAT64Calls++
	return m.createNAT64Err
}

func (m *mockCiliumClient) RemoveNAT64(_ context.Context, _ *cilium.NAT64Config) error {
	m.removeNAT64Calls++
	return m.removeNAT64Err
}

func (m *mockCiliumClient) CreatePortForward(_ context.Context, _ *cilium.PortForwardConfig) error {
	m.createPortForwardCalls++
	if m.failPortForwardAfterN > 0 && m.createPortForwardCalls > m.failPortForwardAfterN {
		return m.createPortForwardErr
	}
	if m.failPortForwardAfterN == 0 && m.createPortForwardErr != nil {
		return m.createPortForwardErr
	}
	return nil
}

func (m *mockCiliumClient) RemovePortForward(_ context.Context, _ *cilium.PortForwardConfig) error {
	m.removePortForwardCalls++
	return m.removePortForwardErr
}

func (m *mockCiliumClient) ConfigureVLANRouting(_ context.Context, _ *cilium.CiliumVLANRoutingConfig) error {
	return nil
}

func (m *mockCiliumClient) ConfigureDPIIntegration(_ context.Context, _ *cilium.CiliumDPIIntegrationConfig) error {
	return nil
}

// validSNATConfig returns a valid SNAT config for testing
func validSNATConfig() Config {
	return Config{
		Name:            "test-snat",
		Namespace:       "default",
		Type:            TypeSNAT,
		Interface:       "eth0",
		ExternalIP:      "203.0.113.1",
		SourceAddresses: []string{"10.0.0.0/24"},
		EnableTracking:  true,
	}
}

// validDNATConfig returns a valid DNAT config for testing
func validDNATConfig() Config {
	return Config{
		Name:       "test-dnat",
		Namespace:  "default",
		Type:       TypeDNAT,
		Interface:  "eth0",
		ExternalIP: "203.0.113.1",
		PortMappings: []PortMapping{
			{
				Protocol:     "tcp",
				ExternalPort: 8080,
				InternalIP:   "10.0.0.5",
				InternalPort: 80,
				Description:  "HTTP",
			},
		},
	}
}

func TestApplyNATPolicy_SuccessfulSNAT(t *testing.T) {
	mock := &mockCiliumClient{}
	mgr := NewManager(mock)

	config := validSNATConfig()
	result, err := mgr.ApplyNATPolicy(config)

	require.NoError(t, err)
	assert.True(t, result.Applied)
	assert.False(t, result.Degraded)
	assert.Equal(t, 1, mock.createNATCalls)

	// Verify status reflects Applied=True
	status, err := mgr.GetNATPolicyStatus("test-snat", "default")
	require.NoError(t, err)

	appliedCond := findCondition(status.Conditions, ConditionApplied)
	require.NotNil(t, appliedCond)
	assert.Equal(t, ConditionStatusTrue, appliedCond.Status)
	assert.Equal(t, "PolicyApplied", appliedCond.Reason)

	invalidCond := findCondition(status.Conditions, ConditionInvalid)
	require.NotNil(t, invalidCond)
	assert.Equal(t, ConditionStatusFalse, invalidCond.Status)

	// Verify hash is set
	assert.NotEmpty(t, status.LastAppliedHash)
	assert.False(t, status.LastAppliedTime.IsZero())
}

func TestApplyNATPolicy_Idempotent(t *testing.T) {
	mock := &mockCiliumClient{}
	mgr := NewManager(mock)

	config := validSNATConfig()

	// First apply
	result1, err := mgr.ApplyNATPolicy(config)
	require.NoError(t, err)
	assert.True(t, result1.Applied)
	assert.Equal(t, 1, mock.createNATCalls)

	// Second apply with same config -> should skip Cilium calls
	result2, err := mgr.ApplyNATPolicy(config)
	require.NoError(t, err)
	assert.False(t, result2.Applied, "second apply of same spec should be skipped")
	assert.Equal(t, 1, mock.createNATCalls, "Cilium should not be called again")
}

func TestApplyNATPolicy_SpecChange_ReApplies(t *testing.T) {
	mock := &mockCiliumClient{}
	mgr := NewManager(mock)

	config := validSNATConfig()

	// First apply
	_, err := mgr.ApplyNATPolicy(config)
	require.NoError(t, err)
	assert.Equal(t, 1, mock.createNATCalls)

	// Change the spec
	config.ExternalIP = "203.0.113.2"

	// Second apply -> should re-apply because spec changed
	result, err := mgr.ApplyNATPolicy(config)
	require.NoError(t, err)
	assert.True(t, result.Applied)
	assert.Equal(t, 2, mock.createNATCalls)
}

func TestApplyNATPolicy_InvalidConfig(t *testing.T) {
	mock := &mockCiliumClient{}
	mgr := NewManager(mock)

	// Missing interface
	config := Config{
		Name:            "bad-policy",
		Namespace:       "default",
		Type:            TypeSNAT,
		ExternalIP:      "1.2.3.4",
		SourceAddresses: []string{"10.0.0.0/24"},
	}

	result, err := mgr.ApplyNATPolicy(config)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "validation failed")
	assert.Equal(t, 0, mock.createNATCalls, "Cilium should not be called for invalid config")

	// Verify status reflects Invalid=True
	status, err := mgr.GetNATPolicyStatus("bad-policy", "default")
	require.NoError(t, err)

	invalidCond := findCondition(status.Conditions, ConditionInvalid)
	require.NotNil(t, invalidCond)
	assert.Equal(t, ConditionStatusTrue, invalidCond.Status)
	assert.Equal(t, "ValidationFailed", invalidCond.Reason)

	appliedCond := findCondition(status.Conditions, ConditionApplied)
	require.NotNil(t, appliedCond)
	assert.Equal(t, ConditionStatusFalse, appliedCond.Status)
}

func TestApplyNATPolicy_CiliumFailure(t *testing.T) {
	mock := &mockCiliumClient{
		createNATErr: fmt.Errorf("cilium connection refused"),
	}
	mgr := NewManager(mock)

	config := validSNATConfig()
	result, err := mgr.ApplyNATPolicy(config)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "cilium connection refused")

	// Status should show Applied=False
	status, err := mgr.GetNATPolicyStatus("test-snat", "default")
	require.NoError(t, err)

	appliedCond := findCondition(status.Conditions, ConditionApplied)
	require.NotNil(t, appliedCond)
	assert.Equal(t, ConditionStatusFalse, appliedCond.Status)
	assert.Equal(t, "ApplyFailed", appliedCond.Reason)

	// Hash should be empty so next reconcile retries
	assert.Empty(t, status.LastAppliedHash)
}

func TestApplyNATPolicy_FullNAT_DegradedOnPartialFailure(t *testing.T) {
	mock := &mockCiliumClient{
		// SNAT (CreateNAT) succeeds, DNAT (CreatePortForward) fails
		createPortForwardErr: fmt.Errorf("port forward failed"),
	}
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-full",
		Namespace:       "default",
		Type:            TypeFull,
		Interface:       "eth0",
		ExternalIP:      "203.0.113.1",
		SourceAddresses: []string{"10.0.0.0/24"},
		PortMappings: []PortMapping{
			{Protocol: "tcp", ExternalPort: 80, InternalIP: "10.0.0.5", InternalPort: 80},
		},
	}

	result, err := mgr.ApplyNATPolicy(config)
	// Degraded returns nil error but result.Degraded=true
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Applied)
	assert.True(t, result.Degraded)
	assert.Contains(t, result.Error, "DNAT")

	// Verify status reflects degraded
	status, stErr := mgr.GetNATPolicyStatus("test-full", "default")
	require.NoError(t, stErr)

	degradedCond := findCondition(status.Conditions, ConditionDegraded)
	require.NotNil(t, degradedCond)
	assert.Equal(t, ConditionStatusTrue, degradedCond.Status)

	// Hash should be empty to force retry
	assert.Empty(t, status.LastAppliedHash)
}

func TestRemoveNATPolicy_Success(t *testing.T) {
	mock := &mockCiliumClient{}
	mgr := NewManager(mock)

	config := validSNATConfig()
	_, err := mgr.ApplyNATPolicy(config)
	require.NoError(t, err)

	err = mgr.RemoveNATPolicy("test-snat", "default")
	require.NoError(t, err)
	assert.Equal(t, 1, mock.removeNATCalls)

	// Status should be gone
	_, err = mgr.GetNATPolicyStatus("test-snat", "default")
	require.Error(t, err)
}

func TestRemoveNATPolicy_NonExistent_Idempotent(t *testing.T) {
	mock := &mockCiliumClient{}
	mgr := NewManager(mock)

	// Removing a non-existent policy should succeed (idempotent)
	err := mgr.RemoveNATPolicy("nonexistent", "default")
	require.NoError(t, err)
	assert.Equal(t, 0, mock.removeNATCalls)
}

func TestRemoveNATPolicy_CiliumFailure(t *testing.T) {
	mock := &mockCiliumClient{
		removeNATErr: fmt.Errorf("cilium timeout"),
	}
	mgr := NewManager(mock)

	config := validSNATConfig()
	_, err := mgr.ApplyNATPolicy(config)
	require.NoError(t, err)

	err = mgr.RemoveNATPolicy("test-snat", "default")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cilium timeout")

	// Status should still exist with Removed=False
	status, err := mgr.GetNATPolicyStatus("test-snat", "default")
	require.NoError(t, err)

	removedCond := findCondition(status.Conditions, ConditionRemoved)
	require.NotNil(t, removedCond)
	assert.Equal(t, ConditionStatusFalse, removedCond.Status)
	assert.Equal(t, "RemovalFailed", removedCond.Reason)
}

func TestApplyNATPolicy_DNAT_Success(t *testing.T) {
	mock := &mockCiliumClient{}
	mgr := NewManager(mock)

	config := validDNATConfig()
	result, err := mgr.ApplyNATPolicy(config)
	require.NoError(t, err)
	assert.True(t, result.Applied)
	assert.Equal(t, 1, mock.createPortForwardCalls)
}

func TestApplyNATPolicy_Masquerade_Success(t *testing.T) {
	mock := &mockCiliumClient{}
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-masq",
		Namespace:       "default",
		Type:            TypeMasquerade,
		Interface:       "eth0",
		SourceAddresses: []string{"10.0.0.0/24"},
	}
	result, err := mgr.ApplyNATPolicy(config)
	require.NoError(t, err)
	assert.True(t, result.Applied)
	assert.Equal(t, 1, mock.createNATCalls)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name:    "missing name",
			config:  Config{Type: TypeSNAT, Interface: "eth0", ExternalIP: "1.2.3.4", SourceAddresses: []string{"10.0.0.0/24"}},
			wantErr: "name is required",
		},
		{
			name:    "missing interface",
			config:  Config{Name: "test", Type: TypeSNAT, ExternalIP: "1.2.3.4", SourceAddresses: []string{"10.0.0.0/24"}},
			wantErr: "interface is required",
		},
		{
			name:    "snat missing externalIP",
			config:  Config{Name: "test", Type: TypeSNAT, Interface: "eth0", SourceAddresses: []string{"10.0.0.0/24"}},
			wantErr: "externalIP is required for SNAT",
		},
		{
			name:    "snat missing sourceAddresses",
			config:  Config{Name: "test", Type: TypeSNAT, Interface: "eth0", ExternalIP: "1.2.3.4"},
			wantErr: "sourceAddresses is required for SNAT",
		},
		{
			name: "dnat invalid port",
			config: Config{
				Name: "test", Type: TypeDNAT, Interface: "eth0", ExternalIP: "1.2.3.4",
				PortMappings: []PortMapping{{Protocol: "tcp", ExternalPort: 0, InternalIP: "10.0.0.1", InternalPort: 80}},
			},
			wantErr: "externalPort must be 1-65535",
		},
		{
			name:    "unsupported type",
			config:  Config{Name: "test", Type: "bogus", Interface: "eth0"},
			wantErr: "unsupported NAT type",
		},
		{
			name:   "valid snat",
			config: Config{Name: "test", Type: TypeSNAT, Interface: "eth0", ExternalIP: "1.2.3.4", SourceAddresses: []string{"10.0.0.0/24"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSpecHash_Deterministic(t *testing.T) {
	config := validSNATConfig()
	hash1 := config.SpecHash()
	hash2 := config.SpecHash()
	assert.Equal(t, hash1, hash2)
}

func TestSpecHash_ChangesOnSpecChange(t *testing.T) {
	config := validSNATConfig()
	hash1 := config.SpecHash()

	config.ExternalIP = "203.0.113.99"
	hash2 := config.SpecHash()

	assert.NotEqual(t, hash1, hash2)
}

func TestConditionTransitionTime_OnlyChangesOnStatusChange(t *testing.T) {
	status := &Status{Conditions: []Condition{}}

	// Set Applied=True
	setCondition(status, ConditionApplied, ConditionStatusTrue, "R1", "msg1")
	t1 := findCondition(status.Conditions, ConditionApplied).LastTransitionTime

	// Set Applied=True again (same status) -> time should NOT change
	setCondition(status, ConditionApplied, ConditionStatusTrue, "R2", "msg2")
	t2 := findCondition(status.Conditions, ConditionApplied).LastTransitionTime
	assert.Equal(t, t1, t2, "transition time should not change when status unchanged")
	assert.Equal(t, "R2", findCondition(status.Conditions, ConditionApplied).Reason)

	// Set Applied=False -> time SHOULD change
	setCondition(status, ConditionApplied, ConditionStatusFalse, "R3", "msg3")
	t3 := findCondition(status.Conditions, ConditionApplied).LastTransitionTime
	assert.True(t, !t3.Before(t2), "transition time should advance when status changes")
}

// findCondition returns the condition with the given type, or nil
func findCondition(conditions []Condition, condType string) *Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}
