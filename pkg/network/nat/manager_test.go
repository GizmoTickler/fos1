package nat

import (
	"context"
	"fmt"
	"testing"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// mockCiliumClient is a mock Cilium client for testing NAT manager behavior.
// It records calls and can be configured to return errors.
type mockCiliumClient struct {
	createNATCalls        []*cilium.CiliumNATConfig
	removeNATCalls        []*cilium.CiliumNATConfig
	createNAT64Calls      []*cilium.NAT64Config
	removeNAT64Calls      []*cilium.NAT64Config
	createPortForwardCalls []*cilium.PortForwardConfig
	removePortForwardCalls []*cilium.PortForwardConfig

	// Error injection
	createNATErr        error
	removeNATErr        error
	createNAT64Err      error
	removeNAT64Err      error
	createPortForwardErr error
	removePortForwardErr error
}

func newMockCiliumClient() *mockCiliumClient {
	return &mockCiliumClient{}
}

func (m *mockCiliumClient) ApplyNetworkPolicy(_ context.Context, _ *cilium.CiliumPolicy) error {
	return nil
}

func (m *mockCiliumClient) CreateNAT(_ context.Context, config *cilium.CiliumNATConfig) error {
	m.createNATCalls = append(m.createNATCalls, config)
	return m.createNATErr
}

func (m *mockCiliumClient) RemoveNAT(_ context.Context, config *cilium.CiliumNATConfig) error {
	m.removeNATCalls = append(m.removeNATCalls, config)
	return m.removeNATErr
}

func (m *mockCiliumClient) CreateNAT64(_ context.Context, config *cilium.NAT64Config) error {
	m.createNAT64Calls = append(m.createNAT64Calls, config)
	return m.createNAT64Err
}

func (m *mockCiliumClient) RemoveNAT64(_ context.Context, config *cilium.NAT64Config) error {
	m.removeNAT64Calls = append(m.removeNAT64Calls, config)
	return m.removeNAT64Err
}

func (m *mockCiliumClient) CreatePortForward(_ context.Context, config *cilium.PortForwardConfig) error {
	m.createPortForwardCalls = append(m.createPortForwardCalls, config)
	return m.createPortForwardErr
}

func (m *mockCiliumClient) RemovePortForward(_ context.Context, config *cilium.PortForwardConfig) error {
	m.removePortForwardCalls = append(m.removePortForwardCalls, config)
	return m.removePortForwardErr
}

func (m *mockCiliumClient) ConfigureVLANRouting(_ context.Context, _ *cilium.CiliumVLANRoutingConfig) error {
	return nil
}

func (m *mockCiliumClient) ConfigureDPIIntegration(_ context.Context, _ *cilium.CiliumDPIIntegrationConfig) error {
	return nil
}

// --- Tests ---

func TestApplySNATPolicy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-snat",
		Namespace:       "default",
		Type:            TypeSNAT,
		Interface:       "eth0",
		SourceAddresses: []string{"192.168.1.0/24"},
	}

	err := mgr.ApplyNATPolicy(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify Cilium was called
	if len(mock.createNATCalls) != 1 {
		t.Fatalf("expected 1 CreateNAT call, got %d", len(mock.createNATCalls))
	}
	call := mock.createNATCalls[0]
	if call.SourceNetwork != "192.168.1.0/24" {
		t.Errorf("expected source network 192.168.1.0/24, got %s", call.SourceNetwork)
	}
	if call.DestinationIface != "eth0" {
		t.Errorf("expected destination iface eth0, got %s", call.DestinationIface)
	}
	if call.IPv6 {
		t.Error("expected IPv6=false for SNAT")
	}

	// Verify status is Ready
	status, err := mgr.GetNATPolicyStatus("test-snat", "default")
	if err != nil {
		t.Fatalf("expected no error getting status, got: %v", err)
	}
	assertReadyCondition(t, status, true, "PolicyApplied")
}

func TestApplySNATPolicy_CiliumFailure(t *testing.T) {
	mock := newMockCiliumClient()
	mock.createNATErr = fmt.Errorf("cilium connection refused")
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-snat-fail",
		Namespace:       "default",
		Type:            TypeSNAT,
		Interface:       "eth0",
		SourceAddresses: []string{"192.168.1.0/24"},
	}

	err := mgr.ApplyNATPolicy(config)
	if err == nil {
		t.Fatal("expected error when Cilium fails, got nil")
	}

	// Policy should NOT be stored after failure
	policies, _ := mgr.ListNATPolicies()
	if len(policies) != 0 {
		t.Errorf("expected 0 policies after failure, got %d", len(policies))
	}

	// Status should not exist (policy was cleaned up)
	_, err = mgr.GetNATPolicyStatus("test-snat-fail", "default")
	if err == nil {
		t.Error("expected error getting status for failed policy")
	}
}

func TestApplyMasqueradePolicy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-masq",
		Namespace:       "default",
		Type:            TypeMasquerade,
		Interface:       "eth0",
		SourceAddresses: []string{"10.0.0.0/8"},
	}

	err := mgr.ApplyNATPolicy(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(mock.createNATCalls) != 1 {
		t.Fatalf("expected 1 CreateNAT call, got %d", len(mock.createNATCalls))
	}
	if !mock.createNATCalls[0].MasqueradeEnabled {
		t.Error("expected MasqueradeEnabled=true for masquerade policy")
	}
}

func TestApplyDNATPolicy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:       "test-dnat",
		Namespace:  "default",
		Type:       TypeDNAT,
		ExternalIP: "203.0.113.1",
		PortMappings: []PortMapping{
			{
				Protocol:     "tcp",
				ExternalPort: 80,
				InternalIP:   "192.168.1.10",
				InternalPort: 8080,
				Description:  "HTTP redirect",
			},
			{
				Protocol:     "tcp",
				ExternalPort: 443,
				InternalIP:   "192.168.1.10",
				InternalPort: 8443,
				Description:  "HTTPS redirect",
			},
		},
	}

	err := mgr.ApplyNATPolicy(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Should create one port forward per mapping
	if len(mock.createPortForwardCalls) != 2 {
		t.Fatalf("expected 2 CreatePortForward calls, got %d", len(mock.createPortForwardCalls))
	}

	// Verify first mapping
	pf := mock.createPortForwardCalls[0]
	if pf.ExternalIP != "203.0.113.1" {
		t.Errorf("expected external IP 203.0.113.1, got %s", pf.ExternalIP)
	}
	if pf.ExternalPort != 80 {
		t.Errorf("expected external port 80, got %d", pf.ExternalPort)
	}
	if pf.InternalIP != "192.168.1.10" {
		t.Errorf("expected internal IP 192.168.1.10, got %s", pf.InternalIP)
	}
	if pf.InternalPort != 8080 {
		t.Errorf("expected internal port 8080, got %d", pf.InternalPort)
	}
}

func TestApplyNAT66Policy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-nat66",
		Namespace:       "default",
		Type:            TypeNAT66,
		Interface:       "eth0",
		SourceAddresses: []string{"fd00::/64"},
	}

	err := mgr.ApplyNATPolicy(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(mock.createNATCalls) != 1 {
		t.Fatalf("expected 1 CreateNAT call, got %d", len(mock.createNATCalls))
	}
	call := mock.createNATCalls[0]
	if !call.IPv6 {
		t.Error("expected IPv6=true for NAT66")
	}
	if call.SourceNetwork != "fd00::/64" {
		t.Errorf("expected source fd00::/64, got %s", call.SourceNetwork)
	}
}

func TestApplyNAT64Policy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-nat64",
		Namespace:       "default",
		Type:            TypeNAT64,
		Interface:       "eth0",
		SourceAddresses: []string{"2001:db8::/32"},
	}

	err := mgr.ApplyNATPolicy(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(mock.createNAT64Calls) != 1 {
		t.Fatalf("expected 1 CreateNAT64 call, got %d", len(mock.createNAT64Calls))
	}
	call := mock.createNAT64Calls[0]
	if call.SourceNetwork != "2001:db8::/32" {
		t.Errorf("expected source 2001:db8::/32, got %s", call.SourceNetwork)
	}
	if call.Prefix64 != cilium.DefaultNAT64Prefix {
		t.Errorf("expected prefix64 %s, got %s", cilium.DefaultNAT64Prefix, call.Prefix64)
	}
}

func TestApplyFullNATPolicy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-full",
		Namespace:       "default",
		Type:            TypeFull,
		Interface:       "eth0",
		ExternalIP:      "203.0.113.1",
		SourceAddresses: []string{"192.168.1.0/24"},
		PortMappings: []PortMapping{
			{
				Protocol:     "tcp",
				ExternalPort: 80,
				InternalIP:   "192.168.1.10",
				InternalPort: 8080,
			},
		},
	}

	err := mgr.ApplyNATPolicy(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// SNAT creates one NAT call, DNAT creates one port forward call
	if len(mock.createNATCalls) != 1 {
		t.Errorf("expected 1 CreateNAT call for SNAT, got %d", len(mock.createNATCalls))
	}
	if len(mock.createPortForwardCalls) != 1 {
		t.Errorf("expected 1 CreatePortForward call for DNAT, got %d", len(mock.createPortForwardCalls))
	}
}

func TestRemoveNATPolicy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-remove",
		Namespace:       "default",
		Type:            TypeSNAT,
		Interface:       "eth0",
		SourceAddresses: []string{"192.168.1.0/24"},
	}

	// Apply first
	if err := mgr.ApplyNATPolicy(config); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Remove
	if err := mgr.RemoveNATPolicy("test-remove", "default"); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	// Verify Cilium RemoveNAT was called
	if len(mock.removeNATCalls) != 1 {
		t.Fatalf("expected 1 RemoveNAT call, got %d", len(mock.removeNATCalls))
	}

	// Verify policy is gone
	policies, _ := mgr.ListNATPolicies()
	if len(policies) != 0 {
		t.Errorf("expected 0 policies after removal, got %d", len(policies))
	}

	// Verify status is gone
	_, err := mgr.GetNATPolicyStatus("test-remove", "default")
	if err == nil {
		t.Error("expected error getting status for removed policy")
	}
}

func TestRemoveNATPolicy_CiliumFailure(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-remove-fail",
		Namespace:       "default",
		Type:            TypeSNAT,
		Interface:       "eth0",
		SourceAddresses: []string{"192.168.1.0/24"},
	}

	// Apply first
	if err := mgr.ApplyNATPolicy(config); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	// Inject error for removal
	mock.removeNATErr = fmt.Errorf("cilium unavailable")

	err := mgr.RemoveNATPolicy("test-remove-fail", "default")
	if err == nil {
		t.Fatal("expected error when Cilium removal fails")
	}

	// Policy should still exist since removal failed
	policies, _ := mgr.ListNATPolicies()
	if len(policies) != 1 {
		t.Errorf("expected 1 policy (removal failed), got %d", len(policies))
	}
}

func TestRemoveNonexistentPolicy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.RemoveNATPolicy("does-not-exist", "default")
	if err == nil {
		t.Fatal("expected error removing non-existent policy")
	}
}

// --- Validation tests ---

func TestValidation_MissingName(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Namespace:       "default",
		Type:            TypeSNAT,
		Interface:       "eth0",
		SourceAddresses: []string{"192.168.1.0/24"},
	})
	if err == nil {
		t.Fatal("expected validation error for missing name")
	}
}

func TestValidation_MissingNamespace(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Name:            "test",
		Type:            TypeSNAT,
		Interface:       "eth0",
		SourceAddresses: []string{"192.168.1.0/24"},
	})
	if err == nil {
		t.Fatal("expected validation error for missing namespace")
	}
}

func TestValidation_SNATMissingSourceAddresses(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Name:      "test",
		Namespace: "default",
		Type:      TypeSNAT,
		Interface: "eth0",
	})
	if err == nil {
		t.Fatal("expected validation error for missing source addresses")
	}
}

func TestValidation_DNATMissingExternalIP(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Name:      "test",
		Namespace: "default",
		Type:      TypeDNAT,
		PortMappings: []PortMapping{
			{Protocol: "tcp", ExternalPort: 80, InternalIP: "10.0.0.1", InternalPort: 80},
		},
	})
	if err == nil {
		t.Fatal("expected validation error for missing external IP")
	}
}

func TestValidation_DNATMissingPortMappings(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Name:       "test",
		Namespace:  "default",
		Type:       TypeDNAT,
		ExternalIP: "1.2.3.4",
	})
	if err == nil {
		t.Fatal("expected validation error for missing port mappings")
	}
}

func TestValidation_DNATInvalidPort(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Name:       "test",
		Namespace:  "default",
		Type:       TypeDNAT,
		ExternalIP: "1.2.3.4",
		PortMappings: []PortMapping{
			{Protocol: "tcp", ExternalPort: 0, InternalIP: "10.0.0.1", InternalPort: 80},
		},
	})
	if err == nil {
		t.Fatal("expected validation error for invalid port")
	}
}

func TestValidation_NAT66WithIPv4Source(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Name:            "test",
		Namespace:       "default",
		Type:            TypeNAT66,
		Interface:       "eth0",
		SourceAddresses: []string{"192.168.1.0/24"}, // IPv4 - invalid for NAT66
	})
	if err == nil {
		t.Fatal("expected validation error for IPv4 source in NAT66")
	}
}

func TestValidation_NAT64WithIPv4Source(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Name:            "test",
		Namespace:       "default",
		Type:            TypeNAT64,
		Interface:       "eth0",
		SourceAddresses: []string{"192.168.1.0/24"}, // IPv4 - invalid for NAT64
	})
	if err == nil {
		t.Fatal("expected validation error for IPv4 source in NAT64")
	}
}

func TestValidation_IPv6FlagWithIPv4Address(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Name:            "test",
		Namespace:       "default",
		Type:            TypeSNAT,
		Interface:       "eth0",
		SourceAddresses: []string{"192.168.1.0/24"},
		IPv6:            true, // Mismatch
	})
	if err == nil {
		t.Fatal("expected validation error for IPv6 flag with IPv4 address")
	}
}

func TestValidation_IPv4FlagWithIPv6Address(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Name:            "test",
		Namespace:       "default",
		Type:            TypeSNAT,
		Interface:       "eth0",
		SourceAddresses: []string{"fd00::/64"},
		IPv6:            false, // Mismatch
	})
	if err == nil {
		t.Fatal("expected validation error for IPv4 flag with IPv6 address")
	}
}

func TestValidation_UnsupportedType(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	err := mgr.ApplyNATPolicy(Config{
		Name:      "test",
		Namespace: "default",
		Type:      PolicyType("bogus"),
	})
	if err == nil {
		t.Fatal("expected validation error for unsupported type")
	}
}

func TestIdempotentApply(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-idempotent",
		Namespace:       "default",
		Type:            TypeSNAT,
		Interface:       "eth0",
		SourceAddresses: []string{"192.168.1.0/24"},
	}

	// Apply twice
	if err := mgr.ApplyNATPolicy(config); err != nil {
		t.Fatalf("first apply failed: %v", err)
	}
	if err := mgr.ApplyNATPolicy(config); err != nil {
		t.Fatalf("second apply failed: %v", err)
	}

	// Should have called Cilium twice (idempotent enforcement)
	if len(mock.createNATCalls) != 2 {
		t.Errorf("expected 2 CreateNAT calls (idempotent re-apply), got %d", len(mock.createNATCalls))
	}

	// Should still have exactly 1 policy
	policies, _ := mgr.ListNATPolicies()
	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
}

func TestRemoveDNATPolicy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:       "test-dnat-remove",
		Namespace:  "default",
		Type:       TypeDNAT,
		ExternalIP: "203.0.113.1",
		PortMappings: []PortMapping{
			{Protocol: "tcp", ExternalPort: 80, InternalIP: "192.168.1.10", InternalPort: 8080},
			{Protocol: "tcp", ExternalPort: 443, InternalIP: "192.168.1.10", InternalPort: 8443},
		},
	}

	if err := mgr.ApplyNATPolicy(config); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if err := mgr.RemoveNATPolicy("test-dnat-remove", "default"); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	if len(mock.removePortForwardCalls) != 2 {
		t.Errorf("expected 2 RemovePortForward calls, got %d", len(mock.removePortForwardCalls))
	}
}

func TestRemoveNAT66Policy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-nat66-remove",
		Namespace:       "default",
		Type:            TypeNAT66,
		Interface:       "eth0",
		SourceAddresses: []string{"fd00::/64"},
	}

	if err := mgr.ApplyNATPolicy(config); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if err := mgr.RemoveNATPolicy("test-nat66-remove", "default"); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	if len(mock.removeNATCalls) != 1 {
		t.Fatalf("expected 1 RemoveNAT call, got %d", len(mock.removeNATCalls))
	}
	if !mock.removeNATCalls[0].IPv6 {
		t.Error("expected IPv6=true in NAT66 removal")
	}
}

func TestRemoveNAT64Policy(t *testing.T) {
	mock := newMockCiliumClient()
	mgr := NewManager(mock)

	config := Config{
		Name:            "test-nat64-remove",
		Namespace:       "default",
		Type:            TypeNAT64,
		Interface:       "eth0",
		SourceAddresses: []string{"2001:db8::/32"},
	}

	if err := mgr.ApplyNATPolicy(config); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if err := mgr.RemoveNATPolicy("test-nat64-remove", "default"); err != nil {
		t.Fatalf("remove failed: %v", err)
	}

	if len(mock.removeNAT64Calls) != 1 {
		t.Fatalf("expected 1 RemoveNAT64 call, got %d", len(mock.removeNAT64Calls))
	}
}

// assertReadyCondition checks that the status has a Ready condition with the expected value
func assertReadyCondition(t *testing.T, status *Status, expectedReady bool, expectedReason string) {
	t.Helper()
	expectedStatus := "True"
	if !expectedReady {
		expectedStatus = "False"
	}
	for _, c := range status.Conditions {
		if c.Type == "Ready" {
			if c.Status != expectedStatus {
				t.Errorf("expected Ready=%s, got %s", expectedStatus, c.Status)
			}
			if c.Reason != expectedReason {
				t.Errorf("expected reason %q, got %q", expectedReason, c.Reason)
			}
			return
		}
	}
	t.Error("no Ready condition found in status")
}
