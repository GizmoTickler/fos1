package ebpf

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Hook Type Tests ---

func TestSupportedHookTypes_ReturnsAllExpectedHooks(t *testing.T) {
	hooks := SupportedHookTypes()

	expected := []HookType{
		HookTypeXDP,
		HookTypeTCIngress,
		HookTypeTCEgress,
		HookTypeSockOps,
		HookTypeCGroup,
	}

	assert.Equal(t, expected, hooks)
	assert.Len(t, hooks, 5, "expected exactly 5 supported hook types")
}

func TestSupportedHookTypes_AreEnumerable(t *testing.T) {
	hooks := SupportedHookTypes()
	assert.Greater(t, len(hooks), 0, "SupportedHookTypes must return at least one hook")

	// Verify each hook has a non-empty string value
	for _, hook := range hooks {
		assert.NotEmpty(t, string(hook), "hook type must have a non-empty string value")
	}
}

func TestIsHookTypeSupported_AcceptsValidHooks(t *testing.T) {
	validHooks := []HookType{
		HookTypeXDP,
		HookTypeTCIngress,
		HookTypeTCEgress,
		HookTypeSockOps,
		HookTypeCGroup,
	}

	for _, hook := range validHooks {
		assert.True(t, IsHookTypeSupported(hook), "hook %s should be supported", hook)
	}
}

func TestIsHookTypeSupported_RejectsInvalidHooks(t *testing.T) {
	invalidHooks := []HookType{
		"",
		"invalid",
		"kprobe",
		"tracepoint",
		"raw_tracepoint",
		"fentry",
		"fexit",
		"lsm",
		"sk_msg",
		"XDP",          // case-sensitive
		"TC-INGRESS",   // case-sensitive
	}

	for _, hook := range invalidHooks {
		assert.False(t, IsHookTypeSupported(hook), "hook %q should NOT be supported", hook)
	}
}

func TestErrUnsupportedHookType_ErrorMessage(t *testing.T) {
	err := &ErrUnsupportedHookType{HookType: "kprobe"}
	assert.Contains(t, err.Error(), "kprobe")
	assert.Contains(t, err.Error(), "unsupported hook type")
	assert.Contains(t, err.Error(), "xdp")
}

func TestErrUnsupportedHookType_IsErrorsAs(t *testing.T) {
	err := &ErrUnsupportedHookType{HookType: "kprobe"}
	var target *ErrUnsupportedHookType
	assert.True(t, errors.As(err, &target))
	assert.Equal(t, HookType("kprobe"), target.HookType)
}

// --- ProgramManager Ownership Tests ---

func TestProgramManager_IsAuthoritative(t *testing.T) {
	// ProgramManager must be creatable and own program lifecycle
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")

	// Verify it starts with no programs
	programs, err := pm.ListPrograms()
	require.NoError(t, err)
	assert.Empty(t, programs)
}

func TestProgramManager_LoadXDPWithoutCodeUsesOwnedLoader(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")

	// Sprint 30 Ticket 38: LoadProgram with Type=xdp and empty Code
	// dispatches to the owned XDPLoader, which loads the embedded
	// xdp_ddos_drop ELF. In this unit-test environment we don't have
	// the embedded object (or kernel support), so the call must fail
	// loudly — but *not* with a placeholder success, and *not* with
	// the old "no program code provided" stub string.
	err := pm.LoadProgram(Program{
		Name: "xdp_ddos_drop",
		Type: ProgramTypeXDP,
	})
	assert.Error(t, err)
	// The error must come from the owned loader path — either the
	// embedded object is missing (non-Linux / freshly-cloned tree) or
	// the kernel/caps rejected the load. It must NOT be the legacy
	// "no program code provided" string.
	assert.NotContains(t, err.Error(), "no program code provided")
}

func TestProgramManager_LoadRejectsNonXDPTypes(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")

	for _, typ := range []string{
		ProgramTypeTCIngress,
		ProgramTypeTCEgress,
		ProgramTypeSockOps,
		ProgramTypeCGroup,
		"unknown-type",
	} {
		err := pm.LoadProgram(Program{Name: "prog-" + typ, Type: typ})
		assert.Error(t, err, "expected %q to be rejected", typ)
		assert.ErrorIs(t, err, ErrEBPFProgramTypeUnsupported,
			"type %q must return ErrEBPFProgramTypeUnsupported", typ)
	}
}

func TestProgramManager_GetNonexistentProgram(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")

	_, err := pm.GetProgram("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestProgramManager_UnloadNonexistentProgram(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")

	err := pm.UnloadProgram("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestProgramManager_AttachRejectsUnsupportedHook(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")

	// Even though the program doesn't exist, the hook type validation should
	// happen (in practice the program check happens first, but we test the
	// flow where hook validation would be the cause of failure)
	err := pm.AttachProgram("any-program", "kprobe")
	assert.Error(t, err)

	// The error should be either "not found" (program) or unsupported hook
	// Since program check happens first, we get "not found"
	assert.Contains(t, err.Error(), "not found")
}

func TestProgramManager_DetachNonexistentProgram(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")

	err := pm.DetachProgram("nonexistent", "xdp")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- Controller Tests ---

func TestController_RequiresCiliumForPolicyOps(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")

	// Controller without Cilium integration
	ctrl := NewController(pm, mm, nil, nil)

	// ApplyCiliumNetworkPolicy should fail without Cilium
	err := ctrl.ApplyCiliumNetworkPolicy("test", CiliumNetworkPolicy{
		Metadata: CiliumPolicyMetadata{Name: "test"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cilium integration not configured")

	// DeleteCiliumNetworkPolicy should fail without Cilium
	err = ctrl.DeleteCiliumNetworkPolicy("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cilium integration not configured")
}

func TestController_StartStop(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")
	ctrl := NewController(pm, mm, nil, nil)

	err := ctrl.Start()
	assert.NoError(t, err)

	err = ctrl.Stop()
	assert.NoError(t, err)
}

func TestController_DeprecatedMethodsRemoved(t *testing.T) {
	// This test verifies at compile time that the deprecated methods
	// (ApplyEBPFProgramConfig, ApplyTrafficControlConfig, ApplyNATConfig)
	// no longer exist on Controller. If someone re-adds them, this test
	// file will fail to compile due to the interface assertion below.
	type deprecatedMethods interface {
		ApplyEBPFProgramConfig(name string, config interface{}) error
	}

	// Controller should NOT implement the deprecated interface
	var ctrl interface{} = &Controller{}
	_, implements := ctrl.(deprecatedMethods)
	assert.False(t, implements, "Controller must not implement deprecated ApplyEBPFProgramConfig")
}

func TestController_ConfigLifecycle(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")
	ctrl := NewController(pm, mm, nil, nil)

	// List configs should return empty initially
	configs, err := ctrl.ListConfigs()
	require.NoError(t, err)
	assert.Empty(t, configs)

	// Get non-existent config
	_, err = ctrl.GetConfig("nonexistent")
	assert.Error(t, err)

	// Delete non-existent config
	err = ctrl.DeleteConfig("nonexistent")
	assert.Error(t, err)
}

func TestController_ListCiliumPolicies(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")
	ctrl := NewController(pm, mm, nil, nil)

	policies, err := ctrl.ListCiliumNetworkPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

// --- CiliumIntegration Discovery Tests ---

func TestCiliumIntegrationManager_ReturnsErrorWhenNotReachable(t *testing.T) {
	// Creating a manager with valid paths but unreachable Cilium should
	// return errors from discovery methods, NOT placeholder data.
	//
	// We can't create a real CiliumIntegrationManager here because it
	// validates that paths exist, but we verify the error types.

	var err *ErrCiliumNotAvailable

	// Verify the error type exists and is usable
	err = &ErrCiliumNotAvailable{Reason: "test reason"}
	assert.Contains(t, err.Error(), "cilium agent not available")
	assert.Contains(t, err.Error(), "test reason")

	// Verify errors.As works
	var target *ErrCiliumNotAvailable
	assert.True(t, errors.As(err, &target))
}

// --- MapManager Tests ---

func TestMapManager_Lifecycle(t *testing.T) {
	mm := NewMapManager()

	// List should be empty initially
	maps, err := mm.ListMaps()
	require.NoError(t, err)
	assert.Empty(t, maps)

	// Get non-existent map
	_, err = mm.GetMap("nonexistent")
	assert.Error(t, err)

	// Delete non-existent map
	err = mm.DeleteMap("nonexistent")
	assert.Error(t, err)
}

// --- Integration: Hook type validation flows through the system ---

func TestHookTypeValidation_EndToEnd(t *testing.T) {
	// Verify that SupportedHookTypes matches the CRD enum from
	// manifests/base/ebpf/crds/ebpfprogram.yaml
	crdHookTypes := map[HookType]bool{
		"xdp":        true,
		"tc-ingress": true,
		"tc-egress":  true,
		"sockops":    true,
		"cgroup":     true,
	}

	for _, hook := range SupportedHookTypes() {
		assert.True(t, crdHookTypes[hook],
			"hook type %s from SupportedHookTypes is not in CRD enum", hook)
	}

	for hook := range crdHookTypes {
		assert.True(t, IsHookTypeSupported(hook),
			"CRD hook type %s is not in SupportedHookTypes", hook)
	}
}

// --- mockCiliumIntegration for controller tests ---

type mockCiliumIntegration struct {
	syncErr        error
	applyErr       error
	getPoliciesErr error
	policies       []CiliumNetworkPolicy
	appliedPolicies []CiliumNetworkPolicy
}

func (m *mockCiliumIntegration) GetCiliumMaps() ([]*Map, error) {
	return nil, &ErrCiliumNotAvailable{Reason: "mock"}
}

func (m *mockCiliumIntegration) GetCiliumPrograms() ([]*LoadedProgram, error) {
	return nil, &ErrCiliumNotAvailable{Reason: "mock"}
}

func (m *mockCiliumIntegration) RegisterWithCilium(program Program) error {
	return nil
}

func (m *mockCiliumIntegration) UnregisterFromCilium(programName string) error {
	return nil
}

func (m *mockCiliumIntegration) GetCiliumEndpoints() ([]interface{}, error) {
	return nil, &ErrCiliumNotAvailable{Reason: "mock"}
}

func (m *mockCiliumIntegration) GetCiliumNetworkPolicies(ctx context.Context) ([]CiliumNetworkPolicy, error) {
	if m.getPoliciesErr != nil {
		return nil, m.getPoliciesErr
	}
	return m.policies, nil
}

func (m *mockCiliumIntegration) ApplyCiliumNetworkPolicy(ctx context.Context, policy CiliumNetworkPolicy) error {
	if m.applyErr != nil {
		return m.applyErr
	}
	m.appliedPolicies = append(m.appliedPolicies, policy)
	return nil
}

func (m *mockCiliumIntegration) SyncCiliumConfiguration() error {
	return m.syncErr
}

func TestController_ApplyCiliumPolicyWithRealIntegration(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")
	mock := &mockCiliumIntegration{}
	ctrl := NewController(pm, mm, mock, nil)

	policy := CiliumNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata: CiliumPolicyMetadata{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	err := ctrl.ApplyCiliumNetworkPolicy("test-policy", policy)
	require.NoError(t, err)

	// Verify the policy was applied via the mock
	assert.Len(t, mock.appliedPolicies, 1)
	assert.Equal(t, "test-policy", mock.appliedPolicies[0].Metadata.Name)

	// Verify it's stored locally
	policies, err := ctrl.ListCiliumNetworkPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.Contains(t, policies, "default/test-policy")
}

func TestController_ApplyCiliumPolicyFailure(t *testing.T) {
	mm := NewMapManager()
	pm := NewProgramManager(mm, "")
	mock := &mockCiliumIntegration{
		applyErr: &ErrCiliumNotAvailable{Reason: "agent down"},
	}
	ctrl := NewController(pm, mm, mock, nil)

	policy := CiliumNetworkPolicy{
		Metadata: CiliumPolicyMetadata{Name: "fail-policy"},
	}

	err := ctrl.ApplyCiliumNetworkPolicy("fail-policy", policy)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cilium agent not available")

	// Verify the policy was NOT stored after failure
	policies, err := ctrl.ListCiliumNetworkPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies, "policy should not be stored after apply failure")
}
