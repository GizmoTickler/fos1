package ebpf

import (
	"testing"

	hwEbpf "github.com/GizmoTickler/fos1/pkg/hardware/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiliumIntegration_ReturnsErrors(t *testing.T) {
	pm := NewProgramManager()
	mm := NewMapManager()
	ci := NewCiliumIntegration(pm, mm)

	// All discovery methods must return errors, not placeholder data
	maps, err := ci.GetCiliumMaps()
	assert.Error(t, err, "GetCiliumMaps must return an error, not placeholder data")
	assert.Nil(t, maps)
	assert.Contains(t, err.Error(), "live Cilium agent")

	programs, err := ci.GetCiliumPrograms()
	assert.Error(t, err, "GetCiliumPrograms must return an error, not placeholder data")
	assert.Nil(t, programs)
	assert.Contains(t, err.Error(), "live Cilium agent")

	endpoints, err := ci.GetCiliumEndpoints()
	assert.Error(t, err, "GetCiliumEndpoints must return an error, not placeholder data")
	assert.Nil(t, endpoints)
	assert.Contains(t, err.Error(), "live Cilium agent")

	err = ci.RegisterWithCilium(Program{Name: "test"})
	assert.Error(t, err, "RegisterWithCilium must return an error without live agent")

	err = ci.UnregisterFromCilium("test")
	assert.Error(t, err, "UnregisterFromCilium must return an error without live agent")

	err = ci.SyncWithCilium()
	assert.Error(t, err, "SyncWithCilium must return an error without live agent")
}

func TestProgramManager_NoHardwareManager_ReturnsErrors(t *testing.T) {
	// Create a program manager without hardware support
	pm := &ebpfProgramManager{
		programs:  make(map[string]*ProgramInfo),
		hwManager: nil,
	}

	// Load should fail, not silently succeed
	err := pm.LoadProgram(Program{
		Name: "test",
		Type: ProgramTypeXDP,
	})
	assert.Error(t, err, "LoadProgram must fail without hardware manager")
	assert.Contains(t, err.Error(), "not available")
}

func TestProgramManager_AttachRejectsUnsupportedHook(t *testing.T) {
	pm := &ebpfProgramManager{
		programs: map[string]*ProgramInfo{
			"test-prog": {
				Name:     "test-prog",
				Type:     ProgramTypeXDP,
				Loaded:   true,
				Attached: false,
			},
		},
		hwManager: nil,
	}

	// Unsupported hook type should be rejected
	err := pm.AttachProgram("test-prog", "kprobe")
	assert.Error(t, err)

	var unsupported *hwEbpf.ErrUnsupportedHookType
	assert.ErrorAs(t, err, &unsupported)
	assert.Equal(t, hwEbpf.HookType("kprobe"), unsupported.HookType)
}

func TestProgramManager_AttachValidatesHookBeforeHardware(t *testing.T) {
	pm := &ebpfProgramManager{
		programs: map[string]*ProgramInfo{
			"test-prog": {
				Name:     "test-prog",
				Type:     ProgramTypeXDP,
				Loaded:   true,
				Attached: false,
			},
		},
		hwManager: nil, // no hardware
	}

	// Valid hook type but no hardware -> should get hardware error, not hook error
	err := pm.AttachProgram("test-prog", "xdp")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

func TestMapManager_UpdateAndDump_ReturnErrors(t *testing.T) {
	mm := NewMapManager()

	// Create a map
	_, err := mm.CreateMap("test-map", MapTypeHash, 4, 4, 100)
	require.NoError(t, err)

	// Update should fail because kernel operations are not available
	err = mm.UpdateMap("test-map", map[interface{}]interface{}{})
	assert.Error(t, err, "UpdateMap must fail without kernel eBPF support")
	assert.Contains(t, err.Error(), "kernel eBPF support")

	// Dump should fail because kernel operations are not available
	_, err = mm.DumpMap("test-map")
	assert.Error(t, err, "DumpMap must fail without kernel eBPF support")
	assert.Contains(t, err.Error(), "kernel eBPF support")
}

func TestMapManager_Lifecycle(t *testing.T) {
	mm := NewMapManager()

	// List should be empty
	maps, err := mm.ListMaps()
	require.NoError(t, err)
	assert.Empty(t, maps)

	// Create
	m, err := mm.CreateMap("test", MapTypeHash, 4, 4, 100)
	require.NoError(t, err)
	assert.Equal(t, "test", m.Name)

	// Duplicate create fails
	_, err = mm.CreateMap("test", MapTypeHash, 4, 4, 100)
	assert.Error(t, err)

	// Get
	m, err = mm.GetMap("test")
	require.NoError(t, err)
	assert.Equal(t, "test", m.Name)

	// Get non-existent
	_, err = mm.GetMap("nonexistent")
	assert.Error(t, err)

	// Pin
	err = mm.PinMap("test", "/sys/fs/bpf/test")
	require.NoError(t, err)

	// Unpin
	err = mm.UnpinMap("test")
	require.NoError(t, err)

	// Double unpin fails
	err = mm.UnpinMap("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not pinned")

	// Delete
	err = mm.DeleteMap("test")
	require.NoError(t, err)

	// Delete non-existent
	err = mm.DeleteMap("test")
	assert.Error(t, err)
}

func TestEBPFController_Creates(t *testing.T) {
	ctrl := NewEBPFController()
	assert.NotNil(t, ctrl)
	assert.NotNil(t, ctrl.ProgramManager)
	assert.NotNil(t, ctrl.MapManager)
	assert.NotNil(t, ctrl.CiliumIntegration)
}

func TestSupportedHookTypes_MatchProgramTypes(t *testing.T) {
	// Verify that every ProgramType defined in types.go has a corresponding
	// supported hook type in the hardware layer
	programTypes := map[ProgramType]hwEbpf.HookType{
		ProgramTypeXDP:       hwEbpf.HookTypeXDP,
		ProgramTypeTCIngress: hwEbpf.HookTypeTCIngress,
		ProgramTypeTCEgress:  hwEbpf.HookTypeTCEgress,
		ProgramTypeSockOps:   hwEbpf.HookTypeSockOps,
		ProgramTypeCGroup:    hwEbpf.HookTypeCGroup,
	}

	for progType, hookType := range programTypes {
		assert.True(t, hwEbpf.IsHookTypeSupported(hookType),
			"program type %s maps to unsupported hook type %s", progType, hookType)
	}
}
