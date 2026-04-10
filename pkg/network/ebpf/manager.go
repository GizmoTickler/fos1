package ebpf

import (
	"fmt"
	"sync"
	"time"

	hwEbpf "github.com/GizmoTickler/fos1/pkg/hardware/ebpf"
	hwTypes "github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// Import explanation:
// The authoritative eBPF lifecycle owner is pkg/hardware/ebpf.ProgramManager.
// This wrapper adapts the hardware/ebpf.Manager to implement the ProgramManager
// interface defined in this package, delegating all real operations to the
// hardware layer.

// ebpfProgramManager implements the ProgramManager interface.
// It wraps the hardware/ebpf.Manager to avoid code duplication.
// If the hardware manager is not available (e.g. not on Linux), operations
// return explicit errors rather than placeholder success.
type ebpfProgramManager struct {
	mutex    sync.RWMutex
	programs map[string]*ProgramInfo
	hwManager *hwEbpf.Manager
}

// NewProgramManager creates a new program manager.
// If the hardware eBPF manager cannot be initialized, the returned manager
// will return errors for all operations rather than silently succeeding.
func NewProgramManager() ProgramManager {
	hwManager, err := hwEbpf.NewManager()
	if err != nil {
		// Return a manager that will error on operations, not silently succeed
		return &ebpfProgramManager{
			programs: make(map[string]*ProgramInfo),
			hwManager: nil,
		}
	}

	return &ebpfProgramManager{
		programs: make(map[string]*ProgramInfo),
		hwManager: hwManager,
	}
}

// errNoHardwareManager is returned when the hardware eBPF manager is not available.
var errNoHardwareManager = fmt.Errorf("hardware eBPF manager not available; cannot perform eBPF operations without kernel support")

// LoadProgram loads an eBPF program via the hardware manager.
func (m *ebpfProgramManager) LoadProgram(program Program) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.programs[program.Name]; exists {
		return fmt.Errorf("program %s already loaded", program.Name)
	}

	if m.hwManager == nil {
		return errNoHardwareManager
	}

	hwProgram := hwTypes.EBPFProgram{
		Name:      program.Name,
		Type:      string(program.Type),
		Interface: program.Interface,
	}

	if err := m.hwManager.LoadProgram(hwProgram); err != nil {
		return fmt.Errorf("failed to load program: %w", err)
	}

	m.programs[program.Name] = &ProgramInfo{
		Name:        program.Name,
		Type:        program.Type,
		ID:          0,
		Tag:         "",
		Loaded:      true,
		Attached:    false,
		MapRefs:     make([]string, 0),
		LastUpdated: nowFunc(),
	}

	return nil
}

// UnloadProgram unloads an eBPF program via the hardware manager.
func (m *ebpfProgramManager) UnloadProgram(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	prog, exists := m.programs[name]
	if !exists {
		return fmt.Errorf("program %s not found", name)
	}

	if prog.Attached {
		return fmt.Errorf("program %s is still attached, detach first", name)
	}

	if m.hwManager == nil {
		return errNoHardwareManager
	}

	if err := m.hwManager.UnloadProgram(name); err != nil {
		return fmt.Errorf("failed to unload program: %w", err)
	}

	delete(m.programs, name)
	return nil
}

// AttachProgram attaches an eBPF program to a hook via the hardware manager.
func (m *ebpfProgramManager) AttachProgram(programName, hookName string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	prog, exists := m.programs[programName]
	if !exists {
		return fmt.Errorf("program %s not found", programName)
	}

	// Validate hook type using the authoritative supported hooks list
	if !hwEbpf.IsHookTypeSupported(hwEbpf.HookType(hookName)) {
		return &hwEbpf.ErrUnsupportedHookType{HookType: hwEbpf.HookType(hookName)}
	}

	if m.hwManager == nil {
		return errNoHardwareManager
	}

	if err := m.hwManager.AttachProgram(programName, hookName); err != nil {
		return fmt.Errorf("failed to attach program: %w", err)
	}

	prog.Attached = true
	prog.LastUpdated = nowFunc()
	return nil
}

// DetachProgram detaches an eBPF program from a hook via the hardware manager.
func (m *ebpfProgramManager) DetachProgram(programName, hookName string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	prog, exists := m.programs[programName]
	if !exists {
		return fmt.Errorf("program %s not found", programName)
	}

	if !prog.Attached {
		return fmt.Errorf("program %s is not attached", programName)
	}

	if m.hwManager == nil {
		return errNoHardwareManager
	}

	if err := m.hwManager.DetachProgram(programName, hookName); err != nil {
		return fmt.Errorf("failed to detach program: %w", err)
	}

	prog.Attached = false
	prog.LastUpdated = nowFunc()
	return nil
}

// ReplaceProgram replaces an existing program with a new one.
func (m *ebpfProgramManager) ReplaceProgram(oldName, newName string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	oldProg, oldExists := m.programs[oldName]
	newProg, newExists := m.programs[newName]

	if !oldExists {
		return fmt.Errorf("old program %s not found", oldName)
	}
	if !newExists {
		return fmt.Errorf("new program %s not found", newName)
	}
	if !oldProg.Attached {
		return fmt.Errorf("old program %s is not attached", oldName)
	}

	if m.hwManager == nil {
		return errNoHardwareManager
	}

	// Detach old, attach new via hardware manager
	// The hardware manager's Manager type doesn't support atomic replace,
	// so we do detach + attach.
	if err := m.hwManager.DetachProgram(oldName, string(oldProg.Type)); err != nil {
		return fmt.Errorf("failed to detach old program: %w", err)
	}

	if err := m.hwManager.AttachProgram(newName, string(newProg.Type)); err != nil {
		return fmt.Errorf("failed to attach new program: %w", err)
	}

	oldProg.Attached = false
	newProg.Attached = true
	oldProg.LastUpdated = nowFunc()
	newProg.LastUpdated = nowFunc()

	return nil
}

// ListPrograms lists all loaded eBPF programs.
func (m *ebpfProgramManager) ListPrograms() ([]ProgramInfo, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.hwManager != nil {
		hwPrograms, err := m.hwManager.ListPrograms()
		if err != nil {
			return nil, fmt.Errorf("failed to list programs: %w", err)
		}

		programs := make([]ProgramInfo, 0, len(hwPrograms))
		for _, hwProg := range hwPrograms {
			cachedProg, exists := m.programs[hwProg.Name]
			if exists {
				cachedProg.ID = uint32(hwProg.ID)
				cachedProg.LastUpdated = nowFunc()
				programs = append(programs, *cachedProg)
			} else {
				progType := ProgramTypeXDP
				switch hwProg.Type {
				case "xdp":
					progType = ProgramTypeXDP
				case "tc-ingress":
					progType = ProgramTypeTCIngress
				case "tc-egress":
					progType = ProgramTypeTCEgress
				case "sockops":
					progType = ProgramTypeSockOps
				case "cgroup":
					progType = ProgramTypeCGroup
				}
				programs = append(programs, ProgramInfo{
					Name:        hwProg.Name,
					Type:        progType,
					ID:          uint32(hwProg.ID),
					Loaded:      true,
					Attached:    hwProg.Attached,
					MapRefs:     make([]string, 0),
					LastUpdated: nowFunc(),
				})
			}
		}
		return programs, nil
	}

	programs := make([]ProgramInfo, 0, len(m.programs))
	for _, prog := range m.programs {
		programs = append(programs, *prog)
	}
	return programs, nil
}

// GetProgram retrieves information about a program.
func (m *ebpfProgramManager) GetProgram(name string) (*ProgramInfo, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	prog, exists := m.programs[name]
	if !exists {
		return nil, fmt.Errorf("program %s not found", name)
	}

	result := *prog
	return &result, nil
}

// ebpfMapManager implements the MapManager interface.
// Map operations that require kernel support return errors when the
// hardware manager is not available.
type ebpfMapManager struct {
	mutex sync.RWMutex
	maps  map[string]Map
}

// NewMapManager creates a new map manager.
func NewMapManager() MapManager {
	return &ebpfMapManager{
		maps: make(map[string]Map),
	}
}

// CreateMap creates a new eBPF map.
// Note: This stores metadata only. Actual kernel map creation is handled
// by the hardware layer when programs are loaded.
func (m *ebpfMapManager) CreateMap(name string, mapType MapType, keySize, valueSize, maxEntries int) (Map, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.maps[name]; exists {
		return Map{}, fmt.Errorf("map %s already exists", name)
	}

	mapObj := Map{
		Name:       name,
		Type:       mapType,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
		ID:         0,
	}

	m.maps[name] = mapObj
	return mapObj, nil
}

// DeleteMap removes an eBPF map.
func (m *ebpfMapManager) DeleteMap(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.maps[name]; !exists {
		return fmt.Errorf("map %s not found", name)
	}

	delete(m.maps, name)
	return nil
}

// GetMap retrieves an eBPF map.
func (m *ebpfMapManager) GetMap(name string) (Map, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	mapObj, exists := m.maps[name]
	if !exists {
		return Map{}, fmt.Errorf("map %s not found", name)
	}

	return mapObj, nil
}

// ListMaps lists all eBPF maps.
func (m *ebpfMapManager) ListMaps() ([]Map, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	maps := make([]Map, 0, len(m.maps))
	for _, mapObj := range m.maps {
		maps = append(maps, mapObj)
	}

	return maps, nil
}

// UpdateMap updates entries in an eBPF map.
// Returns an error because kernel map operations require the hardware layer.
func (m *ebpfMapManager) UpdateMap(name string, entries map[interface{}]interface{}) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.maps[name]; !exists {
		return fmt.Errorf("map %s not found", name)
	}

	return fmt.Errorf("map update requires kernel eBPF support; use pkg/hardware/ebpf.MapManager for kernel map operations")
}

// DumpMap dumps the contents of an eBPF map.
// Returns an error because kernel map operations require the hardware layer.
func (m *ebpfMapManager) DumpMap(name string) (map[interface{}]interface{}, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if _, exists := m.maps[name]; !exists {
		return nil, fmt.Errorf("map %s not found", name)
	}

	return nil, fmt.Errorf("map dump requires kernel eBPF support; use pkg/hardware/ebpf.MapManager for kernel map operations")
}

// PinMap pins a map to the BPF filesystem.
func (m *ebpfMapManager) PinMap(name, path string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	mapObj, exists := m.maps[name]
	if !exists {
		return fmt.Errorf("map %s not found", name)
	}

	mapObj.PinPath = path
	m.maps[name] = mapObj
	return nil
}

// UnpinMap unpins a map from the BPF filesystem.
func (m *ebpfMapManager) UnpinMap(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	mapObj, exists := m.maps[name]
	if !exists {
		return fmt.Errorf("map %s not found", name)
	}

	if mapObj.PinPath == "" {
		return fmt.Errorf("map %s is not pinned", name)
	}

	mapObj.PinPath = ""
	m.maps[name] = mapObj
	return nil
}

// ciliumIntegration implements the CiliumIntegration interface.
// All methods return errors indicating that the Cilium agent must be queried
// via the authoritative integration in pkg/hardware/ebpf.CiliumIntegrationManager.
// This type does NOT return placeholder/simulated data.
type ciliumIntegration struct {
	programManager ProgramManager
	mapManager     MapManager
}

// NewCiliumIntegration creates a new Cilium integration.
func NewCiliumIntegration(programManager ProgramManager, mapManager MapManager) CiliumIntegration {
	return &ciliumIntegration{
		programManager: programManager,
		mapManager:     mapManager,
	}
}

// GetCiliumMaps returns an error directing callers to the authoritative integration.
func (c *ciliumIntegration) GetCiliumMaps() ([]Map, error) {
	return nil, fmt.Errorf("cilium map discovery requires a live Cilium agent; use pkg/hardware/ebpf.CiliumIntegrationManager")
}

// GetCiliumPrograms returns an error directing callers to the authoritative integration.
func (c *ciliumIntegration) GetCiliumPrograms() ([]ProgramInfo, error) {
	return nil, fmt.Errorf("cilium program discovery requires a live Cilium agent; use pkg/hardware/ebpf.CiliumIntegrationManager")
}

// RegisterWithCilium returns an error directing callers to the authoritative integration.
func (c *ciliumIntegration) RegisterWithCilium(program Program) error {
	return fmt.Errorf("cilium registration requires a live Cilium agent; use pkg/hardware/ebpf.CiliumIntegrationManager")
}

// UnregisterFromCilium returns an error directing callers to the authoritative integration.
func (c *ciliumIntegration) UnregisterFromCilium(programName string) error {
	return fmt.Errorf("cilium unregistration requires a live Cilium agent; use pkg/hardware/ebpf.CiliumIntegrationManager")
}

// GetCiliumEndpoints returns an error directing callers to the authoritative integration.
func (c *ciliumIntegration) GetCiliumEndpoints() ([]Endpoint, error) {
	return nil, fmt.Errorf("cilium endpoint discovery requires a live Cilium agent; use pkg/hardware/ebpf.CiliumIntegrationManager")
}

// SyncWithCilium returns an error directing callers to the authoritative integration.
func (c *ciliumIntegration) SyncWithCilium() error {
	return fmt.Errorf("cilium sync requires a live Cilium agent; use pkg/hardware/ebpf.CiliumIntegrationManager")
}

// NewEBPFController creates a new eBPF controller.
func NewEBPFController() *EBPFController {
	programManager := NewProgramManager()
	mapManager := NewMapManager()
	ciliumIntegration := NewCiliumIntegration(programManager, mapManager)

	return &EBPFController{
		ProgramManager:    programManager,
		MapManager:        mapManager,
		CiliumIntegration: ciliumIntegration,
	}
}

// nowFunc is a helper for testing; defaults to time.Now.
var nowFunc = func() time.Time {
	return time.Now()
}
