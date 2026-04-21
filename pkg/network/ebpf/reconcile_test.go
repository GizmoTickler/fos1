package ebpf

import (
	"errors"
	"sync"
	"testing"

	hwTypes "github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// fakeHardwareManager is an in-memory implementation of hardwareManager used
// to drive the ebpfProgramManager wrapper through its success paths without
// requiring kernel eBPF support.
type fakeHardwareManager struct {
	mu sync.Mutex

	// programs is the authoritative state: key = program name.
	programs map[string]*hwTypes.EBPFProgramInfo
	// attachments stores "prog:hook" strings.
	attachments map[string]bool

	loadErr   error
	unloadErr error
	attachErr error
	detachErr error
	listErr   error
}

func newFakeHardwareManager() *fakeHardwareManager {
	return &fakeHardwareManager{
		programs:    make(map[string]*hwTypes.EBPFProgramInfo),
		attachments: make(map[string]bool),
	}
}

func (f *fakeHardwareManager) LoadProgram(program hwTypes.EBPFProgram) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loadErr != nil {
		return f.loadErr
	}
	if _, exists := f.programs[program.Name]; exists {
		return errors.New("already loaded")
	}
	f.programs[program.Name] = &hwTypes.EBPFProgramInfo{
		Name:      program.Name,
		Type:      program.Type,
		Interface: program.Interface,
		Attached:  false,
		ID:        len(f.programs) + 1,
	}
	return nil
}

func (f *fakeHardwareManager) UnloadProgram(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unloadErr != nil {
		return f.unloadErr
	}
	if _, exists := f.programs[name]; !exists {
		return errors.New("not loaded")
	}
	delete(f.programs, name)
	return nil
}

func (f *fakeHardwareManager) AttachProgram(programName, hookName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attachErr != nil {
		return f.attachErr
	}
	if _, exists := f.programs[programName]; !exists {
		return errors.New("program not found")
	}
	key := programName + ":" + hookName
	if f.attachments[key] {
		return errors.New("already attached")
	}
	f.attachments[key] = true
	f.programs[programName].Attached = true
	return nil
}

func (f *fakeHardwareManager) DetachProgram(programName, hookName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.detachErr != nil {
		return f.detachErr
	}
	key := programName + ":" + hookName
	if !f.attachments[key] {
		return errors.New("not attached")
	}
	delete(f.attachments, key)
	if p, ok := f.programs[programName]; ok {
		p.Attached = false
	}
	return nil
}

func (f *fakeHardwareManager) ListPrograms() ([]hwTypes.EBPFProgramInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]hwTypes.EBPFProgramInfo, 0, len(f.programs))
	for _, p := range f.programs {
		out = append(out, *p)
	}
	return out, nil
}

// newTestProgramManager returns an ebpfProgramManager wired up with a fake
// hardware manager, so tests can drive the full reconcile lifecycle.
func newTestProgramManager() (*ebpfProgramManager, *fakeHardwareManager) {
	fake := newFakeHardwareManager()
	pm := &ebpfProgramManager{
		programs:  make(map[string]*ProgramInfo),
		hwManager: fake,
	}
	return pm, fake
}

func TestEBPFProgramManagerLoadAttachDetachUnloadLifecycle(t *testing.T) {
	pm, fake := newTestProgramManager()

	prog := Program{Name: "xdp-filter", Type: ProgramTypeXDP, Interface: "eth0"}
	if err := pm.LoadProgram(prog); err != nil {
		t.Fatalf("LoadProgram: %v", err)
	}

	// Read back via GetProgram.
	info, err := pm.GetProgram("xdp-filter")
	if err != nil {
		t.Fatalf("GetProgram: %v", err)
	}
	if !info.Loaded || info.Attached {
		t.Fatalf("loaded info: %+v", info)
	}

	// Load same name twice -> error.
	if err := pm.LoadProgram(prog); err == nil {
		t.Fatalf("expected duplicate load error")
	}

	// Fake hardware state should contain the program.
	if len(fake.programs) != 1 {
		t.Fatalf("fake should have 1 program, got %d", len(fake.programs))
	}

	// Attach to a valid hook.
	if err := pm.AttachProgram("xdp-filter", "xdp"); err != nil {
		t.Fatalf("AttachProgram: %v", err)
	}
	info, _ = pm.GetProgram("xdp-filter")
	if !info.Attached {
		t.Fatalf("program should be attached, got %+v", info)
	}

	// Detach.
	if err := pm.DetachProgram("xdp-filter", "xdp"); err != nil {
		t.Fatalf("DetachProgram: %v", err)
	}
	info, _ = pm.GetProgram("xdp-filter")
	if info.Attached {
		t.Fatalf("program should be detached")
	}

	// Detach when not attached -> error.
	if err := pm.DetachProgram("xdp-filter", "xdp"); err == nil {
		t.Fatalf("expected detach-when-not-attached error")
	}

	// Unload.
	if err := pm.UnloadProgram("xdp-filter"); err != nil {
		t.Fatalf("UnloadProgram: %v", err)
	}
	if _, err := pm.GetProgram("xdp-filter"); err == nil {
		t.Fatalf("expected GetProgram to error after unload")
	}
	if len(fake.programs) != 0 {
		t.Fatalf("fake should have 0 programs after unload, got %d", len(fake.programs))
	}
}

func TestEBPFProgramManagerUnloadRequiresDetach(t *testing.T) {
	pm, _ := newTestProgramManager()
	_ = pm.LoadProgram(Program{Name: "tc-prog", Type: ProgramTypeTCIngress})
	_ = pm.AttachProgram("tc-prog", "tc-ingress")

	err := pm.UnloadProgram("tc-prog")
	if err == nil {
		t.Fatalf("expected unload-while-attached error")
	}
}

func TestEBPFProgramManagerListProgramsMergesHardwareAndCache(t *testing.T) {
	pm, fake := newTestProgramManager()

	// Seed one program through the wrapper (goes into both cache and fake).
	_ = pm.LoadProgram(Program{Name: "a", Type: ProgramTypeXDP})
	// Inject one program only into the fake (not in wrapper cache) to
	// exercise the "cache miss" translation branch.
	fake.programs["b"] = &hwTypes.EBPFProgramInfo{Name: "b", Type: "tc-egress", ID: 42, Attached: true}

	progs, err := pm.ListPrograms()
	if err != nil {
		t.Fatalf("ListPrograms: %v", err)
	}
	if len(progs) != 2 {
		t.Fatalf("expected 2 programs, got %d", len(progs))
	}

	byName := make(map[string]ProgramInfo)
	for _, p := range progs {
		byName[p.Name] = p
	}
	if got := byName["b"]; got.Type != ProgramTypeTCEgress {
		t.Fatalf("expected type %s, got %s", ProgramTypeTCEgress, got.Type)
	}
	if got := byName["b"]; !got.Attached {
		t.Fatalf("expected 'b' attached per fake")
	}
}

func TestEBPFProgramManagerListTranslatesAllHookTypes(t *testing.T) {
	pm, fake := newTestProgramManager()
	fake.programs["xdp-p"] = &hwTypes.EBPFProgramInfo{Name: "xdp-p", Type: "xdp"}
	fake.programs["tci-p"] = &hwTypes.EBPFProgramInfo{Name: "tci-p", Type: "tc-ingress"}
	fake.programs["tce-p"] = &hwTypes.EBPFProgramInfo{Name: "tce-p", Type: "tc-egress"}
	fake.programs["sops-p"] = &hwTypes.EBPFProgramInfo{Name: "sops-p", Type: "sockops"}
	fake.programs["cg-p"] = &hwTypes.EBPFProgramInfo{Name: "cg-p", Type: "cgroup"}

	progs, err := pm.ListPrograms()
	if err != nil {
		t.Fatalf("ListPrograms: %v", err)
	}
	wantTypes := map[string]ProgramType{
		"xdp-p":  ProgramTypeXDP,
		"tci-p":  ProgramTypeTCIngress,
		"tce-p":  ProgramTypeTCEgress,
		"sops-p": ProgramTypeSockOps,
		"cg-p":   ProgramTypeCGroup,
	}
	got := make(map[string]ProgramType)
	for _, p := range progs {
		got[p.Name] = p.Type
	}
	for name, wantType := range wantTypes {
		if got[name] != wantType {
			t.Fatalf("%s: got type %s, want %s", name, got[name], wantType)
		}
	}
}

func TestEBPFProgramManagerListWithoutHardwareReturnsCachedOnly(t *testing.T) {
	pm := &ebpfProgramManager{
		programs: map[string]*ProgramInfo{
			"cached": {Name: "cached", Type: ProgramTypeXDP, Loaded: true},
		},
	}
	progs, err := pm.ListPrograms()
	if err != nil {
		t.Fatalf("ListPrograms: %v", err)
	}
	if len(progs) != 1 || progs[0].Name != "cached" {
		t.Fatalf("unexpected progs: %+v", progs)
	}
}

func TestEBPFProgramManagerReplaceProgram(t *testing.T) {
	pm, _ := newTestProgramManager()
	if err := pm.LoadProgram(Program{Name: "old", Type: ProgramTypeXDP, Interface: "eth0"}); err != nil {
		t.Fatalf("load old: %v", err)
	}
	if err := pm.LoadProgram(Program{Name: "new", Type: ProgramTypeXDP, Interface: "eth0"}); err != nil {
		t.Fatalf("load new: %v", err)
	}
	if err := pm.AttachProgram("old", "xdp"); err != nil {
		t.Fatalf("attach old: %v", err)
	}

	// Replace exercises the detach-old + attach-new path.
	if err := pm.ReplaceProgram("old", "new"); err != nil {
		t.Fatalf("ReplaceProgram: %v", err)
	}
	oldInfo, _ := pm.GetProgram("old")
	newInfo, _ := pm.GetProgram("new")
	if oldInfo.Attached {
		t.Fatalf("old should be detached after replace")
	}
	if !newInfo.Attached {
		t.Fatalf("new should be attached after replace")
	}

	// Error conditions.
	if err := pm.ReplaceProgram("missing", "new"); err == nil {
		t.Fatalf("expected error for missing old")
	}
	if err := pm.ReplaceProgram("new", "missing"); err == nil {
		t.Fatalf("expected error for missing new")
	}
}

func TestEBPFProgramManagerAttachErrorsOnMissingProgram(t *testing.T) {
	pm, _ := newTestProgramManager()
	if err := pm.AttachProgram("nope", "xdp"); err == nil {
		t.Fatalf("expected error when attaching missing program")
	}
	if err := pm.DetachProgram("nope", "xdp"); err == nil {
		t.Fatalf("expected error when detaching missing program")
	}
	if err := pm.UnloadProgram("nope"); err == nil {
		t.Fatalf("expected error when unloading missing program")
	}
}

func TestMapManagerUpdatePaths(t *testing.T) {
	mm := NewMapManager()
	_, err := mm.CreateMap("m", MapTypeHash, 4, 4, 10)
	if err != nil {
		t.Fatalf("CreateMap: %v", err)
	}

	// UpdateMap for existing map returns kernel-required error.
	if err := mm.UpdateMap("m", map[interface{}]interface{}{1: 1}); err == nil {
		t.Fatalf("expected UpdateMap to error without kernel support")
	}
	// UpdateMap for missing map returns not-found error.
	if err := mm.UpdateMap("missing", nil); err == nil {
		t.Fatalf("expected UpdateMap to error for missing map")
	}

	if _, err := mm.DumpMap("missing"); err == nil {
		t.Fatalf("expected DumpMap to error for missing map")
	}

	// PinMap missing.
	if err := mm.PinMap("missing", "/sys/fs/bpf/x"); err == nil {
		t.Fatalf("expected PinMap to error for missing")
	}
	// UnpinMap missing.
	if err := mm.UnpinMap("missing"); err == nil {
		t.Fatalf("expected UnpinMap to error for missing")
	}
}

func TestMapManagerListReflectsOperations(t *testing.T) {
	mm := NewMapManager()
	_, _ = mm.CreateMap("a", MapTypeHash, 4, 4, 10)
	_, _ = mm.CreateMap("b", MapTypeArray, 4, 4, 10)

	maps, err := mm.ListMaps()
	if err != nil {
		t.Fatalf("ListMaps: %v", err)
	}
	if len(maps) != 2 {
		t.Fatalf("expected 2 maps, got %d", len(maps))
	}

	_ = mm.DeleteMap("a")
	maps, _ = mm.ListMaps()
	if len(maps) != 1 {
		t.Fatalf("expected 1 map after delete, got %d", len(maps))
	}
}

func TestEBPFProgramManagerAttachRejectsMissingProgramBeforeHookCheck(t *testing.T) {
	pm, _ := newTestProgramManager()
	// Program doesn't exist -> missing program error regardless of hook.
	if err := pm.AttachProgram("missing", "xdp"); err == nil {
		t.Fatalf("expected missing program error")
	}
}
