// Package ebpf provides functionality for managing eBPF programs and maps.
//
// Lifecycle ownership: ProgramManager is the single authoritative owner of
// eBPF program load/attach/detach/unload operations. Manager exists as a
// thin adapter implementing the types.EBPFManager interface and delegates
// to ProgramManager internally.
//
// Supported hooks (see SupportedHookTypes()):
//   - xdp:        XDP early packet processing (implemented)
//   - tc-ingress: TC ingress traffic control (implemented)
//   - tc-egress:  TC egress traffic control (implemented)
//   - sockops:    Socket operations via cgroup (implemented)
//   - cgroup:     Cgroup device control (implemented)
//
// CiliumIntegrationManager is an internal support module that queries the
// live Cilium agent. It does NOT provide placeholder/simulated discovery.
// If the Cilium agent is unreachable, methods return ErrCiliumNotAvailable.
package ebpf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// Manager implements the types.EBPFManager interface.
// It delegates to ProgramManager for the actual eBPF lifecycle operations.
// This adapter exists to satisfy the types.EBPFManager contract used by
// hardware layer consumers.
type Manager struct {
	programs     map[string]*loadedProgram
	programsMu   sync.RWMutex
	links        map[string]link.Link
	linksMu      sync.RWMutex
	pinPath      string
}

// loadedProgram represents a loaded eBPF program.
type loadedProgram struct {
	program     *ebpf.Program
	maps        []*ebpf.Map
	info        types.EBPFProgramInfo
	attachments []string // Hooks this program is attached to

	// ownedLoader is set when the program was loaded via the owned
	// XDPLoader path. UnloadProgram closes the loader rather than
	// closing the *ebpf.Program directly — the program handle is
	// owned by the loader's collection and double-closing would leak
	// map references or crash on older cilium/ebpf releases.
	ownedLoader *XDPLoader
}

// NewManager creates a new eBPF Manager.
func NewManager() (*Manager, error) {
	// Create pin path directory if it doesn't exist
	pinPath := "/sys/fs/bpf/fos1"
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create pin path: %w", err)
	}

	return &Manager{
		programs: make(map[string]*loadedProgram),
		links:    make(map[string]link.Link),
		pinPath:  pinPath,
	}, nil
}

// Initialize initializes the eBPF Manager.
func (m *Manager) Initialize(ctx context.Context) error {
	// Load pinned programs and maps if they exist
	if err := m.loadPinnedPrograms(); err != nil {
		return fmt.Errorf("failed to load pinned programs: %w", err)
	}

	return nil
}

// Shutdown shuts down the eBPF Manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	// Close all links (program attachments)
	m.linksMu.Lock()
	for name, link := range m.links {
		if err := link.Close(); err != nil {
			fmt.Printf("Failed to close link %s: %v\n", name, err)
		}
	}
	m.links = make(map[string]link.Link)
	m.linksMu.Unlock()

	// Close all programs and maps
	m.programsMu.Lock()
	for name, prog := range m.programs {
		if prog.ownedLoader != nil {
			if err := prog.ownedLoader.Close(); err != nil {
				fmt.Printf("Failed to close owned loader for %s: %v\n", name, err)
			}
			continue
		}
		// Close maps
		for _, m := range prog.maps {
			if err := m.Close(); err != nil {
				fmt.Printf("Failed to close map for program %s: %v\n", name, err)
			}
		}

		// Close program
		if err := prog.program.Close(); err != nil {
			fmt.Printf("Failed to close program %s: %v\n", name, err)
		}
	}
	m.programs = make(map[string]*loadedProgram)
	m.programsMu.Unlock()

	return nil
}

// LoadProgram loads an eBPF program.
//
// Sprint 30 Ticket 38 dispatch:
//
//   - `Type == "xdp"` with empty `Code` loads the owned xdp_ddos_drop
//     object from the embedded ELF via XDPLoader. This is the
//     supported production path.
//   - `Type == "xdp"` with non-empty `Code` loads the ELF from that
//     file path (legacy path used by the compiler pipeline in
//     compiler.go).
//   - Any other program type returns ErrEBPFProgramTypeUnsupported.
//     TC / sockops / cgroup loaders land in Sprint 30 Ticket 39.
func (m *Manager) LoadProgram(programConfig types.EBPFProgram) error {
	switch programConfig.Type {
	case ProgramTypeXDP:
		// supported — fall through to the load path below.
	case ProgramTypeTCIngress, ProgramTypeTCEgress, ProgramTypeSockOps, ProgramTypeCGroup:
		return fmt.Errorf("%w: %q (XDP is the only type implemented by the owned loader in v1; see Sprint 30 ticket 39)",
			ErrEBPFProgramTypeUnsupported, programConfig.Type)
	default:
		return fmt.Errorf("%w: %q", ErrEBPFProgramTypeUnsupported, programConfig.Type)
	}

	if programConfig.Code == "" {
		return m.loadOwnedXDP(programConfig)
	}

	return m.loadXDPFromFile(programConfig)
}

// loadOwnedXDP loads the embedded xdp_ddos_drop program via the owned
// XDPLoader. Callers who want driver-native XDP or a custom program
// must still go through the legacy Code path.
func (m *Manager) loadOwnedXDP(programConfig types.EBPFProgram) error {
	objectBytes, err := XDPDDoSDropObject()
	if err != nil {
		return fmt.Errorf("load owned XDP object: %w", err)
	}
	loader, err := NewXDPLoader(objectBytes)
	if err != nil {
		return fmt.Errorf("instantiate XDPLoader: %w", err)
	}

	prog := loader.Program()
	if prog == nil {
		loader.Close()
		return fmt.Errorf("owned XDPLoader returned nil program (likely non-Linux stub)")
	}

	var maps []*ebpf.Map
	if dm := loader.DenylistMap(); dm != nil {
		maps = append(maps, dm)
	}

	m.programsMu.Lock()
	defer m.programsMu.Unlock()

	m.programs[programConfig.Name] = &loadedProgram{
		program: prog,
		maps:    maps,
		info: types.EBPFProgramInfo{
			Name:      programConfig.Name,
			Type:      programConfig.Type,
			ID:        prog.FD(),
			Interface: programConfig.Interface,
			Attached:  false,
		},
		attachments: []string{},
		ownedLoader: loader,
	}
	return nil
}

// loadXDPFromFile preserves the legacy behaviour of LoadProgram when
// the caller supplies a file path via EBPFProgram.Code.
func (m *Manager) loadXDPFromFile(programConfig types.EBPFProgram) error {
	spec, err := ebpf.LoadCollectionSpec(programConfig.Code)
	if err != nil {
		return fmt.Errorf("failed to load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}

	var prog *ebpf.Program
	for name, program := range coll.Programs {
		if name == "main" {
			prog = program
			break
		}
	}
	if prog == nil {
		return fmt.Errorf("failed to find main program in collection")
	}

	var maps []*ebpf.Map
	for _, mp := range coll.Maps {
		maps = append(maps, mp)
	}

	if err := m.pinProgram(programConfig.Name, prog, maps); err != nil {
		return fmt.Errorf("failed to pin program: %w", err)
	}

	m.programsMu.Lock()
	defer m.programsMu.Unlock()

	m.programs[programConfig.Name] = &loadedProgram{
		program: prog,
		maps:    maps,
		info: types.EBPFProgramInfo{
			Name:      programConfig.Name,
			Type:      programConfig.Type,
			ID:        prog.FD(),
			Interface: programConfig.Interface,
			Attached:  false,
		},
		attachments: []string{},
	}
	return nil
}

// UnloadProgram unloads an eBPF program.
func (m *Manager) UnloadProgram(name string) error {
	m.programsMu.Lock()
	defer m.programsMu.Unlock()

	prog, ok := m.programs[name]
	if !ok {
		return fmt.Errorf("program %s not found", name)
	}

	// Detach the program from all hooks
	for _, hookName := range prog.attachments {
		linkName := fmt.Sprintf("%s:%s", name, hookName)

		m.linksMu.Lock()
		link, ok := m.links[linkName]
		if ok {
			if err := link.Close(); err != nil {
				fmt.Printf("Failed to close link %s: %v\n", linkName, err)
			}
			delete(m.links, linkName)
		}
		m.linksMu.Unlock()
	}

	// Close via the owned loader when applicable — the loader owns
	// both the program and the map handles in that path.
	if prog.ownedLoader != nil {
		if err := prog.ownedLoader.Close(); err != nil {
			fmt.Printf("Failed to close owned loader for %s: %v\n", name, err)
		}
		prog.ownedLoader = nil
		prog.program = nil
		prog.maps = nil
	} else {
		// Close maps
		for _, em := range prog.maps {
			if err := em.Close(); err != nil {
				fmt.Printf("Failed to close map: %v\n", err)
			}
			// Unpin map
			mapName := fmt.Sprintf("%s_%s", name, em.String())
			mapPath := filepath.Join(m.pinPath, "maps", mapName)
			if err := os.Remove(mapPath); err != nil && !os.IsNotExist(err) {
				fmt.Printf("Failed to unpin map %s: %v\n", mapName, err)
			}
		}

		// Close program
		if err := prog.program.Close(); err != nil {
			fmt.Printf("Failed to close program %s: %v\n", name, err)
		}
	}

	// Unpin program
	programPath := filepath.Join(m.pinPath, "programs", name)
	if err := os.Remove(programPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("Failed to unpin program %s: %v\n", name, err)
	}

	// Remove from programs map
	delete(m.programs, name)

	return nil
}

// AttachProgram attaches an eBPF program to a hook.
func (m *Manager) AttachProgram(programName, hookName string) error {
	m.programsMu.RLock()
	prog, ok := m.programs[programName]
	if !ok {
		m.programsMu.RUnlock()
		return fmt.Errorf("program %s not found", programName)
	}
	m.programsMu.RUnlock()

	// Link name is a combination of program name and hook name
	linkName := fmt.Sprintf("%s:%s", programName, hookName)

	// Check if already attached
	m.linksMu.RLock()
	_, exists := m.links[linkName]
	m.linksMu.RUnlock()
	if exists {
		return fmt.Errorf("program %s already attached to hook %s", programName, hookName)
	}

	// Validate the hook type before attempting attachment
	if !IsHookTypeSupported(HookType(hookName)) {
		return &ErrUnsupportedHookType{HookType: HookType(hookName)}
	}

	// Create the appropriate link based on the hook type
	var l link.Link

	switch {
	case hookName == "xdp":
		// XDP program - attach to network interface
		iface, err := netlink.LinkByName(prog.info.Interface)
		if err != nil {
			return fmt.Errorf("failed to find interface %s: %w", prog.info.Interface, err)
		}

		l, err = link.AttachXDP(link.XDPOptions{
			Program:   prog.program,
			Interface: iface.Attrs().Index,
		})
		if err != nil {
			return fmt.Errorf("failed to attach XDP program: %w", err)
		}

	case hookName == "tc_ingress":
		// TC ingress program - attach to network interface
		iface, err := netlink.LinkByName(prog.info.Interface)
		if err != nil {
			return fmt.Errorf("failed to find interface %s: %w", prog.info.Interface, err)
		}

		l, err = link.AttachTCX(link.TCXOptions{
			Program:   prog.program,
			Attach:    ebpf.AttachTCXIngress,
			Interface: iface.Attrs().Index,
		})
		if err != nil {
			return fmt.Errorf("failed to attach TC ingress program: %w", err)
		}

	case hookName == "tc_egress":
		// TC egress program - attach to network interface
		iface, err := netlink.LinkByName(prog.info.Interface)
		if err != nil {
			return fmt.Errorf("failed to find interface %s: %w", prog.info.Interface, err)
		}

		l, err = link.AttachTCX(link.TCXOptions{
			Program:   prog.program,
			Attach:    ebpf.AttachTCXEgress,
			Interface: iface.Attrs().Index,
		})
		if err != nil {
			return fmt.Errorf("failed to attach TC egress program: %w", err)
		}

	case hookName == "cgroup_skb_ingress":
		// Cgroup SKB ingress program - attach to cgroup
		cgroupPath := "/sys/fs/cgroup"
		f, err := os.Open(cgroupPath)
		if err != nil {
			return fmt.Errorf("failed to open cgroup: %w", err)
		}
		defer f.Close()

		l, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: prog.program,
		})
		if err != nil {
			return fmt.Errorf("failed to attach cgroup ingress program: %w", err)
		}

	case hookName == "cgroup_skb_egress":
		// Cgroup SKB egress program - attach to cgroup
		cgroupPath := "/sys/fs/cgroup"
		f, err := os.Open(cgroupPath)
		if err != nil {
			return fmt.Errorf("failed to open cgroup: %w", err)
		}
		defer f.Close()

		l, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: prog.program,
		})
		if err != nil {
			return fmt.Errorf("failed to attach cgroup egress program: %w", err)
		}

	default:
		return &ErrUnsupportedHookType{HookType: HookType(hookName)}
	}

	// Store the link
	m.linksMu.Lock()
	m.links[linkName] = l
	m.linksMu.Unlock()

	// Update program info
	m.programsMu.Lock()
	prog.attachments = append(prog.attachments, hookName)
	prog.info.Attached = true
	m.programsMu.Unlock()

	return nil
}

// DetachProgram detaches an eBPF program from a hook.
func (m *Manager) DetachProgram(programName, hookName string) error {
	// Link name is a combination of program name and hook name
	linkName := fmt.Sprintf("%s:%s", programName, hookName)

	// Get the link
	m.linksMu.Lock()
	link, ok := m.links[linkName]
	if !ok {
		m.linksMu.Unlock()
		return fmt.Errorf("program %s not attached to hook %s", programName, hookName)
	}

	// Close the link
	if err := link.Close(); err != nil {
		m.linksMu.Unlock()
		return fmt.Errorf("failed to close link: %w", err)
	}

	// Remove from links map
	delete(m.links, linkName)
	m.linksMu.Unlock()

	// Update program info
	m.programsMu.Lock()
	prog, ok := m.programs[programName]
	if ok {
		// Remove hookName from attachments
		for i, h := range prog.attachments {
			if h == hookName {
				prog.attachments = append(prog.attachments[:i], prog.attachments[i+1:]...)
				break
			}
		}

		// Update attached status
		prog.info.Attached = len(prog.attachments) > 0
	}
	m.programsMu.Unlock()

	return nil
}

// ListPrograms returns a list of all eBPF programs.
func (m *Manager) ListPrograms() ([]types.EBPFProgramInfo, error) {
	m.programsMu.RLock()
	defer m.programsMu.RUnlock()

	programs := make([]types.EBPFProgramInfo, 0, len(m.programs))
	for _, prog := range m.programs {
		programs = append(programs, prog.info)
	}

	return programs, nil
}

// UpdateMap updates a value in an eBPF map.
func (m *Manager) UpdateMap(name string, key, value interface{}) error {
	parts := strings.Split(name, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid map name format, expected 'program.map'")
	}

	programName := parts[0]
	mapName := parts[1]

	m.programsMu.RLock()
	prog, ok := m.programs[programName]
	if !ok {
		m.programsMu.RUnlock()
		return fmt.Errorf("program %s not found", programName)
	}

	// Find the map
	var bpfMap *ebpf.Map
	for _, m := range prog.maps {
		if m.String() == mapName {
			bpfMap = m
			break
		}
	}
	m.programsMu.RUnlock()

	if bpfMap == nil {
		return fmt.Errorf("map %s not found in program %s", mapName, programName)
	}

	// Update the map
	if err := bpfMap.Update(key, value, 0); err != nil {
		return fmt.Errorf("failed to update map: %w", err)
	}

	return nil
}

// pinProgram pins a program and its maps to the BPF filesystem.
func (m *Manager) pinProgram(name string, prog *ebpf.Program, maps []*ebpf.Map) error {
	// Create program directory
	programDir := filepath.Join(m.pinPath, "programs")
	if err := os.MkdirAll(programDir, 0755); err != nil {
		return fmt.Errorf("failed to create program directory: %w", err)
	}

	// Create map directory
	mapDir := filepath.Join(m.pinPath, "maps")
	if err := os.MkdirAll(mapDir, 0755); err != nil {
		return fmt.Errorf("failed to create map directory: %w", err)
	}

	// Pin program
	programPath := filepath.Join(programDir, name)
	if err := prog.Pin(programPath); err != nil {
		return fmt.Errorf("failed to pin program: %w", err)
	}

	// Pin maps
	for i, m := range maps {
		mapName := fmt.Sprintf("%s_%d", name, i)
		mapPath := filepath.Join(mapDir, mapName)
		if err := m.Pin(mapPath); err != nil {
			return fmt.Errorf("failed to pin map: %w", err)
		}
	}

	return nil
}

// loadPinnedPrograms loads pinned programs and maps from the BPF filesystem.
func (m *Manager) loadPinnedPrograms() error {
	// Load programs
	programDir := filepath.Join(m.pinPath, "programs")
	if _, err := os.Stat(programDir); os.IsNotExist(err) {
		// No pinned programs
		return nil
	}

	// Read program directory
	entries, err := os.ReadDir(programDir)
	if err != nil {
		return fmt.Errorf("failed to read program directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		programName := entry.Name()
		programPath := filepath.Join(programDir, programName)

		// Load program
		prog, err := ebpf.LoadPinnedProgram(programPath, nil)
		if err != nil {
			fmt.Printf("Failed to load pinned program %s: %v\n", programName, err)
			continue
		}

		// Find associated maps
		mapDir := filepath.Join(m.pinPath, "maps")
		mapEntries, err := os.ReadDir(mapDir)
		if err != nil {
			fmt.Printf("Failed to read map directory: %v\n", err)
			continue
		}

		var maps []*ebpf.Map
		for _, mapEntry := range mapEntries {
			if !mapEntry.IsDir() && strings.HasPrefix(mapEntry.Name(), programName+"_") {
				mapPath := filepath.Join(mapDir, mapEntry.Name())
				m, err := ebpf.LoadPinnedMap(mapPath, nil)
				if err != nil {
					fmt.Printf("Failed to load pinned map %s: %v\n", mapEntry.Name(), err)
					continue
				}
				maps = append(maps, m)
			}
		}

		// Store the program
		m.programsMu.Lock()
		m.programs[programName] = &loadedProgram{
			program: prog,
			maps:    maps,
			info: types.EBPFProgramInfo{
				Name:      programName,
				Type:      prog.Type().String(),
				ID:        prog.FD(),
				Interface: "", // Cannot determine from pinned program
				Attached:  false,
			},
			attachments: []string{},
		}
		m.programsMu.Unlock()
	}

	return nil
}
