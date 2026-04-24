// Package ebpf provides functionality for managing eBPF programs and maps.
package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

// HookType represents the type of hook to attach an eBPF program to.
type HookType string

const (
	// HookTypeXDP represents an XDP hook.
	// Status: Implemented. Attaches programs at the XDP layer for early packet processing.
	HookTypeXDP HookType = "xdp"

	// HookTypeTCIngress represents a TC ingress hook.
	// Status: Implemented. Attaches programs at the TC ingress layer for inbound traffic processing.
	HookTypeTCIngress HookType = "tc-ingress"

	// HookTypeTCEgress represents a TC egress hook.
	// Status: Implemented. Attaches programs at the TC egress layer for outbound traffic processing.
	HookTypeTCEgress HookType = "tc-egress"

	// HookTypeSockOps represents a socket operations hook.
	// Status: Implemented. Attaches programs to cgroup sockops for socket-level operations.
	HookTypeSockOps HookType = "sockops"

	// HookTypeCGroup represents a cgroup hook.
	// Status: Implemented. Attaches programs to cgroup for device-level control.
	HookTypeCGroup HookType = "cgroup"
)

// SupportedHookTypes returns all hook types that the eBPF runtime supports.
// This is the authoritative list of hooks that can be used with AttachProgram.
func SupportedHookTypes() []HookType {
	return []HookType{
		HookTypeXDP,
		HookTypeTCIngress,
		HookTypeTCEgress,
		HookTypeSockOps,
		HookTypeCGroup,
	}
}

// IsHookTypeSupported returns true if the given hook type is supported by the runtime.
func IsHookTypeSupported(hookType HookType) bool {
	for _, supported := range SupportedHookTypes() {
		if supported == hookType {
			return true
		}
	}
	return false
}

// ErrUnsupportedHookType is returned when an unsupported hook type is used.
type ErrUnsupportedHookType struct {
	HookType HookType
}

func (e *ErrUnsupportedHookType) Error() string {
	return fmt.Sprintf("unsupported hook type: %s (supported: xdp, tc-ingress, tc-egress, sockops, cgroup)", e.HookType)
}

// Program represents an eBPF program.
type Program struct {
	Name      string
	Type      string
	Code      []byte
	Interface string
	Priority  int
	Maps      []string
}

// LoadedProgram represents a loaded eBPF program.
type LoadedProgram struct {
	Name      string
	Type      string
	Interface string
	Priority  int
	InnerProg *ebpf.Program
	Link      link.Link
	Maps      []string
	Attached  bool

	// xdpLoader is set when the program was loaded via the owned XDP
	// loader path (Type == ProgramTypeXDP with empty Code). It carries
	// the backing *ebpf.Collection and map handles so UnloadProgram can
	// release them deterministically. Nil for legacy Code-based loads.
	xdpLoader *XDPLoader

	// tcLoader is set when the program was loaded via the owned TC
	// loader path (Type == ProgramTypeTCIngress or ProgramTypeTCEgress
	// with empty Code). Same ownership contract as xdpLoader: the
	// collection and map handles are released through this loader, not
	// through InnerProg.Close, to avoid a double-close. Nil for legacy
	// Code-based loads and for XDP programs.
	tcLoader *TCLoader
}

// ProgramManager handles the lifecycle of eBPF programs.
type ProgramManager struct {
	programs     map[string]*LoadedProgram
	programsMu   sync.RWMutex
	mapManager   *MapManager
	pinPath      string
}

// NewProgramManager creates a new ProgramManager.
func NewProgramManager(mapManager *MapManager, pinPath string) *ProgramManager {
	// Create the pin directory if it doesn't exist
	if pinPath != "" {
		if err := os.MkdirAll(pinPath, 0755); err != nil {
			// Log error, but continue
			fmt.Printf("Failed to create pin directory: %v\n", err)
		}
	}

	return &ProgramManager{
		programs:   make(map[string]*LoadedProgram),
		mapManager: mapManager,
		pinPath:    pinPath,
	}
}

// ProgramType is the string set recognised by LoadProgram.
// These mirror the HookType constants but describe the program's shape
// (XDP vs. TC vs. sockops etc.), not the attach point.
const (
	ProgramTypeXDP       = "xdp"
	ProgramTypeTCIngress = "tc-ingress"
	ProgramTypeTCEgress  = "tc-egress"
	ProgramTypeSockOps   = "sockops"
	ProgramTypeCGroup    = "cgroup"
)

// LoadProgram loads an eBPF program.
//
// Dispatch:
//
//   - `Type == "xdp"` with empty Code loads the owned xdp_ddos_drop
//     object from the embedded ELF (see `bpf/xdp_ddos_drop.o`). This is
//     the supported path for Sprint 30 ticket 38.
//   - `Type == "tc-ingress"` or `"tc-egress"` with empty Code loads the
//     owned tc_qos_shape object (see `bpf/tc_qos_shape.o`). The
//     ingress vs. egress split selects which of the two SEC()s in the
//     object gets bound to InnerProg — the other stays live inside the
//     loader's *ebpf.Collection until Close. Sprint 30 ticket 39.
//   - `Type == "xdp" | "tc-ingress" | "tc-egress"` with non-empty Code
//     loads the caller-supplied ELF bytes (legacy compile-and-pass
//     path, used by older callers that hand-compile programs into
//     [Program.Code]).
//   - Sockops / cgroup program types still return
//     [ErrEBPFProgramTypeUnsupported]; those loaders are future work.
func (p *ProgramManager) LoadProgram(program Program) error {
	p.programsMu.Lock()
	defer p.programsMu.Unlock()

	// Check if program already exists
	if _, ok := p.programs[program.Name]; ok {
		return fmt.Errorf("program %s already exists", program.Name)
	}

	switch program.Type {
	case ProgramTypeXDP, ProgramTypeTCIngress, ProgramTypeTCEgress:
		// fall through to load path below.
	case ProgramTypeSockOps, ProgramTypeCGroup:
		return fmt.Errorf("%w: %q (XDP and TC are implemented by the owned loader; sockops / cgroup are future work)",
			ErrEBPFProgramTypeUnsupported, program.Type)
	default:
		return fmt.Errorf("%w: %q", ErrEBPFProgramTypeUnsupported, program.Type)
	}

	var loadedProg *ebpf.Program
	var ownedXDP *XDPLoader
	var ownedTC *TCLoader

	if len(program.Code) > 0 {
		// Legacy path: caller supplies raw ELF bytes. Used by the
		// hardware compiler pipeline in pkg/hardware/ebpf/compiler.go
		// and by tests that inject hand-compiled programs.
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("failed to remove memlock: %w", err)
		}
		objectPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s.o", program.Name))
		if err := os.WriteFile(objectPath, program.Code, 0644); err != nil {
			return fmt.Errorf("failed to write object file: %w", err)
		}
		defer os.Remove(objectPath)

		spec, err := ebpf.LoadCollectionSpec(objectPath)
		if err != nil {
			return fmt.Errorf("failed to load eBPF spec: %w", err)
		}

		progSpec := spec.Programs["main"]
		if progSpec == nil {
			return fmt.Errorf("program main not found in object file")
		}

		loadedProg, err = ebpf.NewProgram(progSpec)
		if err != nil {
			return fmt.Errorf("failed to load eBPF program: %w", err)
		}
	} else {
		// Owned path: instantiate the loader that matches the program
		// type. Both loaders parse the embedded object and return
		// ErrEBPFObjectMissing when `make bpf-objects` has not been
		// run.
		switch program.Type {
		case ProgramTypeXDP:
			objectBytes, err := XDPDDoSDropObject()
			if err != nil {
				return fmt.Errorf("load owned XDP object: %w", err)
			}
			loader, err := NewXDPLoader(objectBytes)
			if err != nil {
				return fmt.Errorf("instantiate XDPLoader: %w", err)
			}
			loadedProg = loader.Program()
			ownedXDP = loader
		case ProgramTypeTCIngress, ProgramTypeTCEgress:
			objectBytes, err := TCQoSShapeObject()
			if err != nil {
				return fmt.Errorf("load owned TC object: %w", err)
			}
			loader, err := NewTCLoader(objectBytes)
			if err != nil {
				return fmt.Errorf("instantiate TCLoader: %w", err)
			}
			if program.Type == ProgramTypeTCIngress {
				loadedProg = loader.IngressProgram()
			} else {
				loadedProg = loader.EgressProgram()
			}
			ownedTC = loader
		}
	}

	// Create a loaded program object
	loaded := &LoadedProgram{
		Name:      program.Name,
		Type:      program.Type,
		Interface: program.Interface,
		Priority:  program.Priority,
		InnerProg: loadedProg,
		Maps:      program.Maps,
		Attached:  false,
		xdpLoader: ownedXDP,
		tcLoader:  ownedTC,
	}

	// Store the program
	p.programs[program.Name] = loaded

	// Pin the program if pinPath is set
	if p.pinPath != "" {
		progPinPath := filepath.Join(p.pinPath, fmt.Sprintf("%s.prog", program.Name))
		if err := loadedProg.Pin(progPinPath); err != nil {
			// Log error, but continue
			fmt.Printf("Failed to pin program: %v\n", err)
		}
	}

	return nil
}

// UnloadProgram unloads an eBPF program.
func (p *ProgramManager) UnloadProgram(name string) error {
	p.programsMu.Lock()
	defer p.programsMu.Unlock()

	// Check if program exists
	prog, ok := p.programs[name]
	if !ok {
		return fmt.Errorf("program %s not found", name)
	}

	// Detach the program if it's attached
	if prog.Attached && prog.Link != nil {
		if err := prog.Link.Close(); err != nil {
			return fmt.Errorf("failed to detach eBPF program: %w", err)
		}
		prog.Attached = false
	}

	// Close the program. When the program was loaded via one of the
	// owned loaders (XDP or TC) the *ebpf.Program handle is owned by
	// the collection inside the loader, so we release via the loader
	// to avoid a double-close. Legacy Code-based loads own InnerProg
	// directly.
	switch {
	case prog.xdpLoader != nil:
		if err := prog.xdpLoader.Close(); err != nil {
			return fmt.Errorf("failed to close owned XDP loader: %w", err)
		}
		prog.xdpLoader = nil
		prog.InnerProg = nil
	case prog.tcLoader != nil:
		if err := prog.tcLoader.Close(); err != nil {
			return fmt.Errorf("failed to close owned TC loader: %w", err)
		}
		prog.tcLoader = nil
		prog.InnerProg = nil
	case prog.InnerProg != nil:
		if err := prog.InnerProg.Close(); err != nil {
			return fmt.Errorf("failed to close eBPF program: %w", err)
		}
	}

	// Remove the program from pinPath if it's pinned
	if p.pinPath != "" {
		progPinPath := filepath.Join(p.pinPath, fmt.Sprintf("%s.prog", name))
		if _, err := os.Stat(progPinPath); err == nil {
			if err := os.Remove(progPinPath); err != nil {
				// Log error, but continue
				fmt.Printf("Failed to remove pinned program: %v\n", err)
			}
		}
	}

	// Remove the program
	delete(p.programs, name)

	return nil
}

// AttachProgram attaches an eBPF program to a hook.
func (p *ProgramManager) AttachProgram(programName string, hookName string) error {
	p.programsMu.Lock()
	defer p.programsMu.Unlock()

	// Check if program exists
	prog, ok := p.programs[programName]
	if !ok {
		return fmt.Errorf("program %s not found", programName)
	}

	// Check if program is already attached
	if prog.Attached {
		return fmt.Errorf("program %s is already attached", programName)
	}

	// Validate hook type before attempting attachment
	hookType := HookType(hookName)
	if !IsHookTypeSupported(hookType) {
		return &ErrUnsupportedHookType{HookType: hookType}
	}

	var l link.Link
	var err error

	// Attach the program to the hook
	switch hookType {
	case HookTypeXDP:
		// Get the interface
		iface, err := netlink.LinkByName(prog.Interface)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %w", prog.Interface, err)
		}
		// Attach XDP program
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   prog.InnerProg,
			Interface: iface.Attrs().Index,
		})
		if err != nil {
			return fmt.Errorf("failed to attach XDP program: %w", err)
		}
	case HookTypeTCIngress:
		// attachTCProgram wraps both the owned-loader and legacy
		// (Code-based) paths. On Linux the helper ensures a clsact
		// qdisc is in place before calling AttachTCX. On non-Linux it
		// returns ErrEBPFUnsupportedPlatform.
		l, err = attachTCProgram(prog, ebpf.AttachTCXIngress)
		if err != nil {
			return fmt.Errorf("failed to attach TC ingress program: %w", err)
		}
	case HookTypeTCEgress:
		l, err = attachTCProgram(prog, ebpf.AttachTCXEgress)
		if err != nil {
			return fmt.Errorf("failed to attach TC egress program: %w", err)
		}
	case HookTypeSockOps:
		// Attach socket operations program
		// Note: This is a simplified implementation
		l, err = link.AttachCgroup(link.CgroupOptions{
			Path:    "/sys/fs/cgroup",
			Attach:  ebpf.AttachCGroupSockOps,
			Program: prog.InnerProg,
		})
		if err != nil {
			return fmt.Errorf("failed to attach sockops program: %w", err)
		}
	case HookTypeCGroup:
		// Attach cgroup program
		// Note: This is a simplified implementation
		l, err = link.AttachCgroup(link.CgroupOptions{
			Path:    "/sys/fs/cgroup",
			Attach:  ebpf.AttachCGroupDevice,
			Program: prog.InnerProg,
		})
		if err != nil {
			return fmt.Errorf("failed to attach cgroup program: %w", err)
		}
	default:
		return &ErrUnsupportedHookType{HookType: hookType}
	}

	// Store the link
	prog.Link = l
	prog.Attached = true

	return nil
}

// DetachProgram detaches an eBPF program from a hook.
func (p *ProgramManager) DetachProgram(programName string, hookName string) error {
	p.programsMu.Lock()
	defer p.programsMu.Unlock()

	// Check if program exists
	prog, ok := p.programs[programName]
	if !ok {
		return fmt.Errorf("program %s not found", programName)
	}

	// Check if program is attached
	if !prog.Attached || prog.Link == nil {
		return fmt.Errorf("program %s is not attached", programName)
	}

	// Detach the program
	if err := prog.Link.Close(); err != nil {
		return fmt.Errorf("failed to detach eBPF program: %w", err)
	}

	// Update program state
	prog.Link = nil
	prog.Attached = false

	return nil
}

// ReplaceProgram replaces an existing program with a new one.
func (p *ProgramManager) ReplaceProgram(oldName, newName string) error {
	p.programsMu.Lock()
	defer p.programsMu.Unlock()

	// Check if old program exists
	oldProg, ok := p.programs[oldName]
	if !ok {
		return fmt.Errorf("old program %s not found", oldName)
	}

	// Check if new program exists
	newProg, ok := p.programs[newName]
	if !ok {
		return fmt.Errorf("new program %s not found", newName)
	}

	// Check if old program is attached
	if !oldProg.Attached || oldProg.Link == nil {
		return fmt.Errorf("old program %s is not attached", oldName)
	}

	// Store old program info
	oldInterface := oldProg.Interface
	oldHookType := oldProg.Type

	// Detach the old program
	if err := oldProg.Link.Close(); err != nil {
		return fmt.Errorf("failed to detach old eBPF program: %w", err)
	}

	// Update old program state
	oldProg.Link = nil
	oldProg.Attached = false

	// Set the interface on the new program if needed
	if newProg.Interface == "" {
		newProg.Interface = oldInterface
	}

	// Attach the new program
	var l link.Link

	switch HookType(oldHookType) {
	case HookTypeXDP:
		// Get the interface
		iface, err := netlink.LinkByName(newProg.Interface)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %w", newProg.Interface, err)
		}
		// Attach XDP program
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   newProg.InnerProg,
			Interface: iface.Attrs().Index,
		})
		if err != nil {
			return fmt.Errorf("failed to attach XDP program: %w", err)
		}
	case HookTypeTCIngress:
		tcLink, tcErr := attachTCProgram(newProg, ebpf.AttachTCXIngress)
		if tcErr != nil {
			return fmt.Errorf("failed to attach TC ingress program: %w", tcErr)
		}
		l = tcLink
	case HookTypeTCEgress:
		tcLink, tcErr := attachTCProgram(newProg, ebpf.AttachTCXEgress)
		if tcErr != nil {
			return fmt.Errorf("failed to attach TC egress program: %w", tcErr)
		}
		l = tcLink
	case HookTypeSockOps, HookTypeCGroup:
		return fmt.Errorf("hot swap not supported for hook type %s", oldHookType)
	default:
		return fmt.Errorf("unsupported hook type for replacement: %s", oldHookType)
	}

	// Store the link
	newProg.Link = l
	newProg.Attached = true

	return nil
}

// ListPrograms lists all loaded eBPF programs.
func (p *ProgramManager) ListPrograms() ([]*LoadedProgram, error) {
	p.programsMu.RLock()
	defer p.programsMu.RUnlock()

	programs := make([]*LoadedProgram, 0, len(p.programs))
	for _, prog := range p.programs {
		programs = append(programs, prog)
	}

	return programs, nil
}

// GetProgram gets a loaded eBPF program by name.
func (p *ProgramManager) GetProgram(name string) (*LoadedProgram, error) {
	p.programsMu.RLock()
	defer p.programsMu.RUnlock()

	// Check if program exists
	prog, ok := p.programs[name]
	if !ok {
		return nil, fmt.Errorf("program %s not found", name)
	}

	return prog, nil
}

// GetProgramMetrics gets metrics for a loaded eBPF program.
func (p *ProgramManager) GetProgramMetrics(name string) (map[string]interface{}, error) {
	p.programsMu.RLock()
	defer p.programsMu.RUnlock()

	// Check if program exists
	prog, ok := p.programs[name]
	if !ok {
		return nil, fmt.Errorf("program %s not found", name)
	}

	// In a real implementation, we would collect actual metrics
	// This is a placeholder
	metrics := map[string]interface{}{
		"name":     prog.Name,
		"type":     prog.Type,
		"attached": prog.Attached,
		"maps":     prog.Maps,
	}

	return metrics, nil
}
