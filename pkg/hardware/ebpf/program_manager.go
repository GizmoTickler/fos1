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
	HookTypeXDP HookType = "xdp"
	// HookTypeTCIngress represents a TC ingress hook.
	HookTypeTCIngress HookType = "tc-ingress"
	// HookTypeTCEgress represents a TC egress hook.
	HookTypeTCEgress HookType = "tc-egress"
	// HookTypeSockOps represents a socket operations hook.
	HookTypeSockOps HookType = "sockops"
	// HookTypeCGroup represents a cgroup hook.
	HookTypeCGroup HookType = "cgroup"
)

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

// LoadProgram loads an eBPF program.
func (p *ProgramManager) LoadProgram(program Program) error {
	p.programsMu.Lock()
	defer p.programsMu.Unlock()

	// Check if program already exists
	if _, ok := p.programs[program.Name]; ok {
		return fmt.Errorf("program %s already exists", program.Name)
	}

	// Increase RLIMIT_MEMLOCK to allow BPF verifier to do more work
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	var loadedProg *ebpf.Program
	var err error

	// Check if we're loading from object file or code
	if len(program.Code) > 0 {
		// Load from code (via object file)
		// This is a placeholder - in production you would use a more sophisticated
		// approach to compile the code or use pre-compiled object files
		objectPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s.o", program.Name))
		if err := os.WriteFile(objectPath, program.Code, 0644); err != nil {
			return fmt.Errorf("failed to write object file: %w", err)
		}
		defer os.Remove(objectPath)

		// Load the object file
		spec, err := ebpf.LoadCollectionSpec(objectPath)
		if err != nil {
			return fmt.Errorf("failed to load eBPF spec: %w", err)
		}

		// For simplicity, assume the main program is named "main"
		// In a real implementation, you would need to know the section name
		progSpec := spec.Programs["main"]
		if progSpec == nil {
			return fmt.Errorf("program main not found in object file")
		}

		// Load the program
		loadedProg, err = ebpf.NewProgram(progSpec)
		if err != nil {
			return fmt.Errorf("failed to load eBPF program: %w", err)
		}
	} else {
		// In a real implementation, we would have more ways to load programs
		return fmt.Errorf("no program code provided")
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

	// Close the program
	if prog.InnerProg != nil {
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

	// Parse the hook type from the hook name
	// Format: "hooktype:interface" or just "hooktype"
	hookType := HookType(hookName)
	if prog.Interface != "" {
		hookType = HookType(fmt.Sprintf("%s:%s", hookName, prog.Interface))
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
		// Get the interface
		iface, err := netlink.LinkByName(prog.Interface)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %w", prog.Interface, err)
		}
		// Attach TC ingress program
		l, err = link.AttachTCX(link.TCXOptions{
			Program:   prog.InnerProg,
			Interface: iface.Attrs().Index,
			Attach:    ebpf.AttachTCIngress,
			Priority:  uint32(prog.Priority),
		})
		if err != nil {
			return fmt.Errorf("failed to attach TC ingress program: %w", err)
		}
	case HookTypeTCEgress:
		// Get the interface
		iface, err := netlink.LinkByName(prog.Interface)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %w", prog.Interface, err)
		}
		// Attach TC egress program
		l, err = link.AttachTCX(link.TCXOptions{
			Program:   prog.InnerProg,
			Interface: iface.Attrs().Index,
			Attach:    ebpf.AttachTCEgress,
			Priority:  uint32(prog.Priority),
		})
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
		return fmt.Errorf("unsupported hook type: %s", hookType)
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
	var err error

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
		// Get the interface
		iface, err := netlink.LinkByName(newProg.Interface)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %w", newProg.Interface, err)
		}
		// Attach TC ingress program
		l, err = link.AttachTCX(link.TCXOptions{
			Program:   newProg.InnerProg,
			Interface: iface.Attrs().Index,
			Attach:    ebpf.AttachTCIngress,
			Priority:  uint32(newProg.Priority),
		})
		if err != nil {
			return fmt.Errorf("failed to attach TC ingress program: %w", err)
		}
	case HookTypeTCEgress:
		// Get the interface
		iface, err := netlink.LinkByName(newProg.Interface)
		if err != nil {
			return fmt.Errorf("failed to get interface %s: %w", newProg.Interface, err)
		}
		// Attach TC egress program
		l, err = link.AttachTCX(link.TCXOptions{
			Program:   newProg.InnerProg,
			Interface: iface.Attrs().Index,
			Attach:    ebpf.AttachTCEgress,
			Priority:  uint32(newProg.Priority),
		})
		if err != nil {
			return fmt.Errorf("failed to attach TC egress program: %w", err)
		}
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
