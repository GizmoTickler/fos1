package types

import (
	"context"
)

// EBPFManager defines the interface for eBPF program management
type EBPFManager interface {
	// Initialize initializes the eBPF manager
	Initialize(ctx context.Context) error

	// Shutdown shuts down the eBPF manager
	Shutdown(ctx context.Context) error

	// LoadProgram loads an eBPF program
	LoadProgram(program EBPFProgram) error

	// UnloadProgram unloads an eBPF program
	UnloadProgram(name string) error

	// AttachProgram attaches an eBPF program to a hook
	AttachProgram(programName, hookName string) error

	// DetachProgram detaches an eBPF program from a hook
	DetachProgram(programName, hookName string) error

	// ListPrograms returns a list of all eBPF programs
	ListPrograms() ([]EBPFProgramInfo, error)

	// UpdateMap updates a value in an eBPF map
	UpdateMap(name string, key, value interface{}) error
}

// EBPFProgram defines the configuration for an eBPF program
type EBPFProgram struct {
	// Name is the name of the program
	Name string

	// Type is the type of program (XDP, TC, etc.)
	Type string

	// Code is the program code (ELF file path or source code)
	Code string

	// Interface is the interface to attach to (if applicable)
	Interface string
}

// EBPFProgramInfo defines information about a loaded eBPF program
type EBPFProgramInfo struct {
	// Name is the name of the program
	Name string

	// Type is the type of program (XDP, TC, etc.)
	Type string

	// ID is the program ID
	ID int

	// Interface is the interface the program is attached to (if applicable)
	Interface string

	// Attached indicates whether the program is attached to a hook
	Attached bool
}
