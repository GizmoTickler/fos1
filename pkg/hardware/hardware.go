// Package hardware provides hardware integration for the router/firewall system.
// It handles interaction with physical network interfaces, eBPF programs,
// hardware offloading, packet capture, and multi-WAN management.
package hardware

import (
	"context"
	"fmt"
)

// Manager is the main hardware integration manager that coordinates all hardware-related components.
type Manager struct {
	NICManager     NICManager
	EBPFManager    EBPFManager
	OffloadManager OffloadManager
	CaptureManager CaptureManager
	WANManager     WANManager
}

// Config represents the configuration for the hardware manager.
type Config struct {
	EnableOffloading bool
	EnableEBPF       bool
	EnableMultiWAN   bool
	EnableCapture    bool
}

// NewManager creates a new hardware manager with the provided configuration.
func NewManager(config Config) (*Manager, error) {
	nicManager, err := NewNICManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create NIC manager: %w", err)
	}

	ebpfManager, err := NewEBPFManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF manager: %w", err)
	}

	offloadManager, err := NewOffloadManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create offload manager: %w", err)
	}

	captureManager, err := NewCaptureManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create capture manager: %w", err)
	}

	wanManager, err := NewWANManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create WAN manager: %w", err)
	}

	return &Manager{
		NICManager:     nicManager,
		EBPFManager:    ebpfManager,
		OffloadManager: offloadManager,
		CaptureManager: captureManager,
		WANManager:     wanManager,
	}, nil
}

// Initialize initializes all hardware components.
func (m *Manager) Initialize(ctx context.Context) error {
	// Initialize NIC Manager
	if err := m.NICManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize NIC manager: %w", err)
	}

	// Initialize eBPF Manager
	if err := m.EBPFManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize eBPF manager: %w", err)
	}

	// Initialize Offload Manager
	if err := m.OffloadManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize offload manager: %w", err)
	}

	// Initialize Capture Manager
	if err := m.CaptureManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize capture manager: %w", err)
	}

	// Initialize WAN Manager
	if err := m.WANManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize WAN manager: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down all hardware components.
func (m *Manager) Shutdown(ctx context.Context) error {
	var errors []error

	if err := m.NICManager.Shutdown(ctx); err != nil {
		errors = append(errors, fmt.Errorf("failed to shutdown NIC manager: %w", err))
	}

	if err := m.EBPFManager.Shutdown(ctx); err != nil {
		errors = append(errors, fmt.Errorf("failed to shutdown eBPF manager: %w", err))
	}

	if err := m.OffloadManager.Shutdown(ctx); err != nil {
		errors = append(errors, fmt.Errorf("failed to shutdown offload manager: %w", err))
	}

	if err := m.CaptureManager.Shutdown(ctx); err != nil {
		errors = append(errors, fmt.Errorf("failed to shutdown capture manager: %w", err))
	}

	if err := m.WANManager.Shutdown(ctx); err != nil {
		errors = append(errors, fmt.Errorf("failed to shutdown WAN manager: %w", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to shutdown hardware manager: %v", errors)
	}

	return nil
}

// NICManager defines the interface for network interface management.
type NICManager interface {
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
	ConfigureInterface(name string, config InterfaceConfig) error
	GetInterface(name string) (*NetworkInterface, error)
	ListInterfaces() ([]*NetworkInterface, error)
	MonitorInterfaces(ctx context.Context) error
}

// EBPFManager defines the interface for eBPF program management.
type EBPFManager interface {
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
	LoadProgram(program EBPFProgram) error
	UnloadProgram(name string) error
	AttachProgram(programName, hookName string) error
	DetachProgram(programName, hookName string) error
	ListPrograms() ([]EBPFProgramInfo, error)
	UpdateMap(name string, key, value interface{}) error
}

// OffloadManager defines the interface for hardware offloading configuration.
type OffloadManager interface {
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
	ConfigureOffload(ifName string, features OffloadFeatures) error
	GetOffloadCapabilities(ifName string) (*OffloadCapabilities, error)
	ResetOffload(ifName string) error
}

// CaptureManager defines the interface for packet capture management.
type CaptureManager interface {
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
	StartCapture(config CaptureConfig) (string, error)
	StopCapture(captureID string) error
	GetCaptureStatus(captureID string) (*CaptureStatus, error)
	ListCaptures() ([]string, error)
}

// WANManager defines the interface for WAN interface management.
type WANManager interface {
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
	AddWANInterface(config WANInterfaceConfig) error
	RemoveWANInterface(name string) error
	GetWANStatus(name string) (*WANStatus, error)
	SetActiveWAN(name string) error
	ListWANInterfaces() ([]WANInterfaceStatus, error)
	StartMonitoring(ctx context.Context) error
}

// Common Types

// InterfaceType represents the type of network interface.
type InterfaceType string

const (
	// InterfaceTypePhysical represents a physical network interface.
	InterfaceTypePhysical InterfaceType = "physical"
	// InterfaceTypeVLAN represents a VLAN interface.
	InterfaceTypeVLAN InterfaceType = "vlan"
	// InterfaceTypeBridge represents a bridge interface.
	InterfaceTypeBridge InterfaceType = "bridge"
	// InterfaceTypeBond represents a bonded interface.
	InterfaceTypeBond InterfaceType = "bond"
)

// NetworkInterface represents a network interface.
type NetworkInterface struct {
	Name            string
	Type            InterfaceType
	MAC             string
	MTU             int
	Enabled         bool
	Addresses       []string
	State           string
	Parent          string // For VLAN interfaces
	VLANID          int    // For VLAN interfaces
	Statistics      InterfaceStatistics
	OffloadFeatures OffloadFeatures
}

// InterfaceConfig represents the configuration for a network interface.
type InterfaceConfig struct {
	MTU            int
	Enabled        bool
	Addresses      []string
	EnableOffload  bool
	OffloadFeatures OffloadFeatures
}

// InterfaceStatistics represents statistics for a network interface.
type InterfaceStatistics struct {
	RxBytes    uint64
	RxPackets  uint64
	RxErrors   uint64
	RxDropped  uint64
	TxBytes    uint64
	TxPackets  uint64
	TxErrors   uint64
	TxDropped  uint64
	Collisions uint64
}

// OffloadFeatures represents hardware offloading features.
type OffloadFeatures struct {
	TxChecksum  bool
	RxChecksum  bool
	TSO         bool
	GSO         bool
	GRO         bool
	LRO         bool
	RPS         bool
	XPS         bool
	NTUPLE      bool
	RFS         bool
}

// OffloadCapabilities represents the hardware offloading capabilities.
type OffloadCapabilities struct {
	SupportsTxChecksum bool
	SupportsRxChecksum bool
	SupportsTSO        bool
	SupportsGSO        bool
	SupportsGRO        bool
	SupportsLRO        bool
	SupportsRPS        bool
	SupportsXPS        bool
	SupportsNTUPLE     bool
	SupportsRFS        bool
}

// EBPFProgram represents an eBPF program.
type EBPFProgram struct {
	Name     string
	Type     string
	Code     string
	Maps     []string
	Interface string
	Priority  int
}

// EBPFProgramInfo represents information about a loaded eBPF program.
type EBPFProgramInfo struct {
	Name      string
	Type      string
	ID        uint32
	Interface string
	Attached  bool
}

// CaptureConfig represents the configuration for a packet capture.
type CaptureConfig struct {
	Interface   string
	Filter      string
	MaxDuration string
	MaxSize     string
	Filename    string
}

// CaptureStatus represents the status of a packet capture.
type CaptureStatus struct {
	ID          string
	Interface   string
	Filter      string
	StartTime   string
	Duration    string
	Size        int64
	PacketCount int64
	Status      string
	Error       string
}

// WANInterfaceConfig represents the configuration for a WAN interface.
type WANInterfaceConfig struct {
	Name            string
	Weight          int
	MonitorEnabled  bool
	MonitorInterval int
	MonitorTargets  []string
	Failover        bool
	Gateway         string
}

// WANStatus represents the status of a WAN interface.
type WANStatus struct {
	Name            string
	State           string
	LastStateChange string
	Latency         int
	PacketLoss      float64
	Jitter          int
	Active          bool
}

// WANInterfaceStatus represents the status of a WAN interface.
type WANInterfaceStatus struct {
	Name            string
	State           string
	LastStateChange string
	Active          bool
}
