// Package network provides unified network management for the FOS1 router/firewall.
package network

import (
	"context"
)

// InterfaceConfig contains configuration for a network interface.
type InterfaceConfig struct {
	MTU       int
	Addresses []string
	Enabled   bool
}

// VLANConfig contains configuration specific to VLAN interfaces.
type VLANConfig struct {
	Parent      string
	VLANID      int
	QoSPriority int
	DSCP        int
}

// NetworkInterface represents a physical or virtual network interface.
type NetworkInterface struct {
	Name             string
	Type             string // "physical", "vlan", "bridge", "bond"
	OperationalState string
	Config           InterfaceConfig
	VLANConfig       *VLANConfig // Only for VLAN interfaces
	ActualMTU        int
	ErrorMessage     string
}

// Manager is the unified entry point for all network operations. It coordinates
// interface management, routing, VLANs, IPAM, and protocol management.
type Manager interface {
	// Lifecycle
	Start(ctx context.Context) error
	Stop()

	// Interface management
	CreateInterface(name string, interfaceType string, config InterfaceConfig) (*NetworkInterface, error)
	CreateVLAN(name string, config InterfaceConfig, vlanConfig VLANConfig) (*NetworkInterface, error)
	DeleteInterface(name string) error
	GetInterface(name string) (*NetworkInterface, error)
	ListInterfaces() ([]*NetworkInterface, error)
	SetInterfaceState(name string, up bool) error

	// Cross-component operations
	ConfigureVLANWithIPAM(parent string, vlanID int, subnet string, config InterfaceConfig) (*NetworkInterface, error)
	DeleteInterfaceWithCleanup(name string) error
}
