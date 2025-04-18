package vpn

import (
	"time"
)

// WireGuardVPN represents a WireGuard VPN configuration
type WireGuardVPN struct {
	Name      string
	Enabled   bool
	Interface InterfaceConfig
	Peers     []PeerConfig
	Routing   RoutingConfig
	Security  SecurityConfig
	Monitoring MonitoringConfig
}

// InterfaceConfig represents the WireGuard interface configuration
type InterfaceConfig struct {
	Name         string
	PrivateKey   string
	ListenPort   int
	Addresses    []string
	DNS          []string
	MTU          int
	Firewall     bool
	Table        int
	PreUp        []string
	PostUp       []string
	PreDown      []string
	PostDown     []string
}

// PeerConfig represents a WireGuard peer configuration
type PeerConfig struct {
	PublicKey          string
	PresharedKey       string
	Endpoint           string
	PersistentKeepalive int
	AllowedIPs         []string
	Description        string
}

// RoutingConfig represents the routing configuration for the VPN
type RoutingConfig struct {
	DefaultRoute bool
	AllowedIPs   []string
	ExcludedIPs  []string
	Metric       int
}

// SecurityConfig represents security settings for the VPN
type SecurityConfig struct {
	KeyRotation   KeyRotationConfig
	AccessControl AccessControlConfig
}

// KeyRotationConfig represents key rotation settings
type KeyRotationConfig struct {
	Enabled  bool
	Interval string
}

// AccessControlConfig represents access control settings
type AccessControlConfig struct {
	AllowedIPs  []string
	BlockedIPs  []string
}

// MonitoringConfig represents monitoring settings
type MonitoringConfig struct {
	Enabled  bool
	Metrics  bool
	Logging  bool
	LogLevel string
}

// Status represents the status of a WireGuard VPN
type Status struct {
	Phase          string
	PublicKey      string
	ConnectedPeers int
	LastHandshake  time.Time
	TransferRx     int64
	TransferTx     int64
	Conditions     []Condition
}

// Condition represents a status condition
type Condition struct {
	Type               string
	Status             string
	Reason             string
	Message            string
	LastTransitionTime time.Time
}

// PeerStatus represents the status of a WireGuard peer
type PeerStatus struct {
	PublicKey     string
	Endpoint      string
	LastHandshake time.Time
	TransferRx    int64
	TransferTx    int64
	Connected     bool
}

// WireGuardManager defines the interface for managing WireGuard VPNs
type WireGuardManager interface {
	// CreateVPN creates a new WireGuard VPN
	CreateVPN(vpn *WireGuardVPN) error
	
	// UpdateVPN updates an existing WireGuard VPN
	UpdateVPN(vpn *WireGuardVPN) error
	
	// DeleteVPN deletes a WireGuard VPN
	DeleteVPN(name string) error
	
	// GetVPNStatus gets the status of a WireGuard VPN
	GetVPNStatus(name string) (*Status, error)
	
	// GetPeerStatus gets the status of a WireGuard peer
	GetPeerStatus(vpnName, peerPublicKey string) (*PeerStatus, error)
	
	// RotateKeys rotates the keys for a WireGuard VPN
	RotateKeys(name string) error
}

// WireGuardClient defines the interface for interacting with WireGuard
type WireGuardClient interface {
	// CreateInterface creates a WireGuard interface
	CreateInterface(name string, config InterfaceConfig) error
	
	// DeleteInterface deletes a WireGuard interface
	DeleteInterface(name string) error
	
	// AddPeer adds a peer to a WireGuard interface
	AddPeer(interfaceName string, peer PeerConfig) error
	
	// RemovePeer removes a peer from a WireGuard interface
	RemovePeer(interfaceName, publicKey string) error
	
	// GetInterfaceStatus gets the status of a WireGuard interface
	GetInterfaceStatus(name string) (*Status, error)
	
	// GetPeerStatus gets the status of a WireGuard peer
	GetPeerStatus(interfaceName, publicKey string) (*PeerStatus, error)
}
