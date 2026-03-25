package network

import "time"

// ManagerConfig holds configuration for the unified NetworkManager.
type ManagerConfig struct {
	// ReconcileInterval is how often to check for state drift.
	// Zero disables periodic reconciliation.
	ReconcileInterval time.Duration

	// DefaultMTU for new interfaces when not specified.
	DefaultMTU int

	// EnableEventBus controls whether the event bus is active.
	EnableEventBus bool
}

// DefaultManagerConfig returns a ManagerConfig with sensible defaults.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		ReconcileInterval: 30 * time.Second,
		DefaultMTU:        1500,
		EnableEventBus:    true,
	}
}
