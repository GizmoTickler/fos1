//go:build linux

package network

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/GizmoTickler/fos1/pkg/network/events"
	"k8s.io/klog/v2"
)

// DesiredInterfaceState represents the desired state of a network interface.
type DesiredInterfaceState struct {
	Name       string
	Type       string
	Config     InterfaceConfig
	VLANConfig *VLANConfig
}

// DesiredNetworkState represents the complete desired state of the network.
type DesiredNetworkState struct {
	Interfaces map[string]DesiredInterfaceState
}

// ReconcileResult captures the outcome of a reconciliation run.
type ReconcileResult struct {
	Created   []string
	Deleted   []string
	Updated   []string
	Errors    []error
	Timestamp time.Time
	Duration  time.Duration
}

// Reconciler compares desired state with actual kernel state and corrects drift.
type Reconciler struct {
	manager      *NetworkInterfaceManager
	desiredState *DesiredNetworkState
	mu           sync.RWMutex
	interval     time.Duration
	eventBus     *events.Bus
	lastResult   *ReconcileResult
}

// NewReconciler creates a new Reconciler.
func NewReconciler(manager *NetworkInterfaceManager, interval time.Duration) *Reconciler {
	return &Reconciler{
		manager:      manager,
		desiredState: &DesiredNetworkState{Interfaces: make(map[string]DesiredInterfaceState)},
		interval:     interval,
		eventBus:     manager.EventBus(),
	}
}

// SetDesiredState updates the desired network state.
func (r *Reconciler) SetDesiredState(state *DesiredNetworkState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.desiredState = state
}

// GetDesiredState returns the current desired state.
func (r *Reconciler) GetDesiredState() *DesiredNetworkState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.desiredState
}

// LastResult returns the result of the most recent reconciliation.
func (r *Reconciler) LastResult() *ReconcileResult {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastResult
}

// Start begins periodic reconciliation. It blocks until the context is cancelled.
func (r *Reconciler) Start(ctx context.Context) error {
	klog.Infof("Starting network reconciler with interval %s", r.interval)

	// Initial reconciliation
	if result := r.Reconcile(); len(result.Errors) > 0 {
		klog.Warningf("Initial reconciliation had %d errors", len(result.Errors))
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			klog.Info("Network reconciler stopped")
			return ctx.Err()
		case <-ticker.C:
			result := r.Reconcile()
			if len(result.Errors) > 0 {
				klog.Warningf("Reconciliation had %d errors", len(result.Errors))
			}
			if len(result.Created) > 0 || len(result.Deleted) > 0 || len(result.Updated) > 0 {
				klog.Infof("Reconciliation: created=%d deleted=%d updated=%d errors=%d duration=%s",
					len(result.Created), len(result.Deleted), len(result.Updated),
					len(result.Errors), result.Duration)
			}
		}
	}
}

// Reconcile performs a single reconciliation pass comparing desired vs actual state.
func (r *Reconciler) Reconcile() ReconcileResult {
	start := time.Now()
	result := ReconcileResult{Timestamp: start}

	r.mu.RLock()
	desired := r.desiredState
	r.mu.RUnlock()

	if desired == nil {
		result.Duration = time.Since(start)
		return result
	}

	// Get actual state
	actual, err := r.manager.ListInterfaces()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("failed to list interfaces: %w", err))
		result.Duration = time.Since(start)
		return result
	}

	actualMap := make(map[string]*NetworkInterface, len(actual))
	for _, iface := range actual {
		actualMap[iface.Name] = iface
	}

	// Create missing interfaces
	for name, desiredIf := range desired.Interfaces {
		if _, exists := actualMap[name]; !exists {
			if err := r.createInterface(desiredIf); err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("create %s: %w", name, err))
			} else {
				result.Created = append(result.Created, name)
			}
		}
	}

	// Update interfaces with drifted config
	for name, desiredIf := range desired.Interfaces {
		actualIf, exists := actualMap[name]
		if !exists {
			continue // handled above
		}
		if r.needsUpdate(desiredIf, actualIf) {
			if err := r.updateInterface(desiredIf, actualIf); err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("update %s: %w", name, err))
			} else {
				result.Updated = append(result.Updated, name)
			}
		}
	}

	// Delete interfaces not in desired state
	for name := range actualMap {
		if _, desired := desired.Interfaces[name]; !desired {
			if err := r.manager.DeleteInterfaceWithCleanup(name); err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("delete %s: %w", name, err))
			} else {
				result.Deleted = append(result.Deleted, name)
			}
		}
	}

	result.Duration = time.Since(start)

	r.mu.Lock()
	r.lastResult = &result
	r.mu.Unlock()

	return result
}

// createInterface creates an interface based on desired state.
func (r *Reconciler) createInterface(desired DesiredInterfaceState) error {
	if desired.VLANConfig != nil {
		_, err := r.manager.CreateVLAN(desired.Name, desired.Config, *desired.VLANConfig)
		return err
	}
	_, err := r.manager.CreateInterface(desired.Name, desired.Type, desired.Config)
	return err
}

// needsUpdate checks if an interface's actual state differs from desired.
func (r *Reconciler) needsUpdate(desired DesiredInterfaceState, actual *NetworkInterface) bool {
	// Check MTU
	if desired.Config.MTU > 0 && desired.Config.MTU != actual.ActualMTU {
		return true
	}

	// Check enabled state
	if desired.Config.Enabled && actual.OperationalState != "up" {
		return true
	}
	if !desired.Config.Enabled && actual.OperationalState == "up" {
		return true
	}

	return false
}

// updateInterface corrects drift on an existing interface.
func (r *Reconciler) updateInterface(desired DesiredInterfaceState, actual *NetworkInterface) error {
	// Fix enabled state
	if desired.Config.Enabled && actual.OperationalState != "up" {
		if err := r.manager.SetInterfaceState(desired.Name, true); err != nil {
			return fmt.Errorf("failed to bring interface up: %w", err)
		}
	} else if !desired.Config.Enabled && actual.OperationalState == "up" {
		if err := r.manager.SetInterfaceState(desired.Name, false); err != nil {
			return fmt.Errorf("failed to bring interface down: %w", err)
		}
	}

	// Fix MTU via UpdateInterface
	if desired.Config.MTU > 0 && desired.Config.MTU != actual.ActualMTU {
		_, err := r.manager.UpdateInterface(desired.Name, desired.Config)
		if err != nil {
			return fmt.Errorf("failed to update interface config: %w", err)
		}
	}

	return nil
}
