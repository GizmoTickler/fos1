//go:build linux

package network

import (
	"testing"
	"time"
)

func TestReconcilerDesiredState(t *testing.T) {
	r := &Reconciler{
		desiredState: &DesiredNetworkState{Interfaces: make(map[string]DesiredInterfaceState)},
		interval:     10 * time.Second,
	}

	state := &DesiredNetworkState{
		Interfaces: map[string]DesiredInterfaceState{
			"eth0": {
				Name: "eth0",
				Type: "physical",
				Config: InterfaceConfig{
					MTU:     1500,
					Enabled: true,
				},
			},
			"eth0.100": {
				Name: "eth0.100",
				Type: "vlan",
				Config: InterfaceConfig{
					MTU:       1496,
					Addresses: []string{"10.0.100.1/24"},
					Enabled:   true,
				},
				VLANConfig: &VLANConfig{
					Parent: "eth0",
					VLANID: 100,
				},
			},
		},
	}

	r.SetDesiredState(state)
	got := r.GetDesiredState()

	if len(got.Interfaces) != 2 {
		t.Errorf("expected 2 interfaces in desired state, got %d", len(got.Interfaces))
	}

	if got.Interfaces["eth0"].Config.MTU != 1500 {
		t.Errorf("expected MTU 1500, got %d", got.Interfaces["eth0"].Config.MTU)
	}
}

func TestNeedsUpdate(t *testing.T) {
	r := &Reconciler{}

	tests := []struct {
		name     string
		desired  DesiredInterfaceState
		actual   *NetworkInterface
		expected bool
	}{
		{
			name: "no drift",
			desired: DesiredInterfaceState{
				Config: InterfaceConfig{MTU: 1500, Enabled: true},
			},
			actual: &NetworkInterface{
				ActualMTU:        1500,
				OperationalState: "up",
			},
			expected: false,
		},
		{
			name: "MTU drift",
			desired: DesiredInterfaceState{
				Config: InterfaceConfig{MTU: 9000, Enabled: true},
			},
			actual: &NetworkInterface{
				ActualMTU:        1500,
				OperationalState: "up",
			},
			expected: true,
		},
		{
			name: "state drift - should be up",
			desired: DesiredInterfaceState{
				Config: InterfaceConfig{Enabled: true},
			},
			actual: &NetworkInterface{
				OperationalState: "down",
			},
			expected: true,
		},
		{
			name: "state drift - should be down",
			desired: DesiredInterfaceState{
				Config: InterfaceConfig{Enabled: false},
			},
			actual: &NetworkInterface{
				OperationalState: "up",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.needsUpdate(tt.desired, tt.actual)
			if got != tt.expected {
				t.Errorf("needsUpdate() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestReconcileResult(t *testing.T) {
	result := ReconcileResult{
		Created:   []string{"eth0", "eth1"},
		Deleted:   []string{"old0"},
		Updated:   []string{"br0"},
		Timestamp: time.Now(),
		Duration:  50 * time.Millisecond,
	}

	if len(result.Created) != 2 {
		t.Errorf("expected 2 created, got %d", len(result.Created))
	}
	if len(result.Deleted) != 1 {
		t.Errorf("expected 1 deleted, got %d", len(result.Deleted))
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(result.Errors))
	}
}
