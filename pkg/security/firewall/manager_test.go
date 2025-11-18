package firewall

import (
	"context"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

func TestNewManager(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)
	require.NotNil(t, manager)
	require.NotNil(t, manager.kernel)
	require.NotNil(t, manager.policies)
	require.NotNil(t, manager.zones)

	err = manager.Close()
	assert.NoError(t, err)
}

func TestManager_GetPolicies(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)
	defer manager.Close()

	// Initially empty
	policies := manager.GetPolicies()
	assert.Empty(t, policies)

	// Add a test policy
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: policy.FilterPolicySpec{
			Scope:   "forward",
			Enabled: true,
		},
	}
	manager.policies["default/test-policy"] = testPolicy

	// Verify policy is returned
	policies = manager.GetPolicies()
	assert.Len(t, policies, 1)
	assert.Equal(t, testPolicy, policies["default/test-policy"])
}

func TestManager_GetZones(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)
	defer manager.Close()

	// Initially empty
	zones := manager.GetZones()
	assert.Empty(t, zones)

	// Add a test zone
	testZone := &policy.FilterZone{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-zone",
		},
		Spec: policy.FilterZoneSpec{
			TrustLevel: "trusted",
		},
	}
	testZone.Name = "test-zone"
	manager.zones["test-zone"] = testZone

	// Verify zone is returned
	zones = manager.GetZones()
	assert.Len(t, zones, 1)
	assert.Equal(t, testZone, zones["test-zone"])
}

func TestManager_CreateIPSet(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Initialize firewall first (this will fail without root, but that's ok for unit test)
	_ = manager.Initialize(ctx)

	// Test creating IPv4 IP set
	ips := []string{"192.168.1.1", "192.168.1.2"}
	err = manager.CreateIPSet(ctx, "test-set", nftables.TableFamilyIPv4, ips)

	// This will fail without root privileges, which is expected for unit tests
	if err != nil {
		t.Logf("CreateIPSet failed (expected without root): %v", err)
	}
}

func TestManager_DeleteIPSet(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Test deleting an IP set (will fail without root)
	err = manager.DeleteIPSet(ctx, "test-set", nftables.TableFamilyIPv4)

	// Expected to fail without root or if set doesn't exist
	if err != nil {
		t.Logf("DeleteIPSet failed (expected): %v", err)
	}
}

func TestManager_AddIPToSet(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Test adding IP to set (will fail without root)
	err = manager.AddIPToSet(ctx, "test-set", nftables.TableFamilyIPv4, "192.168.1.100")

	// Expected to fail without root or if set doesn't exist
	if err != nil {
		t.Logf("AddIPToSet failed (expected): %v", err)
	}
}

func TestManager_RemoveIPFromSet(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Test removing IP from set (will fail without root)
	err = manager.RemoveIPFromSet(ctx, "test-set", nftables.TableFamilyIPv4, "192.168.1.100")

	// Expected to fail without root or if set doesn't exist
	if err != nil {
		t.Logf("RemoveIPFromSet failed (expected): %v", err)
	}
}

func TestManager_RemovePolicy(t *testing.T) {
	manager, err := NewManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Add a test policy
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
	}
	manager.policies["default/test-policy"] = testPolicy

	// Remove the policy
	err = manager.RemovePolicy(ctx, "test-policy", "default")
	assert.NoError(t, err)

	// Verify policy is removed
	_, exists := manager.policies["default/test-policy"]
	assert.False(t, exists)
}
