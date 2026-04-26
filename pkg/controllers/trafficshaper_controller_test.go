package controllers

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	networkv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/network/v1alpha1"
)

// fakeTSBackend records every call made through the TCBackend interface
// so assertions can verify both the call shape and ordering. Modelled
// after fakeTCBackend in pkg/security/qos/traffic_shaper_test.go but
// kept private to this test file so the controller and translator tests
// can evolve their fakes independently.
type fakeTSBackend struct {
	setPriorityCalls   []tsSetPriorityCall
	clearPriorityCalls []string
	attachCalls        []tsAttachCall
	detachCalls        []string

	setPriorityErr error
	attachErr      error
}

type tsSetPriorityCall struct {
	iface    string
	priority uint32
}

type tsAttachCall struct {
	iface     string
	direction networkv1alpha1.TrafficShaperDirection
}

func (f *fakeTSBackend) SetPriority(iface string, priority uint32) error {
	f.setPriorityCalls = append(f.setPriorityCalls, tsSetPriorityCall{iface: iface, priority: priority})
	return f.setPriorityErr
}

func (f *fakeTSBackend) ClearPriority(iface string) error {
	f.clearPriorityCalls = append(f.clearPriorityCalls, iface)
	return nil
}

func (f *fakeTSBackend) EnsureAttached(iface string, dir networkv1alpha1.TrafficShaperDirection) error {
	f.attachCalls = append(f.attachCalls, tsAttachCall{iface: iface, direction: dir})
	return f.attachErr
}

func (f *fakeTSBackend) EnsureDetached(iface string) error {
	f.detachCalls = append(f.detachCalls, iface)
	return nil
}

// newTSFakeDynamicClient returns a dynamic client that accepts arbitrary
// TrafficShaper status writes. Mirrors the pattern in
// qos_controller_test.go; the dynamic fake doesn't natively know about
// TrafficShaper but a passthrough Update reactor is enough for the
// status.Writer round-trip.
func newTSFakeDynamicClient() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme)
	client.PrependReactor("update", "trafficshapers", func(action clienttesting.Action) (bool, runtime.Object, error) {
		u := action.(clienttesting.UpdateActionImpl)
		return true, u.GetObject(), nil
	})
	return client
}

// makeTrafficShaperCR builds a minimal unstructured TrafficShaper CR.
func makeTrafficShaperCR(name, namespace, iface string, rules []map[string]interface{}) *unstructured.Unstructured {
	rawRules := make([]interface{}, 0, len(rules))
	for _, r := range rules {
		rawRules = append(rawRules, r)
	}
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "TrafficShaper",
			"metadata": map[string]interface{}{
				"name":       name,
				"namespace":  namespace,
				"generation": int64(1),
			},
			"spec": map[string]interface{}{
				"interface": iface,
				"rules":     rawRules,
			},
		},
	}
}

// trafficShaperControllerForTest builds a TrafficShaperController wired
// to the fake backend. No informer is started — handle* methods are
// invoked directly. Mirrors controllerForTest in qos_controller_test.go.
func trafficShaperControllerForTest(backend *fakeTSBackend) *TrafficShaperController {
	return &TrafficShaperController{
		dynamicClient: newTSFakeDynamicClient(),
		backend:       backend,
		// statusWriter deliberately left nil: the tests focus on the
		// reconcile decision tree, not the CRD subresource path
		// (covered independently by status.Writer tests).
	}
}

// TestTrafficShaperController_Apply_HappyPath drives the canonical
// translator+backend path and asserts SetPriority + EnsureAttached were
// invoked with the expected (interface, priority, direction) tuple.
func TestTrafficShaperController_Apply_HappyPath(t *testing.T) {
	backend := &fakeTSBackend{}
	c := trafficShaperControllerForTest(backend)

	cr := makeTrafficShaperCR("uplink-prio", "network", "eth0", []map[string]interface{}{
		{"matchCIDR": "10.0.0.0/8", "priority": int64(5), "rate": "100Mbit"},
		{"matchDSCP": int64(46), "priority": int64(1)},
	})

	require.NoError(t, c.handleTrafficShaperCreateOrUpdate(cr))

	require.Len(t, backend.setPriorityCalls, 1)
	assert.Equal(t, "eth0", backend.setPriorityCalls[0].iface)
	assert.Equal(t, uint32(1), backend.setPriorityCalls[0].priority,
		"controller must collapse to the lowest priority across rules")

	require.Len(t, backend.attachCalls, 1)
	assert.Equal(t, "eth0", backend.attachCalls[0].iface)
	assert.Equal(t, networkv1alpha1.TrafficShaperDirectionEgress, backend.attachCalls[0].direction)
}

// TestTrafficShaperController_Apply_Idempotent: two reconciles of the
// same spec must each call SetPriority+Attach (the kernel-level
// idempotency lives in the backend, not the controller). The hash on
// the plan must be identical across calls.
func TestTrafficShaperController_Apply_Idempotent(t *testing.T) {
	backend := &fakeTSBackend{}
	c := trafficShaperControllerForTest(backend)

	cr := makeTrafficShaperCR("uplink-prio", "network", "eth0", []map[string]interface{}{
		{"matchCIDR": "10.0.0.0/8", "priority": int64(3)},
	})

	require.NoError(t, c.handleTrafficShaperCreateOrUpdate(cr))
	require.NoError(t, c.handleTrafficShaperCreateOrUpdate(cr))

	assert.Len(t, backend.setPriorityCalls, 2, "every reconcile invokes SetPriority; backend handles dedup")
	assert.Equal(t, backend.setPriorityCalls[0], backend.setPriorityCalls[1],
		"two reconciles of the same spec must produce identical SetPriority calls")
	assert.Len(t, backend.attachCalls, 2)
	assert.Equal(t, backend.attachCalls[0], backend.attachCalls[1])
}

// TestTrafficShaperController_Apply_RuleUpdate: changing the rules
// changes what we push into the backend. The lowest priority of the
// new rule set is what should land.
func TestTrafficShaperController_Apply_RuleUpdate(t *testing.T) {
	backend := &fakeTSBackend{}
	c := trafficShaperControllerForTest(backend)

	first := makeTrafficShaperCR("uplink-prio", "network", "eth0", []map[string]interface{}{
		{"matchCIDR": "10.0.0.0/8", "priority": int64(5)},
	})
	require.NoError(t, c.handleTrafficShaperCreateOrUpdate(first))

	second := makeTrafficShaperCR("uplink-prio", "network", "eth0", []map[string]interface{}{
		{"matchCIDR": "10.0.0.0/8", "priority": int64(2)},
	})
	require.NoError(t, c.handleTrafficShaperCreateOrUpdate(second))

	require.Len(t, backend.setPriorityCalls, 2)
	assert.Equal(t, uint32(5), backend.setPriorityCalls[0].priority)
	assert.Equal(t, uint32(2), backend.setPriorityCalls[1].priority,
		"second reconcile must push the updated priority")
}

// TestTrafficShaperController_Apply_NoInterface is the Invalid=True
// branch.
func TestTrafficShaperController_Apply_NoInterface(t *testing.T) {
	backend := &fakeTSBackend{}
	c := trafficShaperControllerForTest(backend)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "TrafficShaper",
			"metadata": map[string]interface{}{
				"name":      "bad",
				"namespace": "network",
			},
			"spec": map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{"matchCIDR": "10.0.0.0/8", "priority": int64(3)},
				},
			},
		},
	}

	err := c.handleTrafficShaperCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "interface")
	assert.Empty(t, backend.setPriorityCalls, "Invalid path must not touch backend")
	assert.Empty(t, backend.attachCalls)
}

// TestTrafficShaperController_Apply_NoRules is the other Invalid=True
// branch.
func TestTrafficShaperController_Apply_NoRules(t *testing.T) {
	backend := &fakeTSBackend{}
	c := trafficShaperControllerForTest(backend)

	cr := makeTrafficShaperCR("empty", "network", "eth0", nil)

	err := c.handleTrafficShaperCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rules")
	assert.Empty(t, backend.setPriorityCalls)
}

// TestTrafficShaperController_Apply_BadPriority rejects rules with a
// priority outside [1,7].
func TestTrafficShaperController_Apply_BadPriority(t *testing.T) {
	backend := &fakeTSBackend{}
	c := trafficShaperControllerForTest(backend)

	cr := makeTrafficShaperCR("bad-prio", "network", "eth0", []map[string]interface{}{
		{"matchCIDR": "10.0.0.0/8", "priority": int64(99)},
	})

	err := c.handleTrafficShaperCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "priority")
	assert.Empty(t, backend.setPriorityCalls)
}

// TestTrafficShaperController_Apply_MissingSpec: a CR with no spec at
// all must be reported as Invalid without calling the backend.
func TestTrafficShaperController_Apply_MissingSpec(t *testing.T) {
	backend := &fakeTSBackend{}
	c := trafficShaperControllerForTest(backend)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "TrafficShaper",
			"metadata": map[string]interface{}{
				"name":      "no-spec",
				"namespace": "network",
			},
		},
	}
	err := c.handleTrafficShaperCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec not found")
	assert.Empty(t, backend.setPriorityCalls)
}

// TestTrafficShaperController_Apply_NilBackend: a controller built
// without a backend surfaces Invalid=NoBackend rather than silently
// no-opping.
func TestTrafficShaperController_Apply_NilBackend(t *testing.T) {
	c := &TrafficShaperController{
		dynamicClient: newTSFakeDynamicClient(),
		// backend deliberately nil
	}

	cr := makeTrafficShaperCR("uplink-prio", "network", "eth0", []map[string]interface{}{
		{"matchCIDR": "10.0.0.0/8", "priority": int64(3)},
	})
	err := c.handleTrafficShaperCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend")
}

// TestTrafficShaperController_Apply_BackendSetPriorityErr surfaces a
// backend SetPriority failure as a reconcile error and records Degraded
// on the next status write.
func TestTrafficShaperController_Apply_BackendSetPriorityErr(t *testing.T) {
	backend := &fakeTSBackend{setPriorityErr: errors.New("map full")}
	c := trafficShaperControllerForTest(backend)

	cr := makeTrafficShaperCR("uplink-prio", "network", "eth0", []map[string]interface{}{
		{"matchCIDR": "10.0.0.0/8", "priority": int64(3)},
	})

	err := c.handleTrafficShaperCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set priority")
	// Attach must NOT be invoked when SetPriority failed.
	assert.Empty(t, backend.attachCalls)
}

// TestTrafficShaperController_Apply_BackendAttachErr: backend Attach
// failure surfaces as a reconcile error so the workqueue retries.
func TestTrafficShaperController_Apply_BackendAttachErr(t *testing.T) {
	backend := &fakeTSBackend{attachErr: errors.New("kernel < 6.6")}
	c := trafficShaperControllerForTest(backend)

	cr := makeTrafficShaperCR("uplink-prio", "network", "eth0", []map[string]interface{}{
		{"matchCIDR": "10.0.0.0/8", "priority": int64(3)},
	})

	err := c.handleTrafficShaperCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attach")
	assert.Len(t, backend.setPriorityCalls, 1, "SetPriority runs before Attach")
}

// TestTrafficShaperController_Delete: a delete is best-effort in v1
// (the spec is unrecoverable from the workqueue key alone). The
// handler returns nil without touching the backend; the next
// controller restart's resync of surviving CRs reconciles the world.
func TestTrafficShaperController_Delete(t *testing.T) {
	backend := &fakeTSBackend{}
	c := trafficShaperControllerForTest(backend)

	require.NoError(t, c.handleTrafficShaperDelete("network/uplink-prio"))
	assert.Empty(t, backend.detachCalls,
		"v1 delete handler does not touch the backend; documented in the controller comment")
	assert.Empty(t, backend.clearPriorityCalls)
}

// TestTrafficShaperController_Delete_BadKey rejects malformed keys with
// an error so the workqueue can drop them.
func TestTrafficShaperController_Delete_BadKey(t *testing.T) {
	backend := &fakeTSBackend{}
	c := trafficShaperControllerForTest(backend)

	err := c.handleTrafficShaperDelete("not/a/valid/key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key")
}

// TestExtractTrafficShaperSpec_FullRoundTrip exercises every spec
// field through the unstructured → typed extraction path.
func TestExtractTrafficShaperSpec_FullRoundTrip(t *testing.T) {
	c := trafficShaperControllerForTest(&fakeTSBackend{})

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"interface": "vlan100",
				"direction": "both",
				"rules": []interface{}{
					map[string]interface{}{
						"matchCIDR": "192.168.1.0/24",
						"priority":  int64(2),
						"rate":      "50Mbit",
					},
					map[string]interface{}{
						"matchDSCP": int64(46),
						"priority":  int64(1),
					},
				},
			},
		},
	}

	spec, err := c.extractTrafficShaperSpec(cr)
	require.NoError(t, err)
	require.NotNil(t, spec)
	assert.Equal(t, "vlan100", spec.Interface)
	assert.Equal(t, networkv1alpha1.TrafficShaperDirectionBoth, spec.Direction)
	require.Len(t, spec.Rules, 2)
	assert.Equal(t, "192.168.1.0/24", spec.Rules[0].MatchCIDR)
	assert.Equal(t, uint32(2), spec.Rules[0].Priority)
	assert.Equal(t, "50Mbit", spec.Rules[0].Rate)
	assert.Equal(t, int32(46), spec.Rules[1].MatchDSCP)
	assert.Equal(t, uint32(1), spec.Rules[1].Priority)
}
