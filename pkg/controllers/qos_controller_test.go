package controllers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/GizmoTickler/fos1/pkg/security/qos"
)

// fakeReconciler records each call to ApplyToPods and RemoveFromPods and
// returns a preconfigured ReconcileResult. It satisfies the qosReconciler
// interface so the controller can be driven without a real kubernetes
// clientset; the translator path is already exercised in
// pkg/security/qos/bandwidth_manager_test.go.
type fakeReconciler struct {
	applyCalls     int
	removeCalls    int
	lastResult     *qos.TranslationResult
	lastRemoveNS   string
	lastRemoveName string
	applyResult    *qos.ReconcileResult
	applyErr       error
	removeErr      error
}

func (f *fakeReconciler) ApplyToPods(_ context.Context, r *qos.TranslationResult) (*qos.ReconcileResult, error) {
	f.applyCalls++
	f.lastResult = r
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	if f.applyResult != nil {
		return f.applyResult, nil
	}
	return &qos.ReconcileResult{}, nil
}

func (f *fakeReconciler) RemoveFromPods(_ context.Context, ns, name string) (int, error) {
	f.removeCalls++
	f.lastRemoveNS = ns
	f.lastRemoveName = name
	if f.removeErr != nil {
		return 0, f.removeErr
	}
	return 1, nil
}

// newQoSFakeDynamicClient returns a dynamic client that accepts arbitrary
// QoSProfile status writes. Used so the controller's writeStatus path
// does not short-circuit on a 404 from the fake.
func newQoSFakeDynamicClient() *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme)
	// Both UpdateStatus and Get are plausible paths the status.Writer
	// may hit; accept them unconditionally for the fake dynamic client.
	client.PrependReactor("update", "qosprofiles", func(action clienttesting.Action) (bool, runtime.Object, error) {
		u := action.(clienttesting.UpdateActionImpl)
		return true, u.GetObject(), nil
	})
	return client
}

// makeQoSProfileCR builds a minimal unstructured QoSProfile CR shaped for
// the Bandwidth Manager path (podSelector + egressBandwidth).
func makeQoSProfileCR(name, namespace string, matchLabels map[string]string, egress string) *unstructured.Unstructured {
	labelMap := make(map[string]interface{}, len(matchLabels))
	for k, v := range matchLabels {
		labelMap[k] = v
	}
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "QoSProfile",
			"metadata": map[string]interface{}{
				"name":       name,
				"namespace":  namespace,
				"generation": int64(1),
			},
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": labelMap,
				},
				"egressBandwidth": egress,
			},
		},
	}
}

// controllerForTest builds a QoSController wired to an in-memory
// reconciler. No informer is started — handle* methods are invoked
// directly.
func controllerForTest(recon *fakeReconciler) *QoSController {
	return &QoSController{
		dynamicClient: newQoSFakeDynamicClient(),
		reconciler:    recon,
		// statusWriter deliberately left nil: the tests focus on the
		// reconcile decision tree, not the CRD subresource path (covered
		// independently by the status.Writer tests).
	}
}

// TestQoSController_Apply_Clean drives the translator+reconciler happy
// path and asserts ApplyToPods was called once with the expected
// translation result.
func TestQoSController_Apply_Clean(t *testing.T) {
	recon := &fakeReconciler{
		applyResult: &qos.ReconcileResult{
			Matched: 2, Patched: 2, Skipped: 0,
		},
	}
	c := controllerForTest(recon)

	cr := makeQoSProfileCR("noisy-qos", "default", map[string]string{"app": "noisy"}, "10M")
	err := c.handleQoSProfileCreateOrUpdate(cr)
	require.NoError(t, err)

	assert.Equal(t, 1, recon.applyCalls)
	require.NotNil(t, recon.lastResult)
	assert.Equal(t, "10M", recon.lastResult.Annotations[qos.AnnotationEgressBandwidth])
	assert.Equal(t, "noisy-qos", recon.lastResult.ProfileName)
}

// TestQoSController_Apply_Idempotent asserts that two identical reconciles
// both translate to the same hash. The reconciler (fake here) would see
// the second call as all-skipped when wired to a real pod-patch loop;
// pod-patch idempotency itself is covered in the bandwidth_manager tests.
func TestQoSController_Apply_Idempotent(t *testing.T) {
	recon := &fakeReconciler{
		applyResult: &qos.ReconcileResult{Matched: 1, Skipped: 1},
	}
	c := controllerForTest(recon)

	cr := makeQoSProfileCR("noisy-qos", "default", map[string]string{"app": "noisy"}, "10M")
	require.NoError(t, c.handleQoSProfileCreateOrUpdate(cr))
	firstHash := recon.lastResult.Hash

	require.NoError(t, c.handleQoSProfileCreateOrUpdate(cr))
	assert.Equal(t, firstHash, recon.lastResult.Hash, "identical spec must produce identical hash")
	assert.Equal(t, 2, recon.applyCalls, "each reconcile still calls ApplyToPods; Skipped is reported inside the result")
}

// TestQoSController_Apply_NoSelector is the Invalid=True branch: a CR with
// no podSelector never reaches the pod-patch loop.
func TestQoSController_Apply_NoSelector(t *testing.T) {
	recon := &fakeReconciler{}
	c := controllerForTest(recon)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "QoSProfile",
			"metadata": map[string]interface{}{
				"name":      "bad",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"egressBandwidth": "10M",
				// no podSelector
			},
		},
	}

	err := c.handleQoSProfileCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "podSelector")
	assert.Equal(t, 0, recon.applyCalls, "Invalid path must not call ApplyToPods")
}

// TestQoSController_Apply_NoBandwidth is the other Invalid=True branch.
func TestQoSController_Apply_NoBandwidth(t *testing.T) {
	recon := &fakeReconciler{}
	c := controllerForTest(recon)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "QoSProfile",
			"metadata": map[string]interface{}{
				"name":      "bad",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{"app": "noisy"},
				},
			},
		},
	}

	err := c.handleQoSProfileCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "egressBandwidth")
	assert.Equal(t, 0, recon.applyCalls)
}

// TestQoSController_Apply_MissingSpec: a CR with no spec at all must be
// reported as Invalid without calling ApplyToPods.
func TestQoSController_Apply_MissingSpec(t *testing.T) {
	recon := &fakeReconciler{}
	c := controllerForTest(recon)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "QoSProfile",
			"metadata": map[string]interface{}{
				"name":      "no-spec",
				"namespace": "default",
			},
		},
	}
	err := c.handleQoSProfileCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec not found")
	assert.Equal(t, 0, recon.applyCalls)
}

// TestQoSController_Apply_ReconcilerError: an ApplyToPods-level failure
// (pod list call errored) is surfaced as a reconcile error so the
// workqueue can rate-limit-retry.
func TestQoSController_Apply_ReconcilerError(t *testing.T) {
	recon := &fakeReconciler{applyErr: errors.New("list pods exploded")}
	c := controllerForTest(recon)

	cr := makeQoSProfileCR("noisy-qos", "default", map[string]string{"app": "noisy"}, "10M")
	err := c.handleQoSProfileCreateOrUpdate(cr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list pods exploded")
}

// TestQoSController_Apply_PartialDegradation: ApplyToPods returns a
// non-empty Errors slice but also a non-zero Patched count. The reconcile
// must succeed (Applied=True) and the controller must not re-enqueue.
func TestQoSController_Apply_PartialDegradation(t *testing.T) {
	recon := &fakeReconciler{
		applyResult: &qos.ReconcileResult{
			Matched: 2, Patched: 1, Skipped: 0,
			Errors: []error{errors.New("pod A unreachable")},
		},
	}
	c := controllerForTest(recon)

	cr := makeQoSProfileCR("noisy-qos", "default", map[string]string{"app": "noisy"}, "10M")
	err := c.handleQoSProfileCreateOrUpdate(cr)
	require.NoError(t, err, "partial apply must not surface as a reconcile error")
	assert.Equal(t, 1, recon.applyCalls)
}

// TestQoSController_Delete sweeps through RemoveFromPods with the profile
// name so any previously-annotated pods are cleared.
func TestQoSController_Delete(t *testing.T) {
	recon := &fakeReconciler{}
	c := controllerForTest(recon)

	err := c.handleQoSProfileDelete("default/noisy-qos")
	require.NoError(t, err)

	assert.Equal(t, 1, recon.removeCalls)
	assert.Equal(t, "", recon.lastRemoveNS, "delete should sweep cluster-wide")
	assert.Equal(t, "noisy-qos", recon.lastRemoveName)
}

// TestQoSController_Delete_RemoveError surfaces an error so the workqueue
// can retry. Matches the pattern of every other Sprint-30 controller.
func TestQoSController_Delete_RemoveError(t *testing.T) {
	recon := &fakeReconciler{removeErr: errors.New("api flaky")}
	c := controllerForTest(recon)

	err := c.handleQoSProfileDelete("default/noisy-qos")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api flaky")
}

// TestQoSController_Apply_FallbackUploadBandwidth: legacy CRs that set
// spec.uploadBandwidth instead of spec.egressBandwidth should still
// reconcile — the extractor treats uploadBandwidth as a fallback.
func TestQoSController_Apply_FallbackUploadBandwidth(t *testing.T) {
	recon := &fakeReconciler{applyResult: &qos.ReconcileResult{Matched: 1, Patched: 1}}
	c := controllerForTest(recon)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "network.fos1.io/v1alpha1",
			"kind":       "QoSProfile",
			"metadata": map[string]interface{}{
				"name":      "legacy-qos",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{"app": "legacy"},
				},
				"uploadBandwidth": "25Mbit",
			},
		},
	}
	err := c.handleQoSProfileCreateOrUpdate(cr)
	require.NoError(t, err)
	assert.Equal(t, "25Mbit", recon.lastResult.Annotations[qos.AnnotationEgressBandwidth])
}
