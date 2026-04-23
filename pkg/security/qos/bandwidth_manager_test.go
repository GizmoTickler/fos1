package qos

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// makePod constructs a minimal *corev1.Pod with labels and optional
// existing annotations. Tests use this to seed the fake client.
func makePod(name, namespace string, labels map[string]string, annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
	}
}

// TestTranslate_HappyPath verifies the translator accepts a well-formed
// spec and emits the two annotations Cilium expects.
func TestTranslate_HappyPath(t *testing.T) {
	spec := &QoSProfileSpec{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "noisy"},
		},
		Namespace:        "default",
		EgressBandwidth:  "10M",
		IngressBandwidth: "5M",
	}

	result, err := Translate("noisy-qos", spec)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "default", result.Namespace)
	assert.Equal(t, "app=noisy", result.Selector.String())
	assert.Equal(t, "10M", result.Annotations[AnnotationEgressBandwidth])
	assert.Equal(t, "5M", result.Annotations[AnnotationIngressBandwidth])
	assert.Equal(t, "noisy-qos", result.ProfileName)
	assert.NotEmpty(t, result.Hash, "hash must be populated for drift detection")
}

// TestTranslate_EgressOnly exercises the common case: only egress rate
// limiting, no ingress hint. Verifies the ingress key is *absent* rather
// than set to "".
func TestTranslate_EgressOnly(t *testing.T) {
	spec := &QoSProfileSpec{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "noisy"},
		},
		Namespace:       "default",
		EgressBandwidth: "10M",
	}
	result, err := Translate("egress-only", spec)
	require.NoError(t, err)

	_, hasIngress := result.Annotations[AnnotationIngressBandwidth]
	assert.False(t, hasIngress, "unset ingress must not produce an empty annotation")
	assert.Equal(t, "10M", result.Annotations[AnnotationEgressBandwidth])
}

// TestTranslate_ClusterScoped confirms ClusterScoped=true clears the
// namespace on the emitted TranslationResult.
func TestTranslate_ClusterScoped(t *testing.T) {
	spec := &QoSProfileSpec{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"tier": "batch"},
		},
		Namespace:       "default",
		ClusterScoped:   true,
		EgressBandwidth: "1M",
	}
	result, err := Translate("cluster-wide", spec)
	require.NoError(t, err)
	assert.Equal(t, "", result.Namespace, "ClusterScoped must zero out namespace")
}

// TestTranslate_Deterministic verifies the hash is stable across calls —
// otherwise every reconcile would re-patch every pod because the "applied"
// annotation would never match.
func TestTranslate_Deterministic(t *testing.T) {
	spec := &QoSProfileSpec{
		PodSelector:      &metav1.LabelSelector{MatchLabels: map[string]string{"app": "noisy"}},
		Namespace:        "default",
		EgressBandwidth:  "10M",
		IngressBandwidth: "5M",
	}
	a, err := Translate("p", spec)
	require.NoError(t, err)
	b, err := Translate("p", spec)
	require.NoError(t, err)
	assert.Equal(t, a.Hash, b.Hash, "Translate must be deterministic")
}

// TestTranslate_HashSensitiveToBandwidthChange ensures changing either
// bandwidth field produces a different hash so drift is detected.
func TestTranslate_HashSensitiveToBandwidthChange(t *testing.T) {
	base := &QoSProfileSpec{
		PodSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "noisy"}},
		Namespace:       "default",
		EgressBandwidth: "10M",
	}
	a, err := Translate("p", base)
	require.NoError(t, err)

	bumped := *base
	bumped.EgressBandwidth = "20M"
	b, err := Translate("p", &bumped)
	require.NoError(t, err)

	assert.NotEqual(t, a.Hash, b.Hash)
}

// TestTranslate_NoSelector maps to Invalid=True on the CRD status.
func TestTranslate_NoSelector(t *testing.T) {
	_, err := Translate("bad", &QoSProfileSpec{
		EgressBandwidth: "10M",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoSelector)
}

// TestTranslate_NoBandwidth: a profile with a selector but no bandwidths
// is a configuration error, not a no-op.
func TestTranslate_NoBandwidth(t *testing.T) {
	_, err := Translate("bad", &QoSProfileSpec{
		PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "noisy"}},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoBandwidth)
}

// TestTranslate_NilSpec: the controller should never pass nil, but guard
// anyway so a translator-level panic never escapes to the reconcile loop.
func TestTranslate_NilSpec(t *testing.T) {
	_, err := Translate("x", nil)
	require.Error(t, err)
}

// TestApplyToPods_PatchesMatchingPods is the end-to-end translator +
// reconciler happy path: two matching pods, one non-matching, the
// non-matching pod must be left untouched.
func TestApplyToPods_PatchesMatchingPods(t *testing.T) {
	ctx := context.Background()
	p1 := makePod("noisy-1", "default", map[string]string{"app": "noisy"}, nil)
	p2 := makePod("noisy-2", "default", map[string]string{"app": "noisy"}, nil)
	p3 := makePod("quiet-1", "default", map[string]string{"app": "quiet"}, nil)

	client := fake.NewSimpleClientset(p1, p2, p3)

	spec := &QoSProfileSpec{
		PodSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "noisy"}},
		Namespace:       "default",
		EgressBandwidth: "10M",
	}
	result, err := Translate("noisy-qos", spec)
	require.NoError(t, err)

	r := NewBandwidthManagerReconciler(client)
	out, err := r.ApplyToPods(ctx, result)
	require.NoError(t, err)

	assert.Equal(t, 2, out.Matched)
	assert.Equal(t, 2, out.Patched)
	assert.Equal(t, 0, out.Skipped)
	assert.Empty(t, out.Errors)

	// Verify the actual state of the pods.
	got1, err := client.CoreV1().Pods("default").Get(ctx, "noisy-1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "10M", got1.Annotations[AnnotationEgressBandwidth])
	assert.Equal(t, "noisy-qos", got1.Annotations[AnnotationProfileName])
	assert.Equal(t, result.Hash, got1.Annotations[AnnotationAppliedHash])

	// Non-matching pod must not have been touched.
	got3, err := client.CoreV1().Pods("default").Get(ctx, "quiet-1", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Empty(t, got3.Annotations[AnnotationEgressBandwidth])
	assert.Empty(t, got3.Annotations[AnnotationProfileName])
}

// TestApplyToPods_Idempotent is the key correctness property: re-applying
// the same translation against an already-reconciled pod must issue no
// PATCH calls and return Skipped=Matched.
func TestApplyToPods_Idempotent(t *testing.T) {
	ctx := context.Background()
	pod := makePod("noisy-1", "default", map[string]string{"app": "noisy"}, nil)

	client := fake.NewSimpleClientset(pod)

	spec := &QoSProfileSpec{
		PodSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "noisy"}},
		Namespace:       "default",
		EgressBandwidth: "10M",
	}
	result, err := Translate("noisy-qos", spec)
	require.NoError(t, err)

	r := NewBandwidthManagerReconciler(client)

	// First apply: expect a patch.
	first, err := r.ApplyToPods(ctx, result)
	require.NoError(t, err)
	assert.Equal(t, 1, first.Patched)
	assert.Equal(t, 0, first.Skipped)

	// Capture the action count so we can verify the second apply issues
	// no PATCH. The fake client records every action.
	patchesBefore := countActions(client, "patch", "pods")

	second, err := r.ApplyToPods(ctx, result)
	require.NoError(t, err)
	assert.Equal(t, 0, second.Patched, "re-apply of identical state must not patch")
	assert.Equal(t, 1, second.Skipped, "re-apply must mark matched pod as skipped")

	patchesAfter := countActions(client, "patch", "pods")
	assert.Equal(t, patchesBefore, patchesAfter, "idempotent re-apply must issue zero PATCH calls")
}

// TestApplyToPods_RepairsDriftedAnnotation: a user strips the bandwidth
// key from a pod but leaves our hash annotation — next reconcile should
// notice the drift and re-patch.
func TestApplyToPods_RepairsDriftedAnnotation(t *testing.T) {
	ctx := context.Background()
	pod := makePod("noisy-1", "default", map[string]string{"app": "noisy"}, nil)
	client := fake.NewSimpleClientset(pod)

	spec := &QoSProfileSpec{
		PodSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "noisy"}},
		Namespace:       "default",
		EgressBandwidth: "10M",
	}
	result, err := Translate("noisy-qos", spec)
	require.NoError(t, err)

	r := NewBandwidthManagerReconciler(client)
	_, err = r.ApplyToPods(ctx, result)
	require.NoError(t, err)

	// Simulate drift: user or admission webhook removes the egress key
	// but leaves the hash annotation behind.
	fresh, _ := client.CoreV1().Pods("default").Get(ctx, "noisy-1", metav1.GetOptions{})
	delete(fresh.Annotations, AnnotationEgressBandwidth)
	_, err = client.CoreV1().Pods("default").Update(ctx, fresh, metav1.UpdateOptions{})
	require.NoError(t, err)

	out, err := r.ApplyToPods(ctx, result)
	require.NoError(t, err)
	assert.Equal(t, 1, out.Patched, "drift must be repaired on next reconcile")
}

// TestApplyToPods_NoMatches returns Matched=0 without error, which maps
// to Applied=True with zero targets — a valid steady state.
func TestApplyToPods_NoMatches(t *testing.T) {
	ctx := context.Background()
	pod := makePod("quiet-1", "default", map[string]string{"app": "quiet"}, nil)
	client := fake.NewSimpleClientset(pod)

	spec := &QoSProfileSpec{
		PodSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "noisy"}},
		Namespace:       "default",
		EgressBandwidth: "10M",
	}
	result, _ := Translate("noisy-qos", spec)

	r := NewBandwidthManagerReconciler(client)
	out, err := r.ApplyToPods(context.Background(), result)
	_ = ctx
	require.NoError(t, err)
	assert.Equal(t, 0, out.Matched)
	assert.Equal(t, 0, out.Patched)
	assert.Empty(t, out.Errors)
}

// TestApplyToPods_ClusterScopedListsAllNamespaces verifies the
// ClusterScoped path lists pods across every namespace.
func TestApplyToPods_ClusterScopedListsAllNamespaces(t *testing.T) {
	ctx := context.Background()
	p1 := makePod("noisy-1", "ns-a", map[string]string{"app": "noisy"}, nil)
	p2 := makePod("noisy-2", "ns-b", map[string]string{"app": "noisy"}, nil)
	client := fake.NewSimpleClientset(p1, p2)

	spec := &QoSProfileSpec{
		PodSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "noisy"}},
		ClusterScoped:   true,
		EgressBandwidth: "1M",
	}
	result, err := Translate("cluster-qos", spec)
	require.NoError(t, err)

	r := NewBandwidthManagerReconciler(client)
	out, err := r.ApplyToPods(ctx, result)
	require.NoError(t, err)
	assert.Equal(t, 2, out.Matched)
	assert.Equal(t, 2, out.Patched)
}

// TestApplyToPods_PatchErrorIsPartialDegradation: a transient Patch
// failure on one of N matching pods must be reported as an error in the
// ReconcileResult but not abort the other patches.
func TestApplyToPods_PatchErrorIsPartialDegradation(t *testing.T) {
	ctx := context.Background()
	p1 := makePod("noisy-1", "default", map[string]string{"app": "noisy"}, nil)
	p2 := makePod("noisy-2", "default", map[string]string{"app": "noisy"}, nil)
	client := fake.NewSimpleClientset(p1, p2)

	// Inject an error on every PATCH to pod "noisy-1" only. Other pods
	// should still get patched.
	client.PrependReactor("patch", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		patchAction := action.(clienttesting.PatchAction)
		if patchAction.GetName() == "noisy-1" {
			return true, nil, errors.New("synthetic patch failure")
		}
		return false, nil, nil
	})

	spec := &QoSProfileSpec{
		PodSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "noisy"}},
		Namespace:       "default",
		EgressBandwidth: "10M",
	}
	result, _ := Translate("noisy-qos", spec)

	r := NewBandwidthManagerReconciler(client)
	out, err := r.ApplyToPods(ctx, result)
	require.NoError(t, err)

	assert.Equal(t, 2, out.Matched)
	assert.Equal(t, 1, out.Patched, "second pod must still be patched despite first-pod error")
	assert.Len(t, out.Errors, 1)
}

// TestApplyToPods_NotFoundIsTreatedAsSuccess: a pod disappearing between
// List and Patch is a normal race and must not surface as an error.
func TestApplyToPods_NotFoundIsTreatedAsSuccess(t *testing.T) {
	ctx := context.Background()
	p1 := makePod("noisy-1", "default", map[string]string{"app": "noisy"}, nil)
	client := fake.NewSimpleClientset(p1)

	client.PrependReactor("patch", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "noisy-1")
	})

	spec := &QoSProfileSpec{
		PodSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "noisy"}},
		Namespace:       "default",
		EgressBandwidth: "10M",
	}
	result, _ := Translate("noisy-qos", spec)

	r := NewBandwidthManagerReconciler(client)
	out, err := r.ApplyToPods(ctx, result)
	require.NoError(t, err)
	assert.Empty(t, out.Errors, "NotFound on Patch must not be reported as an error")
}

// TestRemoveFromPods_StripsOnlyOwnedPods: the tear-down path must not
// clear annotations on pods owned by a *different* QoSProfile.
func TestRemoveFromPods_StripsOnlyOwnedPods(t *testing.T) {
	ctx := context.Background()
	ours := makePod("owned-1", "default", map[string]string{"app": "noisy"},
		map[string]string{
			AnnotationEgressBandwidth: "10M",
			AnnotationProfileName:     "noisy-qos",
			AnnotationAppliedHash:     "abc",
		})
	theirs := makePod("other-1", "default", map[string]string{"app": "chatty"},
		map[string]string{
			AnnotationEgressBandwidth: "50M",
			AnnotationProfileName:     "chatty-qos",
			AnnotationAppliedHash:     "def",
		})
	client := fake.NewSimpleClientset(ours, theirs)

	r := NewBandwidthManagerReconciler(client)
	n, err := r.RemoveFromPods(ctx, "default", "noisy-qos")
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	oursAfter, _ := client.CoreV1().Pods("default").Get(ctx, "owned-1", metav1.GetOptions{})
	assert.Empty(t, oursAfter.Annotations[AnnotationEgressBandwidth], "owned pod must be cleared")
	assert.Empty(t, oursAfter.Annotations[AnnotationProfileName])

	theirsAfter, _ := client.CoreV1().Pods("default").Get(ctx, "other-1", metav1.GetOptions{})
	assert.Equal(t, "50M", theirsAfter.Annotations[AnnotationEgressBandwidth], "other-profile pod must NOT be cleared")
	assert.Equal(t, "chatty-qos", theirsAfter.Annotations[AnnotationProfileName])
}

// TestNewBandwidthManagerReconciler_NilClient: the reconciler should
// explicitly error on misconfiguration rather than silently no-op.
func TestNewBandwidthManagerReconciler_NilClient(t *testing.T) {
	r := NewBandwidthManagerReconciler(nil)
	_, err := r.ApplyToPods(context.Background(), &TranslationResult{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil BandwidthManagerReconciler")
}

// countActions returns the number of recorded actions matching verb/resource
// on a fake clientset. Used to assert a reconcile issued (or did not issue)
// the expected API calls.
func countActions(client kubernetes.Interface, verb, resource string) int {
	tc, ok := client.(*fake.Clientset)
	if !ok {
		return 0
	}
	n := 0
	for _, a := range tc.Actions() {
		if a.GetVerb() == verb && a.GetResource().Resource == resource {
			n++
		}
	}
	return n
}
