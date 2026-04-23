// Package qos provides QoS enforcement translators. Sprint 30 / Ticket 45
// introduced the Bandwidth Manager path: QoSProfile CRs map to pod
// annotations (kubernetes.io/egress-bandwidth, kubernetes.io/ingress-bandwidth)
// that Cilium's Bandwidth Manager reads at pod admission to install eBPF
// rate-limiters. See docs/design/qos.md for the scope decision.
//
// The v1 contract is intentionally narrow:
//
//   - Input:  QoSProfileSpec with a podSelector and an egress (+ optional
//     ingress) bandwidth string in a unit Cilium understands (e.g. "10M").
//   - Output: []PodAnnotationPatch describing the exact annotations every
//     matching pod should carry, plus a reconciler that applies them via
//     MergePatch and is idempotent on re-apply.
//
// Non-goals for v1: classful HTB shaping, per-VLAN tagging, DSCP-aware
// classification. Those belong to Ticket 39's TC shaper.
package qos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Annotation keys honoured by Cilium's Bandwidth Manager. See
// https://docs.cilium.io/en/stable/network/kubernetes/bandwidth-manager/
const (
	// AnnotationEgressBandwidth is the egress rate limit annotation key.
	// Cilium reads this at pod scheduling/admission and installs a TBF-style
	// eBPF rate limiter on the pod's veth.
	AnnotationEgressBandwidth = "kubernetes.io/egress-bandwidth"

	// AnnotationIngressBandwidth is the ingress rate limit annotation key.
	// NOTE: Cilium's Bandwidth Manager currently enforces egress only;
	// ingress is accepted as a forward-compatible hint so that when the
	// kernel / Cilium versions catch up no CRD changes are required.
	AnnotationIngressBandwidth = "kubernetes.io/ingress-bandwidth"

	// AnnotationAppliedHash is the bookkeeping annotation the controller
	// writes so it can detect drift without a full spec re-read on every
	// resync. Value is a short SHA-256 of the desired bandwidth pair.
	AnnotationAppliedHash = "fos1.io/qos-applied-hash"

	// AnnotationProfileName records which QoSProfile owns the pod's
	// bandwidth annotations. Used during tear-down to avoid clobbering
	// annotations owned by a different profile.
	AnnotationProfileName = "fos1.io/qos-profile"
)

// QoSProfileSpec is the v1 Bandwidth-Manager-shaped view of a QoSProfile CR.
// The controller extracts it from the unstructured spec before calling the
// translator; this keeps the translator itself free of Kubernetes dynamic
// types and makes it trivially unit-testable.
type QoSProfileSpec struct {
	// PodSelector is the label selector that identifies which pods the
	// profile applies to. When nil the translator returns ErrNoSelector and
	// the caller records Invalid on the CRD status.
	PodSelector *metav1.LabelSelector

	// Namespace scopes the selector. Empty string means cluster-wide (all
	// namespaces). The controller fills this in from the CR's metadata
	// unless the CR explicitly opts into cluster-wide mode via
	// ClusterScoped=true below.
	Namespace string

	// ClusterScoped, when true, makes the selector match pods in every
	// namespace. Useful for cluster-wide noisy-neighbor defaults.
	ClusterScoped bool

	// EgressBandwidth is the rate string written into
	// kubernetes.io/egress-bandwidth. Cilium accepts SI-suffixed values
	// ("10M", "100k", "1G"). Required for the translator to emit anything.
	EgressBandwidth string

	// IngressBandwidth is the optional kubernetes.io/ingress-bandwidth
	// value. Empty string means "do not set"; the annotation is omitted
	// entirely rather than set to the empty string, matching Cilium's
	// parser expectations.
	IngressBandwidth string
}

// TranslationResult is what the translator produces: a parsed selector plus
// the exact annotations to apply. The controller passes this into the
// reconciler's ApplyToPods so the translator itself performs no I/O.
type TranslationResult struct {
	// Selector is the parsed labels.Selector ready for List matching.
	Selector labels.Selector

	// Namespace is the namespace in which to list pods. Empty means all
	// namespaces (ClusterScoped path).
	Namespace string

	// Annotations is the exact {key: value} set the translator wants to
	// write onto every matching pod. Absent keys must be absent from the
	// pod (not empty-string): ApplyToPods enforces this invariant.
	Annotations map[string]string

	// Hash is a short content hash of the Annotations map. The controller
	// stores this in fos1.io/qos-applied-hash so it can skip re-patching
	// pods whose hash already matches the desired state.
	Hash string

	// ProfileName is stamped into fos1.io/qos-profile on every touched
	// pod so a later tear-down knows which profile to clear.
	ProfileName string
}

// ErrNoSelector is returned when the spec has no PodSelector — this maps to
// Invalid=True on the CRD status rather than a retry loop.
var ErrNoSelector = fmt.Errorf("qos: QoSProfile.spec.podSelector is required for Bandwidth Manager enforcement")

// ErrNoBandwidth is returned when the spec has neither EgressBandwidth nor
// IngressBandwidth — there is nothing the translator can emit.
var ErrNoBandwidth = fmt.Errorf("qos: QoSProfile.spec requires at least egressBandwidth or ingressBandwidth")

// Translate converts a QoSProfileSpec into a TranslationResult. It is a pure
// function (no cluster access), idempotent, and deterministic — two calls
// with an equal spec return an equal result including the same Hash.
//
// The returned selector uses labels.SelectorFromSet if matchExpressions are
// absent so the happy-path stays allocation-light.
func Translate(profileName string, spec *QoSProfileSpec) (*TranslationResult, error) {
	if spec == nil {
		return nil, fmt.Errorf("qos: nil spec")
	}
	if spec.PodSelector == nil {
		return nil, ErrNoSelector
	}
	if strings.TrimSpace(spec.EgressBandwidth) == "" && strings.TrimSpace(spec.IngressBandwidth) == "" {
		return nil, ErrNoBandwidth
	}

	sel, err := metav1.LabelSelectorAsSelector(spec.PodSelector)
	if err != nil {
		return nil, fmt.Errorf("qos: invalid podSelector: %w", err)
	}

	ann := make(map[string]string, 2)
	if v := strings.TrimSpace(spec.EgressBandwidth); v != "" {
		ann[AnnotationEgressBandwidth] = v
	}
	if v := strings.TrimSpace(spec.IngressBandwidth); v != "" {
		ann[AnnotationIngressBandwidth] = v
	}

	namespace := spec.Namespace
	if spec.ClusterScoped {
		namespace = ""
	}

	return &TranslationResult{
		Selector:    sel,
		Namespace:   namespace,
		Annotations: ann,
		Hash:        annotationHash(ann),
		ProfileName: profileName,
	}, nil
}

// annotationHash produces a short stable hash over the annotations map so
// the controller can cheaply detect drift between the desired and actual
// annotations on a pod.
func annotationHash(ann map[string]string) string {
	keys := make([]string, 0, len(ann))
	for k := range ann {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%s=%s;", k, ann[k])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// PodAnnotationPatch is the per-pod record emitted when ApplyToPods diffs
// desired vs. actual annotations. It is returned to the controller for
// logging and status reporting, and drives the MergePatch payload.
type PodAnnotationPatch struct {
	// Namespace of the patched pod.
	Namespace string

	// Name of the patched pod.
	Name string

	// Annotations are the keys the patch writes; an empty-string value
	// means "remove this key", which MergePatch interprets via JSON null.
	// For tracing / testing we keep the post-diff desired set here rather
	// than the raw patch bytes.
	Annotations map[string]string

	// AlreadyApplied is true when the pod's annotations already matched
	// the desired set and no PATCH was issued. Counted separately from
	// Patched in the reconciler result.
	AlreadyApplied bool
}

// BandwidthManagerReconciler glues the translator to the Kubernetes API. It
// owns the list-pods-then-patch loop and is the sole writer to pod
// annotations in the QoS path.
//
// Construction takes a kubernetes.Interface so tests can inject a fake
// clientset. The reconciler does not cache pod state — it relies on the
// caller's reconcile cadence for change detection.
type BandwidthManagerReconciler struct {
	client kubernetes.Interface
}

// NewBandwidthManagerReconciler returns a reconciler wired to the provided
// clientset. Passing a nil client yields a reconciler whose ApplyToPods
// will always return an error — exposed so the caller can detect
// misconfiguration (e.g. tests that forgot to seed a client) explicitly
// instead of silently skipping every reconcile.
func NewBandwidthManagerReconciler(client kubernetes.Interface) *BandwidthManagerReconciler {
	return &BandwidthManagerReconciler{client: client}
}

// ReconcileResult summarises one ApplyToPods call. It is the return value
// the controller hands to the status writer so conditions and counts stay
// in lock-step with the actual patches issued.
type ReconcileResult struct {
	// Matched is the total number of pods the selector matched.
	Matched int

	// Patched is the subset of Matched whose annotations differed from
	// desired and were actually mutated.
	Patched int

	// Skipped is Matched - Patched: pods whose hash annotation already
	// matched the translator's hash and whose annotations were left alone.
	Skipped int

	// Patches is the per-pod record. Length equals Matched; Patched+Skipped
	// equals Matched as an invariant.
	Patches []PodAnnotationPatch

	// Errors records per-pod patch errors. A non-empty Errors slice with a
	// non-zero Patched count is the "partial degradation" state — the
	// controller records Degraded=True but leaves Applied=True.
	Errors []error
}

// ApplyToPods lists pods matching result.Selector (scoped to result.Namespace)
// and patches their annotations to match result.Annotations. The patch is
// idempotent: a pod whose fos1.io/qos-applied-hash already equals
// result.Hash is skipped without issuing a PATCH.
//
// The MergePatch payload sets every key in result.Annotations plus
// fos1.io/qos-applied-hash + fos1.io/qos-profile. Stale Bandwidth-Manager
// keys (from a previous profile that also egress-rate-limited these pods)
// are preserved — see RemoveFromPods for the tear-down path.
func (r *BandwidthManagerReconciler) ApplyToPods(ctx context.Context, result *TranslationResult) (*ReconcileResult, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("qos: nil BandwidthManagerReconciler / client")
	}
	if result == nil {
		return nil, fmt.Errorf("qos: nil TranslationResult")
	}

	// Pod list is scoped to result.Namespace; empty string => all namespaces.
	pods, err := r.client.CoreV1().Pods(result.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: result.Selector.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("list pods for selector %q: %w", result.Selector.String(), err)
	}

	out := &ReconcileResult{
		Matched: len(pods.Items),
		Patches: make([]PodAnnotationPatch, 0, len(pods.Items)),
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		patch, alreadyApplied, perr := r.reconcilePod(ctx, pod, result)
		out.Patches = append(out.Patches, patch)
		if perr != nil {
			out.Errors = append(out.Errors, fmt.Errorf("pod %s/%s: %w", pod.Namespace, pod.Name, perr))
			continue
		}
		if alreadyApplied {
			out.Skipped++
		} else {
			out.Patched++
		}
	}

	return out, nil
}

// reconcilePod diffs one pod's annotations against the desired set and
// issues a MergePatch when they differ. Returns the per-pod PodAnnotationPatch
// record, whether the pod was already at the desired state, and any patch
// error. The helper deliberately returns no error when the pod has been
// deleted between List and Patch (NotFound) — the next reconcile will pick
// up the new pod list.
func (r *BandwidthManagerReconciler) reconcilePod(
	ctx context.Context,
	pod *corev1.Pod,
	result *TranslationResult,
) (PodAnnotationPatch, bool, error) {
	patch := PodAnnotationPatch{
		Namespace:   pod.Namespace,
		Name:        pod.Name,
		Annotations: cloneStringMap(result.Annotations),
	}

	// Short-circuit: if the pod's applied-hash matches ours and its
	// bandwidth annotations already equal the desired values, skip the
	// patch. Checking annotation equality too (not just the hash)
	// protects against a user manually stripping the bandwidth keys while
	// leaving our bookkeeping annotation intact.
	if existing := pod.GetAnnotations(); existing[AnnotationAppliedHash] == result.Hash &&
		annotationsEqual(existing, result.Annotations) {
		patch.AlreadyApplied = true
		return patch, true, nil
	}

	// MergePatch payload: desired annotations + our bookkeeping keys. We
	// do NOT write empty-string values; a key absent from desired is
	// simply not touched. Tear-down is the explicit RemoveFromPods path.
	payload := map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": mergePatchAnnotations(result.Annotations, result.Hash, result.ProfileName),
		},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return patch, false, fmt.Errorf("marshal merge-patch: %w", err)
	}

	_, err = r.client.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name, types.MergePatchType, buf, metav1.PatchOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Pod disappeared between List and Patch — safe to ignore.
			return patch, false, nil
		}
		return patch, false, err
	}
	return patch, false, nil
}

// RemoveFromPods strips Bandwidth-Manager annotations from every pod that
// still carries fos1.io/qos-profile=<profileName>. Invoked on CR delete
// and whenever the profile's selector is narrowed, so pods that are no
// longer covered by the selector stop being rate-limited.
//
// Scan scope is the ns argument; pass "" to cover all namespaces. Returns
// the count of pods cleared and the first error encountered.
func (r *BandwidthManagerReconciler) RemoveFromPods(ctx context.Context, ns, profileName string) (int, error) {
	if r == nil || r.client == nil {
		return 0, fmt.Errorf("qos: nil BandwidthManagerReconciler / client")
	}
	if profileName == "" {
		return 0, fmt.Errorf("qos: empty profile name")
	}

	// No server-side selector on annotations, so list everything in scope
	// and filter in memory. Matches the pattern in pkg/security/policy.
	pods, err := r.client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list pods for removal of profile %q: %w", profileName, err)
	}

	cleared := 0
	var firstErr error
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.GetAnnotations()[AnnotationProfileName] != profileName {
			continue
		}
		if err := r.clearPod(ctx, pod); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		cleared++
	}
	return cleared, firstErr
}

// clearPod writes a MergePatch that nulls out every Bandwidth-Manager
// annotation plus our two bookkeeping keys. Using JSON null (not
// empty string) is what tells the Kubernetes API to delete the key.
func (r *BandwidthManagerReconciler) clearPod(ctx context.Context, pod *corev1.Pod) error {
	annotations := map[string]interface{}{
		AnnotationEgressBandwidth:  nil,
		AnnotationIngressBandwidth: nil,
		AnnotationAppliedHash:      nil,
		AnnotationProfileName:      nil,
	}
	payload := map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": annotations,
		},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal clear-patch: %w", err)
	}
	_, err = r.client.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name, types.MergePatchType, buf, metav1.PatchOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// annotationsEqual reports whether `existing` contains every key=value
// pair in `desired`. Extra keys in `existing` do not break equality —
// other annotations on the pod (scheduler, CNI, etc.) must be preserved.
func annotationsEqual(existing, desired map[string]string) bool {
	for k, v := range desired {
		if existing[k] != v {
			return false
		}
	}
	return true
}

// mergePatchAnnotations builds the annotations sub-map for the MergePatch
// payload: the desired bandwidth annotations plus the two bookkeeping keys.
func mergePatchAnnotations(desired map[string]string, hash, profileName string) map[string]interface{} {
	out := make(map[string]interface{}, len(desired)+2)
	for k, v := range desired {
		out[k] = v
	}
	out[AnnotationAppliedHash] = hash
	out[AnnotationProfileName] = profileName
	return out
}

// cloneStringMap returns a shallow copy of m. Used so ReconcileResult
// records are stable even if the caller mutates the source map later.
func cloneStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
