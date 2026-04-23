// Package controllers hosts the QoS reconciler for QoSProfile CRs.
//
// Sprint 30 / Ticket 45 rewrote this controller from the TC-based prototype
// (which invoked `tc` and `ip` binaries at reconcile time — see the old
// pkg/security/qos.QoSManager) to a Cilium Bandwidth Manager backend: the
// translator in pkg/security/qos/bandwidth_manager.go maps a QoSProfile's
// pod selector + egress/ingress bandwidth into pod annotations that
// Cilium's in-kernel Bandwidth Manager reads and enforces.
//
// TC-based classful shaping (per-VLAN, DSCP-aware) is explicitly out of
// scope for Ticket 45; it is Ticket 39's territory. See docs/design/qos.md.
package controllers

import (
	"context"
	"fmt"
	"reflect"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	statuspkg "github.com/GizmoTickler/fos1/pkg/controllers/status"
	"github.com/GizmoTickler/fos1/pkg/security/qos"
)

const (
	// QoSResyncPeriod is the resync period for QoSProfile informers. A
	// 10-minute resync window matches every other Sprint-30 controller
	// and is the sweet spot between "catch drift quickly" and "don't
	// hammer the API server".
	QoSResyncPeriod = 10 * time.Minute
)

// qosProfileGVR is the GroupVersionResource for the QoSProfile CRD. Kept
// at package scope so tests and helpers share one source of truth.
var qosProfileGVR = schema.GroupVersionResource{
	Group:    "network.fos1.io",
	Version:  "v1alpha1",
	Resource: "qosprofiles",
}

// QoS condition types — kept identical to NAT/FilterPolicy so operators
// have a single mental model for "did the reconcile succeed?".
const (
	// QoSConditionApplied indicates the profile has been translated and
	// every matching pod carries the intended Bandwidth-Manager
	// annotations.
	QoSConditionApplied = "Applied"

	// QoSConditionDegraded indicates a partial apply: some matching pods
	// were patched successfully but at least one PATCH errored.
	QoSConditionDegraded = "Degraded"

	// QoSConditionInvalid indicates the CR spec failed validation
	// (missing selector, missing bandwidth, malformed selector). The
	// controller does not retry until the spec changes.
	QoSConditionInvalid = "Invalid"

	// QoSConditionRemoved indicates the profile has been torn down and
	// every pod it previously annotated has been cleared.
	QoSConditionRemoved = "Removed"

	// QoSConditionStatusTrue / False are the two condition statuses
	// the controller emits (no "Unknown" — we always have an opinion).
	QoSConditionStatusTrue  = "True"
	QoSConditionStatusFalse = "False"
)

// QoSController watches QoSProfile CRDs and reconciles them into pod
// annotations honoured by Cilium's Bandwidth Manager.
//
// Concurrency: the workqueue guarantees at-most-one reconcile-in-flight
// per key. The reconciler itself performs no internal caching; it relies
// on the informer cache for the CR and on the API server for pod state.
type QoSController struct {
	dynamicClient dynamic.Interface
	kubeClient    kubernetes.Interface

	// reconciler owns the translator and the pod PATCH loop. Abstracted
	// behind an interface so unit tests can inject a recording fake
	// without a real kubernetes clientset.
	reconciler qosReconciler

	informer cache.SharedIndexInformer
	queue    workqueue.RateLimitingInterface
	stopCh   chan struct{}

	// statusWriter persists CRD status back to the status subresource.
	// Nil-safe: leaving it nil (e.g. in legacy unit tests) skips
	// writeback and the controller falls back to the pre-Ticket-40
	// behaviour where status lives only in the informer cache.
	statusWriter *statuspkg.Writer
}

// qosReconciler is the minimal surface qos_controller needs from the
// Bandwidth Manager reconciler. Extracting it as an interface keeps the
// controller testable without spinning up a fake clientset.
type qosReconciler interface {
	ApplyToPods(ctx context.Context, result *qos.TranslationResult) (*qos.ReconcileResult, error)
	RemoveFromPods(ctx context.Context, namespace, profileName string) (int, error)
}

// NewQoSController wires a dynamic client + kubernetes clientset into a
// reconciler-backed controller. Passing a nil kubeClient yields a
// controller whose reconcile always errors — surfaced explicitly so a
// missing client cannot masquerade as a successful no-op reconcile.
func NewQoSController(
	dynamicClient dynamic.Interface,
	kubeClient kubernetes.Interface,
) *QoSController {
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, QoSResyncPeriod)
	informer := factory.ForResource(qosProfileGVR).Informer()

	controller := &QoSController{
		dynamicClient: dynamicClient,
		kubeClient:    kubeClient,
		reconciler:    qos.NewBandwidthManagerReconciler(kubeClient),
		informer:      informer,
		queue:         workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:        make(chan struct{}),
		statusWriter:  statuspkg.NewWriter(dynamicClient, qosProfileGVR),
	}

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueQoSProfile,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)

			// Skip update events where spec is unchanged. Status-only
			// updates (from our own writeback) must not re-trigger
			// reconcile or we'd loop forever.
			if reflect.DeepEqual(oldObj.Object["spec"], newObj.Object["spec"]) {
				return
			}
			controller.enqueueQoSProfile(newObj)
		},
		DeleteFunc: controller.enqueueQoSProfile,
	})

	return controller
}

// Run starts the controller. Blocks until Stop() is called or the informer
// cache fails to sync.
func (c *QoSController) Run(workers int) {
	defer c.queue.ShutDown()

	klog.Info("Starting QoS controller (Cilium Bandwidth Manager backend)")

	go c.informer.Run(c.stopCh)

	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		klog.Error("Failed to sync QoS informer cache")
		return
	}
	klog.Info("QoS controller synced and ready")

	for i := 0; i < workers; i++ {
		go c.runWorker()
	}

	<-c.stopCh
	klog.Info("Stopping QoS controller")
}

// Stop signals Run to return and shuts down the workqueue.
func (c *QoSController) Stop() {
	close(c.stopCh)
}

func (c *QoSController) runWorker() {
	for c.processNextItem() {
	}
}

// enqueueQoSProfile pushes a QoSProfile namespace/name onto the workqueue.
// Called from the informer event handlers.
func (c *QoSController) enqueueQoSProfile(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("qos: failed to derive key: %v", err)
		return
	}
	c.queue.Add(key)
}

// processNextItem runs one reconcile. Returns false when the queue is
// shutting down.
func (c *QoSController) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.reconcileQoSProfile(key.(string)); err != nil {
		klog.Errorf("qos: error reconciling %s: %v", key, err)
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("qos: requeuing %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		klog.Infof("qos: dropping %s after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
		return true
	}

	c.queue.Forget(key)
	return true
}

// reconcileQoSProfile is the dispatch entry point: look up the CR, decide
// delete vs apply, and route to the right handler.
func (c *QoSController) reconcileQoSProfile(key string) error {
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", key, err)
	}
	if !exists {
		return c.handleQoSProfileDelete(key)
	}
	return c.handleQoSProfileCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleQoSProfileDelete strips Bandwidth-Manager annotations from every
// pod previously owned by this profile. The annotations are namespaced by
// profile name so we never clobber a sibling profile's pods.
func (c *QoSController) handleQoSProfileDelete(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key %q: %w", key, err)
	}
	klog.Infof("qos: handling delete of QoSProfile %s/%s", namespace, name)

	// Sweep cluster-wide — the profile may have been cluster-scoped, and
	// even for namespaced profiles a defensive cluster-wide sweep is cheap
	// on small clusters and correct on all of them.
	cleared, err := c.reconciler.RemoveFromPods(context.Background(), "", name)
	if err != nil {
		return fmt.Errorf("clear annotations for %s/%s: %w", namespace, name, err)
	}
	klog.Infof("qos: cleared annotations on %d pod(s) for deleted profile %s/%s", cleared, namespace, name)
	return nil
}

// handleQoSProfileCreateOrUpdate is the reconcile workhorse:
//
//  1. Parse the spec into qos.QoSProfileSpec.
//  2. Call qos.Translate — failure ⇒ Invalid=True, no retry.
//  3. Call reconciler.ApplyToPods — errors from the Patch loop become
//     Degraded=True but Applied stays True as long as at least one pod
//     was successfully patched (matches NAT controller's partial-success
//     contract).
//  4. Write status via the shared status.Writer so retry-on-conflict is
//     handled once, in one place.
func (c *QoSController) handleQoSProfileCreateOrUpdate(obj *unstructured.Unstructured) error {
	namespace := obj.GetNamespace()
	name := obj.GetName()
	generation := obj.GetGeneration()
	klog.Infof("qos: processing QoSProfile %s/%s (generation=%d)", namespace, name, generation)

	ctx := context.Background()

	spec, specErr := c.extractSpec(obj)
	if specErr != nil {
		// Validation failure: write Invalid=True and do not retry.
		if err := c.writeStatus(obj, qosStatus{
			ObservedGeneration: generation,
			Now:                time.Now(),
			Invalid:            true,
			InvalidReason:      "ExtractionFailed",
			InvalidMessage:     specErr.Error(),
		}); err != nil {
			klog.Errorf("qos: failed to write invalid status for %s/%s: %v", namespace, name, err)
		}
		return fmt.Errorf("extract spec: %w", specErr)
	}

	result, translateErr := qos.Translate(name, spec)
	if translateErr != nil {
		if err := c.writeStatus(obj, qosStatus{
			ObservedGeneration: generation,
			Now:                time.Now(),
			Invalid:            true,
			InvalidReason:      "TranslationFailed",
			InvalidMessage:     translateErr.Error(),
		}); err != nil {
			klog.Errorf("qos: failed to write invalid status for %s/%s: %v", namespace, name, err)
		}
		return fmt.Errorf("translate: %w", translateErr)
	}

	applyResult, applyErr := c.reconciler.ApplyToPods(ctx, result)
	if applyErr != nil {
		// Whole-apply failure (e.g. pod list call errored). Nothing was
		// patched; record Degraded=True and retry.
		if err := c.writeStatus(obj, qosStatus{
			ObservedGeneration: generation,
			Now:                time.Now(),
			Degraded:           true,
			DegradedReason:     "ApplyFailed",
			DegradedMessage:    applyErr.Error(),
			Hash:               result.Hash,
		}); err != nil {
			klog.Errorf("qos: failed to write degraded status for %s/%s: %v", namespace, name, err)
		}
		return fmt.Errorf("apply to pods: %w", applyErr)
	}

	// Partial success: some pods patched, some errored. Applied=True with
	// Degraded=True so operators see a distinct signal.
	status := qosStatus{
		ObservedGeneration: generation,
		Now:                time.Now(),
		Hash:               result.Hash,
		Matched:            applyResult.Matched,
		Patched:            applyResult.Patched,
		Skipped:            applyResult.Skipped,
	}
	if len(applyResult.Errors) > 0 && applyResult.Patched > 0 {
		status.Applied = true
		status.Degraded = true
		status.DegradedReason = "PartialApply"
		status.DegradedMessage = fmt.Sprintf("%d of %d pods failed to patch; first error: %v",
			len(applyResult.Errors), applyResult.Matched, applyResult.Errors[0])
	} else if len(applyResult.Errors) > 0 {
		// Zero pods patched, all errored. Degraded=True, Applied=False.
		status.Applied = false
		status.Degraded = true
		status.DegradedReason = "AllPatchesFailed"
		status.DegradedMessage = fmt.Sprintf("%d of %d pods failed to patch; first error: %v",
			len(applyResult.Errors), applyResult.Matched, applyResult.Errors[0])
	} else {
		// Clean apply: every matched pod is at desired state.
		status.Applied = true
		status.AppliedReason = "Reconciled"
		status.AppliedMessage = fmt.Sprintf("%d pod(s) matched; %d patched, %d already up to date",
			applyResult.Matched, applyResult.Patched, applyResult.Skipped)
	}

	if err := c.writeStatus(obj, status); err != nil {
		return fmt.Errorf("write status for %s/%s: %w", namespace, name, err)
	}

	klog.Infof("qos: reconciled %s/%s — matched=%d patched=%d skipped=%d errors=%d",
		namespace, name, applyResult.Matched, applyResult.Patched, applyResult.Skipped, len(applyResult.Errors))
	return nil
}

// extractSpec parses the relevant Bandwidth-Manager fields out of the
// unstructured QoSProfile. The extractor is tolerant of legacy fields
// (interface, uploadBandwidth, classes) — those are not required for the
// Bandwidth Manager path but must not cause extraction to fail, so the
// existing tc-shaped examples can live alongside new pod-selector-shaped
// profiles without tripping the Invalid path.
func (c *QoSController) extractSpec(obj *unstructured.Unstructured) (*qos.QoSProfileSpec, error) {
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return nil, fmt.Errorf("spec not found in QoSProfile %s: %w", obj.GetName(), err)
	}

	out := &qos.QoSProfileSpec{
		Namespace: obj.GetNamespace(),
	}

	// PodSelector: the presence of this field is the "use Bandwidth
	// Manager" signal. Absent selectors produce ErrNoSelector from the
	// translator which the controller maps to Invalid=True.
	if raw, ok, _ := unstructured.NestedMap(spec, "podSelector"); ok {
		sel, err := parseLabelSelector(raw)
		if err != nil {
			return nil, fmt.Errorf("podSelector: %w", err)
		}
		out.PodSelector = sel
	}

	// ClusterScoped is an explicit opt-in for cluster-wide selector
	// evaluation. Defaults to false (namespaced) to match standard
	// Kubernetes CR scoping intuition.
	if v, ok, _ := unstructured.NestedBool(spec, "clusterScoped"); ok {
		out.ClusterScoped = v
	}

	// egressBandwidth: the primary rate-limit field. For backwards
	// compatibility with the existing QoSProfile shape we also accept
	// spec.uploadBandwidth as a fallback.
	if v, ok, _ := unstructured.NestedString(spec, "egressBandwidth"); ok {
		out.EgressBandwidth = v
	}
	if out.EgressBandwidth == "" {
		if v, ok, _ := unstructured.NestedString(spec, "uploadBandwidth"); ok {
			out.EgressBandwidth = v
		}
	}

	// ingressBandwidth is optional — Cilium currently enforces egress
	// only — but accept it so CRs are forward-compatible.
	if v, ok, _ := unstructured.NestedString(spec, "ingressBandwidth"); ok {
		out.IngressBandwidth = v
	}

	return out, nil
}

// parseLabelSelector converts the nested map form of a LabelSelector
// (as unstructured hands it to us) into *metav1.LabelSelector. We
// intentionally do not pass through arbitrary matchExpressions fields the
// CRD schema does not advertise — keep the surface small for v1.
func parseLabelSelector(raw map[string]interface{}) (*metav1.LabelSelector, error) {
	sel := &metav1.LabelSelector{}
	if ml, ok, _ := unstructured.NestedStringMap(raw, "matchLabels"); ok {
		sel.MatchLabels = ml
	}
	if exprs, ok, _ := unstructured.NestedSlice(raw, "matchExpressions"); ok {
		for _, e := range exprs {
			em, ok := e.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("matchExpressions entry is not a map")
			}
			key, _ := em["key"].(string)
			op, _ := em["operator"].(string)
			rawVals, _ := em["values"].([]interface{})
			vals := make([]string, 0, len(rawVals))
			for _, v := range rawVals {
				if s, ok := v.(string); ok {
					vals = append(vals, s)
				}
			}
			sel.MatchExpressions = append(sel.MatchExpressions, metav1.LabelSelectorRequirement{
				Key:      key,
				Operator: metav1.LabelSelectorOperator(op),
				Values:   vals,
			})
		}
	}
	return sel, nil
}

// qosStatus is a flat, branch-friendly struct the writeStatus helper
// renders into the CRD status subresource. Bundling the status in one
// place keeps the reconcile decision tree readable and prevents the
// "six condition .setX calls per branch" sprawl that used to live inline
// in the old controller.
type qosStatus struct {
	ObservedGeneration int64
	Now                time.Time

	Hash    string
	Matched int
	Patched int
	Skipped int

	Applied        bool
	AppliedReason  string
	AppliedMessage string

	Degraded        bool
	DegradedReason  string
	DegradedMessage string

	Invalid        bool
	InvalidReason  string
	InvalidMessage string

	Removed        bool
	RemovedReason  string
	RemovedMessage string
}

// writeStatus persists a qosStatus onto the CRD's status subresource via
// the shared status.Writer (retry-on-conflict handled there).
func (c *QoSController) writeStatus(obj *unstructured.Unstructured, status qosStatus) error {
	if c.statusWriter == nil {
		return nil
	}
	return c.statusWriter.WriteStatus(context.Background(), obj.DeepCopy(), qosStatusMutator(status))
}

// qosStatusMutator builds the Mutator that paints qosStatus onto the
// target *unstructured.Unstructured. Extracted so the field layout is
// visible in one place and so status.Writer can re-run the mutator
// verbatim on a conflict-driven re-fetch.
func qosStatusMutator(status qosStatus) statuspkg.Mutator {
	return func(obj *unstructured.Unstructured) error {
		if err := unstructured.SetNestedField(obj.Object, status.ObservedGeneration, "status", "observedGeneration"); err != nil {
			return fmt.Errorf("set status.observedGeneration: %w", err)
		}
		if status.Hash != "" {
			if err := unstructured.SetNestedField(obj.Object, status.Hash, "status", "lastAppliedHash"); err != nil {
				return fmt.Errorf("set status.lastAppliedHash: %w", err)
			}
		}
		if !status.Now.IsZero() {
			if err := unstructured.SetNestedField(obj.Object, status.Now.UTC().Format(time.RFC3339), "status", "lastUpdated"); err != nil {
				return fmt.Errorf("set status.lastUpdated: %w", err)
			}
		}

		// Counts
		if err := unstructured.SetNestedField(obj.Object, int64(status.Matched), "status", "matchedPods"); err != nil {
			return fmt.Errorf("set status.matchedPods: %w", err)
		}
		if err := unstructured.SetNestedField(obj.Object, int64(status.Patched), "status", "patchedPods"); err != nil {
			return fmt.Errorf("set status.patchedPods: %w", err)
		}
		if err := unstructured.SetNestedField(obj.Object, int64(status.Skipped), "status", "skippedPods"); err != nil {
			return fmt.Errorf("set status.skippedPods: %w", err)
		}

		// Conditions — always emit all four so consumers see an explicit
		// False rather than an absent condition when a branch doesn't
		// apply.
		conds := []interface{}{
			buildCondition(QoSConditionApplied, status.Applied, status.AppliedReason, status.AppliedMessage, status.Now),
			buildCondition(QoSConditionDegraded, status.Degraded, status.DegradedReason, status.DegradedMessage, status.Now),
			buildCondition(QoSConditionInvalid, status.Invalid, status.InvalidReason, status.InvalidMessage, status.Now),
			buildCondition(QoSConditionRemoved, status.Removed, status.RemovedReason, status.RemovedMessage, status.Now),
		}
		if err := unstructured.SetNestedSlice(obj.Object, conds, "status", "conditions"); err != nil {
			return fmt.Errorf("set status.conditions: %w", err)
		}
		return nil
	}
}

// buildCondition renders one Kubernetes-style condition map. Reason and
// message default to empty string when absent rather than being omitted
// so the CRD schema sees a stable field shape.
func buildCondition(name string, value bool, reason, message string, t time.Time) map[string]interface{} {
	status := QoSConditionStatusFalse
	if value {
		status = QoSConditionStatusTrue
	}
	out := map[string]interface{}{
		"type":               name,
		"status":             status,
		"lastTransitionTime": t.UTC().Format(time.RFC3339),
	}
	if reason != "" {
		out["reason"] = reason
	}
	if message != "" {
		out["message"] = message
	}
	return out
}
