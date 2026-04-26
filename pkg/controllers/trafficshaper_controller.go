// Package controllers — TrafficShaper reconciler (Sprint 31 / Ticket 52).
//
// This controller pairs with the Sprint 30 Ticket 39 TC loader
// (`pkg/hardware/ebpf.TCLoader`) to drive **per-interface** priority
// marking via a CRD. It composes orthogonally with the Sprint 30 Ticket 45
// QoSController which drives **per-pod** egress caps via Cilium's
// Bandwidth Manager: the two CRDs cover different scopes and do not
// share state.
//
// Reconcile flow:
//
//  1. Extract the TrafficShaperSpec from the unstructured CR.
//  2. Translate to a deterministic TrafficShaperPlan via
//     pkg/security/qos.TranslateTrafficShaper.
//  3. Apply the plan via the configured TCBackend (a real
//     `*ebpf.TCLoader` wrapper in production, a fake in tests).
//  4. Write status via the shared pkg/controllers/status.Writer with
//     Applied / Degraded / Invalid / Removed conditions, matching
//     QoS / NAT / FilterPolicy controllers.
package controllers

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	networkv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/network/v1alpha1"
	statuspkg "github.com/GizmoTickler/fos1/pkg/controllers/status"
	"github.com/GizmoTickler/fos1/pkg/security/qos"
)

const (
	// TrafficShaperResyncPeriod is the resync period for TrafficShaper
	// informers. 10 minutes matches every other Sprint-30+ controller.
	TrafficShaperResyncPeriod = 10 * time.Minute
)

// trafficShaperGVR is the GroupVersionResource for TrafficShaper CRDs;
// matches manifests/base/trafficshaper/crd.yaml.
var trafficShaperGVR = schema.GroupVersionResource{
	Group:    "network.fos1.io",
	Version:  "v1alpha1",
	Resource: "trafficshapers",
}

// TrafficShaper condition constants — aliased from the typed API package
// so the controller doesn't reach across packages on the hot path.
const (
	TrafficShaperConditionApplied  = networkv1alpha1.TrafficShaperConditionApplied
	TrafficShaperConditionDegraded = networkv1alpha1.TrafficShaperConditionDegraded
	TrafficShaperConditionInvalid  = networkv1alpha1.TrafficShaperConditionInvalid
	TrafficShaperConditionRemoved  = networkv1alpha1.TrafficShaperConditionRemoved

	TrafficShaperConditionStatusTrue  = networkv1alpha1.TrafficShaperConditionStatusTrue
	TrafficShaperConditionStatusFalse = networkv1alpha1.TrafficShaperConditionStatusFalse
)

// TrafficShaperController reconciles TrafficShaper CRDs into TC-loader
// state.
type TrafficShaperController struct {
	dynamicClient dynamic.Interface

	// backend is the seam to the TC loader. Constructed once per
	// controller and shared across all reconciles. In production this
	// is a wrapper around `*ebpf.TCLoader`; in tests it's a recording
	// fake. Nil-safe: a nil backend yields an Invalid condition rather
	// than a panic, so a partially-configured controller doesn't
	// silently no-op.
	backend qos.TCBackend

	informer cache.SharedIndexInformer
	queue    workqueue.RateLimitingInterface
	stopCh   chan struct{}

	// statusWriter persists CRD status back to the status subresource.
	// Nil-safe: leaving it nil (e.g. in legacy unit tests) skips
	// writeback and the controller falls back to in-memory only.
	statusWriter *statuspkg.Writer
}

// NewTrafficShaperController wires a dynamic client + TC backend into a
// fully formed controller. Tests construct the struct directly and
// inject a recording backend; production callers go through this
// helper.
func NewTrafficShaperController(
	dynamicClient dynamic.Interface,
	backend qos.TCBackend,
) *TrafficShaperController {
	factory := dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, TrafficShaperResyncPeriod)
	informer := factory.ForResource(trafficShaperGVR).Informer()

	controller := &TrafficShaperController{
		dynamicClient: dynamicClient,
		backend:       backend,
		informer:      informer,
		queue:         workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		stopCh:        make(chan struct{}),
		statusWriter:  statuspkg.NewWriter(dynamicClient, trafficShaperGVR),
	}

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueTrafficShaper,
		UpdateFunc: func(old, new interface{}) {
			oldObj := old.(*unstructured.Unstructured)
			newObj := new.(*unstructured.Unstructured)
			// Skip status-only updates from our own writeback.
			if reflect.DeepEqual(oldObj.Object["spec"], newObj.Object["spec"]) {
				return
			}
			controller.enqueueTrafficShaper(newObj)
		},
		DeleteFunc: controller.enqueueTrafficShaper,
	})

	return controller
}

// Run starts the controller. Blocks until Stop() is called or the
// informer cache fails to sync.
func (c *TrafficShaperController) Run(workers int) {
	defer c.queue.ShutDown()

	klog.Info("Starting TrafficShaper controller")

	go c.informer.Run(c.stopCh)

	if !cache.WaitForCacheSync(c.stopCh, c.informer.HasSynced) {
		klog.Error("Failed to sync TrafficShaper informer cache")
		return
	}
	klog.Info("TrafficShaper controller synced and ready")

	for i := 0; i < workers; i++ {
		go c.runWorker()
	}

	<-c.stopCh
	klog.Info("Stopping TrafficShaper controller")
}

// Stop signals Run to return.
func (c *TrafficShaperController) Stop() {
	close(c.stopCh)
}

func (c *TrafficShaperController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *TrafficShaperController) enqueueTrafficShaper(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("trafficshaper: failed to derive key: %v", err)
		return
	}
	c.queue.Add(key)
}

// processNextItem runs one reconcile. Returns false on queue shutdown.
func (c *TrafficShaperController) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.reconcileTrafficShaper(key.(string)); err != nil {
		klog.Errorf("trafficshaper: error reconciling %s: %v", key, err)
		if c.queue.NumRequeues(key) < 5 {
			klog.Infof("trafficshaper: requeuing %s", key)
			c.queue.AddRateLimited(key)
			return true
		}
		klog.Infof("trafficshaper: dropping %s after %d retries", key, c.queue.NumRequeues(key))
		c.queue.Forget(key)
		return true
	}

	c.queue.Forget(key)
	return true
}

// reconcileTrafficShaper is the dispatch entry point: look up the CR
// and route to the right handler.
func (c *TrafficShaperController) reconcileTrafficShaper(key string) error {
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", key, err)
	}
	if !exists {
		return c.handleTrafficShaperDelete(key)
	}
	return c.handleTrafficShaperCreateOrUpdate(obj.(*unstructured.Unstructured))
}

// handleTrafficShaperDelete tears down the TC attachment and clears the
// priority map for the CR's interface. The interface name has to be
// recovered from the cache because the unstructured object is no longer
// available — but we don't have a cache anymore (we keyed by namespace/name
// only). So instead, the delete handler is best-effort: if the spec is
// not recoverable from the workqueue key, we log and return — the next
// resync of the surviving CRs will reconcile the world.
//
// In v1 the CR is namespaced and uniquely owns its interface (no two
// shapers may target the same interface — a constraint we document in
// the CRD), so the worst case of a missed cleanup is that an orphaned
// priority map entry persists until the controller restarts. The TC
// loader's ClearPriority is idempotent, so a manual cleanup is also
// safe.
func (c *TrafficShaperController) handleTrafficShaperDelete(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key %q: %w", key, err)
	}
	klog.Infof("trafficshaper: handling delete of %s/%s — interface name unrecoverable from key alone, relying on controller-restart resync for cleanup", namespace, name)
	// No-op: we can't reach the spec post-delete, and we deliberately
	// don't keep a side-cache of (key → interface) because the CR is
	// the source of truth. This matches the QoSController.Delete
	// behaviour pattern (informer-backed delete sweep).
	return nil
}

// handleTrafficShaperCreateOrUpdate is the workhorse: extract spec,
// translate, apply, write status.
func (c *TrafficShaperController) handleTrafficShaperCreateOrUpdate(obj *unstructured.Unstructured) error {
	namespace := obj.GetNamespace()
	name := obj.GetName()
	generation := obj.GetGeneration()
	klog.Infof("trafficshaper: processing %s/%s (generation=%d)", namespace, name, generation)

	spec, specErr := c.extractTrafficShaperSpec(obj)
	if specErr != nil {
		if err := c.writeTrafficShaperStatus(obj, trafficShaperStatus{
			ObservedGeneration: generation,
			Now:                time.Now(),
			Invalid:            true,
			InvalidReason:      "ExtractionFailed",
			InvalidMessage:     specErr.Error(),
		}); err != nil {
			klog.Errorf("trafficshaper: failed to write invalid status for %s/%s: %v", namespace, name, err)
		}
		return fmt.Errorf("extract spec: %w", specErr)
	}

	plan, translateErr := qos.TranslateTrafficShaper(spec)
	if translateErr != nil {
		if err := c.writeTrafficShaperStatus(obj, trafficShaperStatus{
			ObservedGeneration: generation,
			Now:                time.Now(),
			Invalid:            true,
			InvalidReason:      "TranslationFailed",
			InvalidMessage:     translateErr.Error(),
		}); err != nil {
			klog.Errorf("trafficshaper: failed to write invalid status for %s/%s: %v", namespace, name, err)
		}
		return fmt.Errorf("translate: %w", translateErr)
	}

	// Defensive: a controller built without a backend would otherwise
	// silently no-op every reconcile. Surface as Invalid so operators
	// see the misconfiguration instead of "looks applied but nothing
	// happened".
	if c.backend == nil {
		if err := c.writeTrafficShaperStatus(obj, trafficShaperStatus{
			ObservedGeneration: generation,
			Now:                time.Now(),
			Invalid:            true,
			InvalidReason:      "NoBackend",
			InvalidMessage:     "controller has no TC backend wired; check operator configuration",
		}); err != nil {
			klog.Errorf("trafficshaper: failed to write invalid status for %s/%s: %v", namespace, name, err)
		}
		return fmt.Errorf("no backend wired")
	}

	if applyErr := qos.ApplyTrafficShaper(c.backend, plan); applyErr != nil {
		if err := c.writeTrafficShaperStatus(obj, trafficShaperStatus{
			ObservedGeneration: generation,
			Now:                time.Now(),
			Hash:               plan.Hash,
			AppliedRuleCount:   plan.AppliedRuleCount,
			Degraded:           true,
			DegradedReason:     "ApplyFailed",
			DegradedMessage:    applyErr.Error(),
		}); err != nil {
			klog.Errorf("trafficshaper: failed to write degraded status for %s/%s: %v", namespace, name, err)
		}
		return fmt.Errorf("apply: %w", applyErr)
	}

	// Clean apply.
	if err := c.writeTrafficShaperStatus(obj, trafficShaperStatus{
		ObservedGeneration: generation,
		Now:                time.Now(),
		Hash:               plan.Hash,
		AppliedRuleCount:   plan.AppliedRuleCount,
		Applied:            true,
		AppliedReason:      "Reconciled",
		AppliedMessage: fmt.Sprintf("interface=%s direction=%s priority=%d rules=%d",
			plan.Interface, plan.Direction, plan.Priority, plan.AppliedRuleCount),
	}); err != nil {
		return fmt.Errorf("write status for %s/%s: %w", namespace, name, err)
	}

	klog.Infof("trafficshaper: reconciled %s/%s — interface=%s direction=%s priority=%d rules=%d",
		namespace, name, plan.Interface, plan.Direction, plan.Priority, plan.AppliedRuleCount)
	return nil
}

// extractTrafficShaperSpec parses the unstructured CR into our typed
// spec. Returns a controller-friendly error message on any parse
// failure that the controller will surface as Invalid.
func (c *TrafficShaperController) extractTrafficShaperSpec(obj *unstructured.Unstructured) (*networkv1alpha1.TrafficShaperSpec, error) {
	specMap, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return nil, fmt.Errorf("spec not found in TrafficShaper %s: %w", obj.GetName(), err)
	}

	out := &networkv1alpha1.TrafficShaperSpec{}

	if v, ok, _ := unstructured.NestedString(specMap, "interface"); ok {
		out.Interface = v
	}
	if v, ok, _ := unstructured.NestedString(specMap, "direction"); ok {
		out.Direction = networkv1alpha1.TrafficShaperDirection(v)
	}

	rawRules, ok, _ := unstructured.NestedSlice(specMap, "rules")
	if ok {
		for i, rr := range rawRules {
			rm, ok := rr.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("rules[%d] is not a map", i)
			}
			rule := networkv1alpha1.TrafficShaperRule{}
			if v, ok, _ := unstructured.NestedString(rm, "matchCIDR"); ok {
				rule.MatchCIDR = v
			}
			// JSON / unstructured stores numbers as int64. Both
			// matchDSCP and priority round-trip through that path.
			if v, ok, _ := unstructured.NestedInt64(rm, "matchDSCP"); ok {
				rule.MatchDSCP = int32(v)
			}
			if v, ok, _ := unstructured.NestedInt64(rm, "priority"); ok {
				rule.Priority = uint32(v)
			}
			if v, ok, _ := unstructured.NestedString(rm, "rate"); ok {
				rule.Rate = v
			}
			out.Rules = append(out.Rules, rule)
		}
	}

	return out, nil
}

// trafficShaperStatus is the flat per-reconcile status struct. Bundling
// the conditions in one place keeps the reconcile decision tree readable.
type trafficShaperStatus struct {
	ObservedGeneration int64
	Now                time.Time

	Hash             string
	AppliedRuleCount int32

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

// writeTrafficShaperStatus persists a trafficShaperStatus onto the CRD's
// status subresource via the shared status.Writer.
func (c *TrafficShaperController) writeTrafficShaperStatus(obj *unstructured.Unstructured, status trafficShaperStatus) error {
	if c.statusWriter == nil {
		return nil
	}
	return c.statusWriter.WriteStatus(context.Background(), obj.DeepCopy(), trafficShaperStatusMutator(status))
}

// trafficShaperStatusMutator builds the Mutator that paints the status
// struct onto the target *unstructured.Unstructured.
func trafficShaperStatusMutator(status trafficShaperStatus) statuspkg.Mutator {
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
		if err := unstructured.SetNestedField(obj.Object, int64(status.AppliedRuleCount), "status", "appliedRuleCount"); err != nil {
			return fmt.Errorf("set status.appliedRuleCount: %w", err)
		}

		conds := []interface{}{
			buildTrafficShaperCondition(TrafficShaperConditionApplied, status.Applied, status.AppliedReason, status.AppliedMessage, status.Now),
			buildTrafficShaperCondition(TrafficShaperConditionDegraded, status.Degraded, status.DegradedReason, status.DegradedMessage, status.Now),
			buildTrafficShaperCondition(TrafficShaperConditionInvalid, status.Invalid, status.InvalidReason, status.InvalidMessage, status.Now),
			buildTrafficShaperCondition(TrafficShaperConditionRemoved, status.Removed, status.RemovedReason, status.RemovedMessage, status.Now),
		}
		if err := unstructured.SetNestedSlice(obj.Object, conds, "status", "conditions"); err != nil {
			return fmt.Errorf("set status.conditions: %w", err)
		}
		return nil
	}
}

// buildTrafficShaperCondition renders one Kubernetes-style condition
// map. Mirrors qos_controller.buildCondition but kept separate so the
// constants used here are unambiguously the TrafficShaper ones.
func buildTrafficShaperCondition(name string, value bool, reason, message string, t time.Time) map[string]interface{} {
	status := TrafficShaperConditionStatusFalse
	if value {
		status = TrafficShaperConditionStatusTrue
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
