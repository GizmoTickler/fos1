package policy

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	statuspkg "github.com/GizmoTickler/fos1/pkg/controllers/status"
	"github.com/GizmoTickler/fos1/pkg/security/dpi"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// filterPolicyGVR is the GroupVersionResource for the FilterPolicy CRD;
// matches manifests/base/security/filter-policy-crds.yaml:6.
var filterPolicyGVR = schema.GroupVersionResource{
	Group:    "security.fos1.io",
	Version:  "v1alpha1",
	Resource: "filterpolicies",
}

// policyTranslator abstracts FilterPolicy → CiliumPolicy translation so the
// controller can be unit-tested with a deliberately failing translator
// (exercises the Invalid condition branch).
type policyTranslator interface {
	TranslatePolicy(policy *FilterPolicy, zones map[string]*FilterZone) ([]*cilium.CiliumPolicy, error)
}

// PolicyController manages the lifecycle of filtering policies.
type PolicyController struct {
	// Kubernetes clients
	kubeClient    kubernetes.Interface
	ciliumClient  cilium.CiliumClient
	dynamicClient dynamic.Interface

	// Core components
	resolver   *PolicyResolver
	translator policyTranslator
	monitor    *PolicyMonitor
	logger     *PolicyLogger

	// Integration components
	dpiManager *dpi.DPIManager

	// statusWriter persists FilterPolicy.Status back to the CRD status
	// subresource after each reconcile that mutates it. Wired when the
	// controller is constructed with a non-nil dynamic client; otherwise
	// status writes are best-effort to the in-memory cache only (the
	// pre-Sprint-30 contract, kept so the existing unit tests — which do
	// not seed a dynamic client — continue to pass unmodified).
	statusWriter *statuspkg.Writer

	// Internal state
	policies        map[string]*FilterPolicy
	policyGroups    map[string]*FilterPolicyGroup
	zones           map[string]*FilterZone
	informers       map[string]cache.SharedIndexInformer
	appliedPolicies map[string][]string

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	mutex  sync.RWMutex
	config *ControllerConfig
}

// ControllerConfig contains configuration for the policy controller.
type ControllerConfig struct {
	ResyncPeriod           time.Duration
	ConflictAlertThreshold int
	EnableDetailedLogging  bool
	DefaultPolicies        []string
	DefaultPriority        int
	Informers              *ControllerInformers

	// DynamicClient, when non-nil, enables FilterPolicy.Status writeback to
	// the CRD status subresource via the shared pkg/controllers/status.Writer
	// (Sprint 30 / Ticket 40). Leave nil in tests or environments where the
	// dynamic client is not available; reconciled status will still be
	// recorded on the in-memory cache but will not survive controller
	// restart.
	DynamicClient dynamic.Interface
}

// ControllerInformers holds explicit informer wiring for policy resources.
type ControllerInformers struct {
	Policies     cache.SharedIndexInformer
	PolicyGroups cache.SharedIndexInformer
	Zones        cache.SharedIndexInformer
}

// NewPolicyController creates a new policy controller.
func NewPolicyController(
	kubeClient kubernetes.Interface,
	ciliumClient cilium.CiliumClient,
	dpiManager *dpi.DPIManager,
	config *ControllerConfig,
) (*PolicyController, error) {
	if kubeClient == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}

	if ciliumClient == nil {
		return nil, fmt.Errorf("cilium client is required")
	}

	if config == nil {
		config = &ControllerConfig{
			ResyncPeriod:           30 * time.Minute,
			ConflictAlertThreshold: 50,
			EnableDetailedLogging:  true,
			DefaultPriority:        100,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := NewPolicyLogger(config.EnableDetailedLogging)

	controller := &PolicyController{
		kubeClient:      kubeClient,
		ciliumClient:    ciliumClient,
		dynamicClient:   config.DynamicClient,
		dpiManager:      dpiManager,
		resolver:        NewPolicyResolver(logger),
		translator:      NewCiliumPolicyTranslator(ciliumClient, logger),
		monitor:         NewPolicyMonitor(logger),
		logger:          logger,
		policies:        make(map[string]*FilterPolicy),
		policyGroups:    make(map[string]*FilterPolicyGroup),
		zones:           make(map[string]*FilterZone),
		informers:       make(map[string]cache.SharedIndexInformer),
		appliedPolicies: make(map[string][]string),
		ctx:             ctx,
		cancel:          cancel,
		config:          config,
	}
	if config.DynamicClient != nil {
		controller.statusWriter = statuspkg.NewWriter(config.DynamicClient, filterPolicyGVR)
	}
	return controller, nil
}

// Start starts the policy controller.
func (c *PolicyController) Start() error {
	log.Println("Starting policy controller")

	if err := c.setupInformers(); err != nil {
		return fmt.Errorf("failed to setup informers: %w", err)
	}

	for name, informer := range c.informers {
		if informer == nil {
			continue
		}
		log.Printf("Starting informer: %s", name)
		go informer.Run(c.ctx.Done())
	}

	if len(c.informers) == 0 {
		log.Printf("No policy informers configured; controller startup does not enable active reconciliation")
	}

	if len(c.config.DefaultPolicies) > 0 {
		log.Printf("Applying %d default policies", len(c.config.DefaultPolicies))
		for _, policyName := range c.config.DefaultPolicies {
			log.Printf("Would apply default policy: %s", policyName)
		}
	}

	c.monitor.Start(c.ctx)

	log.Println("Policy controller started successfully")
	return nil
}

// Stop stops the policy controller.
func (c *PolicyController) Stop() {
	log.Println("Stopping policy controller")
	c.cancel()
	log.Println("Policy controller stopped")
}

// setupInformers wires only explicitly provided informers.
func (c *PolicyController) setupInformers() error {
	for name := range c.informers {
		delete(c.informers, name)
	}
	if c.config.Informers == nil {
		return nil
	}

	c.registerInformer("policies", c.config.Informers.Policies, c.handlePolicyAdd, c.handlePolicyUpdate, c.handlePolicyDelete)
	c.registerInformer("policyGroups", c.config.Informers.PolicyGroups, c.handlePolicyGroupAdd, c.handlePolicyGroupUpdate, c.handlePolicyGroupDelete)
	c.registerInformer("zones", c.config.Informers.Zones, c.handleZoneAdd, c.handleZoneUpdate, c.handleZoneDelete)
	return nil
}

func (c *PolicyController) registerInformer(
	name string,
	informer cache.SharedIndexInformer,
	addFunc, updateFunc, deleteFunc func(obj interface{}),
) {
	if informer == nil {
		return
	}

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    addFunc,
		UpdateFunc: func(_, newObj interface{}) { updateFunc(newObj) },
		DeleteFunc: deleteFunc,
	})
	c.informers[name] = informer
}

// handlePolicyAdd handles the addition of a new FilterPolicy.
func (c *PolicyController) handlePolicyAdd(obj interface{}) {
	policy, ok := obj.(*FilterPolicy)
	if !ok {
		log.Printf("Error: Expected FilterPolicy, got %T", obj)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	key := policyKey(policy)
	log.Printf("Adding policy: %s", key)
	c.policies[key] = policy
	c.processPolicy(policy)
}

// handlePolicyUpdate handles updates to an existing FilterPolicy.
func (c *PolicyController) handlePolicyUpdate(obj interface{}) {
	policy, ok := obj.(*FilterPolicy)
	if !ok {
		log.Printf("Error: Expected FilterPolicy, got %T", obj)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	key := policyKey(policy)
	log.Printf("Updating policy: %s", key)
	c.policies[key] = policy
	c.processPolicy(policy)
}

// handlePolicyDelete handles the deletion of a FilterPolicy.
func (c *PolicyController) handlePolicyDelete(obj interface{}) {
	policy, ok := obj.(*FilterPolicy)
	if !ok {
		log.Printf("Error: Expected FilterPolicy, got %T", obj)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	key := policyKey(policy)
	log.Printf("Deleting policy: %s", key)
	delete(c.policies, key)
	if err := c.removePolicy(policy); err != nil {
		log.Printf("Error removing policy %s: %v", key, err)
	}
}

// handlePolicyGroupAdd handles the addition of a new FilterPolicyGroup.
func (c *PolicyController) handlePolicyGroupAdd(obj interface{}) {
	group, ok := obj.(*FilterPolicyGroup)
	if !ok {
		log.Printf("Error: Expected FilterPolicyGroup, got %T", obj)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	name := policyGroupName(group)
	log.Printf("Adding policy group: %s", name)
	c.policyGroups[name] = group
	c.processPolicyGroup(group)
}

// handlePolicyGroupUpdate handles updates to an existing FilterPolicyGroup.
func (c *PolicyController) handlePolicyGroupUpdate(obj interface{}) {
	group, ok := obj.(*FilterPolicyGroup)
	if !ok {
		log.Printf("Error: Expected FilterPolicyGroup, got %T", obj)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	name := policyGroupName(group)
	log.Printf("Updating policy group: %s", name)
	c.policyGroups[name] = group
	c.processPolicyGroup(group)
}

// handlePolicyGroupDelete handles the deletion of a FilterPolicyGroup.
func (c *PolicyController) handlePolicyGroupDelete(obj interface{}) {
	group, ok := obj.(*FilterPolicyGroup)
	if !ok {
		log.Printf("Error: Expected FilterPolicyGroup, got %T", obj)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	name := policyGroupName(group)
	log.Printf("Deleting policy group: %s", name)
	delete(c.policyGroups, name)

	for _, policyName := range group.Spec.Policies {
		if policy, exists := c.lookupPolicy(policyName); exists {
			c.processPolicy(policy)
		}
	}
}

// handleZoneAdd handles the addition of a new FilterZone.
func (c *PolicyController) handleZoneAdd(obj interface{}) {
	zone, ok := obj.(*FilterZone)
	if !ok {
		log.Printf("Error: Expected FilterZone, got %T", obj)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	name := zoneName(zone)
	log.Printf("Adding zone: %s", name)
	c.zones[name] = zone
	c.processZone(zone)
}

// handleZoneUpdate handles updates to an existing FilterZone.
func (c *PolicyController) handleZoneUpdate(obj interface{}) {
	zone, ok := obj.(*FilterZone)
	if !ok {
		log.Printf("Error: Expected FilterZone, got %T", obj)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	name := zoneName(zone)
	log.Printf("Updating zone: %s", name)
	c.zones[name] = zone
	c.processZone(zone)
}

// handleZoneDelete handles the deletion of a FilterZone.
func (c *PolicyController) handleZoneDelete(obj interface{}) {
	zone, ok := obj.(*FilterZone)
	if !ok {
		log.Printf("Error: Expected FilterZone, got %T", obj)
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	name := zoneName(zone)
	log.Printf("Deleting zone: %s", name)
	delete(c.zones, name)

	for _, policy := range c.policies {
		if policyReferencesZone(policy, name) {
			c.processPolicy(policy)
		}
	}
}

// processPolicy reconciles a single FilterPolicy. The reconcile shape
// mirrors the NAT controller (pkg/controllers/nat_controller.go) to keep
// status semantics consistent across Cilium-backed controllers:
//
//  1. Disabled policies → tear down any applied Cilium policies and record
//     Applied=False, Removed=True with reason=Disabled.
//  2. Enabled policies → translate, then compare spec hash vs.
//     Status.LastAppliedHash. If unchanged, no-op and record Applied=True.
//  3. Spec changed → apply each translator output via the Cilium client;
//     on full success record Applied=True, on partial failure record
//     Degraded=True with the partial CiliumPolicies set.
//  4. Translator returns an error → record Invalid=True; no retry is
//     attempted until the spec changes.
func (c *PolicyController) processPolicy(policy *FilterPolicy) {
	now := time.Now()
	key := policyKey(policy)

	// Persist whatever status we land on at the end of the reconcile. A
	// defer on the shared helper means every return branch — disabled,
	// unchanged, applied, degraded, invalid — gets its final status
	// written to the CRD status subresource without each branch having
	// to remember to call persistStatus explicitly.
	defer c.persistStatus(policy)

	if !policyEnabled(policy) {
		log.Printf("Policy %s is disabled, removing applied state", key)
		if err := c.removePolicy(policy); err != nil {
			log.Printf("Error removing disabled policy %s: %v", key, err)
			return
		}
		return
	}

	for _, group := range c.policyGroups {
		for _, groupPolicyName := range group.Spec.Policies {
			if groupPolicyName == key || groupPolicyName == policyObjectName(policy) {
				policy = c.applyGroupOverrides(policy, group)
				break
			}
		}
	}

	resolvedPolicy, err := c.resolver.ResolvePolicy(policy, c.policies)
	if err != nil {
		markInvalid(policy, "ResolveFailed", err.Error(), now)
		log.Printf("Error resolving policy %s: %v", key, err)
		return
	}

	ciliumPolicies, err := c.translator.TranslatePolicy(resolvedPolicy, c.zones)
	if err != nil {
		markInvalid(policy, "TranslationFailed", err.Error(), now)
		log.Printf("Error translating policy %s: %v", key, err)
		return
	}

	// Idempotency: skip re-apply when the spec hash matches the last
	// successfully applied hash and we already have the Cilium policies
	// tracked in the controller cache. Matches the NAT controller's
	// SpecHash() shortcut at pkg/controllers/nat_controller.go:82.
	newHash := specHash(resolvedPolicy.Spec)
	if policy.Status.LastAppliedHash == newHash && len(c.appliedPolicies[key]) > 0 {
		policy.Status.Applied = true
		policy.Status.Error = ""
		policy.Status.CiliumPolicies = append([]string(nil), c.appliedPolicies[key]...)
		policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
			Type:               ConditionApplied,
			Status:             ConditionStatusTrue,
			LastTransitionTime: now,
			Reason:             "Unchanged",
			Message:            "spec hash matches last applied state; no Cilium call issued",
		})
		log.Printf("Policy %s unchanged (hash=%s); skipped re-apply", key, newHash)
		return
	}

	applyErr := c.applyTranslatedPolicies(resolvedPolicy, ciliumPolicies)
	applied := append([]string(nil), c.appliedPolicies[key]...)

	if applyErr != nil {
		policy.Status.Applied = len(applied) > 0
		policy.Status.Error = applyErr.Error()
		policy.Status.CiliumPolicies = applied
		policy.Status.LastAppliedHash = "" // force full re-apply next reconcile
		policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
			Type:               ConditionDegraded,
			Status:             ConditionStatusTrue,
			LastTransitionTime: now,
			Reason:             "CiliumApplyFailed",
			Message:            applyErr.Error(),
		})
		policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
			Type:               ConditionApplied,
			Status:             ConditionStatusFalse,
			LastTransitionTime: now,
			Reason:             "CiliumApplyFailed",
			Message:            "at least one translated policy failed to apply",
		})
		log.Printf("Error applying Cilium policy for %s: %v", key, applyErr)
		return
	}

	policy.Status.Applied = len(applied) > 0
	policy.Status.LastApplied = now
	policy.Status.LastAppliedHash = newHash
	policy.Status.Error = ""
	policy.Status.CiliumPolicies = applied
	policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
		Type:               ConditionApplied,
		Status:             ConditionStatusTrue,
		LastTransitionTime: now,
		Reason:             "Reconciled",
		Message:            fmt.Sprintf("%d Cilium policy(ies) applied", len(applied)),
	})
	policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
		Type:               ConditionDegraded,
		Status:             ConditionStatusFalse,
		LastTransitionTime: now,
		Reason:             "Reconciled",
	})
	policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
		Type:               ConditionInvalid,
		Status:             ConditionStatusFalse,
		LastTransitionTime: now,
		Reason:             "Reconciled",
	})
	policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
		Type:               ConditionRemoved,
		Status:             ConditionStatusFalse,
		LastTransitionTime: now,
		Reason:             "Reconciled",
	})

	log.Printf("Successfully processed policy: %s (hash=%s, cilium-policies=%d)", key, newHash, len(applied))
}

// persistStatus writes policy.Status back to the FilterPolicy CRD status
// subresource using the shared status.Writer. Nil-safe: when the controller
// is constructed without a dynamic client (e.g. in existing unit tests)
// the call is a no-op and the in-memory cache remains the only source of
// truth.
//
// Failures are logged but not propagated — the reconcile contract is that
// the in-memory cache reflects the latest decision; a transient API-server
// hiccup should not re-enqueue the policy and risk an apply-storm.
func (c *PolicyController) persistStatus(policy *FilterPolicy) {
	if c.statusWriter == nil || policy == nil {
		return
	}
	obj := filterPolicyToUnstructured(policy)
	if obj == nil {
		return
	}
	mutate := buildFilterPolicyStatusMutator(policy.Status)
	if err := c.statusWriter.WriteStatus(c.ctx, obj, mutate); err != nil {
		log.Printf("persist FilterPolicy status %s: %v", policyKey(policy), err)
	}
}

// filterPolicyToUnstructured builds the minimal *unstructured.Unstructured
// identity needed by status.Writer — only namespace, name, apiVersion, and
// kind must be populated for the Writer's first UpdateStatus attempt. On a
// conflict-driven retry the Writer will re-fetch the full object from the
// API server, which is when the full spec becomes authoritative.
//
// Returns nil when the policy has no name (nothing to write against).
func filterPolicyToUnstructured(policy *FilterPolicy) *unstructured.Unstructured {
	name := policyObjectName(policy)
	if name == "" {
		return nil
	}
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.fos1.io/v1alpha1",
			"kind":       "FilterPolicy",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": policy.ObjectMeta.Namespace,
			},
		},
	}
}

// buildFilterPolicyStatusMutator returns a status.Mutator that writes the
// current FilterPolicyStatus snapshot onto the target unstructured object.
// The mutator captures the status values by value so a retry after conflict
// applies the same logical status — re-running processPolicy inside the
// retry loop would violate status.Writer's idempotency contract.
func buildFilterPolicyStatusMutator(statusSnapshot FilterPolicyStatus) statuspkg.Mutator {
	return func(obj *unstructured.Unstructured) error {
		if err := unstructured.SetNestedField(obj.Object, statusSnapshot.Applied, "status", "applied"); err != nil {
			return fmt.Errorf("set status.applied: %w", err)
		}
		if statusSnapshot.LastAppliedHash != "" {
			if err := unstructured.SetNestedField(obj.Object, statusSnapshot.LastAppliedHash, "status", "lastAppliedHash"); err != nil {
				return fmt.Errorf("set status.lastAppliedHash: %w", err)
			}
		}
		if !statusSnapshot.LastApplied.IsZero() {
			if err := unstructured.SetNestedField(obj.Object, statusSnapshot.LastApplied.UTC().Format(time.RFC3339), "status", "lastApplied"); err != nil {
				return fmt.Errorf("set status.lastApplied: %w", err)
			}
		}
		if statusSnapshot.Error != "" {
			if err := unstructured.SetNestedField(obj.Object, statusSnapshot.Error, "status", "error"); err != nil {
				return fmt.Errorf("set status.error: %w", err)
			}
		}

		// ciliumPolicies is a []string; convert to []interface{} for the
		// unstructured helpers.
		if len(statusSnapshot.CiliumPolicies) > 0 {
			cps := make([]interface{}, len(statusSnapshot.CiliumPolicies))
			for i, n := range statusSnapshot.CiliumPolicies {
				cps[i] = n
			}
			if err := unstructured.SetNestedSlice(obj.Object, cps, "status", "ciliumPolicies"); err != nil {
				return fmt.Errorf("set status.ciliumPolicies: %w", err)
			}
		}

		// Conditions: serialise each PolicyCondition into a map with the
		// timestamp rendered as RFC3339 so the CRD sees a stable
		// representation.
		if len(statusSnapshot.Conditions) > 0 {
			conds := make([]interface{}, 0, len(statusSnapshot.Conditions))
			for _, cond := range statusSnapshot.Conditions {
				cm := map[string]interface{}{
					"type":               cond.Type,
					"status":             cond.Status,
					"lastTransitionTime": cond.LastTransitionTime.UTC().Format(time.RFC3339),
				}
				if cond.Reason != "" {
					cm["reason"] = cond.Reason
				}
				if cond.Message != "" {
					cm["message"] = cond.Message
				}
				conds = append(conds, cm)
			}
			if err := unstructured.SetNestedSlice(obj.Object, conds, "status", "conditions"); err != nil {
				return fmt.Errorf("set status.conditions: %w", err)
			}
		}
		return nil
	}
}

// markInvalid records an Invalid=True condition with Applied=False. No apply
// call is made; the controller waits for a spec change before retrying.
func markInvalid(policy *FilterPolicy, reason, message string, now time.Time) {
	policy.Status.Applied = false
	policy.Status.Error = message
	policy.Status.LastAppliedHash = ""
	policy.Status.CiliumPolicies = nil
	policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
		Type:               ConditionInvalid,
		Status:             ConditionStatusTrue,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	})
	policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
		Type:               ConditionApplied,
		Status:             ConditionStatusFalse,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	})
}

// processPolicyGroup processes all policies in a group.
func (c *PolicyController) processPolicyGroup(group *FilterPolicyGroup) {
	name := policyGroupName(group)
	if !policyGroupEnabled(group) {
		log.Printf("Policy group %s is disabled, skipping", name)
		return
	}

	for _, policyName := range group.Spec.Policies {
		if policy, exists := c.lookupPolicy(policyName); exists {
			c.processPolicy(c.applyGroupOverrides(policy, group))
		} else {
			log.Printf("Warning: Policy %s referenced in group %s does not exist", policyName, name)
		}
	}

	log.Printf("Successfully processed policy group: %s", name)
}

// processZone processes a zone and its associated policies.
func (c *PolicyController) processZone(zone *FilterZone) {
	name := zoneName(zone)
	for _, policyName := range zonePolicyNames(zone) {
		if policy, exists := c.lookupPolicy(policyName); exists {
			c.processPolicy(policy)
		} else {
			log.Printf("Warning: Policy %s referenced in zone %s does not exist", policyName, name)
		}
	}

	c.createImplicitZonePolicies(zone)
	log.Printf("Successfully processed zone: %s", name)
}

// applyGroupOverrides applies policy group overrides to a policy.
func (c *PolicyController) applyGroupOverrides(policy *FilterPolicy, group *FilterPolicyGroup) *FilterPolicy {
	policyCopy := policy.DeepCopy()

	for _, override := range group.Spec.Overrides {
		if override.PolicyName == policyKey(policy) || override.PolicyName == policyObjectName(policy) {
			if override.Enabled != nil {
				policyCopy.Enabled = *override.Enabled
				policyCopy.Spec.Enabled = *override.Enabled
			}

			if override.Priority != nil {
				policyCopy.Priority = *override.Priority
				policyCopy.Spec.Priority = *override.Priority
			}

			log.Printf("Applied overrides from group %s to policy %s", policyGroupName(group), policyKey(policy))
			break
		}
	}

	return policyCopy
}

// applyTranslatedPolicies removes any previously applied Cilium policies
// for this FilterPolicy, then attempts to apply each translated policy in
// order. On partial failure the successfully applied policies are retained
// in the controller cache and the caller records a Degraded condition —
// this matches the NAT controller's partial-success contract rather than
// all-or-nothing rollback.
func (c *PolicyController) applyTranslatedPolicies(policy *FilterPolicy, translated []*cilium.CiliumPolicy) error {
	key := policyKey(policy)
	if err := c.removeAppliedPolicies(key); err != nil {
		return err
	}

	applied := make([]string, 0, len(translated))
	var firstErr error
	for _, translatedPolicy := range translated {
		if translatedPolicy == nil {
			continue
		}
		if err := c.ciliumClient.ApplyNetworkPolicy(c.ctx, translatedPolicy); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("apply translated policy %q: %w", translatedPolicy.Name, err)
			}
			continue
		}
		applied = append(applied, translatedPolicy.Name)
	}

	if len(applied) == 0 {
		delete(c.appliedPolicies, key)
	} else {
		c.appliedPolicies[key] = applied
	}

	return firstErr
}

// removePolicy removes applied Cilium policies for the FilterPolicy and
// records Removed=True / Applied=False on status. Used by both delete and
// disable paths; the reason field distinguishes the two.
func (c *PolicyController) removePolicy(policy *FilterPolicy) error {
	now := time.Now()
	key := policyKey(policy)
	reason := "Removed"
	if policy != nil && !policy.Spec.Enabled {
		reason = "Disabled"
	}
	log.Printf("Removing Cilium policy for: %s (reason=%s)", key, reason)

	if err := c.removeAppliedPolicies(key); err != nil {
		policy.Status.Applied = false
		policy.Status.CiliumPolicies = nil
		policy.Status.Error = err.Error()
		policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
			Type:               ConditionDegraded,
			Status:             ConditionStatusTrue,
			LastTransitionTime: now,
			Reason:             "CiliumDeleteFailed",
			Message:            err.Error(),
		})
		return err
	}

	policy.Status.Applied = false
	policy.Status.CiliumPolicies = nil
	policy.Status.Error = ""
	policy.Status.LastAppliedHash = ""
	policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
		Type:               ConditionRemoved,
		Status:             ConditionStatusTrue,
		LastTransitionTime: now,
		Reason:             reason,
	})
	policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
		Type:               ConditionApplied,
		Status:             ConditionStatusFalse,
		LastTransitionTime: now,
		Reason:             reason,
	})
	policy.Status.Conditions = setCondition(policy.Status.Conditions, PolicyCondition{
		Type:               ConditionDegraded,
		Status:             ConditionStatusFalse,
		LastTransitionTime: now,
		Reason:             reason,
	})
	return nil
}

func (c *PolicyController) removeAppliedPolicies(key string) error {
	applied := c.appliedPolicies[key]
	if len(applied) == 0 {
		delete(c.appliedPolicies, key)
		return nil
	}

	var errs []string
	for _, appliedName := range applied {
		if err := c.ciliumClient.DeleteNetworkPolicy(c.ctx, appliedName); err != nil {
			errs = append(errs, err.Error())
		}
	}

	delete(c.appliedPolicies, key)
	if len(errs) > 0 {
		return fmt.Errorf("remove applied policies for %s: %s", key, strings.Join(errs, "; "))
	}
	return nil
}

// createImplicitZonePolicies creates implicit policies for zone communication.
func (c *PolicyController) createImplicitZonePolicies(zone *FilterZone) {
	name := zoneName(zone)
	log.Printf("Creating implicit zone policies for: %s", name)

	if zoneTrustLevel(zone) == "untrusted" && zoneDefaultIngressAction(zone) == "deny" {
		log.Printf("Would create default deny policy for untrusted zone: %s", name)
	}
}

// policyReferencesZone checks if a policy references a zone.
func policyReferencesZone(policy *FilterPolicy, zoneName string) bool {
	return false
}

// ListPolicies returns a list of all filtering policies.
func (c *PolicyController) ListPolicies() []*FilterPolicy {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	policies := make([]*FilterPolicy, 0, len(c.policies))
	for _, policy := range c.policies {
		policies = append(policies, policy)
	}

	return policies
}

// GetPolicy returns a specific filtering policy.
func (c *PolicyController) GetPolicy(name string) (*FilterPolicy, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	policy, exists := c.lookupPolicy(name)
	if !exists {
		return nil, fmt.Errorf("policy %s not found", name)
	}

	return policy, nil
}

// ListPolicyGroups returns a list of all policy groups.
func (c *PolicyController) ListPolicyGroups() []*FilterPolicyGroup {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	groups := make([]*FilterPolicyGroup, 0, len(c.policyGroups))
	for _, group := range c.policyGroups {
		groups = append(groups, group)
	}

	return groups
}

// ListZones returns a list of all filtering zones.
func (c *PolicyController) ListZones() []*FilterZone {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	zones := make([]*FilterZone, 0, len(c.zones))
	for _, zone := range c.zones {
		zones = append(zones, zone)
	}

	return zones
}

func policyEnabled(policy *FilterPolicy) bool {
	return policy != nil && policy.Spec.Enabled
}

func policyObjectName(policy *FilterPolicy) string {
	if policy == nil {
		return ""
	}
	if policy.Name != "" {
		return policy.Name
	}
	return policy.ObjectMeta.Name
}

func policyGroupName(group *FilterPolicyGroup) string {
	if group == nil {
		return ""
	}
	if group.Name != "" {
		return group.Name
	}
	return group.ObjectMeta.Name
}

func policyGroupEnabled(group *FilterPolicyGroup) bool {
	return group != nil && group.Spec.Enabled
}

func zoneName(zone *FilterZone) string {
	if zone == nil {
		return ""
	}
	if zone.Name != "" {
		return zone.Name
	}
	return zone.ObjectMeta.Name
}

func zonePolicyNames(zone *FilterZone) []string {
	if zone == nil {
		return nil
	}
	if len(zone.Spec.Policies) > 0 {
		return zone.Spec.Policies
	}
	return zone.Policies
}

func zoneTrustLevel(zone *FilterZone) string {
	if zone == nil {
		return ""
	}
	if zone.Spec.TrustLevel != "" {
		return zone.Spec.TrustLevel
	}
	return zone.TrustLevel
}

func zoneDefaultIngressAction(zone *FilterZone) string {
	if zone == nil {
		return ""
	}
	if zone.Spec.DefaultIngressAction != "" {
		return zone.Spec.DefaultIngressAction
	}
	return zone.DefaultIngressAction
}

func (c *PolicyController) lookupPolicy(name string) (*FilterPolicy, bool) {
	if policy, exists := c.policies[name]; exists {
		return policy, true
	}

	for _, policy := range c.policies {
		if policyObjectName(policy) == name {
			return policy, true
		}
	}

	return nil, false
}
