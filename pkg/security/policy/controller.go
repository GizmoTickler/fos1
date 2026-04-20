package policy

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/security/dpi"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// PolicyController manages the lifecycle of filtering policies.
type PolicyController struct {
	// Kubernetes clients
	kubeClient   kubernetes.Interface
	ciliumClient cilium.CiliumClient

	// Core components
	resolver   *PolicyResolver
	translator *CiliumPolicyTranslator
	monitor    *PolicyMonitor
	logger     *PolicyLogger

	// Integration components
	dpiManager *dpi.DPIManager

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

	return &PolicyController{
		kubeClient:      kubeClient,
		ciliumClient:    ciliumClient,
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
	}, nil
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

// processPolicy processes a single policy.
func (c *PolicyController) processPolicy(policy *FilterPolicy) {
	key := policyKey(policy)
	if !policyEnabled(policy) {
		log.Printf("Policy %s is disabled, removing applied state", key)
		if err := c.removePolicy(policy); err != nil {
			log.Printf("Error removing disabled policy %s: %v", key, err)
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
		policy.Status.Applied = false
		policy.Status.Error = err.Error()
		log.Printf("Error resolving policy %s: %v", key, err)
		return
	}

	ciliumPolicies, err := c.translator.TranslatePolicy(resolvedPolicy, c.zones)
	if err != nil {
		policy.Status.Applied = false
		policy.Status.Error = err.Error()
		log.Printf("Error translating policy %s: %v", key, err)
		return
	}

	if err := c.applyTranslatedPolicies(resolvedPolicy, ciliumPolicies); err != nil {
		policy.Status.Applied = false
		policy.Status.Error = err.Error()
		log.Printf("Error applying Cilium policy for %s: %v", key, err)
		return
	}

	applied := append([]string(nil), c.appliedPolicies[key]...)
	policy.Status.Applied = len(applied) > 0
	policy.Status.LastApplied = time.Now()
	policy.Status.Error = ""
	policy.Status.CiliumPolicies = applied

	log.Printf("Successfully processed policy: %s", key)
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

func (c *PolicyController) applyTranslatedPolicies(policy *FilterPolicy, translated []*cilium.CiliumPolicy) error {
	key := policyKey(policy)
	if err := c.removeAppliedPolicies(key); err != nil {
		return err
	}

	applied := make([]string, 0, len(translated))
	for _, translatedPolicy := range translated {
		if translatedPolicy == nil {
			continue
		}
		if err := c.ciliumClient.ApplyNetworkPolicy(c.ctx, translatedPolicy); err != nil {
			for _, appliedName := range applied {
				_ = c.ciliumClient.DeleteNetworkPolicy(c.ctx, appliedName)
			}
			delete(c.appliedPolicies, key)
			return fmt.Errorf("apply translated policy %q: %w", translatedPolicy.Name, err)
		}
		applied = append(applied, translatedPolicy.Name)
	}

	if len(applied) == 0 {
		delete(c.appliedPolicies, key)
		return nil
	}

	c.appliedPolicies[key] = applied
	return nil
}

// removePolicy removes applied Cilium policies for the FilterPolicy.
func (c *PolicyController) removePolicy(policy *FilterPolicy) error {
	key := policyKey(policy)
	log.Printf("Removing Cilium policy for: %s", key)

	if err := c.removeAppliedPolicies(key); err != nil {
		policy.Status.Applied = false
		policy.Status.CiliumPolicies = nil
		policy.Status.Error = err.Error()
		return err
	}

	policy.Status.Applied = false
	policy.Status.CiliumPolicies = nil
	policy.Status.Error = ""
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
