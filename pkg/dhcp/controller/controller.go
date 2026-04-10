package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	networkv1 "github.com/GizmoTickler/fos1/pkg/apis/network/v1"
	clientset "github.com/GizmoTickler/fos1/pkg/client/clientset/versioned"
	informers "github.com/GizmoTickler/fos1/pkg/client/informers/externalversions"
	listers "github.com/GizmoTickler/fos1/pkg/client/listers/network/v1"
	"github.com/GizmoTickler/fos1/pkg/dhcp"
	"github.com/GizmoTickler/fos1/pkg/dhcp/types"
)

const (
	// ControllerName is the name of the DHCP controller
	ControllerName = "dhcp-controller"

	// SuccessSynced is used as part of the Event 'reason' when a resource is synced
	SuccessSynced = "Synced"

	// MessageResourceSynced is the message used for an Event fired when a resource
	// is synced successfully
	MessageResourceSynced = "DHCP service synced successfully"

	// PhaseReady indicates the service has been configured and verified on Kea.
	PhaseReady = "Ready"

	// PhaseDegraded indicates Kea rejected the configuration or is unreachable.
	PhaseDegraded = "Degraded"

	// PhaseError indicates a fatal reconciliation error.
	PhaseError = "Error"

	// ConditionConfigApplied tracks whether the Kea config-set succeeded.
	ConditionConfigApplied = "ConfigApplied"

	// ConditionKeaReachable tracks whether the Kea daemon is reachable.
	ConditionKeaReachable = "KeaReachable"

	// keaReconcileTimeout is how long we wait for Kea operations during reconcile.
	keaReconcileTimeout = 15 * time.Second
)

// Controller is the controller implementation for DHCP resources
type Controller struct {
	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface
	// networkclientset is a clientset for our own API group
	networkclientset clientset.Interface

	dhcpv4Lister  listers.DHCPv4ServiceLister
	dhcpv4Synced  cache.InformerSynced
	dhcpv6Lister  listers.DHCPv6ServiceLister
	dhcpv6Synced  cache.InformerSynced
	vlanLister    listers.VLANLister
	vlanSynced    cache.InformerSynced

	// workqueues is a rate limited work queue. This is used to queue work to be
	// processed instead of performing it as soon as a change happens.
	dhcpv4Workqueue workqueue.RateLimitingInterface
	dhcpv6Workqueue workqueue.RateLimitingInterface

	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder

	// keaManager manages communication with Kea DHCP daemons via control sockets.
	keaManager *dhcp.KeaManager

	// dnsConnector connects DHCP to DNS for updates
	dnsConnector *DNSConnector

	// configMutex protects the configuration from concurrent updates
	configMutex sync.Mutex
}

// NewController returns a new DHCP controller
func NewController(
	kubeclientset kubernetes.Interface,
	networkclientset clientset.Interface,
	networkInformerFactory informers.SharedInformerFactory,
	keaManager *dhcp.KeaManager,
	dnsConnector *DNSConnector) *Controller {

	// Get informers
	dhcpv4Informer := networkInformerFactory.Network().V1().DHCPv4Services()
	dhcpv6Informer := networkInformerFactory.Network().V1().DHCPv6Services()
	vlanInformer := networkInformerFactory.Network().V1().VLANs()

	// Create event broadcaster
	klog.V(4).Info("Creating event broadcaster")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartStructuredLogging(0)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeclientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: ControllerName})

	controller := &Controller{
		kubeclientset:    kubeclientset,
		networkclientset: networkclientset,
		dhcpv4Lister:     dhcpv4Informer.Lister(),
		dhcpv4Synced:     dhcpv4Informer.Informer().HasSynced,
		dhcpv6Lister:     dhcpv6Informer.Lister(),
		dhcpv6Synced:     dhcpv6Informer.Informer().HasSynced,
		vlanLister:       vlanInformer.Lister(),
		vlanSynced:       vlanInformer.Informer().HasSynced,
		dhcpv4Workqueue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "DHCPv4Services"),
		dhcpv6Workqueue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "DHCPv6Services"),
		recorder:         recorder,
		keaManager:       keaManager,
		dnsConnector:     dnsConnector,
	}

	klog.Info("Setting up event handlers")

	// Set up an event handler for when DHCPv4Service resources change
	dhcpv4Informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueDHCPv4Service,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueDHCPv4Service(new)
		},
		DeleteFunc: controller.enqueueDHCPv4Service,
	})

	// Set up an event handler for when DHCPv6Service resources change
	dhcpv6Informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueDHCPv6Service,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueDHCPv6Service(new)
		},
		DeleteFunc: controller.enqueueDHCPv6Service,
	})

	// Set up an event handler for when VLAN resources change that might affect DHCP
	vlanInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleVLAN,
		UpdateFunc: func(old, new interface{}) {
			controller.handleVLAN(new)
		},
		DeleteFunc: controller.handleVLAN,
	})

	return controller
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.dhcpv4Workqueue.ShutDown()
	defer c.dhcpv6Workqueue.ShutDown()

	// Start the informer factories to begin populating the informer caches
	klog.Info("Starting DHCP controller")

	// Wait for the caches to be synced before starting workers
	klog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, c.dhcpv4Synced, c.dhcpv6Synced, c.vlanSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	klog.Info("Starting workers")
	// Launch workers to process DHCP resources
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runDHCPv4Worker, time.Second, stopCh)
		go wait.Until(c.runDHCPv6Worker, time.Second, stopCh)
	}

	klog.Info("Started workers")
	<-stopCh
	klog.Info("Shutting down workers")

	return nil
}

// runDHCPv4Worker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runDHCPv4Worker() {
	for c.processDHCPv4NextWorkItem() {
	}
}

// processDHCPv4NextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processDHCPv4NextWorkItem() bool {
	obj, shutdown := c.dhcpv4Workqueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.dhcpv4Workqueue.Done(obj)
		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			c.dhcpv4Workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		if err := c.syncDHCPv4Handler(key); err != nil {
			c.dhcpv4Workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		c.dhcpv4Workqueue.Forget(obj)
		klog.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// runDHCPv6Worker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runDHCPv6Worker() {
	for c.processDHCPv6NextWorkItem() {
	}
}

// processDHCPv6NextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processDHCPv6NextWorkItem() bool {
	obj, shutdown := c.dhcpv6Workqueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.dhcpv6Workqueue.Done(obj)
		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			c.dhcpv6Workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		if err := c.syncDHCPv6Handler(key); err != nil {
			c.dhcpv6Workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		c.dhcpv6Workqueue.Forget(obj)
		klog.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncDHCPv4Handler compares the actual state with the desired, and attempts to
// converge the two. It pushes the Kea configuration via config-set, verifies it,
// and updates the CRD status to reflect the applied state.
func (c *Controller) syncDHCPv4Handler(key string) error {
	c.configMutex.Lock()
	defer c.configMutex.Unlock()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	dhcpv4Service, err := c.dhcpv4Lister.DHCPv4Services(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("dhcpv4service '%s' in work queue no longer exists", key))
			return nil
		}
		return err
	}

	// Get the referenced VLAN
	vlan, err := c.vlanLister.VLANs(namespace).Get(dhcpv4Service.Spec.VLANRef)
	if err != nil {
		c.setDHCPv4Status(dhcpv4Service, PhaseError, fmt.Sprintf("VLAN %s not found: %v", dhcpv4Service.Spec.VLANRef, err))
		return fmt.Errorf("failed to get VLAN %s referenced by DHCPv4Service %s: %v",
			dhcpv4Service.Spec.VLANRef, name, err)
	}

	// Determine the domain suffix from the CRD spec.
	domain := dhcpv4Service.Spec.Domain
	if domain == "" {
		// Fall back to a reasonable default derived from the VLAN name.
		domain = fmt.Sprintf("vlan%d.local", vlan.Spec.ID)
	}

	// Build the types.DHCPv4Service from the CRD spec.
	typedService := &types.DHCPv4Service{
		Spec: types.DHCPv4ServiceSpec{
			VLANRef:   dhcpv4Service.Spec.VLANRef,
			LeaseTime: dhcpv4Service.Spec.LeaseTime,
			Range:     types.AddressRange{Start: dhcpv4Service.Spec.Range.Start, End: dhcpv4Service.Spec.Range.End},
			Domain:    domain,
		},
	}

	// Create a context with timeout for Kea operations.
	ctx, cancel := context.WithTimeout(context.Background(), keaReconcileTimeout)
	defer cancel()

	// Check if Kea daemon is reachable before pushing config.
	if !c.keaManager.IsDHCPv4Running() {
		c.setDHCPv4Status(dhcpv4Service, PhaseDegraded, "Kea DHCPv4 daemon is not reachable")
		c.recorder.Event(dhcpv4Service, corev1.EventTypeWarning, "KeaUnreachable", "Kea DHCPv4 daemon is not reachable on its control socket")
		return fmt.Errorf("kea dhcp4 daemon unreachable for VLAN %s", dhcpv4Service.Spec.VLANRef)
	}

	// Push the configuration to Kea via config-set and verify via config-get.
	if err := c.keaManager.PushDHCPv4Config(ctx, typedService, vlan.Spec.Subnet, vlan.Spec.Gateway); err != nil {
		c.setDHCPv4Status(dhcpv4Service, PhaseDegraded, fmt.Sprintf("Kea config-set failed: %v", err))
		c.recorder.Event(dhcpv4Service, corev1.EventTypeWarning, "ConfigSetFailed",
			fmt.Sprintf("Failed to push DHCPv4 config to Kea: %v", err))
		return fmt.Errorf("failed to push Kea DHCPv4 config for VLAN %d: %v", vlan.Spec.ID, err)
	}

	// Configuration applied and verified. Mark as Ready.
	c.setDHCPv4Status(dhcpv4Service, PhaseReady, "Configuration applied and verified on Kea")
	c.recorder.Event(dhcpv4Service, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

// syncDHCPv6Handler compares the actual state with the desired, and attempts to
// converge the two. It pushes the Kea configuration via config-set, verifies it,
// and updates the CRD status to reflect the applied state.
func (c *Controller) syncDHCPv6Handler(key string) error {
	c.configMutex.Lock()
	defer c.configMutex.Unlock()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	dhcpv6Service, err := c.dhcpv6Lister.DHCPv6Services(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("dhcpv6service '%s' in work queue no longer exists", key))
			return nil
		}
		return err
	}

	// Get the referenced VLAN
	vlan, err := c.vlanLister.VLANs(namespace).Get(dhcpv6Service.Spec.VLANRef)
	if err != nil {
		c.setDHCPv6Status(dhcpv6Service, PhaseError, fmt.Sprintf("VLAN %s not found: %v", dhcpv6Service.Spec.VLANRef, err))
		return fmt.Errorf("failed to get VLAN %s referenced by DHCPv6Service %s: %v",
			dhcpv6Service.Spec.VLANRef, name, err)
	}

	// Determine the domain suffix from the CRD spec.
	domain := dhcpv6Service.Spec.Domain
	if domain == "" {
		domain = fmt.Sprintf("vlan%d.local", vlan.Spec.ID)
	}

	// Build the types.DHCPv6Service from the CRD spec.
	typedService := &types.DHCPv6Service{
		Spec: types.DHCPv6ServiceSpec{
			VLANRef:   dhcpv6Service.Spec.VLANRef,
			LeaseTime: dhcpv6Service.Spec.LeaseTime,
			Range:     types.AddressRange{Start: dhcpv6Service.Spec.Range.Start, End: dhcpv6Service.Spec.Range.End},
			Domain:    domain,
		},
	}

	// Create a context with timeout for Kea operations.
	ctx, cancel := context.WithTimeout(context.Background(), keaReconcileTimeout)
	defer cancel()

	// Check if Kea daemon is reachable.
	if !c.keaManager.IsDHCPv6Running() {
		c.setDHCPv6Status(dhcpv6Service, PhaseDegraded, "Kea DHCPv6 daemon is not reachable")
		c.recorder.Event(dhcpv6Service, corev1.EventTypeWarning, "KeaUnreachable", "Kea DHCPv6 daemon is not reachable on its control socket")
		return fmt.Errorf("kea dhcp6 daemon unreachable for VLAN %s", dhcpv6Service.Spec.VLANRef)
	}

	// Push the configuration to Kea via config-set and verify via config-get.
	if err := c.keaManager.PushDHCPv6Config(ctx, typedService, vlan.Spec.Subnet6, vlan.Spec.Gateway6); err != nil {
		c.setDHCPv6Status(dhcpv6Service, PhaseDegraded, fmt.Sprintf("Kea config-set failed: %v", err))
		c.recorder.Event(dhcpv6Service, corev1.EventTypeWarning, "ConfigSetFailed",
			fmt.Sprintf("Failed to push DHCPv6 config to Kea: %v", err))
		return fmt.Errorf("failed to push Kea DHCPv6 config for VLAN %d: %v", vlan.Spec.ID, err)
	}

	// Configuration applied and verified. Mark as Ready.
	c.setDHCPv6Status(dhcpv6Service, PhaseReady, "Configuration applied and verified on Kea")
	c.recorder.Event(dhcpv6Service, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

// setDHCPv4Status updates the status of a DHCPv4Service CRD.
func (c *Controller) setDHCPv4Status(svc *networkv1.DHCPv4Service, phase, message string) {
	now := metav1.Now()
	svc.Status.Phase = phase
	svc.Status.Message = message
	svc.Status.LastUpdated = now
	svc.Status.Active = (phase == PhaseReady)

	// Update ConfigApplied condition.
	configApplied := metav1.Condition{
		Type:               ConditionConfigApplied,
		LastTransitionTime: now,
		ObservedGeneration: svc.Generation,
	}
	if phase == PhaseReady {
		configApplied.Status = metav1.ConditionTrue
		configApplied.Reason = "ConfigSetSucceeded"
		configApplied.Message = "Kea accepted and applied the configuration"
	} else {
		configApplied.Status = metav1.ConditionFalse
		configApplied.Reason = "ConfigSetFailed"
		configApplied.Message = message
	}
	setCondition(&svc.Status.Conditions, configApplied)
}

// setDHCPv6Status updates the status of a DHCPv6Service CRD.
func (c *Controller) setDHCPv6Status(svc *networkv1.DHCPv6Service, phase, message string) {
	now := metav1.Now()
	svc.Status.Phase = phase
	svc.Status.Message = message
	svc.Status.LastUpdated = now
	svc.Status.Active = (phase == PhaseReady)

	// Update ConfigApplied condition.
	configApplied := metav1.Condition{
		Type:               ConditionConfigApplied,
		LastTransitionTime: now,
		ObservedGeneration: svc.Generation,
	}
	if phase == PhaseReady {
		configApplied.Status = metav1.ConditionTrue
		configApplied.Reason = "ConfigSetSucceeded"
		configApplied.Message = "Kea accepted and applied the configuration"
	} else {
		configApplied.Status = metav1.ConditionFalse
		configApplied.Reason = "ConfigSetFailed"
		configApplied.Message = message
	}
	setCondition(&svc.Status.Conditions, configApplied)
}

// setCondition updates or appends a condition in the conditions slice.
func setCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	if *conditions == nil {
		*conditions = []metav1.Condition{}
	}
	for i, existing := range *conditions {
		if existing.Type == condition.Type {
			(*conditions)[i] = condition
			return
		}
	}
	*conditions = append(*conditions, condition)
}

// enqueueDHCPv4Service takes a DHCPv4Service resource and converts it into a namespace/name
// string which is then put onto the work queue.
func (c *Controller) enqueueDHCPv4Service(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.dhcpv4Workqueue.Add(key)
}

// enqueueDHCPv6Service takes a DHCPv6Service resource and converts it into a namespace/name
// string which is then put onto the work queue.
func (c *Controller) enqueueDHCPv6Service(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.dhcpv6Workqueue.Add(key)
}

// handleVLAN takes a VLAN resource and enqueues all DHCPv4 and DHCPv6 services
// that reference it.
func (c *Controller) handleVLAN(obj interface{}) {
	var vlan *networkv1.VLAN
	var ok bool
	if vlan, ok = obj.(*networkv1.VLAN); !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			return
		}
		vlan, ok = tombstone.Obj.(*networkv1.VLAN)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			return
		}
	}

	// Find all DHCPv4Services that reference this VLAN
	dhcpv4Services, err := c.dhcpv4Lister.DHCPv4Services(metav1.NamespaceAll).List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error listing DHCPv4Services: %v", err))
		return
	}

	for _, dhcpv4Service := range dhcpv4Services {
		if dhcpv4Service.Spec.VLANRef == vlan.Name {
			c.enqueueDHCPv4Service(dhcpv4Service)
		}
	}

	// Find all DHCPv6Services that reference this VLAN
	dhcpv6Services, err := c.dhcpv6Lister.DHCPv6Services(metav1.NamespaceAll).List(labels.Everything())
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error listing DHCPv6Services: %v", err))
		return
	}

	for _, dhcpv6Service := range dhcpv6Services {
		if dhcpv6Service.Spec.VLANRef == vlan.Name {
			c.enqueueDHCPv6Service(dhcpv6Service)
		}
	}
}
