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

	networkv1 "github.com/fos/pkg/apis/network/v1"
	clientset "github.com/fos/pkg/client/clientset/versioned"
	informers "github.com/fos/pkg/client/informers/externalversions"
	listers "github.com/fos/pkg/client/listers/network/v1"
	"github.com/fos/pkg/dhcp/kea"
	"github.com/fos/pkg/dhcp/types"
	"github.com/fos/pkg/dns/manager"
)

const (
	// ControllerName is the name of the DHCP controller
	ControllerName = "dhcp-controller"

	// SuccessSynced is used as part of the Event 'reason' when a resource is synced
	SuccessSynced = "Synced"

	// MessageResourceSynced is the message used for an Event fired when a resource
	// is synced successfully
	MessageResourceSynced = "DHCP service synced successfully"
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

	// keaManager manages the Kea DHCP server configuration
	keaManager *kea.Manager

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
	dnsManager *manager.Manager) *Controller {

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

	// Create Kea manager
	keaManager := kea.NewManager("/etc/kea", "kea-dhcp")

	// Create DNS connector
	dnsConnector := NewDNSConnector(dnsManager)

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

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// re-queued with a backoff.
		defer c.dhcpv4Workqueue.Done(obj)
		var key string
		var ok bool
		// We expect strings to come off the workqueue. These are of the
		// form namespace/name. We do this as the delayed nature of the
		// workqueue means the items in the informer cache may actually be
		// more up to date that when the item was initially put onto the
		// workqueue.
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.dhcpv4Workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the syncHandler, passing it the namespace/name string of the
		// DHCPv4Service resource to be synced.
		if err := c.syncDHCPv4Handler(key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			c.dhcpv4Workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
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

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// re-queued with a backoff.
		defer c.dhcpv6Workqueue.Done(obj)
		var key string
		var ok bool
		// We expect strings to come off the workqueue. These are of the
		// form namespace/name. We do this as the delayed nature of the
		// workqueue means the items in the informer cache may actually be
		// more up to date that when the item was initially put onto the
		// workqueue.
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.dhcpv6Workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the syncHandler, passing it the namespace/name string of the
		// DHCPv6Service resource to be synced.
		if err := c.syncDHCPv6Handler(key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			c.dhcpv6Workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
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
// converge the two. It then updates the Status block of the DHCPv4Service resource
// with the current status of the resource.
func (c *Controller) syncDHCPv4Handler(key string) error {
	c.configMutex.Lock()
	defer c.configMutex.Unlock()

	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the DHCPv4Service resource with this namespace/name
	dhcpv4Service, err := c.dhcpv4Lister.DHCPv4Services(namespace).Get(name)
	if err != nil {
		// The DHCPv4Service resource may no longer exist, in which case we stop processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("dhcpv4service '%s' in work queue no longer exists", key))
			return nil
		}
		return err
	}

	// Get the referenced VLAN
	vlan, err := c.vlanLister.VLANs(namespace).Get(dhcpv4Service.Spec.VLANRef)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to get VLAN %s referenced by DHCPv4Service %s: %v", 
			dhcpv4Service.Spec.VLANRef, name, err))
		return err
	}

	// Create Kea subnet configuration from DHCPv4Service and VLAN
	subnetConfig, err := c.createDHCPv4SubnetConfig(dhcpv4Service, vlan)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to create subnet configuration for DHCPv4Service %s: %v", name, err))
		return err
	}

	// Update Kea configuration
	err = c.keaManager.UpdateDHCPv4Subnet(vlan.Spec.ID, subnetConfig)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to update Kea DHCPv4 configuration for VLAN %d: %v", 
			vlan.Spec.ID, err))
		return err
	}

	// Restart Kea service for this VLAN
	err = c.keaManager.RestartDHCPv4Service(vlan.Spec.ID)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to restart Kea DHCPv4 service for VLAN %d: %v", 
			vlan.Spec.ID, err))
		return err
	}

	c.recorder.Event(dhcpv4Service, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

// syncDHCPv6Handler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the DHCPv6Service resource
// with the current status of the resource.
func (c *Controller) syncDHCPv6Handler(key string) error {
	c.configMutex.Lock()
	defer c.configMutex.Unlock()

	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the DHCPv6Service resource with this namespace/name
	dhcpv6Service, err := c.dhcpv6Lister.DHCPv6Services(namespace).Get(name)
	if err != nil {
		// The DHCPv6Service resource may no longer exist, in which case we stop processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("dhcpv6service '%s' in work queue no longer exists", key))
			return nil
		}
		return err
	}

	// Get the referenced VLAN
	vlan, err := c.vlanLister.VLANs(namespace).Get(dhcpv6Service.Spec.VLANRef)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to get VLAN %s referenced by DHCPv6Service %s: %v", 
			dhcpv6Service.Spec.VLANRef, name, err))
		return err
	}

	// Create Kea subnet configuration from DHCPv6Service and VLAN
	subnetConfig, err := c.createDHCPv6SubnetConfig(dhcpv6Service, vlan)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to create subnet configuration for DHCPv6Service %s: %v", name, err))
		return err
	}

	// Update Kea configuration
	err = c.keaManager.UpdateDHCPv6Subnet(vlan.Spec.ID, subnetConfig)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to update Kea DHCPv6 configuration for VLAN %d: %v", 
			vlan.Spec.ID, err))
		return err
	}

	// Restart Kea service for this VLAN
	err = c.keaManager.RestartDHCPv6Service(vlan.Spec.ID)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("failed to restart Kea DHCPv6 service for VLAN %d: %v", 
			vlan.Spec.ID, err))
		return err
	}

	c.recorder.Event(dhcpv6Service, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
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
		// If the object is not a VLAN, it is probably a
		// DeletionFinalStateUnknown, so we use its metadata to queue
		// affected DHCP services
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

// createDHCPv4SubnetConfig creates a Kea DHCPv4 subnet configuration from a DHCPv4Service and VLAN
func (c *Controller) createDHCPv4SubnetConfig(dhcpService *networkv1.DHCPv4Service, vlan *networkv1.VLAN) (*types.DHCPv4SubnetConfig, error) {
	// This is a placeholder for the actual implementation, which would:
	// 1. Extract the subnet information from the VLAN
	// 2. Configure the gateway address from the VLAN interface
	// 3. Set up the DHCP pool from the DHCPv4Service range
	// 4. Configure options from the DHCPv4Service
	// 5. Set up static reservations
	
	// For now, return a dummy configuration
	return &types.DHCPv4SubnetConfig{
		Subnet: vlan.Spec.Subnet,
		Pools: []types.Pool{
			{
				Start: dhcpService.Spec.Range.Start,
				End:   dhcpService.Spec.Range.End,
			},
		},
		ValidLifetime: dhcpService.Spec.LeaseTime,
		RenewTimer:    dhcpService.Spec.LeaseTime / 2,
		RebindTimer:   dhcpService.Spec.LeaseTime * 3 / 4,
		Options: []types.DHCPOption{
			{
				Name: "domain-name",
				Data: dhcpService.Spec.Domain,
			},
		},
		// Additional configuration would be set up here
	}, nil
}

// createDHCPv6SubnetConfig creates a Kea DHCPv6 subnet configuration from a DHCPv6Service and VLAN
func (c *Controller) createDHCPv6SubnetConfig(dhcpService *networkv1.DHCPv6Service, vlan *networkv1.VLAN) (*types.DHCPv6SubnetConfig, error) {
	// This is a placeholder for the actual implementation, which would:
	// 1. Extract the subnet information from the VLAN
	// 2. Configure the gateway address from the VLAN interface
	// 3. Set up the DHCP pool from the DHCPv6Service range
	// 4. Configure options from the DHCPv6Service
	// 5. Set up static reservations
	
	// For now, return a dummy configuration
	return &types.DHCPv6SubnetConfig{
		Subnet: vlan.Spec.Subnet6,
		Pools: []types.Pool{
			{
				Start: dhcpService.Spec.Range.Start,
				End:   dhcpService.Spec.Range.End,
			},
		},
		ValidLifetime:    dhcpService.Spec.LeaseTime,
		PreferredLifetime: dhcpService.Spec.LeaseTime * 3 / 4,
		RenewTimer:       dhcpService.Spec.LeaseTime / 2,
		RebindTimer:      dhcpService.Spec.LeaseTime * 3 / 4,
		Options: []types.DHCPOption{
			{
				Name: "domain-name",
				Data: dhcpService.Spec.Domain,
			},
		},
		// Additional configuration would be set up here
	}, nil
}