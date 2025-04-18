package certificates

import (
	"context"
	"fmt"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certmanagerclientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	certmanagerinformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	certmanagerlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

// Controller is the certificate controller
type Controller struct {
	// Kubernetes client
	kubeClient kubernetes.Interface

	// cert-manager client
	certClient certmanagerclientset.Interface

	// Certificate manager
	certManager *CertManager

	// Informers
	certificateInformer cache.SharedIndexInformer
	issuerInformer      cache.SharedIndexInformer

	// Listers
	certificateLister certmanagerlisters.CertificateLister
	issuerLister      certmanagerlisters.IssuerLister

	// Work queue
	certificateQueue workqueue.RateLimitingInterface
	issuerQueue      workqueue.RateLimitingInterface

	// Configuration
	config *ControllerConfig
}

// ControllerConfig holds the configuration for the certificate controller
type ControllerConfig struct {
	// Namespace is the namespace to watch for certificates and issuers
	Namespace string

	// ResyncPeriod is the period for resynchronizing the informers
	ResyncPeriod time.Duration

	// Workers is the number of workers for processing the queues
	Workers int
}

// NewController creates a new certificate controller
func NewController(
	kubeClient kubernetes.Interface,
	certClient certmanagerclientset.Interface,
	certManager *CertManager,
	config *ControllerConfig) (*Controller, error) {

	if kubeClient == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}

	if certClient == nil {
		return nil, fmt.Errorf("cert-manager client is required")
	}

	if certManager == nil {
		return nil, fmt.Errorf("certificate manager is required")
	}

	if config == nil {
		config = &ControllerConfig{
			Namespace:    "cert-manager",
			ResyncPeriod: 10 * time.Minute,
			Workers:      2,
		}
	}

	// Create informer factory
	informerFactory := certmanagerinformers.NewSharedInformerFactoryWithOptions(
		certClient,
		config.ResyncPeriod,
		certmanagerinformers.WithNamespace(config.Namespace),
	)

	// Create certificate informer
	certificateInformer := informerFactory.Certmanager().V1().Certificates().Informer()
	certificateLister := informerFactory.Certmanager().V1().Certificates().Lister()

	// Create issuer informer
	issuerInformer := informerFactory.Certmanager().V1().Issuers().Informer()
	issuerLister := informerFactory.Certmanager().V1().Issuers().Lister()

	// Create work queues
	certificateQueue := workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(),
		"Certificates",
	)
	issuerQueue := workqueue.NewNamedRateLimitingQueue(
		workqueue.DefaultControllerRateLimiter(),
		"Issuers",
	)

	// Create controller
	controller := &Controller{
		kubeClient:          kubeClient,
		certClient:          certClient,
		certManager:         certManager,
		certificateInformer: certificateInformer,
		issuerInformer:      issuerInformer,
		certificateLister:   certificateLister,
		issuerLister:        issuerLister,
		certificateQueue:    certificateQueue,
		issuerQueue:         issuerQueue,
		config:              config,
	}

	// Set up event handlers
	certificateInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueCertificate,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueCertificate(new)
		},
		DeleteFunc: controller.enqueueCertificate,
	})

	issuerInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueIssuer,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueIssuer(new)
		},
		DeleteFunc: controller.enqueueIssuer,
	})

	return controller, nil
}

// Run starts the controller
func (c *Controller) Run(ctx context.Context) error {
	defer c.certificateQueue.ShutDown()
	defer c.issuerQueue.ShutDown()

	klog.Info("Starting certificate controller")

	// Start the informers
	go c.certificateInformer.Run(ctx.Done())
	go c.issuerInformer.Run(ctx.Done())

	// Wait for the caches to be synced
	klog.Info("Waiting for informer caches to sync")
	if !cache.WaitForCacheSync(ctx.Done(), c.certificateInformer.HasSynced, c.issuerInformer.HasSynced) {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	klog.Info("Starting certificate workers")
	for i := 0; i < c.config.Workers; i++ {
		go wait.UntilWithContext(ctx, c.runCertificateWorker, time.Second)
		go wait.UntilWithContext(ctx, c.runIssuerWorker, time.Second)
	}

	klog.Info("Certificate controller started successfully")
	<-ctx.Done()
	klog.Info("Shutting down certificate controller")

	return nil
}

// runCertificateWorker runs a worker for processing certificate items
func (c *Controller) runCertificateWorker(ctx context.Context) {
	for c.processCertificateItem(ctx) {
	}
}

// runIssuerWorker runs a worker for processing issuer items
func (c *Controller) runIssuerWorker(ctx context.Context) {
	for c.processIssuerItem(ctx) {
	}
}

// processCertificateItem processes a certificate item from the queue
func (c *Controller) processCertificateItem(ctx context.Context) bool {
	obj, shutdown := c.certificateQueue.Get()
	if shutdown {
		return false
	}

	defer c.certificateQueue.Done(obj)

	key, ok := obj.(string)
	if !ok {
		c.certificateQueue.Forget(obj)
		klog.Errorf("Expected string in certificate queue but got %#v", obj)
		return true
	}

	if err := c.syncCertificate(ctx, key); err != nil {
		c.certificateQueue.AddRateLimited(key)
		klog.Errorf("Error syncing certificate %q: %v", key, err)
		return true
	}

	c.certificateQueue.Forget(obj)
	klog.Infof("Successfully synced certificate %q", key)
	return true
}

// processIssuerItem processes an issuer item from the queue
func (c *Controller) processIssuerItem(ctx context.Context) bool {
	obj, shutdown := c.issuerQueue.Get()
	if shutdown {
		return false
	}

	defer c.issuerQueue.Done(obj)

	key, ok := obj.(string)
	if !ok {
		c.issuerQueue.Forget(obj)
		klog.Errorf("Expected string in issuer queue but got %#v", obj)
		return true
	}

	if err := c.syncIssuer(ctx, key); err != nil {
		c.issuerQueue.AddRateLimited(key)
		klog.Errorf("Error syncing issuer %q: %v", key, err)
		return true
	}

	c.issuerQueue.Forget(obj)
	klog.Infof("Successfully synced issuer %q", key)
	return true
}

// enqueueCertificate enqueues a certificate
func (c *Controller) enqueueCertificate(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	c.certificateQueue.Add(key)
}

// enqueueIssuer enqueues an issuer
func (c *Controller) enqueueIssuer(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Failed to get key for object: %v", err)
		return
	}
	c.issuerQueue.Add(key)
}

// syncCertificate syncs a certificate
func (c *Controller) syncCertificate(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid resource key: %s", key)
	}

	// Get the certificate
	certificate, err := c.certificateLister.Certificates(namespace).Get(name)
	if err != nil {
		return fmt.Errorf("failed to get certificate %s/%s: %w", namespace, name, err)
	}

	// Process the certificate
	klog.Infof("Processing certificate %s/%s", namespace, name)

	// Check if the certificate is ready
	isReady := false
	for _, condition := range certificate.Status.Conditions {
		if condition.Type == certmanagerv1.CertificateConditionReady && condition.Status == certmanagerv1.ConditionTrue {
			isReady = true
			break
		}
	}

	if isReady {
		klog.Infof("Certificate %s/%s is ready", namespace, name)
	} else {
		klog.Infof("Certificate %s/%s is not ready", namespace, name)
	}

	return nil
}

// syncIssuer syncs an issuer
func (c *Controller) syncIssuer(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid resource key: %s", key)
	}

	// Get the issuer
	issuer, err := c.issuerLister.Issuers(namespace).Get(name)
	if err != nil {
		return fmt.Errorf("failed to get issuer %s/%s: %w", namespace, name, err)
	}

	// Process the issuer
	klog.Infof("Processing issuer %s/%s", namespace, name)

	// Check if the issuer is ready
	isReady := false
	for _, condition := range issuer.Status.Conditions {
		if condition.Type == certmanagerv1.IssuerConditionReady && condition.Status == certmanagerv1.ConditionTrue {
			isReady = true
			break
		}
	}

	if isReady {
		klog.Infof("Issuer %s/%s is ready", namespace, name)
	} else {
		klog.Infof("Issuer %s/%s is not ready", namespace, name)
	}

	return nil
}

// GetCertificateStatus gets the status of a certificate
func (c *Controller) GetCertificateStatus(namespace, name string) (*CertificateStatus, error) {
	// Get the certificate
	certificate, err := c.certificateLister.Certificates(namespace).Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate %s/%s: %w", namespace, name, err)
	}

	// Create certificate status
	status := &CertificateStatus{}

	// Set conditions
	for _, condition := range certificate.Status.Conditions {
		certificateCondition := CertificateCondition{
			Type:               string(condition.Type),
			Status:             string(condition.Status),
			Reason:             condition.Reason,
			Message:            condition.Message,
			LastTransitionTime: condition.LastTransitionTime.Time,
		}
		status.Conditions = append(status.Conditions, certificateCondition)
	}

	return status, nil
}

// GetIssuerStatus gets the status of an issuer
func (c *Controller) GetIssuerStatus(namespace, name string) (*IssuerStatus, error) {
	// Get the issuer
	issuer, err := c.issuerLister.Issuers(namespace).Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer %s/%s: %w", namespace, name, err)
	}

	// Create issuer status
	status := &IssuerStatus{}

	// Set conditions
	for _, condition := range issuer.Status.Conditions {
		issuerCondition := IssuerCondition{
			Type:               string(condition.Type),
			Status:             string(condition.Status),
			Reason:             condition.Reason,
			Message:            condition.Message,
			LastTransitionTime: condition.LastTransitionTime.Time,
		}
		status.Conditions = append(status.Conditions, issuerCondition)
	}

	return status, nil
}
