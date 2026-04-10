package certificates

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

// CertificateConsumer is the interface that downstream services implement to
// receive certificate updates from cert-manager. When a cert-manager Certificate
// resource becomes ready, the resulting Secret (containing tls.crt and tls.key)
// is delivered to registered consumers.
type CertificateConsumer interface {
	// CertificateSecretName returns the name of the Secret this consumer is
	// interested in. The watcher uses this to route events.
	CertificateSecretName() string

	// CertificateSecretNamespace returns the namespace of the Secret.
	CertificateSecretNamespace() string

	// OnCertificateIssued is called when the certificate Secret is created or
	// updated (i.e. on initial issuance or renewal). The consumer receives the
	// TLS certificate, private key, and CA certificate bytes from the Secret.
	OnCertificateIssued(ctx context.Context, cert CertificateData) error
}

// CertificateData holds the raw certificate material extracted from a
// cert-manager Secret.
type CertificateData struct {
	// SecretName is the name of the Kubernetes Secret.
	SecretName string

	// Namespace is the namespace of the Secret.
	Namespace string

	// CertPEM is the PEM-encoded certificate chain (tls.crt).
	CertPEM []byte

	// KeyPEM is the PEM-encoded private key (tls.key).
	KeyPEM []byte

	// CaPEM is the PEM-encoded CA certificate (ca.crt), if present.
	CaPEM []byte

	// IssuedAt records when this data was observed.
	IssuedAt time.Time
}

// SecretWatcher watches Kubernetes Secrets that back cert-manager Certificates
// and dispatches updates to registered CertificateConsumer instances. It uses a
// standard informer/work-queue pattern so that multiple consumers can be served
// from a single shared watch.
type SecretWatcher struct {
	kubeClient kubernetes.Interface

	// consumers is keyed by "namespace/secretName"
	consumers map[string][]CertificateConsumer
	mu        sync.RWMutex

	// informer infrastructure
	factory        informers.SharedInformerFactory
	secretInformer cache.SharedIndexInformer
	secretLister   corelisters.SecretLister
	queue          workqueue.RateLimitingInterface

	// namespace restricts the watch scope; empty means all namespaces.
	namespace string
	workers   int
}

// SecretWatcherConfig configures the SecretWatcher.
type SecretWatcherConfig struct {
	// Namespace to watch. Empty string watches all namespaces.
	Namespace string

	// ResyncPeriod for the underlying informer.
	ResyncPeriod time.Duration

	// Workers is the number of concurrent reconciliation workers.
	Workers int
}

// NewSecretWatcher creates a SecretWatcher that watches for TLS Secret changes.
func NewSecretWatcher(kubeClient kubernetes.Interface, config *SecretWatcherConfig) (*SecretWatcher, error) {
	if kubeClient == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}
	if config == nil {
		config = &SecretWatcherConfig{
			ResyncPeriod: 5 * time.Minute,
			Workers:      2,
		}
	}
	if config.Workers == 0 {
		config.Workers = 2
	}
	if config.ResyncPeriod == 0 {
		config.ResyncPeriod = 5 * time.Minute
	}

	var factory informers.SharedInformerFactory
	if config.Namespace != "" {
		factory = informers.NewSharedInformerFactoryWithOptions(
			kubeClient,
			config.ResyncPeriod,
			informers.WithNamespace(config.Namespace),
		)
	} else {
		factory = informers.NewSharedInformerFactory(kubeClient, config.ResyncPeriod)
	}

	secretInformer := factory.Core().V1().Secrets().Informer()
	secretLister := factory.Core().V1().Secrets().Lister()

	watcher := &SecretWatcher{
		kubeClient:     kubeClient,
		consumers:      make(map[string][]CertificateConsumer),
		factory:        factory,
		secretInformer: secretInformer,
		secretLister:   secretLister,
		queue: workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(),
			"CertificateSecretWatcher",
		),
		namespace: config.Namespace,
		workers:   config.Workers,
	}

	// Register event handlers that filter for TLS-type secrets
	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: watcher.onSecretAdd,
		UpdateFunc: func(oldObj, newObj interface{}) {
			watcher.onSecretUpdate(oldObj, newObj)
		},
		DeleteFunc: watcher.onSecretDelete,
	})

	return watcher, nil
}

// RegisterConsumer registers a CertificateConsumer to receive updates for its
// declared Secret. This must be called before Run.
func (w *SecretWatcher) RegisterConsumer(consumer CertificateConsumer) {
	w.mu.Lock()
	defer w.mu.Unlock()

	key := consumer.CertificateSecretNamespace() + "/" + consumer.CertificateSecretName()
	w.consumers[key] = append(w.consumers[key], consumer)
	klog.Infof("Registered certificate consumer for secret %s", key)
}

// Run starts the watcher. It blocks until ctx is cancelled.
func (w *SecretWatcher) Run(ctx context.Context) error {
	defer w.queue.ShutDown()

	klog.Info("Starting certificate secret watcher")

	// Start the informer factory
	w.factory.Start(ctx.Done())

	// Wait for cache sync
	klog.Info("Waiting for secret informer cache to sync")
	if !cache.WaitForCacheSync(ctx.Done(), w.secretInformer.HasSynced) {
		return fmt.Errorf("failed to sync secret informer cache")
	}

	// On startup, do an initial check for any secrets that already exist and
	// match a registered consumer.
	w.reconcileExistingSecrets(ctx)

	klog.Info("Starting certificate secret watcher workers")
	for i := 0; i < w.workers; i++ {
		go wait.UntilWithContext(ctx, w.runWorker, time.Second)
	}

	klog.Info("Certificate secret watcher started successfully")
	<-ctx.Done()
	klog.Info("Shutting down certificate secret watcher")
	return nil
}

// reconcileExistingSecrets checks for any secrets that already exist and match
// registered consumers, delivering an initial OnCertificateIssued call.
func (w *SecretWatcher) reconcileExistingSecrets(ctx context.Context) {
	w.mu.RLock()
	keys := make([]string, 0, len(w.consumers))
	for k := range w.consumers {
		keys = append(keys, k)
	}
	w.mu.RUnlock()

	for _, key := range keys {
		w.queue.Add(key)
	}
}

func (w *SecretWatcher) onSecretAdd(obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}
	// Only process TLS secrets (cert-manager creates kubernetes.io/tls secrets)
	if secret.Type != corev1.SecretTypeTLS {
		return
	}
	key := secret.Namespace + "/" + secret.Name
	w.mu.RLock()
	_, hasConsumer := w.consumers[key]
	w.mu.RUnlock()
	if hasConsumer {
		w.queue.Add(key)
	}
}

func (w *SecretWatcher) onSecretUpdate(oldObj, newObj interface{}) {
	newSecret, ok := newObj.(*corev1.Secret)
	if !ok {
		return
	}
	if newSecret.Type != corev1.SecretTypeTLS {
		return
	}
	key := newSecret.Namespace + "/" + newSecret.Name
	w.mu.RLock()
	_, hasConsumer := w.consumers[key]
	w.mu.RUnlock()
	if hasConsumer {
		// Check if the TLS data actually changed
		oldSecret, ok := oldObj.(*corev1.Secret)
		if ok && string(oldSecret.Data["tls.crt"]) == string(newSecret.Data["tls.crt"]) &&
			string(oldSecret.Data["tls.key"]) == string(newSecret.Data["tls.key"]) {
			return // No change in certificate material
		}
		w.queue.Add(key)
	}
}

func (w *SecretWatcher) onSecretDelete(obj interface{}) {
	// On deletion we do not notify consumers; the certificate is gone.
	// Consumers will detect the missing cert through their own status checks.
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		secret, ok = tombstone.Obj.(*corev1.Secret)
		if !ok {
			return
		}
	}
	klog.Infof("Certificate secret %s/%s deleted", secret.Namespace, secret.Name)
}

func (w *SecretWatcher) runWorker(ctx context.Context) {
	for w.processNextItem(ctx) {
	}
}

func (w *SecretWatcher) processNextItem(ctx context.Context) bool {
	obj, shutdown := w.queue.Get()
	if shutdown {
		return false
	}
	defer w.queue.Done(obj)

	key, ok := obj.(string)
	if !ok {
		w.queue.Forget(obj)
		klog.Errorf("Expected string in certificate watcher queue but got %#v", obj)
		return true
	}

	if err := w.syncSecret(ctx, key); err != nil {
		w.queue.AddRateLimited(key)
		klog.Errorf("Error syncing certificate secret %q: %v", key, err)
		return true
	}

	w.queue.Forget(obj)
	return true
}

func (w *SecretWatcher) syncSecret(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid key %q: %w", key, err)
	}

	// Fetch the secret from the lister (cache)
	secret, err := w.secretLister.Secrets(namespace).Get(name)
	if err != nil {
		// Secret not found -- it may not exist yet (cert-manager hasn't issued it).
		// We log and do not requeue; the informer will notify us when it appears.
		klog.V(2).Infof("Certificate secret %s not found, waiting for cert-manager to issue it", key)
		return nil
	}

	// Verify it is a TLS secret
	if secret.Type != corev1.SecretTypeTLS {
		klog.V(2).Infof("Secret %s is not a TLS secret (type=%s), skipping", key, secret.Type)
		return nil
	}

	// Extract certificate data
	certData := CertificateData{
		SecretName: name,
		Namespace:  namespace,
		CertPEM:    secret.Data["tls.crt"],
		KeyPEM:     secret.Data["tls.key"],
		CaPEM:      secret.Data["ca.crt"],
		IssuedAt:   time.Now(),
	}

	if len(certData.CertPEM) == 0 || len(certData.KeyPEM) == 0 {
		klog.Warningf("Certificate secret %s has empty tls.crt or tls.key, skipping", key)
		return nil
	}

	// Dispatch to all registered consumers for this secret
	w.mu.RLock()
	consumers := w.consumers[key]
	w.mu.RUnlock()

	var firstErr error
	for _, consumer := range consumers {
		if err := consumer.OnCertificateIssued(ctx, certData); err != nil {
			klog.Errorf("Consumer failed to process certificate %s: %v", key, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	if firstErr != nil {
		return fmt.Errorf("one or more consumers failed for secret %s: %w", key, firstErr)
	}

	klog.Infof("Successfully dispatched certificate %s to %d consumer(s)", key, len(consumers))
	return nil
}

// GetSecretData fetches certificate data from a Secret directly (not from cache).
// This is useful for one-shot lookups outside the watch loop.
func (w *SecretWatcher) GetSecretData(ctx context.Context, namespace, name string) (*CertificateData, error) {
	secret, err := w.kubeClient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, name, err)
	}

	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("secret %s/%s is not a TLS secret (type=%s)", namespace, name, secret.Type)
	}

	return &CertificateData{
		SecretName: name,
		Namespace:  namespace,
		CertPEM:    secret.Data["tls.crt"],
		KeyPEM:     secret.Data["tls.key"],
		CaPEM:      secret.Data["ca.crt"],
		IssuedAt:   time.Now(),
	}, nil
}
