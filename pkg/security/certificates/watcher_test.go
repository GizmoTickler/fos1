package certificates

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// testConsumer is a mock CertificateConsumer for testing.
type testConsumer struct {
	secretName      string
	secretNamespace string

	mu            sync.Mutex
	receivedCerts []CertificateData
	returnErr     error
}

func (c *testConsumer) CertificateSecretName() string      { return c.secretName }
func (c *testConsumer) CertificateSecretNamespace() string  { return c.secretNamespace }
func (c *testConsumer) OnCertificateIssued(_ context.Context, cert CertificateData) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.receivedCerts = append(c.receivedCerts, cert)
	return c.returnErr
}

func (c *testConsumer) received() []CertificateData {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]CertificateData, len(c.receivedCerts))
	copy(result, c.receivedCerts)
	return result
}

func TestSecretWatcher_DispatchesOnSecretCreate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kubeClient := fake.NewSimpleClientset()

	watcher, err := NewSecretWatcher(kubeClient, &SecretWatcherConfig{
		Namespace:    "ntp-system",
		ResyncPeriod: 1 * time.Second,
		Workers:      1,
	})
	if err != nil {
		t.Fatalf("NewSecretWatcher() error = %v", err)
	}

	consumer := &testConsumer{
		secretName:      "nts-cert-tls",
		secretNamespace: "ntp-system",
	}
	watcher.RegisterConsumer(consumer)

	// Start watcher in background
	watcherDone := make(chan error, 1)
	go func() {
		watcherDone <- watcher.Run(ctx)
	}()

	// Give the informer time to sync
	time.Sleep(500 * time.Millisecond)

	// Create a TLS secret simulating cert-manager output
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nts-cert-tls",
			Namespace: "ntp-system",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"),
			"tls.key": []byte("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"),
			"ca.crt":  []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n"),
		},
	}

	_, err = kubeClient.CoreV1().Secrets("ntp-system").Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait for the consumer to receive the certificate
	deadline := time.After(5 * time.Second)
	for {
		certs := consumer.received()
		if len(certs) > 0 {
			cert := certs[0]
			if cert.SecretName != "nts-cert-tls" {
				t.Errorf("SecretName = %q, want %q", cert.SecretName, "nts-cert-tls")
			}
			if cert.Namespace != "ntp-system" {
				t.Errorf("Namespace = %q, want %q", cert.Namespace, "ntp-system")
			}
			if len(cert.CertPEM) == 0 {
				t.Error("CertPEM should not be empty")
			}
			if len(cert.KeyPEM) == 0 {
				t.Error("KeyPEM should not be empty")
			}
			if len(cert.CaPEM) == 0 {
				t.Error("CaPEM should not be empty")
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("Timed out waiting for consumer to receive certificate")
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	cancel()
}

func TestSecretWatcher_DispatchesOnSecretUpdate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Pre-create the secret
	initialSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nts-cert-tls",
			Namespace: "ntp-system",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("old-cert"),
			"tls.key": []byte("old-key"),
		},
	}

	kubeClient := fake.NewSimpleClientset(initialSecret)

	watcher, err := NewSecretWatcher(kubeClient, &SecretWatcherConfig{
		Namespace:    "ntp-system",
		ResyncPeriod: 1 * time.Second,
		Workers:      1,
	})
	if err != nil {
		t.Fatalf("NewSecretWatcher() error = %v", err)
	}

	consumer := &testConsumer{
		secretName:      "nts-cert-tls",
		secretNamespace: "ntp-system",
	}
	watcher.RegisterConsumer(consumer)

	// Start watcher
	go func() {
		_ = watcher.Run(ctx)
	}()

	// Wait for informer sync and initial reconciliation
	time.Sleep(1 * time.Second)

	// The initial reconciliation should have delivered the existing secret
	initialCerts := consumer.received()
	if len(initialCerts) == 0 {
		t.Fatal("Expected initial certificate delivery on startup")
	}

	// Now update the secret (simulating cert-manager renewal)
	updatedSecret := initialSecret.DeepCopy()
	updatedSecret.Data["tls.crt"] = []byte("renewed-cert")
	updatedSecret.Data["tls.key"] = []byte("renewed-key")

	_, err = kubeClient.CoreV1().Secrets("ntp-system").Update(ctx, updatedSecret, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to update secret: %v", err)
	}

	// Wait for the renewal to be delivered
	deadline := time.After(5 * time.Second)
	for {
		certs := consumer.received()
		// We expect at least 2 deliveries: initial + renewal
		if len(certs) >= 2 {
			latest := certs[len(certs)-1]
			if string(latest.CertPEM) != "renewed-cert" {
				t.Errorf("Expected renewed cert, got %q", string(latest.CertPEM))
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("Timed out waiting for renewal delivery, got %d deliveries", len(consumer.received()))
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	cancel()
}

func TestSecretWatcher_IgnoresNonTLSSecrets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	kubeClient := fake.NewSimpleClientset()

	watcher, err := NewSecretWatcher(kubeClient, &SecretWatcherConfig{
		Namespace:    "ntp-system",
		ResyncPeriod: 1 * time.Second,
		Workers:      1,
	})
	if err != nil {
		t.Fatalf("NewSecretWatcher() error = %v", err)
	}

	consumer := &testConsumer{
		secretName:      "nts-cert-tls",
		secretNamespace: "ntp-system",
	}
	watcher.RegisterConsumer(consumer)

	go func() {
		_ = watcher.Run(ctx)
	}()

	time.Sleep(500 * time.Millisecond)

	// Create an Opaque secret (not TLS)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nts-cert-tls",
			Namespace: "ntp-system",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"some-data": []byte("not a certificate"),
		},
	}

	_, err = kubeClient.CoreV1().Secrets("ntp-system").Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Wait a bit and confirm no delivery
	time.Sleep(1 * time.Second)
	certs := consumer.received()
	if len(certs) != 0 {
		t.Errorf("Expected no certificate delivery for Opaque secret, got %d", len(certs))
	}

	cancel()
}

func TestSecretWatcher_MissingCertificateNotDelivered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	kubeClient := fake.NewSimpleClientset()

	watcher, err := NewSecretWatcher(kubeClient, &SecretWatcherConfig{
		Namespace:    "ntp-system",
		ResyncPeriod: 1 * time.Second,
		Workers:      1,
	})
	if err != nil {
		t.Fatalf("NewSecretWatcher() error = %v", err)
	}

	consumer := &testConsumer{
		secretName:      "nonexistent-cert",
		secretNamespace: "ntp-system",
	}
	watcher.RegisterConsumer(consumer)

	go func() {
		_ = watcher.Run(ctx)
	}()

	// Wait for startup and initial reconciliation
	time.Sleep(1 * time.Second)

	// No secret exists, so no delivery should occur
	certs := consumer.received()
	if len(certs) != 0 {
		t.Errorf("Expected no delivery for missing secret, got %d", len(certs))
	}

	cancel()
}

func TestNewSecretWatcher_Validation(t *testing.T) {
	_, err := NewSecretWatcher(nil, nil)
	if err == nil {
		t.Fatal("Expected error when kubeClient is nil")
	}

	kubeClient := fake.NewSimpleClientset()
	watcher, err := NewSecretWatcher(kubeClient, nil)
	if err != nil {
		t.Fatalf("Expected default config to work, got: %v", err)
	}
	if watcher.workers != 2 {
		t.Errorf("Default workers = %d, want 2", watcher.workers)
	}
}

func TestSecretWatcher_GetSecretData(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-tls",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("cert-data"),
			"tls.key": []byte("key-data"),
			"ca.crt":  []byte("ca-data"),
		},
	}

	kubeClient := fake.NewSimpleClientset(secret)
	watcher, err := NewSecretWatcher(kubeClient, nil)
	if err != nil {
		t.Fatalf("NewSecretWatcher() error = %v", err)
	}

	ctx := context.Background()
	data, err := watcher.GetSecretData(ctx, "default", "my-tls")
	if err != nil {
		t.Fatalf("GetSecretData() error = %v", err)
	}

	if string(data.CertPEM) != "cert-data" {
		t.Errorf("CertPEM = %q, want %q", string(data.CertPEM), "cert-data")
	}
	if string(data.KeyPEM) != "key-data" {
		t.Errorf("KeyPEM = %q, want %q", string(data.KeyPEM), "key-data")
	}
	if string(data.CaPEM) != "ca-data" {
		t.Errorf("CaPEM = %q, want %q", string(data.CaPEM), "ca-data")
	}
}

func TestSecretWatcher_GetSecretData_NotTLS(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-opaque",
			Namespace: "default",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"data": []byte("something"),
		},
	}

	kubeClient := fake.NewSimpleClientset(secret)
	watcher, err := NewSecretWatcher(kubeClient, nil)
	if err != nil {
		t.Fatalf("NewSecretWatcher() error = %v", err)
	}

	_, err = watcher.GetSecretData(context.Background(), "default", "my-opaque")
	if err == nil {
		t.Fatal("Expected error for non-TLS secret")
	}
}
