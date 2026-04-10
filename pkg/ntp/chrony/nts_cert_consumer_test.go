package chrony

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/security/certificates"
)

// mockReloader is a test double for ServiceReloader.
type mockReloader struct {
	mu        sync.Mutex
	callCount int
	err       error
}

func (m *mockReloader) RestartService() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	return m.err
}

func (m *mockReloader) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func TestNewNTSCertConsumer_Validation(t *testing.T) {
	reloader := &mockReloader{}

	tests := []struct {
		name     string
		config   *NTSCertConsumerConfig
		reloader ServiceReloader
		wantErr  bool
	}{
		{
			name:     "nil config",
			config:   nil,
			reloader: reloader,
			wantErr:  true,
		},
		{
			name:     "empty secret name",
			config:   &NTSCertConsumerConfig{SecretNamespace: "ns"},
			reloader: reloader,
			wantErr:  true,
		},
		{
			name:     "empty secret namespace",
			config:   &NTSCertConsumerConfig{SecretName: "cert"},
			reloader: reloader,
			wantErr:  true,
		},
		{
			name: "nil reloader",
			config: &NTSCertConsumerConfig{
				SecretName:      "cert",
				SecretNamespace: "ns",
			},
			reloader: nil,
			wantErr:  true,
		},
		{
			name: "valid config",
			config: &NTSCertConsumerConfig{
				SecretName:      "nts-cert-tls",
				SecretNamespace: "ntp-system",
			},
			reloader: reloader,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewNTSCertConsumer(tt.config, tt.reloader)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewNTSCertConsumer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNTSCertConsumer_DefaultPaths(t *testing.T) {
	consumer, err := NewNTSCertConsumer(&NTSCertConsumerConfig{
		SecretName:      "nts-cert",
		SecretNamespace: "ntp-system",
	}, &mockReloader{})
	if err != nil {
		t.Fatalf("NewNTSCertConsumer() error = %v", err)
	}

	if consumer.certPath != "/etc/chrony/nts/cert.pem" {
		t.Errorf("certPath = %q, want default", consumer.certPath)
	}
	if consumer.keyPath != "/etc/chrony/nts/key.pem" {
		t.Errorf("keyPath = %q, want default", consumer.keyPath)
	}
}

func TestNTSCertConsumer_CustomPaths(t *testing.T) {
	consumer, err := NewNTSCertConsumer(&NTSCertConsumerConfig{
		SecretName:      "nts-cert",
		SecretNamespace: "ntp-system",
		CertPath:        "/custom/cert.pem",
		KeyPath:         "/custom/key.pem",
		CAPath:          "/custom/ca.pem",
	}, &mockReloader{})
	if err != nil {
		t.Fatalf("NewNTSCertConsumer() error = %v", err)
	}

	if consumer.certPath != "/custom/cert.pem" {
		t.Errorf("certPath = %q", consumer.certPath)
	}
	if consumer.keyPath != "/custom/key.pem" {
		t.Errorf("keyPath = %q", consumer.keyPath)
	}
	if consumer.caPath != "/custom/ca.pem" {
		t.Errorf("caPath = %q", consumer.caPath)
	}
}

func TestNTSCertConsumer_InterfaceCompliance(t *testing.T) {
	consumer, err := NewNTSCertConsumer(&NTSCertConsumerConfig{
		SecretName:      "nts-cert",
		SecretNamespace: "ntp-system",
	}, &mockReloader{})
	if err != nil {
		t.Fatalf("NewNTSCertConsumer() error = %v", err)
	}

	// Verify it satisfies the CertificateConsumer interface
	var _ certificates.CertificateConsumer = consumer

	if consumer.CertificateSecretName() != "nts-cert" {
		t.Errorf("CertificateSecretName() = %q", consumer.CertificateSecretName())
	}
	if consumer.CertificateSecretNamespace() != "ntp-system" {
		t.Errorf("CertificateSecretNamespace() = %q", consumer.CertificateSecretNamespace())
	}
}

func TestNTSCertConsumer_OnCertificateIssued_WritesCertAndKey(t *testing.T) {
	tmpDir := t.TempDir()

	certPath := filepath.Join(tmpDir, "nts", "cert.pem")
	keyPath := filepath.Join(tmpDir, "nts", "key.pem")
	caPath := filepath.Join(tmpDir, "nts", "ca.pem")

	reloader := &mockReloader{}

	consumer, err := NewNTSCertConsumer(&NTSCertConsumerConfig{
		SecretName:      "nts-cert-tls",
		SecretNamespace: "ntp-system",
		CertPath:        certPath,
		KeyPath:         keyPath,
		CAPath:          caPath,
	}, reloader)
	if err != nil {
		t.Fatalf("NewNTSCertConsumer() error = %v", err)
	}

	certData := certificates.CertificateData{
		SecretName: "nts-cert-tls",
		Namespace:  "ntp-system",
		CertPEM:    []byte("-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n"),
		KeyPEM:     []byte("-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----\n"),
		CaPEM:      []byte("-----BEGIN CERTIFICATE-----\ntest-ca\n-----END CERTIFICATE-----\n"),
		IssuedAt:   time.Now(),
	}

	ctx := context.Background()
	if err := consumer.OnCertificateIssued(ctx, certData); err != nil {
		t.Fatalf("OnCertificateIssued() error = %v", err)
	}

	// Verify the certificate was written
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}
	if string(certBytes) != string(certData.CertPEM) {
		t.Errorf("Cert file content = %q, want %q", string(certBytes), string(certData.CertPEM))
	}

	// Verify the key was written with restricted permissions
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}
	if string(keyBytes) != string(certData.KeyPEM) {
		t.Errorf("Key file content = %q, want %q", string(keyBytes), string(certData.KeyPEM))
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("Key file permissions = %o, want 0600", keyInfo.Mode().Perm())
	}

	// Verify the CA was written
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("Failed to read CA file: %v", err)
	}
	if string(caBytes) != string(certData.CaPEM) {
		t.Errorf("CA file content = %q, want %q", string(caBytes), string(certData.CaPEM))
	}

	// Verify the reloader was called
	if reloader.calls() != 1 {
		t.Errorf("Reloader call count = %d, want 1", reloader.calls())
	}

	// Verify status
	status := consumer.Status()
	if !status.CertificateReady {
		t.Error("CertificateReady should be true after successful delivery")
	}
	if status.LastError != "" {
		t.Errorf("LastError should be empty, got %q", status.LastError)
	}
	if status.CertPath != certPath {
		t.Errorf("CertPath = %q, want %q", status.CertPath, certPath)
	}
	if status.KeyPath != keyPath {
		t.Errorf("KeyPath = %q, want %q", status.KeyPath, keyPath)
	}
}

func TestNTSCertConsumer_OnCertificateIssued_RenewalOverwritesPrevious(t *testing.T) {
	tmpDir := t.TempDir()

	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	reloader := &mockReloader{}

	consumer, err := NewNTSCertConsumer(&NTSCertConsumerConfig{
		SecretName:      "nts-cert-tls",
		SecretNamespace: "ntp-system",
		CertPath:        certPath,
		KeyPath:         keyPath,
	}, reloader)
	if err != nil {
		t.Fatalf("NewNTSCertConsumer() error = %v", err)
	}

	ctx := context.Background()

	// First issuance
	firstCert := certificates.CertificateData{
		SecretName: "nts-cert-tls",
		Namespace:  "ntp-system",
		CertPEM:    []byte("first-cert"),
		KeyPEM:     []byte("first-key"),
		IssuedAt:   time.Now(),
	}
	if err := consumer.OnCertificateIssued(ctx, firstCert); err != nil {
		t.Fatalf("First OnCertificateIssued() error = %v", err)
	}

	// Second issuance (renewal)
	renewedCert := certificates.CertificateData{
		SecretName: "nts-cert-tls",
		Namespace:  "ntp-system",
		CertPEM:    []byte("renewed-cert"),
		KeyPEM:     []byte("renewed-key"),
		IssuedAt:   time.Now(),
	}
	if err := consumer.OnCertificateIssued(ctx, renewedCert); err != nil {
		t.Fatalf("Renewed OnCertificateIssued() error = %v", err)
	}

	// Verify the renewed cert is on disk
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}
	if string(certBytes) != "renewed-cert" {
		t.Errorf("Cert file should contain renewed cert, got %q", string(certBytes))
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}
	if string(keyBytes) != "renewed-key" {
		t.Errorf("Key file should contain renewed key, got %q", string(keyBytes))
	}

	// Reloader should have been called twice (once per issuance)
	if reloader.calls() != 2 {
		t.Errorf("Reloader call count = %d, want 2", reloader.calls())
	}
}

func TestNTSCertConsumer_OnCertificateIssued_NoCAPath(t *testing.T) {
	tmpDir := t.TempDir()

	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	reloader := &mockReloader{}

	// No CAPath configured
	consumer, err := NewNTSCertConsumer(&NTSCertConsumerConfig{
		SecretName:      "nts-cert-tls",
		SecretNamespace: "ntp-system",
		CertPath:        certPath,
		KeyPath:         keyPath,
	}, reloader)
	if err != nil {
		t.Fatalf("NewNTSCertConsumer() error = %v", err)
	}

	certData := certificates.CertificateData{
		SecretName: "nts-cert-tls",
		Namespace:  "ntp-system",
		CertPEM:    []byte("test-cert"),
		KeyPEM:     []byte("test-key"),
		CaPEM:      []byte("test-ca"),
		IssuedAt:   time.Now(),
	}

	ctx := context.Background()
	if err := consumer.OnCertificateIssued(ctx, certData); err != nil {
		t.Fatalf("OnCertificateIssued() error = %v", err)
	}

	// Cert and key should exist
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("Cert file should exist: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("Key file should exist: %v", err)
	}

	// CA file should NOT exist since no CAPath was configured
	caPath := filepath.Join(tmpDir, "ca.pem")
	if _, err := os.Stat(caPath); err == nil {
		t.Error("CA file should not exist when CAPath is not configured")
	}
}

func TestNTSCertConsumer_Status_DegradedOnReloadFailure(t *testing.T) {
	tmpDir := t.TempDir()

	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// Use a reloader that always fails
	reloader := &mockReloader{err: fmt.Errorf("reload failed: chronyd not running")}

	consumer, err := NewNTSCertConsumer(&NTSCertConsumerConfig{
		SecretName:      "nts-cert-tls",
		SecretNamespace: "ntp-system",
		CertPath:        certPath,
		KeyPath:         keyPath,
	}, reloader)
	if err != nil {
		t.Fatalf("NewNTSCertConsumer() error = %v", err)
	}

	certData := certificates.CertificateData{
		SecretName: "nts-cert-tls",
		Namespace:  "ntp-system",
		CertPEM:    []byte("test-cert"),
		KeyPEM:     []byte("test-key"),
		IssuedAt:   time.Now(),
	}

	ctx := context.Background()
	err = consumer.OnCertificateIssued(ctx, certData)
	if err == nil {
		t.Fatal("Expected error when chrony reload fails")
	}

	// Status should reflect the error
	status := consumer.Status()
	if status.CertificateReady {
		t.Error("CertificateReady should be false when reload fails")
	}
	if status.LastError == "" {
		t.Error("LastError should be set when reload fails")
	}
}

func TestNTSCertConsumer_Status_InitialState(t *testing.T) {
	consumer, err := NewNTSCertConsumer(&NTSCertConsumerConfig{
		SecretName:      "nts-cert",
		SecretNamespace: "ntp-system",
	}, &mockReloader{})
	if err != nil {
		t.Fatalf("NewNTSCertConsumer() error = %v", err)
	}

	status := consumer.Status()
	if status.CertificateReady {
		t.Error("CertificateReady should be false initially")
	}
	if status.LastError != "" {
		t.Errorf("LastError should be empty initially, got %q", status.LastError)
	}
	if status.CertPath != "" {
		t.Errorf("CertPath should be empty initially, got %q", status.CertPath)
	}
}
