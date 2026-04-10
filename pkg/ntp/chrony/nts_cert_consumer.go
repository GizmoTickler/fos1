package chrony

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/security/certificates"
)

// ServiceReloader abstracts the ability to reload a service after certificate
// material has been written to disk. The chrony Manager satisfies this interface.
type ServiceReloader interface {
	RestartService() error
}

// NTSCertConsumerStatus tracks the state of the NTS certificate consumer.
type NTSCertConsumerStatus struct {
	// CertificateReady indicates whether a valid certificate has been received.
	CertificateReady bool

	// LastIssuedAt records the time of the most recent certificate delivery.
	LastIssuedAt time.Time

	// LastError holds the most recent error, if any.
	LastError string

	// CertPath is the path where the certificate was written.
	CertPath string

	// KeyPath is the path where the private key was written.
	KeyPath string
}

// NTSCertConsumer implements certificates.CertificateConsumer to receive
// cert-manager-issued TLS certificates for the NTS (Network Time Security)
// server. When a certificate is issued or renewed, it writes the cert and key
// to disk and triggers a Chrony configuration reload so that the NTS server
// picks up the new material without a full restart.
type NTSCertConsumer struct {
	// secretName is the name of the cert-manager Secret to watch.
	secretName string

	// secretNamespace is the namespace of the Secret.
	secretNamespace string

	// certPath is the filesystem path to write the certificate PEM.
	certPath string

	// keyPath is the filesystem path to write the private key PEM.
	keyPath string

	// caPath is the optional filesystem path for the CA certificate.
	caPath string

	// reloader is used to reload the service after writing new cert material.
	reloader ServiceReloader

	// status tracks the current state of the consumer.
	status NTSCertConsumerStatus
	mu     sync.RWMutex
}

// NTSCertConsumerConfig configures the NTS certificate consumer.
type NTSCertConsumerConfig struct {
	// SecretName is the name of the cert-manager Secret containing the NTS cert.
	SecretName string

	// SecretNamespace is the namespace of the Secret.
	SecretNamespace string

	// CertPath is the filesystem path where the certificate PEM will be written.
	// Defaults to /etc/chrony/nts/cert.pem if empty.
	CertPath string

	// KeyPath is the filesystem path where the private key PEM will be written.
	// Defaults to /etc/chrony/nts/key.pem if empty.
	KeyPath string

	// CAPath is an optional filesystem path for the CA certificate PEM.
	CAPath string
}

// NewNTSCertConsumer creates an NTSCertConsumer. The reloader is typically a
// *chrony.Manager, but any ServiceReloader implementation is accepted to
// support testing.
func NewNTSCertConsumer(
	config *NTSCertConsumerConfig,
	reloader ServiceReloader,
) (*NTSCertConsumer, error) {
	if config == nil {
		return nil, fmt.Errorf("NTS certificate consumer configuration is required")
	}
	if config.SecretName == "" {
		return nil, fmt.Errorf("secret name is required for NTS certificate consumer")
	}
	if config.SecretNamespace == "" {
		return nil, fmt.Errorf("secret namespace is required for NTS certificate consumer")
	}
	if reloader == nil {
		return nil, fmt.Errorf("service reloader is required for NTS certificate consumer")
	}

	certPath := config.CertPath
	if certPath == "" {
		certPath = "/etc/chrony/nts/cert.pem"
	}
	keyPath := config.KeyPath
	if keyPath == "" {
		keyPath = "/etc/chrony/nts/key.pem"
	}

	return &NTSCertConsumer{
		secretName:      config.SecretName,
		secretNamespace: config.SecretNamespace,
		certPath:        certPath,
		keyPath:         keyPath,
		caPath:          config.CAPath,
		reloader:        reloader,
	}, nil
}

// CertificateSecretName implements certificates.CertificateConsumer.
func (c *NTSCertConsumer) CertificateSecretName() string {
	return c.secretName
}

// CertificateSecretNamespace implements certificates.CertificateConsumer.
func (c *NTSCertConsumer) CertificateSecretNamespace() string {
	return c.secretNamespace
}

// OnCertificateIssued implements certificates.CertificateConsumer. It writes
// the certificate and key to disk and reloads Chrony to pick up the new
// NTS material.
func (c *NTSCertConsumer) OnCertificateIssued(ctx context.Context, cert certificates.CertificateData) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	klog.Infof("Received NTS certificate update from secret %s/%s", cert.Namespace, cert.SecretName)

	// Write the certificate PEM to disk
	if err := c.writeFile(c.certPath, cert.CertPEM, 0644); err != nil {
		c.status.LastError = fmt.Sprintf("failed to write certificate: %v", err)
		return fmt.Errorf("failed to write NTS certificate to %s: %w", c.certPath, err)
	}

	// Write the private key PEM to disk (restricted permissions)
	if err := c.writeFile(c.keyPath, cert.KeyPEM, 0600); err != nil {
		c.status.LastError = fmt.Sprintf("failed to write key: %v", err)
		return fmt.Errorf("failed to write NTS key to %s: %w", c.keyPath, err)
	}

	// Write CA certificate if present and a path is configured
	if c.caPath != "" && len(cert.CaPEM) > 0 {
		if err := c.writeFile(c.caPath, cert.CaPEM, 0644); err != nil {
			c.status.LastError = fmt.Sprintf("failed to write CA certificate: %v", err)
			return fmt.Errorf("failed to write NTS CA certificate to %s: %w", c.caPath, err)
		}
	}

	// Reload the service so it picks up the new certificate material.
	// For Chrony, this calls "chronyc reload sources" which causes chronyd to
	// re-read its configuration, including the NTS cert/key paths.
	if err := c.reloader.RestartService(); err != nil {
		c.status.LastError = fmt.Sprintf("failed to reload chrony: %v", err)
		return fmt.Errorf("failed to reload Chrony after NTS certificate update: %w", err)
	}

	// Update status
	c.status.CertificateReady = true
	c.status.LastIssuedAt = cert.IssuedAt
	c.status.LastError = ""
	c.status.CertPath = c.certPath
	c.status.KeyPath = c.keyPath

	klog.Infof("NTS certificate written to %s and key to %s, Chrony reloaded", c.certPath, c.keyPath)
	return nil
}

// Status returns the current status of the NTS certificate consumer.
func (c *NTSCertConsumer) Status() NTSCertConsumerStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

// writeFile writes data to a file, creating parent directories as needed.
func (c *NTSCertConsumer) writeFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	return nil
}
