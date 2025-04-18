package certificates

import (
	"context"
	"fmt"
	"sync"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certmanagerclientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// CertManager implements the Manager interface using cert-manager
type CertManager struct {
	// Kubernetes client
	kubeClient kubernetes.Interface

	// cert-manager client
	certClient certmanagerclientset.Interface

	// Configuration
	config *Config

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	mutex  sync.RWMutex
}

// Config holds the configuration for the certificate manager
type Config struct {
	// DefaultIssuerName is the name of the default issuer
	DefaultIssuerName string

	// DefaultIssuerKind is the kind of the default issuer
	DefaultIssuerKind string

	// DefaultIssuerGroup is the group of the default issuer
	DefaultIssuerGroup string

	// DefaultNamespace is the default namespace for certificates and issuers
	DefaultNamespace string

	// RenewalCheckInterval is the interval for checking certificate renewals
	RenewalCheckInterval time.Duration

	// DefaultKeySize is the default key size for certificates
	DefaultKeySize int

	// DefaultKeyAlgorithm is the default key algorithm for certificates
	DefaultKeyAlgorithm string

	// DefaultKeyEncoding is the default key encoding for certificates
	DefaultKeyEncoding string

	// DefaultDuration is the default duration for certificates
	DefaultDuration time.Duration

	// DefaultRenewBefore is the default time before expiration to renew certificates
	DefaultRenewBefore time.Duration
}

// NewCertManager creates a new certificate manager
func NewCertManager(
	kubeClient kubernetes.Interface,
	certClient certmanagerclientset.Interface,
	config *Config) (*CertManager, error) {

	if kubeClient == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}

	if certClient == nil {
		return nil, fmt.Errorf("cert-manager client is required")
	}

	if config == nil {
		config = &Config{
			DefaultIssuerName:     "selfsigned-issuer",
			DefaultIssuerKind:     "Issuer",
			DefaultIssuerGroup:    "cert-manager.io",
			DefaultNamespace:      "cert-manager",
			RenewalCheckInterval:  24 * time.Hour,
			DefaultKeySize:        2048,
			DefaultKeyAlgorithm:   "RSA",
			DefaultKeyEncoding:    "PKCS1",
			DefaultDuration:       90 * 24 * time.Hour,
			DefaultRenewBefore:    30 * 24 * time.Hour,
		}
	}

	// Create context for management
	ctx, cancel := context.WithCancel(context.Background())

	return &CertManager{
		kubeClient: kubeClient,
		certClient: certClient,
		config:     config,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Initialize initializes the certificate manager
func (m *CertManager) Initialize(ctx context.Context) error {
	klog.Info("Initializing certificate manager")

	// Check if cert-manager is installed
	_, err := m.certClient.CertmanagerV1().Issuers("").List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return fmt.Errorf("failed to connect to cert-manager API: %w", err)
	}

	// Create default self-signed issuer if it doesn't exist
	if m.config.DefaultIssuerName != "" && m.config.DefaultIssuerKind == "Issuer" {
		_, err := m.certClient.CertmanagerV1().Issuers(m.config.DefaultNamespace).Get(
			ctx, m.config.DefaultIssuerName, metav1.GetOptions{})
		if err != nil {
			klog.Infof("Creating default self-signed issuer %s in namespace %s",
				m.config.DefaultIssuerName, m.config.DefaultNamespace)

			issuer := &certmanagerv1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      m.config.DefaultIssuerName,
					Namespace: m.config.DefaultNamespace,
				},
				Spec: certmanagerv1.IssuerSpec{
					IssuerConfig: certmanagerv1.IssuerConfig{
						SelfSigned: &certmanagerv1.SelfSignedIssuer{},
					},
				},
			}

			_, err = m.certClient.CertmanagerV1().Issuers(m.config.DefaultNamespace).Create(
				ctx, issuer, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create default self-signed issuer: %w", err)
			}
		}
	}

	klog.Info("Certificate manager initialized successfully")
	return nil
}

// Shutdown shuts down the certificate manager
func (m *CertManager) Shutdown(ctx context.Context) error {
	klog.Info("Shutting down certificate manager")
	m.cancel()
	return nil
}

// CreateCertificate creates a new certificate
func (m *CertManager) CreateCertificate(config *CertificateConfig) (*Certificate, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if config == nil {
		return nil, fmt.Errorf("certificate configuration is required")
	}

	if config.Name == "" {
		return nil, fmt.Errorf("certificate name is required")
	}

	if config.Namespace == "" {
		config.Namespace = m.config.DefaultNamespace
	}

	if config.SecretName == "" {
		config.SecretName = fmt.Sprintf("%s-tls", config.Name)
	}

	if config.KeySize == 0 {
		config.KeySize = m.config.DefaultKeySize
	}

	if config.KeyAlgorithm == "" {
		config.KeyAlgorithm = m.config.DefaultKeyAlgorithm
	}

	if config.KeyEncoding == "" {
		config.KeyEncoding = m.config.DefaultKeyEncoding
	}

	if config.Duration == 0 {
		config.Duration = m.config.DefaultDuration
	}

	if config.RenewBefore == 0 {
		config.RenewBefore = m.config.DefaultRenewBefore
	}

	// Set default issuer if not specified
	if config.IssuerRef.Name == "" {
		config.IssuerRef.Name = m.config.DefaultIssuerName
		config.IssuerRef.Kind = m.config.DefaultIssuerKind
		config.IssuerRef.Group = m.config.DefaultIssuerGroup
	}

	// Create cert-manager Certificate resource
	cert := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.Name,
			Namespace: config.Namespace,
		},
		Spec: certmanagerv1.CertificateSpec{
			SecretName: config.SecretName,
			CommonName: config.CommonName,
			DNSNames:   config.DNSNames,
			IssuerRef: certmanagerv1.ObjectReference{
				Name:  config.IssuerRef.Name,
				Kind:  config.IssuerRef.Kind,
				Group: config.IssuerRef.Group,
			},
			PrivateKey: &certmanagerv1.CertificatePrivateKey{
				Algorithm: certmanagerv1.PrivateKeyAlgorithm(config.KeyAlgorithm),
				Size:      config.KeySize,
				Encoding:  certmanagerv1.PrivateKeyEncoding(config.KeyEncoding),
			},
		},
	}

	// Set IP addresses if specified
	if len(config.IPAddresses) > 0 {
		cert.Spec.IPAddresses = config.IPAddresses
	}

	// Set duration if specified
	if config.Duration > 0 {
		duration := metav1.Duration{Duration: config.Duration}
		cert.Spec.Duration = &duration
	}

	// Set renewBefore if specified
	if config.RenewBefore > 0 {
		renewBefore := metav1.Duration{Duration: config.RenewBefore}
		cert.Spec.RenewBefore = &renewBefore
	}

	// Set isCA if specified
	if config.IsCA {
		cert.Spec.IsCA = config.IsCA
	}

	// Set usages if specified
	if config.UsageType != "" {
		switch config.UsageType {
		case "server":
			cert.Spec.Usages = []certmanagerv1.KeyUsage{
				certmanagerv1.UsageDigitalSignature,
				certmanagerv1.UsageKeyEncipherment,
				certmanagerv1.UsageServerAuth,
			}
		case "client":
			cert.Spec.Usages = []certmanagerv1.KeyUsage{
				certmanagerv1.UsageDigitalSignature,
				certmanagerv1.UsageKeyEncipherment,
				certmanagerv1.UsageClientAuth,
			}
		case "signing":
			cert.Spec.Usages = []certmanagerv1.KeyUsage{
				certmanagerv1.UsageDigitalSignature,
				certmanagerv1.UsageCertSign,
				certmanagerv1.UsageCRLSign,
			}
		}
	}

	// Create the certificate
	createdCert, err := m.certClient.CertmanagerV1().Certificates(config.Namespace).Create(
		m.ctx, cert, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	klog.Infof("Created certificate %s in namespace %s", config.Name, config.Namespace)

	// Convert to internal Certificate type
	return m.convertCertificate(createdCert)
}

// GetCertificate gets a certificate by name
func (m *CertManager) GetCertificate(name string) (*Certificate, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if name == "" {
		return nil, fmt.Errorf("certificate name is required")
	}

	// Get the certificate from cert-manager
	cert, err := m.certClient.CertmanagerV1().Certificates(m.config.DefaultNamespace).Get(
		m.ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Convert to internal Certificate type
	return m.convertCertificate(cert)
}

// ListCertificates lists all certificates
func (m *CertManager) ListCertificates() ([]*Certificate, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// List certificates from cert-manager
	certList, err := m.certClient.CertmanagerV1().Certificates(m.config.DefaultNamespace).List(
		m.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	// Convert to internal Certificate type
	var certificates []*Certificate
	for _, cert := range certList.Items {
		certificate, err := m.convertCertificate(&cert)
		if err != nil {
			klog.Warningf("Failed to convert certificate %s: %v", cert.Name, err)
			continue
		}
		certificates = append(certificates, certificate)
	}

	return certificates, nil
}

// RevokeCertificate revokes a certificate
func (m *CertManager) RevokeCertificate(name string, reason string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if name == "" {
		return fmt.Errorf("certificate name is required")
	}

	// Get the certificate from cert-manager
	cert, err := m.certClient.CertmanagerV1().Certificates(m.config.DefaultNamespace).Get(
		m.ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get certificate: %w", err)
	}

	// Add revocation annotation
	if cert.Annotations == nil {
		cert.Annotations = make(map[string]string)
	}
	cert.Annotations["cert-manager.io/revoked"] = "true"
	cert.Annotations["cert-manager.io/revocation-reason"] = reason

	// Update the certificate
	_, err = m.certClient.CertmanagerV1().Certificates(m.config.DefaultNamespace).Update(
		m.ctx, cert, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	klog.Infof("Revoked certificate %s in namespace %s", name, m.config.DefaultNamespace)
	return nil
}

// RenewCertificate renews a certificate
func (m *CertManager) RenewCertificate(name string) (*Certificate, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if name == "" {
		return nil, fmt.Errorf("certificate name is required")
	}

	// Get the certificate from cert-manager
	cert, err := m.certClient.CertmanagerV1().Certificates(m.config.DefaultNamespace).Get(
		m.ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Add renewal annotation
	if cert.Annotations == nil {
		cert.Annotations = make(map[string]string)
	}
	cert.Annotations["cert-manager.io/renew"] = "true"

	// Update the certificate
	updatedCert, err := m.certClient.CertmanagerV1().Certificates(m.config.DefaultNamespace).Update(
		m.ctx, cert, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %w", err)
	}

	klog.Infof("Renewed certificate %s in namespace %s", name, m.config.DefaultNamespace)

	// Convert to internal Certificate type
	return m.convertCertificate(updatedCert)
}

// CreateIssuer creates a certificate issuer
func (m *CertManager) CreateIssuer(config *IssuerConfig) (*Issuer, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if config == nil {
		return nil, fmt.Errorf("issuer configuration is required")
	}

	if config.Name == "" {
		return nil, fmt.Errorf("issuer name is required")
	}

	if config.Namespace == "" {
		config.Namespace = m.config.DefaultNamespace
	}

	if config.Type == "" {
		return nil, fmt.Errorf("issuer type is required")
	}

	// Create cert-manager Issuer resource
	var issuerSpec certmanagerv1.IssuerSpec

	switch config.Type {
	case "SelfSigned":
		issuerSpec = certmanagerv1.IssuerSpec{
			IssuerConfig: certmanagerv1.IssuerConfig{
				SelfSigned: &certmanagerv1.SelfSignedIssuer{},
			},
		}
	case "CA":
		if config.CA == nil || config.CA.SecretName == "" {
			return nil, fmt.Errorf("CA configuration is required for CA issuer")
		}
		issuerSpec = certmanagerv1.IssuerSpec{
			IssuerConfig: certmanagerv1.IssuerConfig{
				CA: &certmanagerv1.CAIssuer{
					SecretName: config.CA.SecretName,
				},
			},
		}
	case "ACME":
		if config.ACME == nil || config.ACME.Server == "" || config.ACME.Email == "" {
			return nil, fmt.Errorf("ACME configuration is required for ACME issuer")
		}

		// Create ACME issuer
		acmeIssuer := &certmanagerv1.ACMEIssuer{
			Server: config.ACME.Server,
			Email:  config.ACME.Email,
			PrivateKey: certmanagerv1.SecretKeySelector{
				LocalObjectReference: certmanagerv1.LocalObjectReference{
					Name: config.ACME.PrivateKeySecretRef.Name,
				},
				Key: config.ACME.PrivateKeySecretRef.Key,
			},
		}

		// Add solvers if specified
		if len(config.ACME.Solvers) > 0 {
			for _, solver := range config.ACME.Solvers {
				acmeSolver := certmanagerv1.ACMEChallengeSolver{}

				// Add HTTP01 solver if specified
				if solver.HTTP01 != nil {
					acmeSolver.HTTP01 = &certmanagerv1.ACMEChallengeSolverHTTP01{}

					// Add ingress solver if specified
					if solver.HTTP01.Ingress != nil {
						acmeSolver.HTTP01.Ingress = &certmanagerv1.ACMEChallengeSolverHTTP01Ingress{}

						// Add class if specified
						if solver.HTTP01.Ingress.Class != "" {
							acmeSolver.HTTP01.Ingress.Class = &solver.HTTP01.Ingress.Class
						}

						// Add name if specified
						if solver.HTTP01.Ingress.Name != "" {
							acmeSolver.HTTP01.Ingress.Name = &solver.HTTP01.Ingress.Name
						}
					}
				}

				// Add DNS01 solver if specified
				if solver.DNS01 != nil {
					acmeSolver.DNS01 = &certmanagerv1.ACMEChallengeSolverDNS01{
						// Add provider-specific configuration
						// This is a simplified implementation
						// In a real implementation, you would add provider-specific configuration
					}
				}

				// Add selector if specified
				if solver.Selector != nil {
					acmeSolver.Selector = &certmanagerv1.CertificateDNSNameSelector{}

					// Add DNS names if specified
					if len(solver.Selector.DNSNames) > 0 {
						acmeSolver.Selector.DNSNames = solver.Selector.DNSNames
					}

					// Add DNS zones if specified
					if len(solver.Selector.DNSZones) > 0 {
						acmeSolver.Selector.DNSZones = solver.Selector.DNSZones
					}
				}

				acmeIssuer.Solvers = append(acmeIssuer.Solvers, acmeSolver)
			}
		}

		issuerSpec = certmanagerv1.IssuerSpec{
			IssuerConfig: certmanagerv1.IssuerConfig{
				ACME: acmeIssuer,
			},
		}
	case "Vault":
		if config.Vault == nil || config.Vault.Server == "" || config.Vault.Path == "" {
			return nil, fmt.Errorf("Vault configuration is required for Vault issuer")
		}

		// Create Vault issuer
		vaultIssuer := &certmanagerv1.VaultIssuer{
			Server: config.Vault.Server,
			Path:   config.Vault.Path,
		}

		// Add authentication configuration
		if config.Vault.Auth.TokenSecretRef.Name != "" {
			vaultIssuer.Auth.TokenSecretRef = &certmanagerv1.SecretKeySelector{
				LocalObjectReference: certmanagerv1.LocalObjectReference{
					Name: config.Vault.Auth.TokenSecretRef.Name,
				},
				Key: config.Vault.Auth.TokenSecretRef.Key,
			}
		} else if config.Vault.Auth.AppRole != nil {
			vaultIssuer.Auth.AppRole = &certmanagerv1.VaultAppRole{
				Path:   config.Vault.Auth.AppRole.Path,
				RoleId: config.Vault.Auth.AppRole.RoleID,
				SecretRef: certmanagerv1.SecretKeySelector{
					LocalObjectReference: certmanagerv1.LocalObjectReference{
						Name: config.Vault.Auth.AppRole.SecretIDSecretRef.Name,
					},
					Key: config.Vault.Auth.AppRole.SecretIDSecretRef.Key,
				},
			}
		} else if config.Vault.Auth.Kubernetes != nil {
			vaultIssuer.Auth.Kubernetes = &certmanagerv1.VaultKubernetesAuth{
				Path: config.Vault.Auth.Kubernetes.Path,
				Role: config.Vault.Auth.Kubernetes.Role,
				ServiceAccountRef: &certmanagerv1.ServiceAccountRef{
					Name: config.Vault.Auth.Kubernetes.ServiceAccountRef.Name,
				},
			}
		}

		issuerSpec = certmanagerv1.IssuerSpec{
			IssuerConfig: certmanagerv1.IssuerConfig{
				Vault: vaultIssuer,
			},
		}
	default:
		return nil, fmt.Errorf("unsupported issuer type: %s", config.Type)
	}

	// Create the issuer
	issuer := &certmanagerv1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.Name,
			Namespace: config.Namespace,
		},
		Spec: issuerSpec,
	}

	// Create the issuer
	createdIssuer, err := m.certClient.CertmanagerV1().Issuers(config.Namespace).Create(
		m.ctx, issuer, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create issuer: %w", err)
	}

	klog.Infof("Created issuer %s in namespace %s", config.Name, config.Namespace)

	// Convert to internal Issuer type
	return m.convertIssuer(createdIssuer)
}

// GetIssuer gets an issuer by name
func (m *CertManager) GetIssuer(name string) (*Issuer, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if name == "" {
		return nil, fmt.Errorf("issuer name is required")
	}

	// Get the issuer from cert-manager
	issuer, err := m.certClient.CertmanagerV1().Issuers(m.config.DefaultNamespace).Get(
		m.ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer: %w", err)
	}

	// Convert to internal Issuer type
	return m.convertIssuer(issuer)
}

// ListIssuers lists all issuers
func (m *CertManager) ListIssuers() ([]*Issuer, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// List issuers from cert-manager
	issuerList, err := m.certClient.CertmanagerV1().Issuers(m.config.DefaultNamespace).List(
		m.ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list issuers: %w", err)
	}

	// Convert to internal Issuer type
	var issuers []*Issuer
	for _, issuer := range issuerList.Items {
		convertedIssuer, err := m.convertIssuer(&issuer)
		if err != nil {
			klog.Warningf("Failed to convert issuer %s: %v", issuer.Name, err)
			continue
		}
		issuers = append(issuers, convertedIssuer)
	}

	return issuers, nil
}

// convertCertificate converts a cert-manager Certificate to an internal Certificate
func (m *CertManager) convertCertificate(cert *certmanagerv1.Certificate) (*Certificate, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	// Create internal Certificate
	certificate := &Certificate{
		Name:       cert.Name,
		Namespace:  cert.Namespace,
		CommonName: cert.Spec.CommonName,
		DNSNames:   cert.Spec.DNSNames,
		SecretName: cert.Spec.SecretName,
	}

	// Set IP addresses if specified
	if len(cert.Spec.IPAddresses) > 0 {
		certificate.IPAddresses = cert.Spec.IPAddresses
	}

	// Set issuer
	if cert.Spec.IssuerRef.Name != "" {
		certificate.Issuer = cert.Spec.IssuerRef.Name
	}

	// Set status
	if len(cert.Status.Conditions) > 0 {
		for _, condition := range cert.Status.Conditions {
			certificateCondition := CertificateCondition{
				Type:               string(condition.Type),
				Status:             string(condition.Status),
				Reason:             condition.Reason,
				Message:            condition.Message,
				LastTransitionTime: condition.LastTransitionTime.Time,
			}
			certificate.Status.Conditions = append(certificate.Status.Conditions, certificateCondition)
		}
	}

	// Set renewal time
	if cert.Status.RenewalTime != nil {
		certificate.RenewalTime = cert.Status.RenewalTime.Time
	}

	// Set not before and not after times
	if cert.Status.NotBefore != nil {
		certificate.NotBefore = cert.Status.NotBefore.Time
	}

	if cert.Status.NotAfter != nil {
		certificate.NotAfter = cert.Status.NotAfter.Time
	}

	return certificate, nil
}

// convertIssuer converts a cert-manager Issuer to an internal Issuer
func (m *CertManager) convertIssuer(issuer *certmanagerv1.Issuer) (*Issuer, error) {
	if issuer == nil {
		return nil, fmt.Errorf("issuer is nil")
	}

	// Create internal Issuer
	internalIssuer := &Issuer{
		Name:         issuer.Name,
		Namespace:    issuer.Namespace,
		CreationTime: issuer.CreationTimestamp.Time,
	}

	// Set issuer type
	if issuer.Spec.SelfSigned != nil {
		internalIssuer.Type = "SelfSigned"
	} else if issuer.Spec.CA != nil {
		internalIssuer.Type = "CA"
	} else if issuer.Spec.ACME != nil {
		internalIssuer.Type = "ACME"
	} else if issuer.Spec.Vault != nil {
		internalIssuer.Type = "Vault"
	}

	// Set status
	if len(issuer.Status.Conditions) > 0 {
		for _, condition := range issuer.Status.Conditions {
			issuerCondition := IssuerCondition{
				Type:               string(condition.Type),
				Status:             string(condition.Status),
				Reason:             condition.Reason,
				Message:            condition.Message,
				LastTransitionTime: condition.LastTransitionTime.Time,
			}
			internalIssuer.Status.Conditions = append(internalIssuer.Status.Conditions, issuerCondition)
		}
	}

	return internalIssuer, nil
}
