package certificates

import (
	"context"
	"time"
)

// Manager defines the interface for certificate management
type Manager interface {
	// Initialize initializes the certificate manager
	Initialize(ctx context.Context) error

	// Shutdown shuts down the certificate manager
	Shutdown(ctx context.Context) error

	// CreateCertificate creates a new certificate
	CreateCertificate(config *CertificateConfig) (*Certificate, error)

	// GetCertificate gets a certificate by name
	GetCertificate(name string) (*Certificate, error)

	// ListCertificates lists all certificates
	ListCertificates() ([]*Certificate, error)

	// RevokeCertificate revokes a certificate
	RevokeCertificate(name string, reason string) error

	// RenewCertificate renews a certificate
	RenewCertificate(name string) (*Certificate, error)

	// CreateIssuer creates a certificate issuer
	CreateIssuer(config *IssuerConfig) (*Issuer, error)

	// GetIssuer gets an issuer by name
	GetIssuer(name string) (*Issuer, error)

	// ListIssuers lists all issuers
	ListIssuers() ([]*Issuer, error)
}

// CertificateConfig defines the configuration for a certificate
type CertificateConfig struct {
	// Name is the name of the certificate
	Name string

	// Namespace is the namespace for the certificate
	Namespace string

	// CommonName is the common name for the certificate
	CommonName string

	// DNSNames are the DNS names for the certificate
	DNSNames []string

	// IPAddresses are the IP addresses for the certificate
	IPAddresses []string

	// IssuerRef is a reference to the issuer
	IssuerRef IssuerRef

	// Duration is the duration of the certificate
	Duration time.Duration

	// RenewBefore is the time before expiration to renew the certificate
	RenewBefore time.Duration

	// SecretName is the name of the secret to store the certificate
	SecretName string

	// KeySize is the size of the private key
	KeySize int

	// KeyAlgorithm is the algorithm for the private key
	KeyAlgorithm string

	// KeyEncoding is the encoding for the private key
	KeyEncoding string

	// UsageType is the usage type for the certificate
	UsageType string

	// IsCA indicates whether this is a CA certificate
	IsCA bool
}

// Certificate represents a certificate
type Certificate struct {
	// Name is the name of the certificate
	Name string

	// Namespace is the namespace for the certificate
	Namespace string

	// CommonName is the common name for the certificate
	CommonName string

	// DNSNames are the DNS names for the certificate
	DNSNames []string

	// IPAddresses are the IP addresses for the certificate
	IPAddresses []string

	// Issuer is the issuer of the certificate
	Issuer string

	// NotBefore is the time when the certificate becomes valid
	NotBefore time.Time

	// NotAfter is the time when the certificate expires
	NotAfter time.Time

	// SerialNumber is the serial number of the certificate
	SerialNumber string

	// Status is the status of the certificate
	Status CertificateStatus

	// SecretName is the name of the secret containing the certificate
	SecretName string

	// RenewalTime is the time when the certificate will be renewed
	RenewalTime time.Time
}

// CertificateStatus represents the status of a certificate
type CertificateStatus struct {
	// Conditions are the conditions of the certificate
	Conditions []CertificateCondition

	// LastFailureTime is the time of the last failure
	LastFailureTime time.Time

	// LastFailureMessage is the message of the last failure
	LastFailureMessage string

	// RenewalStatus is the status of the renewal
	RenewalStatus string

	// RevocationStatus is the status of the revocation
	RevocationStatus string
}

// CertificateCondition represents a condition of a certificate
type CertificateCondition struct {
	// Type is the type of the condition
	Type string

	// Status is the status of the condition
	Status string

	// Reason is the reason for the condition
	Reason string

	// Message is the message for the condition
	Message string

	// LastTransitionTime is the time of the last transition
	LastTransitionTime time.Time
}

// IssuerConfig defines the configuration for a certificate issuer
type IssuerConfig struct {
	// Name is the name of the issuer
	Name string

	// Namespace is the namespace for the issuer
	Namespace string

	// Type is the type of the issuer (e.g., SelfSigned, CA, ACME)
	Type string

	// ACME is the ACME configuration for the issuer
	ACME *ACMEConfig

	// CA is the CA configuration for the issuer
	CA *CAConfig

	// SelfSigned is the self-signed configuration for the issuer
	SelfSigned *SelfSignedConfig

	// Vault is the Vault configuration for the issuer
	Vault *VaultConfig
}

// ACMEConfig defines the ACME configuration for an issuer
type ACMEConfig struct {
	// Server is the ACME server URL
	Server string

	// Email is the email address for the ACME account
	Email string

	// PrivateKeySecretRef is a reference to the secret containing the private key
	PrivateKeySecretRef SecretRef

	// Solvers are the ACME challenge solvers
	Solvers []ACMESolver
}

// ACMESolver defines an ACME challenge solver
type ACMESolver struct {
	// HTTP01 is the HTTP01 challenge solver
	HTTP01 *HTTP01Solver

	// DNS01 is the DNS01 challenge solver
	DNS01 *DNS01Solver

	// Selector is the selector for the solver
	Selector *ACMESolverSelector
}

// HTTP01Solver defines an HTTP01 challenge solver
type HTTP01Solver struct {
	// Ingress is the ingress configuration for the solver
	Ingress *HTTP01IngressSolver
}

// HTTP01IngressSolver defines an HTTP01 ingress challenge solver
type HTTP01IngressSolver struct {
	// Class is the ingress class for the solver
	Class string

	// Name is the name of the ingress for the solver
	Name string
}

// DNS01Solver defines a DNS01 challenge solver
type DNS01Solver struct {
	// Provider is the DNS provider for the solver
	Provider string

	// Config is the configuration for the DNS provider
	Config map[string]string
}

// ACMESolverSelector defines a selector for an ACME challenge solver
type ACMESolverSelector struct {
	// DNSNames are the DNS names for the selector
	DNSNames []string

	// DNSZones are the DNS zones for the selector
	DNSZones []string
}

// CAConfig defines the CA configuration for an issuer
type CAConfig struct {
	// SecretName is the name of the secret containing the CA certificate
	SecretName string
}

// SelfSignedConfig defines the self-signed configuration for an issuer
type SelfSignedConfig struct {
	// CRLDistributionPoints are the CRL distribution points
	CRLDistributionPoints []string
}

// VaultConfig defines the Vault configuration for an issuer
type VaultConfig struct {
	// Server is the Vault server URL
	Server string

	// Path is the path to the PKI backend
	Path string

	// Auth is the authentication configuration for Vault
	Auth VaultAuth
}

// VaultAuth defines the authentication configuration for Vault
type VaultAuth struct {
	// TokenSecretRef is a reference to the secret containing the token
	TokenSecretRef SecretRef

	// AppRole is the AppRole authentication configuration
	AppRole *VaultAppRole

	// Kubernetes is the Kubernetes authentication configuration
	Kubernetes *VaultKubernetes
}

// VaultAppRole defines the AppRole authentication configuration for Vault
type VaultAppRole struct {
	// Path is the path to the AppRole auth backend
	Path string

	// RoleID is the role ID for the AppRole
	RoleID string

	// SecretIDSecretRef is a reference to the secret containing the secret ID
	SecretIDSecretRef SecretRef
}

// VaultKubernetes defines the Kubernetes authentication configuration for Vault
type VaultKubernetes struct {
	// Path is the path to the Kubernetes auth backend
	Path string

	// Role is the role for Kubernetes auth
	Role string

	// ServiceAccountRef is a reference to the service account
	ServiceAccountRef ServiceAccountRef
}

// Issuer represents a certificate issuer
type Issuer struct {
	// Name is the name of the issuer
	Name string

	// Namespace is the namespace for the issuer
	Namespace string

	// Type is the type of the issuer
	Type string

	// Status is the status of the issuer
	Status IssuerStatus

	// CreationTime is the time when the issuer was created
	CreationTime time.Time
}

// IssuerStatus represents the status of an issuer
type IssuerStatus struct {
	// Conditions are the conditions of the issuer
	Conditions []IssuerCondition

	// LastFailureTime is the time of the last failure
	LastFailureTime time.Time

	// LastFailureMessage is the message of the last failure
	LastFailureMessage string
}

// IssuerCondition represents a condition of an issuer
type IssuerCondition struct {
	// Type is the type of the condition
	Type string

	// Status is the status of the condition
	Status string

	// Reason is the reason for the condition
	Reason string

	// Message is the message for the condition
	Message string

	// LastTransitionTime is the time of the last transition
	LastTransitionTime time.Time
}

// IssuerRef is a reference to an issuer
type IssuerRef struct {
	// Name is the name of the issuer
	Name string

	// Kind is the kind of the issuer
	Kind string

	// Group is the group of the issuer
	Group string
}

// SecretRef is a reference to a secret
type SecretRef struct {
	// Name is the name of the secret
	Name string

	// Key is the key in the secret
	Key string
}

// ServiceAccountRef is a reference to a service account
type ServiceAccountRef struct {
	// Name is the name of the service account
	Name string
}
