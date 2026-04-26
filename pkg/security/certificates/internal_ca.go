// Package certificates: internal_ca.go documents the trust-anchor model for
// inter-controller TLS introduced in Sprint 31 / Ticket 49.
//
// Trust chain:
//
//	fos1-internal-ca-root  (self-signed, 10y, RSA 4096)
//	    └── ClusterIssuer fos1-internal-ca   (CA-typed, key in cluster Secret)
//	            └── Certificate <controller>-tls   (server auth, 90d / 15d renew)
//
// Every owned controller mounts its `<controller>-tls` Secret at
// DefaultTLSMountPath and loads it through tlsconfig.LoadTLSConfig. Renewals
// trigger an fsnotify-driven reload — no pod restart is required.
//
// This file deliberately does NOT construct cert-manager objects from Go
// code: the cert chain is GitOps-managed under
// manifests/base/certificates/cluster-issuer-internal.yaml so an operator
// can review and audit it before rollout. The constants here exist so
// controller code and tests can refer to canonical names without
// stringly-typed drift between the manifest and the loader.
package certificates

const (
	// InternalRootIssuerName is the self-signed root ClusterIssuer that
	// underwrites the rest of the chain. It is intentionally distinct from
	// the day-to-day issuer so a key rotation can issue a new root
	// without invalidating all in-flight certs at once.
	InternalRootIssuerName = "fos1-internal-ca-root"

	// InternalCAIssuerName is the CA-typed ClusterIssuer every owned
	// controller Certificate references. Rotation strategy: provision a
	// new root, re-issue the intermediate, update this issuer's caRef,
	// trigger a sweeping renewal via `cmctl renew --all`.
	InternalCAIssuerName = "fos1-internal-ca"

	// InternalRootCertName is the cert-manager Certificate object that
	// produces the root key + cert in a Secret consumed by the
	// fos1-internal-ca CA-typed ClusterIssuer.
	InternalRootCertName = "fos1-internal-ca-root"

	// InternalRootSecretName is the Kubernetes Secret holding the root
	// certificate and private key. It lives in the cert-manager namespace
	// because that is the only namespace cert-manager consults for
	// CA-typed ClusterIssuer secrets.
	InternalRootSecretName = "fos1-internal-ca-root"

	// InternalCANamespace is where root + intermediate Secrets live.
	// cert-manager v1.x reads CA secrets from its own namespace by
	// default; this is overridable via the issuer spec but we follow the
	// default to keep the manifest minimal.
	InternalCANamespace = "cert-manager"
)

// ControllerCertSpec is the canonical per-controller Certificate metadata.
// It is consumed by tests that assert manifest shape; the runtime path does
// not synthesize Certificate objects in Go.
type ControllerCertSpec struct {
	// Name is the cert-manager Certificate object name. By convention
	// `<controller>-tls`.
	Name string

	// Namespace is the namespace the controller deploys into.
	Namespace string

	// SecretName is the Kubernetes Secret cert-manager writes the
	// material to. By convention identical to Name so a single label
	// selects both.
	SecretName string

	// ServiceName is the Kubernetes Service in front of the controller
	// pods. Used to derive the SAN list.
	ServiceName string
}

// SANs returns the canonical Subject Alternative Names for the controller
// cert. Two forms are emitted: the short form `<svc>.<ns>.svc` and the
// fully qualified `<svc>.<ns>.svc.cluster.local`. Anything dialing the
// service with kube-dns gets a hit on at least one.
func (s ControllerCertSpec) SANs() []string {
	return []string{
		s.ServiceName + "." + s.Namespace + ".svc",
		s.ServiceName + "." + s.Namespace + ".svc.cluster.local",
	}
}
