package certificates

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// LoadMutualTLSConfig loads the cert-manager-mounted tls.crt / tls.key /
// ca.crt bundle and configures it for both server-side client verification
// and client-side peer verification. It is the shared Sprint 32 controller
// mesh primitive: the same fos1-internal-ca bundle signs server and client
// identities, so ca.crt is installed as both ClientCAs and RootCAs.
func LoadMutualTLSConfig(certDir string) (*tls.Config, *TLSReloader, error) {
	cfg, reloader, err := LoadTLSConfig(certDir)
	if err != nil {
		return nil, nil, err
	}

	cfg.ClientCAs = reloader.CABundle()
	cfg.RootCAs = reloader.CABundle()
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert := reloader.Certificate()
		if cert == nil {
			return nil, fmt.Errorf("certificates: TLS reloader has no client certificate loaded")
		}
		return cert, nil
	}

	return cfg, reloader, nil
}

// NewMutualTLSHTTPClient returns an HTTP client whose transport presents the
// mounted controller certificate and trusts the mounted fos1-internal-ca
// bundle. Callers that need a specific DNS name should set serverName.
func NewMutualTLSHTTPClient(certDir, serverName string) (*http.Client, *TLSReloader, error) {
	cfg, reloader, err := LoadMutualTLSConfig(certDir)
	if err != nil {
		return nil, nil, err
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
	}, reloader, nil
}

// SubjectAllowlist is a thread-safe deny-by-default allowlist for peer
// certificate Subject Common Names.
type SubjectAllowlist struct {
	mu      sync.RWMutex
	allowed map[string]struct{}
}

// NewSubjectAllowlist constructs an allowlist from Subject Common Names.
// Empty entries are ignored. An empty allowlist denies every request.
func NewSubjectAllowlist(cns []string) *SubjectAllowlist {
	a := &SubjectAllowlist{}
	a.Set(cns)
	return a
}

// Set replaces the allowlist contents atomically.
func (a *SubjectAllowlist) Set(cns []string) {
	set := make(map[string]struct{}, len(cns))
	for _, cn := range cns {
		if cn == "" {
			continue
		}
		set[cn] = struct{}{}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.allowed = set
}

// Allows reports whether cn is present in the allowlist.
func (a *SubjectAllowlist) Allows(cn string) bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.allowed[cn]
	return ok
}

// RequireAllowedPeerSubject wraps an HTTP handler with Subject-CN allowlist
// enforcement. It assumes the surrounding tls.Config already uses
// RequireAndVerifyClientCert, but still fails closed when TLS state is absent
// so tests and miswired servers cannot accidentally bypass authorization.
func RequireAllowedPeerSubject(allowed []string, next http.Handler) http.Handler {
	return RequirePeerSubject(NewSubjectAllowlist(allowed), next)
}

// RequirePeerSubject is the handler form for callers that keep a mutable
// allowlist object.
func RequirePeerSubject(allowlist *SubjectAllowlist, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject := peerSubjectCN(r.TLS)
		if !allowlist.Allows(subject) {
			writePeerForbidden(w, subject)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func peerSubjectCN(state *tls.ConnectionState) string {
	if state == nil {
		return ""
	}
	if len(state.VerifiedChains) > 0 && len(state.VerifiedChains[0]) > 0 {
		return state.VerifiedChains[0][0].Subject.CommonName
	}
	if len(state.PeerCertificates) > 0 {
		return state.PeerCertificates[0].Subject.CommonName
	}
	return ""
}

func writePeerForbidden(w http.ResponseWriter, subject string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind":    "Status",
		"status":  "Failure",
		"code":    http.StatusForbidden,
		"reason":  "Forbidden",
		"message": "subject not in allowlist",
		"subject": subject,
	})
}
