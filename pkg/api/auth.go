package api

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"sync"
)

// Authorizer decides whether a client presented by the TLS handshake is
// permitted to call the API. It is kept as an interface so tests can inject
// a deterministic decision without going through the TLS stack.
type Authorizer interface {
	// Authorize returns nil if the subject is permitted, or an error with a
	// human-readable message explaining the denial otherwise. The error is
	// surfaced as the 403 body; callers must not include sensitive data.
	Authorize(subjectCN string) error
}

// StaticAllowlist is an Authorizer backed by a fixed set of client-cert
// Subject Common Names. The allowlist is intended to be populated from a
// ConfigMap or command-line argument at bootstrap; live reloading is out of
// scope for v0.
type StaticAllowlist struct {
	mu      sync.RWMutex
	allowed map[string]struct{}
}

// NewStaticAllowlist constructs a StaticAllowlist from a slice of Common
// Names. Nil or empty input produces an empty allowlist — every caller will
// then receive 403 until the allowlist is populated.
func NewStaticAllowlist(cns []string) *StaticAllowlist {
	set := make(map[string]struct{}, len(cns))
	for _, cn := range cns {
		if cn == "" {
			continue
		}
		set[cn] = struct{}{}
	}
	return &StaticAllowlist{allowed: set}
}

// Set replaces the current allowlist contents atomically. It is intended
// for test injection; production callers do not mutate the allowlist after
// construction in v0.
func (a *StaticAllowlist) Set(cns []string) {
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

// Authorize implements Authorizer. It returns nil if cn is allowlisted.
func (a *StaticAllowlist) Authorize(cn string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if _, ok := a.allowed[cn]; ok {
		return nil
	}
	return &forbiddenError{reason: "subject not in allowlist", subject: cn}
}

// forbiddenError encodes a denial reason so the middleware can emit a
// JSON body without the handler knowing the HTTP shape.
type forbiddenError struct {
	reason  string
	subject string
}

func (e *forbiddenError) Error() string {
	return e.reason
}

// authMiddleware wraps next in mTLS subject extraction and allowlist
// enforcement. It assumes the surrounding tls.Config uses
// RequireAndVerifyClientCert, so the presence of at least one verified
// chain is guaranteed before the handler runs. If no authorizer is set the
// middleware treats the request as denied — fail-closed is the correct
// posture for a management surface.
func authMiddleware(auth Authorizer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health and OpenAPI paths are cheap and safe to expose to every
		// caller that successfully completed the mTLS handshake. The
		// handshake itself is the authentication bar; we still require
		// allowlist membership for every data-plane endpoint.
		path := r.URL.Path
		isPublic := path == "/healthz" || path == "/readyz" || path == "/openapi.json"

		// Extract the verified client-cert subject. With
		// RequireAndVerifyClientCert in place, VerifiedChains is guaranteed
		// to be non-empty for non-nil TLS state.
		cn := extractSubjectCN(r.TLS)

		if !isPublic {
			if auth == nil {
				writeForbidden(w, "no authorizer configured", cn)
				return
			}
			if err := auth.Authorize(cn); err != nil {
				writeForbidden(w, err.Error(), cn)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// extractSubjectCN returns the Common Name of the leaf certificate from
// the first verified chain. The empty string is returned if the TLS state
// is unavailable — callers treat this as an unauthorized subject.
func extractSubjectCN(state *tls.ConnectionState) string {
	if state == nil {
		return ""
	}
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		// Fall back to PeerCertificates for non-verified states; production
		// code runs behind RequireAndVerifyClientCert so this branch is
		// only exercised in tests that bypass TLS verification.
		if len(state.PeerCertificates) == 0 {
			return ""
		}
		return state.PeerCertificates[0].Subject.CommonName
	}
	return state.VerifiedChains[0][0].Subject.CommonName
}

// writeForbidden emits a machine-readable 403 body. The response uses the
// same error envelope as the FilterPolicy handler so clients can share a
// single decode path.
func writeForbidden(w http.ResponseWriter, reason, subject string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	payload := map[string]any{
		"kind":    "Status",
		"status":  "Failure",
		"code":    http.StatusForbidden,
		"reason":  "Forbidden",
		"message": reason,
		"subject": subject,
	}
	_ = json.NewEncoder(w).Encode(payload)
}
