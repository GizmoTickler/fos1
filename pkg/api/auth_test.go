package api_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GizmoTickler/fos1/pkg/api"
)

func TestStaticAllowlistAuthorize(t *testing.T) {
	t.Parallel()
	al := api.NewStaticAllowlist([]string{"alice", "bob"})
	require.NoError(t, al.Authorize("alice"))
	require.NoError(t, al.Authorize("bob"))
	require.Error(t, al.Authorize("carol"))
	require.Error(t, al.Authorize(""))
}

func TestStaticAllowlistIgnoresEmptyEntries(t *testing.T) {
	t.Parallel()
	al := api.NewStaticAllowlist([]string{"alice", "", "bob"})
	require.NoError(t, al.Authorize("alice"))
	require.NoError(t, al.Authorize("bob"))
	require.Error(t, al.Authorize(""))
}

func TestStaticAllowlistSetReplaces(t *testing.T) {
	t.Parallel()
	al := api.NewStaticAllowlist([]string{"alice"})
	require.NoError(t, al.Authorize("alice"))
	al.Set([]string{"bob"})
	require.Error(t, al.Authorize("alice"))
	require.NoError(t, al.Authorize("bob"))
}

// TestAuthMiddlewareUnauthorizedReturns403 exercises the middleware directly
// by simulating a TLS state with a subject that is not in the allowlist.
func TestAuthMiddlewareUnauthorizedReturns403(t *testing.T) {
	t.Parallel()
	srv := &api.Server{
		Client:     newFakeClient(t),
		Authorizer: api.NewStaticAllowlist([]string{"alice"}),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies", nil)
	req.TLS = peerTLSState(t, "carol")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Forbidden")
	assert.Contains(t, rr.Body.String(), "carol")
}

// TestAuthMiddlewareAuthorizedPasses verifies an allowlisted subject reaches
// the downstream handler.
func TestAuthMiddlewareAuthorizedPasses(t *testing.T) {
	t.Parallel()
	srv := &api.Server{
		Client:     newFakeClient(t),
		Authorizer: api.NewStaticAllowlist([]string{"alice"}),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies", nil)
	req.TLS = peerTLSState(t, "alice")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

// TestPublicRoutesSkipAllowlist confirms /healthz, /readyz and /openapi.json
// do not require allowlist membership. The TLS handshake is still required
// in production (RequireAndVerifyClientCert) but an accepted handshake from
// any CA-signed cert is enough to hit these endpoints — by design.
func TestPublicRoutesSkipAllowlist(t *testing.T) {
	t.Parallel()
	srv := &api.Server{
		Client:     newFakeClient(t),
		Authorizer: api.NewStaticAllowlist([]string{}),
	}

	for _, path := range []string{"/healthz", "/readyz", "/openapi.json"} {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.TLS = peerTLSState(t, "no-allowlist")
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "path %s", path)
		})
	}
}

// TestAuthMiddlewareNoAuthorizerFailsClosed ensures the middleware denies
// every request when Authorizer is nil. Management surfaces must fail
// closed; this test makes that contract load-bearing.
func TestAuthMiddlewareNoAuthorizerFailsClosed(t *testing.T) {
	t.Parallel()
	srv := &api.Server{
		Client:     newFakeClient(t),
		Authorizer: nil,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/filter-policies", nil)
	req.TLS = peerTLSState(t, "alice")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// peerTLSState synthesizes a *tls.ConnectionState with a verified chain
// whose leaf has the given Common Name. The certificate content beyond CN
// is arbitrary — we only exercise the subject extraction code path, not
// chain validation (which is the TLS stack's job).
func peerTLSState(t *testing.T, cn string) *tls.ConnectionState {
	t.Helper()
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	return &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
		VerifiedChains:    [][]*x509.Certificate{{cert}},
	}
}
