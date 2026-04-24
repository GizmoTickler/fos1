package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GizmoTickler/fos1/pkg/api"
)

// TestNewServerValidatesInputs asserts NewServer fails fast on missing
// required paths. Early construction errors save us from booting a manager
// only to fail when the TLS listener refuses to open.
func TestNewServerValidatesInputs(t *testing.T) {
	t.Parallel()

	c := newFakeClient(t)

	tests := []struct {
		name string
		cfg  api.ServerConfig
	}{
		{"missing server cert", api.ServerConfig{ServerKeyFile: "k", ClientCAFile: "c"}},
		{"missing server key", api.ServerConfig{ServerCertFile: "s", ClientCAFile: "c"}},
		{"missing client CA", api.ServerConfig{ServerCertFile: "s", ServerKeyFile: "k"}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := api.NewServer(c, tc.cfg)
			require.Error(t, err)
		})
	}
}

func TestNewServerAppliesDefaults(t *testing.T) {
	t.Parallel()
	c := newFakeClient(t)
	srv, err := api.NewServer(c, api.ServerConfig{
		ServerCertFile: "s",
		ServerKeyFile:  "k",
		ClientCAFile:   "ca",
	})
	require.NoError(t, err)
	assert.Equal(t, api.DefaultListenAddress, srv.Config.Address)
	assert.Equal(t, api.DefaultReadTimeout, srv.Config.ReadTimeout)
	assert.Equal(t, api.DefaultWriteTimeout, srv.Config.WriteTimeout)
}

// TestOpenAPIEndpointServesEmbeddedSpec confirms the Go binary serves the
// exact bytes stored at pkg/api/testdata/openapi.json. We compare the JSON
// object, not the raw bytes, to tolerate trailing whitespace differences
// produced by the encoder.
func TestOpenAPIEndpointServesEmbeddedSpec(t *testing.T) {
	t.Parallel()
	srv := &api.Server{
		Client:     newFakeClient(t),
		Authorizer: allowAll{},
	}
	req, err := http.NewRequest(http.MethodGet, "/openapi.json", nil)
	require.NoError(t, err)
	rr := newResponseRecorder()
	srv.Handler().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	// Decode both the served document and the file on disk; they must
	// describe the same OpenAPI paths.
	var served map[string]any
	require.NoError(t, json.Unmarshal(rr.Body, &served))

	disk, err := os.ReadFile("testdata/openapi.json")
	require.NoError(t, err)
	var fromDisk map[string]any
	require.NoError(t, json.Unmarshal(disk, &fromDisk))

	assert.Equal(t, fromDisk["paths"], served["paths"])
	assert.Equal(t, fromDisk["info"], served["info"])
}

// TestMTLSEndToEnd spins up a live Server on :0, generates a CA + server +
// two client certs (one allowlisted, one not), and verifies:
//
//   - an authorized client can list FilterPolicy
//   - an unauthorized (CN not in allowlist) client with a cert from the
//     same CA receives a 403
//   - a client with no certificate is rejected at the TLS layer (handshake
//     failure, not a 403)
//
// This test is the single integration point that exercises the real TLS
// stack. Handler-level unit tests elsewhere cover the rest of the surface.
func TestMTLSEndToEnd(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	caCert, caKey := generateCA(t)
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", caCert.Raw)

	serverCert, serverKey := generateCert(t, caCert, caKey, "localhost", true)
	writePEM(t, filepath.Join(dir, "server.crt"), "CERTIFICATE", serverCert.Raw)
	writeKeyPEM(t, filepath.Join(dir, "server.key"), serverKey)

	allowedCert, allowedKey := generateCert(t, caCert, caKey, "allowed-client", false)
	deniedCert, deniedKey := generateCert(t, caCert, caKey, "denied-client", false)

	cfg := api.ServerConfig{
		Address:        "127.0.0.1:0",
		ServerCertFile: filepath.Join(dir, "server.crt"),
		ServerKeyFile:  filepath.Join(dir, "server.key"),
		ClientCAFile:   filepath.Join(dir, "ca.crt"),
		Allowlist:      []string{"allowed-client"},
	}
	srv, err := api.NewServer(newFakeClient(t), cfg)
	require.NoError(t, err)

	// Bind a listener on a random port; we'll hand it to http.Serve via
	// the tls.Listener wrapped inside Run. To avoid race conditions on
	// picking the port we run Run in a goroutine and poll until the
	// listener accepts a connection.
	addr, stop := runServerOnEphemeralPort(t, srv)
	defer stop()

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	allowedClient := newMTLSClient(t, caPool, allowedCert, allowedKey)
	deniedClient := newMTLSClient(t, caPool, deniedCert, deniedKey)
	plainClient := newPlainTLSClient(t, caPool)

	t.Run("allowed client gets 200", func(t *testing.T) {
		resp, err := allowedClient.Get(fmt.Sprintf("https://%s/v1/filter-policies", addr))
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", string(body))
	})

	t.Run("denied client gets 403", func(t *testing.T) {
		resp, err := deniedClient.Get(fmt.Sprintf("https://%s/v1/filter-policies", addr))
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "body: %s", string(body))
		assert.Contains(t, string(body), "denied-client")
	})

	t.Run("client without cert fails handshake", func(t *testing.T) {
		_, err := plainClient.Get(fmt.Sprintf("https://%s/v1/filter-policies", addr))
		require.Error(t, err, "TLS handshake must reject clients without a certificate")
	})

	t.Run("public endpoints reachable by any trusted cert", func(t *testing.T) {
		resp, err := deniedClient.Get(fmt.Sprintf("https://%s/healthz", addr))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("allowed client can POST a new FilterPolicy", func(t *testing.T) {
		body := bytes.NewBuffer(nil)
		require.NoError(t, json.NewEncoder(body).Encode(fixturePolicy("security", "mtls-created")))
		req, err := http.NewRequest(http.MethodPost,
			fmt.Sprintf("https://%s/v1/filter-policies", addr), body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := allowedClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusCreated, resp.StatusCode, "body: %s", string(respBody))
	})

	t.Run("denied client cannot POST a new FilterPolicy", func(t *testing.T) {
		body := bytes.NewBuffer(nil)
		require.NoError(t, json.NewEncoder(body).Encode(fixturePolicy("security", "mtls-denied")))
		req, err := http.NewRequest(http.MethodPost,
			fmt.Sprintf("https://%s/v1/filter-policies", addr), body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := deniedClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

// runServerOnEphemeralPort starts srv.Run on ctx-derived lifecycle and
// returns the address the server is listening on and a teardown function.
// We discover the port by opening a listener ourselves first, closing it,
// and handing the address back — the server will reopen the same port on
// Run.
func runServerOnEphemeralPort(t *testing.T, srv *api.Server) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	srv.Config.Address = addr

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv.Run(ctx)
	}()

	// Wait until the listener is actually accepting.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr, func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatalf("server did not shut down in time")
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	t.Fatalf("server never started listening on %s", addr)
	return "", func() {}
}

func newMTLSClient(t *testing.T, caPool *x509.CertPool, cert *x509.Certificate, key *ecdsa.PrivateKey) *http.Client {
	t.Helper()
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				Certificates: []tls.Certificate{tlsCert},
				ServerName:   "localhost",
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}

func newPlainTLSClient(t *testing.T, caPool *x509.CertPool) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: "localhost",
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// generateCA returns a self-signed CA certificate and its private key.
func generateCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fos1-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return parsed, key
}

// generateCert signs a leaf certificate under the supplied CA. If server is
// true the certificate carries the ServerAuth extended key usage and a SAN
// for localhost + 127.0.0.1; otherwise it is configured as a client
// certificate.
func generateCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, server bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return parsed, key
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: typ, Bytes: der}))
}

func writeKeyPEM(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	writePEM(t, path, "EC PRIVATE KEY", der)
}

// responseRecorder is a minimal httptest-style response writer that keeps
// the body as a slice so tests can assert on bytes without round-tripping
// through a ResponseRecorder.
type responseRecorder struct {
	Code    int
	Body    []byte
	headers http.Header
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{Code: http.StatusOK, headers: http.Header{}}
}

func (r *responseRecorder) Header() http.Header { return r.headers }

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.Body = append(r.Body, b...)
	return len(b), nil
}

func (r *responseRecorder) WriteHeader(status int) { r.Code = status }
