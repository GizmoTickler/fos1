// Package api implements the REST management API for the fos1
// router/firewall. It exposes a single resource family, FilterPolicy, over
// HTTPS with mTLS client-cert authentication. The server is backed by a
// controller-runtime client so it shares a cached view of the cluster with
// other in-process controllers when run side-by-side.
//
// Scope: Sprint 30 Ticket 41 shipped list/get (read-only v0). Sprint 31
// Ticket 48 adds Create (POST), Replace (PUT), Patch (JSON Merge Patch /
// Strategic Merge Patch), and Delete verbs. Watch / streaming endpoints
// and additional resource families (NAT, routing, DPI, zones) remain
// explicit non-goals. See docs/design/api-server.md for the full
// architecture and the list of explicit deferrals.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/GizmoTickler/fos1/pkg/security/certificates"
)

// DefaultListenAddress is the mTLS listen socket used when the caller does
// not override ServerConfig.Address. 8443 is the convention for internal
// HTTPS management endpoints in this repository.
const DefaultListenAddress = ":8443"

// DefaultReadTimeout bounds request reads to protect the server from slow-
// loris-style misuse. Management clients are expected to be fast and
// machine-generated so a short timeout is appropriate.
const DefaultReadTimeout = 15 * time.Second

// DefaultWriteTimeout bounds response writes for the same reason.
const DefaultWriteTimeout = 30 * time.Second

// Readiness is an interface exposed by components that can report whether
// they are ready to serve traffic. The readyz handler consults the informer
// cache via this interface.
type Readiness interface {
	// Ready returns nil if the component is ready to serve traffic, and a
	// non-nil error describing why it is not otherwise.
	Ready(ctx context.Context) error
}

// ServerConfig captures the inputs to build and run the API server.
type ServerConfig struct {
	// Address is the TCP listen address (host:port). If empty,
	// DefaultListenAddress is used.
	Address string

	// CertDir is the directory holding tls.crt / tls.key / ca.crt as
	// written by cert-manager. When set it takes precedence over the
	// per-file ServerCertFile/ServerKeyFile/ClientCAFile fields and the
	// server picks up rotation via certificates.WatchAndReload. This is
	// the Sprint 31 / Ticket 49 path; the per-file fields remain for
	// backward-compatibility with overlays that point at custom paths.
	CertDir string

	// ServerCertFile is the path to the PEM-encoded server certificate.
	// cert-manager typically mounts it as tls.crt inside a Secret.
	// Ignored when CertDir is set.
	ServerCertFile string

	// ServerKeyFile is the path to the PEM-encoded server private key.
	// cert-manager typically mounts it as tls.key inside a Secret.
	// Ignored when CertDir is set.
	ServerKeyFile string

	// ClientCAFile is the path to the PEM-encoded CA bundle used to verify
	// client certificates. The bundle identifies the trust anchor for
	// accepted callers; every client presenting a cert chain rooted in this
	// bundle is authenticated at the TLS layer. Authorization still requires
	// the subject to appear in Allowlist. Ignored when CertDir is set —
	// in that case ca.crt under CertDir is used as the client CA bundle.
	ClientCAFile string

	// Allowlist is the set of client-cert Subject Common Names authorized to
	// call the API. A caller whose cert chains to ClientCAFile but whose CN
	// is not in this set receives a 403.
	Allowlist []string

	// ReadTimeout bounds request reads. Zero means DefaultReadTimeout.
	ReadTimeout time.Duration

	// WriteTimeout bounds response writes. Zero means DefaultWriteTimeout.
	WriteTimeout time.Duration
}

// Server is the read-only REST management API. It is built around the
// controller-runtime client.Client interface so tests can drive it with a
// fake client and production can share the cached manager client.
type Server struct {
	// Client is a read-capable Kubernetes client. The handlers only use
	// List/Get so the implementation may be a cached controller-runtime
	// client or a direct one; the choice is a concern of the caller.
	Client client.Client

	// Config is the validated configuration used to construct the server.
	Config ServerConfig

	// Readiness, if set, is consulted by readyz_handler. If nil the
	// /readyz endpoint reports ready immediately.
	Readiness Readiness

	// Authorizer extracts client identity from the TLS connection and
	// consults the allowlist. It is pluggable so tests can inject a fake.
	Authorizer Authorizer
}

// NewServer constructs a Server from a controller-runtime client and a
// ServerConfig. It validates that required cert/key/CA paths are set but
// does not yet touch the filesystem — Run is responsible for loading files
// and building tls.Config. Returning construction errors early lets the
// caller fail fast before any Kubernetes informer cache is started.
func NewServer(c client.Client, cfg ServerConfig) (*Server, error) {
	if c == nil {
		return nil, errors.New("api: nil controller-runtime client")
	}
	if cfg.CertDir == "" {
		// Backward-compat path: every per-file field must be set.
		if cfg.ServerCertFile == "" {
			return nil, errors.New("api: ServerCertFile is required (or set CertDir)")
		}
		if cfg.ServerKeyFile == "" {
			return nil, errors.New("api: ServerKeyFile is required (or set CertDir)")
		}
		if cfg.ClientCAFile == "" {
			return nil, errors.New("api: ClientCAFile is required (or set CertDir)")
		}
	}
	if cfg.Address == "" {
		cfg.Address = DefaultListenAddress
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = DefaultReadTimeout
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = DefaultWriteTimeout
	}
	allow := NewStaticAllowlist(cfg.Allowlist)
	return &Server{
		Client:     c,
		Config:     cfg,
		Authorizer: allow,
	}, nil
}

// Handler returns the http.Handler that serves the API. It is exported so
// tests can drive it without building a TLS listener.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// List/Create FilterPolicy on the collection route; Get/Replace/
	// Patch/Delete on the item route. handleList and handleItem
	// internally dispatch on HTTP method.
	fpHandler := &FilterPolicyHandler{Client: s.Client}
	mux.HandleFunc("/v1/filter-policies", fpHandler.handleList)
	mux.HandleFunc("/v1/filter-policies/", fpHandler.handleItem)

	// Health probes. /healthz is cheap; /readyz consults the informer
	// cache via Readiness.
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/readyz", readyzHandler(s.Readiness))

	// Static OpenAPI document for the v0 surface.
	mux.Handle("/openapi.json", openAPIHandler())

	// Wrap the mux in mTLS subject extraction + allowlist enforcement.
	return authMiddleware(s.Authorizer, mux)
}

// Run starts the HTTPS server and blocks until ctx is canceled or a fatal
// error occurs. It performs graceful shutdown on context cancellation.
func (s *Server) Run(ctx context.Context) error {
	tlsConfig, reloader, err := buildTLSConfig(s.Config)
	if err != nil {
		return fmt.Errorf("api: build TLS config: %w", err)
	}

	// Sprint 31 / Ticket 49: when CertDir is configured the shared
	// certificates.TLSReloader watches the mount for cert-manager
	// rotation and swaps the active certificate in place. The HTTP
	// listener never bounces; in-flight handshakes always observe a
	// valid cert because tls.Config.GetCertificate is the single source
	// of truth.
	if reloader != nil {
		go func() {
			if werr := reloader.WatchAndReload(ctx, nil, tlsConfig, nil); werr != nil {
				klog.ErrorS(werr, "api server: TLS watcher exited")
			}
		}()
	}

	srv := &http.Server{
		Addr:         s.Config.Address,
		Handler:      s.Handler(),
		TLSConfig:    tlsConfig,
		ReadTimeout:  s.Config.ReadTimeout,
		WriteTimeout: s.Config.WriteTimeout,
	}

	listener, err := tls.Listen("tcp", s.Config.Address, tlsConfig)
	if err != nil {
		return fmt.Errorf("api: listen %s: %w", s.Config.Address, err)
	}

	klog.InfoS("api server listening", "address", s.Config.Address, "endpoints", []string{
		"GET/POST /v1/filter-policies",
		"GET/PUT/PATCH/DELETE /v1/filter-policies/{ns}/{name}",
		"/healthz", "/readyz", "/openapi.json",
	})

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			klog.ErrorS(err, "api server shutdown")
			return err
		}
		// Drain the Serve goroutine.
		err := <-serveErr
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// buildTLSConfig loads the server identity and client-CA bundle and
// constructs a tls.Config that requires and verifies a client certificate on
// every connection. This is the mTLS contract for v0.
//
// Two loading paths are supported:
//
//  1. CertDir set — the Sprint 31 / Ticket 49 path. Material is loaded via
//     the shared certificates.TLSReloader so renewals rotate in place.
//     ca.crt is reused as the client-CA bundle (the fos1-internal-ca chain
//     signs both server and client identities for inter-controller mTLS).
//  2. Per-file paths set — backward-compatible v0 path. Used by overlays
//     that point at an external CA distinct from the controller's server
//     trust anchor.
//
// In both paths ClientAuth is RequireAndVerifyClientCert; layering the mTLS
// requirement on top of the shared helper is the deliberate design.
//
// The returned *certificates.TLSReloader is non-nil only on the CertDir
// path — the caller starts WatchAndReload to pick up rotation.
func buildTLSConfig(cfg ServerConfig) (*tls.Config, *certificates.TLSReloader, error) {
	if cfg.CertDir != "" {
		base, reloader, err := certificates.LoadTLSConfig(cfg.CertDir)
		if err != nil {
			return nil, nil, fmt.Errorf("load TLS material from %s: %w", cfg.CertDir, err)
		}
		// Layer mTLS on top of the shared helper. ClientCAs comes from
		// the same ca.crt the server cert chains to: every owned
		// controller and every authorized client carries a cert minted
		// by fos1-internal-ca, so the same pool authenticates both
		// directions.
		base.ClientCAs = reloader.CABundle()
		base.ClientAuth = tls.RequireAndVerifyClientCert
		return base, reloader, nil
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load server key pair: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read client CA bundle: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("client CA bundle %s did not contain any PEM certs", cfg.ClientCAFile)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil, nil
}

// listenAddr returns the actual address the server is listening on. It is
// used by tests that bind to :0 and need to discover the chosen port.
func listenAddr(l net.Listener) string {
	if l == nil {
		return ""
	}
	return l.Addr().String()
}
