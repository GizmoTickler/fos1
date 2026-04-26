// Package certificates: tlsconfig.go provides the shared TLS bootstrap used by
// every owned fos1 controller that exposes an HTTP listener.
//
// Sprint 31 / Ticket 49 introduces a per-controller server cert signed by the
// `fos1-internal-ca` ClusterIssuer (chained from a 10y self-signed root). The
// cert / key / CA bundle land in a Kubernetes Secret of type
// `kubernetes.io/tls`, which the deployment manifest mounts at
// `/var/run/secrets/fos1.io/tls/`. Each controller calls LoadTLSConfig at
// startup to load the initial certificate material and WatchAndReload to
// re-load on cert-manager renewals — no pod restart, no listener bounce.
//
// Design notes:
//   - The reload path uses a single GetCertificate hook on tls.Config so the
//     active cert pointer is swapped under a sync.RWMutex; in-flight TLS
//     handshakes always observe a valid certificate.
//   - We rely on Kubernetes' Secret-mount atomicity: kubelet replaces
//     `..data` with a symlink swap, so a partial read across the rollover is
//     impossible. fsnotify on the directory's symlinked targets fires once
//     the swap completes.
//   - The watcher gracefully degrades to a 30s polling fallback when fsnotify
//     cannot be initialized (e.g. inotify watch limit). This keeps the
//     reload path correct under adverse conditions even if it widens the
//     observed-renewal latency from milliseconds to seconds.
package certificates

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"k8s.io/klog/v2"
)

// File names cert-manager writes inside a kubernetes.io/tls Secret. These
// constants centralize the on-disk contract so every controller mounts the
// same paths.
const (
	// TLSCertFile is the PEM-encoded server certificate chain.
	TLSCertFile = "tls.crt"

	// TLSKeyFile is the PEM-encoded server private key.
	TLSKeyFile = "tls.key"

	// CABundleFile is the PEM-encoded CA bundle that signed tls.crt.
	// cert-manager populates this when the issuer is a CA-typed Issuer or
	// ClusterIssuer; the fos1-internal-ca chain always populates it.
	CABundleFile = "ca.crt"

	// DefaultTLSMountPath is the canonical mount path for fos1 controller
	// TLS material. Every owned Deployment in manifests/base/ mounts the
	// cert-manager Secret here.
	DefaultTLSMountPath = "/var/run/secrets/fos1.io/tls"

	// pollFallbackInterval is the cadence used when fsnotify is unavailable.
	// Renewals happen 15 days before expiry on a 90 day cert, so a 30s poll
	// is plenty fast.
	pollFallbackInterval = 30 * time.Second
)

// TLSReloader holds the live tls.Config and atomically swaps the underlying
// certificate when the on-disk material changes. The zero value is not
// usable; callers must construct via LoadTLSConfig.
type TLSReloader struct {
	mu      sync.RWMutex
	cert    *tls.Certificate
	caPool  *x509.CertPool
	certDir string
}

// LoadTLSConfig reads tls.crt / tls.key / ca.crt from certDir and returns a
// *tls.Config wired to the TLSReloader so subsequent reloads are visible to
// the running listener. The returned config requires TLS 1.2+, sets the
// cipher policy via Go's defaults (ECDHE/AES-GCM and ChaCha20 are the modern
// minimum), and leaves ClientAuth at the zero value — callers that need
// mTLS layer it on top via a thin wrapper (see pkg/api.buildTLSConfig).
//
// The function returns an error if any required file is missing, the key
// pair fails to parse, or the CA bundle is empty. ca.crt is treated as
// required because every fos1-internal-ca cert ships one; an empty bundle
// would silently disable client-cert verification on any caller that opts
// into mTLS.
func LoadTLSConfig(certDir string) (*tls.Config, *TLSReloader, error) {
	if certDir == "" {
		return nil, nil, fmt.Errorf("certificates: certDir must be set")
	}

	r := &TLSReloader{certDir: certDir}
	if err := r.reload(); err != nil {
		return nil, nil, err
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// GetCertificate is consulted on every handshake. We wrap the
		// stored cert pointer in an RLock so a swap mid-handshake never
		// observes a torn read. The signature returns (*tls.Certificate,
		// error); returning the underlying pointer is safe because
		// Certificate is treated as immutable once installed.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			r.mu.RLock()
			defer r.mu.RUnlock()
			if r.cert == nil {
				return nil, fmt.Errorf("certificates: TLS reloader has no certificate loaded")
			}
			return r.cert, nil
		},
	}

	return cfg, r, nil
}

// CABundle returns the most recently loaded CA bundle as an *x509.CertPool.
// Callers that want to use the same CA to verify peer client certs (mTLS)
// can install it as ClientCAs on the tls.Config returned by LoadTLSConfig.
// The pool is replaced atomically on every reload.
func (r *TLSReloader) CABundle() *x509.CertPool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.caPool
}

// Certificate returns a copy-by-pointer of the currently loaded certificate.
// It is exposed for tests that want to assert NotBefore / NotAfter after a
// reload; production code should rely on tls.Config.GetCertificate.
func (r *TLSReloader) Certificate() *tls.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert
}

// reload reads the three files inside certDir and swaps the in-memory
// certificate + CA pool under the write lock.
func (r *TLSReloader) reload() error {
	certPath := filepath.Join(r.certDir, TLSCertFile)
	keyPath := filepath.Join(r.certDir, TLSKeyFile)
	caPath := filepath.Join(r.certDir, CABundleFile)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("certificates: load %s/%s: %w", TLSCertFile, TLSKeyFile, err)
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("certificates: read %s: %w", CABundleFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("certificates: %s contained no PEM certs", CABundleFile)
	}

	r.mu.Lock()
	r.cert = &cert
	r.caPool = pool
	r.mu.Unlock()
	return nil
}

// WatchAndReload runs a long-lived watch loop that reloads the tls.Config in
// place on cert-manager renewals. It blocks until ctx is cancelled.
//
// The onReload callback is invoked (if non-nil) after every successful
// reload. Production callers usually pass nil — the reload happens
// transparently because tls.Config.GetCertificate already routes through
// the reloader. The callback exists so tests can assert that a reload was
// observed and so observability code can emit a "tls cert rotated" log.
//
// errCh, if non-nil, receives non-fatal reload errors (e.g. transient
// EISDIR while kubelet swaps the symlink). The watcher itself never returns
// these — it logs and continues — so callers can choose to ignore them.
func (r *TLSReloader) WatchAndReload(ctx context.Context, onReload func(*tls.Config), tlsCfg *tls.Config, errCh chan<- error) error {
	if tlsCfg == nil {
		return fmt.Errorf("certificates: tlsCfg must be non-nil")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		klog.Warningf("certificates: fsnotify unavailable (%v); falling back to %s polling", err, pollFallbackInterval)
		return r.runPollFallback(ctx, onReload, tlsCfg, errCh)
	}
	defer func() {
		if cerr := watcher.Close(); cerr != nil {
			klog.Warningf("certificates: fsnotify close: %v", cerr)
		}
	}()

	// Watch the directory itself; kubelet's atomic Secret rollover writes a
	// new ..data symlink so individual file watches miss the swap. The
	// directory rename event always fires.
	if err := watcher.Add(r.certDir); err != nil {
		klog.Warningf("certificates: fsnotify add %s: %v; falling back to %s polling", r.certDir, err, pollFallbackInterval)
		return r.runPollFallback(ctx, onReload, tlsCfg, errCh)
	}

	klog.Infof("certificates: watching %s for cert rotation", r.certDir)

	// Coalesce rapid event bursts: kubelet's symlink dance fires multiple
	// fsnotify events within milliseconds. A 100ms debounce reloads exactly
	// once per rollover.
	const debounce = 100 * time.Millisecond
	var debounceTimer *time.Timer

	for {
		select {
		case <-ctx.Done():
			return nil
		case evt, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			klog.V(4).Infof("certificates: fs event %s on %s", evt.Op, evt.Name)
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(debounce, func() {
				r.handleReload(onReload, tlsCfg, errCh)
			})
		case werr, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			klog.Warningf("certificates: fsnotify error: %v", werr)
			if errCh != nil {
				select {
				case errCh <- werr:
				default:
				}
			}
		}
	}
}

func (r *TLSReloader) runPollFallback(ctx context.Context, onReload func(*tls.Config), tlsCfg *tls.Config, errCh chan<- error) error {
	ticker := time.NewTicker(pollFallbackInterval)
	defer ticker.Stop()

	// Track the last observed cert mtime so we only reload on real change.
	lastMtime := mtimeOrZero(filepath.Join(r.certDir, TLSCertFile))

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cur := mtimeOrZero(filepath.Join(r.certDir, TLSCertFile))
			if !cur.Equal(lastMtime) {
				lastMtime = cur
				r.handleReload(onReload, tlsCfg, errCh)
			}
		}
	}
}

func (r *TLSReloader) handleReload(onReload func(*tls.Config), tlsCfg *tls.Config, errCh chan<- error) {
	if err := r.reload(); err != nil {
		klog.Errorf("certificates: reload failed: %v", err)
		if errCh != nil {
			select {
			case errCh <- err:
			default:
			}
		}
		return
	}
	klog.Infof("certificates: TLS material reloaded from %s", r.certDir)
	if onReload != nil {
		onReload(tlsCfg)
	}
}

func mtimeOrZero(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
