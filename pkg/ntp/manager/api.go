package manager

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/security/certificates"
)

// APIServer provides a REST API for the NTP service
type APIServer struct {
	ntpManager *Manager
	server     *http.Server
	port       int
	tlsCertDir string
	tlsCancel  context.CancelFunc
	mutex      sync.Mutex
	running    bool
}

// NewAPIServer creates a new API server for NTP
func NewAPIServer(ntpManager *Manager) (*APIServer, error) {
	if ntpManager == nil {
		return nil, errors.New("NTP manager is required")
	}

	return &APIServer{
		ntpManager: ntpManager,
		port:       8080, // Default port, could be configurable
	}, nil
}

// SetTLSCertDir enables HTTPS on the API server using cert-manager-rotated
// material from the given directory. Must be called before Start.
// Sprint 31 / Ticket 49.
func (a *APIServer) SetTLSCertDir(dir string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.tlsCertDir = dir
}

// Start starts the API server
func (a *APIServer) Start() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.running {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ntp/status", a.handleStatus)
	mux.HandleFunc("/api/v1/ntp/sources", a.handleSources)
	mux.HandleFunc("/api/v1/ntp/health", a.handleHealth)
	mux.HandleFunc("/healthz", a.handleLiveness)
	mux.HandleFunc("/readyz", a.handleReadiness)

	a.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", a.port),
		Handler: mux,
	}

	if a.tlsCertDir != "" {
		tlsCfg, reloader, err := certificates.LoadTLSConfig(a.tlsCertDir)
		if err != nil {
			return fmt.Errorf("load TLS config from %s: %w", a.tlsCertDir, err)
		}
		a.server.TLSConfig = tlsCfg

		watchCtx, cancel := context.WithCancel(context.Background())
		a.tlsCancel = cancel
		go func() {
			if werr := reloader.WatchAndReload(watchCtx, nil, tlsCfg, nil); werr != nil {
				klog.Errorf("NTP API: TLS watcher exited: %v", werr)
			}
		}()

		klog.Infof("Starting NTP API server on port %d (TLS)", a.port)
		a.running = true
		go func() {
			ln, err := net.Listen("tcp", a.server.Addr)
			if err != nil {
				klog.Errorf("Error binding NTP API listener: %v", err)
				return
			}
			tlsLn := tls.NewListener(ln, tlsCfg)
			if err := a.server.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
				klog.Errorf("Error starting NTP API server: %v", err)
			}
		}()
		return nil
	}

	klog.Infof("Starting NTP API server on port %d", a.port)
	a.running = true

	// Start HTTP server in a goroutine
	go func() {
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			klog.Errorf("Error starting NTP API server: %v", err)
		}
	}()

	return nil
}

// Stop stops the API server
func (a *APIServer) Stop() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if !a.running {
		return nil
	}

	klog.Info("Stopping NTP API server")
	if a.server != nil {
		if err := a.server.Close(); err != nil {
			return fmt.Errorf("error closing API server: %w", err)
		}
	}
	if a.tlsCancel != nil {
		a.tlsCancel()
	}

	a.running = false
	return nil
}

// handleStatus handles the status endpoint
func (a *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status, err := a.ntpManager.Status()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting NTP status: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleSources handles the sources endpoint
func (a *APIServer) handleSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status, err := a.ntpManager.Status()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting NTP sources: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status.Sources)
}

// handleHealth handles the health check endpoint
func (a *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status, err := a.ntpManager.Status()
	if err != nil {
		http.Error(w, "NTP service unavailable", http.StatusServiceUnavailable)
		return
	}

	if status.Synchronized && status.Running {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("NTP service is healthy"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("NTP service is not synchronized"))
	}
}

// handleLiveness reports whether the API process itself is serving requests.
func (a *APIServer) handleLiveness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleReadiness reports whether the controller API is ready to serve requests.
func (a *APIServer) handleReadiness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.ntpManager == nil {
		http.Error(w, "NTP manager unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
