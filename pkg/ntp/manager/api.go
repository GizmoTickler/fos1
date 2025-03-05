package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"k8s.io/klog/v2"
)

// APIServer provides a REST API for the NTP service
type APIServer struct {
	ntpManager *Manager
	server     *http.Server
	port       int
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

	a.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", a.port),
		Handler: mux,
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