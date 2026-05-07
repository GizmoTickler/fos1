package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const maxRequestBytes = 1 << 20

type sidecarConfig struct {
	ListenAddr string
	VtyshPath  string
	TLSCert    string
	TLSKey     string
	TLSCA      string
	AllowedCNs []string
	Timeout    time.Duration
}

type vtyshRequest struct {
	Command string `json:"command"`
}

type vtyshResponse struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	cfg, err := configFromEnv()
	if err != nil {
		log.Fatalf("frr-vtysh-sidecar config: %v", err)
	}
	tlsConfig, err := loadTLSConfig(cfg)
	if err != nil {
		log.Fatalf("frr-vtysh-sidecar tls: %v", err)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           buildHandler(cfg),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("frr-vtysh-sidecar listening on %s", cfg.ListenAddr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func configFromEnv() (sidecarConfig, error) {
	cfg := sidecarConfig{
		ListenAddr: envOrDefault("FOS1_FRR_VTYSH_SIDECAR_ADDR", ":9443"),
		VtyshPath:  envOrDefault("FOS1_FRR_VTYSH_PATH", "/usr/bin/vtysh"),
		TLSCert:    os.Getenv("FOS1_FRR_VTYSH_TLS_CERT"),
		TLSKey:     os.Getenv("FOS1_FRR_VTYSH_TLS_KEY"),
		TLSCA:      os.Getenv("FOS1_FRR_VTYSH_TLS_CA"),
		AllowedCNs: splitCSV(os.Getenv("FOS1_FRR_VTYSH_ALLOWED_CNS")),
		Timeout:    envDuration("FOS1_FRR_VTYSH_TIMEOUT", 10*time.Second),
	}
	if cfg.TLSCert == "" || cfg.TLSKey == "" || cfg.TLSCA == "" {
		return cfg, errors.New("TLS cert, key, and CA file paths are required")
	}
	if len(cfg.AllowedCNs) == 0 {
		return cfg, errors.New("at least one allowed client CommonName is required")
	}
	return cfg, nil
}

func buildHandler(cfg sidecarConfig) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	vtyshHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		defer r.Body.Close()

		var req vtyshRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBytes)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON request")
			return
		}
		if strings.TrimSpace(req.Command) == "" {
			writeJSONError(w, http.StatusBadRequest, "command must not be empty")
			return
		}

		output, err := runVtysh(r.Context(), cfg.VtyshPath, req.Command, cfg.Timeout)
		if err != nil {
			writeJSONError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, vtyshResponse{Output: output})
	})
	if len(cfg.AllowedCNs) > 0 {
		mux.Handle("/vtysh", requireAllowedCNs(cfg.AllowedCNs, vtyshHandler))
	} else {
		mux.Handle("/vtysh", vtyshHandler)
	}
	return mux
}

func runVtysh(ctx context.Context, path, command string, timeout time.Duration) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, path, "-c", command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if cmdCtx.Err() != nil {
			return "", fmt.Errorf("vtysh command timed out: %w", cmdCtx.Err())
		}
		return "", fmt.Errorf("vtysh command failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func loadTLSConfig(cfg sidecarConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.TLSCA)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA bundle contained no PEM certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clientCAs,
	}, nil
}

func requireAllowedCNs(allowed []string, next http.Handler) http.Handler {
	allowedSet := map[string]struct{}{}
	for _, cn := range allowed {
		allowedSet[cn] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(allowedSet) == 0 {
			writeJSONError(w, http.StatusForbidden, "no allowed client subjects configured")
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			writeJSONError(w, http.StatusForbidden, "missing verified client certificate")
			return
		}
		cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
		if _, ok := allowedSet[cn]; !ok {
			writeJSONError(w, http.StatusForbidden, "client subject is not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, vtyshResponse{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, resp vtyshResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("write response: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
