package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/GizmoTickler/fos1/pkg/security/ids/suricata"
)

const maxRequestBytes = 1 << 20

type sidecarConfig struct {
	ListenAddr    string
	SocketPath    string
	AuthTokenFile string
	TLSCert       string
	TLSKey        string
	TLSCA         string
	AllowedCNs    []string
	Timeout       time.Duration
}

func main() {
	cfg, err := configFromEnv()
	if err != nil {
		log.Fatalf("suricata-command-sidecar config: %v", err)
	}
	tlsConfig, err := loadTLSConfig(cfg)
	if err != nil {
		log.Fatalf("suricata-command-sidecar tls: %v", err)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           buildHandler(cfg),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("suricata-command-sidecar listening on %s", cfg.ListenAddr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func configFromEnv() (sidecarConfig, error) {
	cfg := sidecarConfig{
		ListenAddr:    envOrDefault("FOS1_SURICATA_COMMAND_SIDECAR_ADDR", ":9444"),
		SocketPath:    envOrDefault("FOS1_SURICATA_COMMAND_SOCKET", "/var/run/suricata/suricata-command.socket"),
		AuthTokenFile: os.Getenv("FOS1_SURICATA_COMMAND_AUTH_TOKEN_FILE"),
		TLSCert:       os.Getenv("FOS1_SURICATA_COMMAND_TLS_CERT"),
		TLSKey:        os.Getenv("FOS1_SURICATA_COMMAND_TLS_KEY"),
		TLSCA:         os.Getenv("FOS1_SURICATA_COMMAND_TLS_CA"),
		AllowedCNs:    splitCSV(os.Getenv("FOS1_SURICATA_COMMAND_ALLOWED_CNS")),
		Timeout:       envDuration("FOS1_SURICATA_COMMAND_TIMEOUT", 10*time.Second),
	}
	if cfg.AuthTokenFile == "" {
		return cfg, errors.New("auth token file path is required")
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

	commandHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		defer r.Body.Close()

		var cmd suricata.Command
		if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBytes)).Decode(&cmd); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON request")
			return
		}
		if strings.TrimSpace(cmd.Command) == "" {
			writeJSONError(w, http.StatusBadRequest, "command must not be empty")
			return
		}
		if err := requireSharedSecret(r, cfg); err != nil {
			writeJSONError(w, http.StatusUnauthorized, err.Error())
			return
		}

		resp, err := runSuricataCommand(r.Context(), cfg, cmd)
		if err != nil {
			writeJSONError(w, http.StatusBadGateway, err.Error())
			return
		}
		status := http.StatusOK
		if resp.Return != "OK" {
			status = http.StatusBadGateway
		}
		writeJSON(w, status, *resp)
	})
	if len(cfg.AllowedCNs) > 0 {
		mux.Handle("/suricata-command", requireAllowedCNs(cfg.AllowedCNs, commandHandler))
	} else {
		mux.Handle("/suricata-command", commandHandler)
	}
	return mux
}

func requireSharedSecret(r *http.Request, cfg sidecarConfig) error {
	if cfg.AuthTokenFile == "" {
		return nil
	}
	token, err := readTokenFile(cfg.AuthTokenFile)
	if err != nil {
		return err
	}
	if r.Header.Get("X-FOS1-Suricata-Auth") != token {
		return errors.New("missing or invalid Suricata auth token")
	}
	return nil
}

func runSuricataCommand(ctx context.Context, cfg sidecarConfig, cmd suricata.Command) (*suricata.Response, error) {
	if cfg.SocketPath == "" {
		return nil, errors.New("Suricata socket path is required")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(cfg.Timeout)
	}
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "unix", cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("connect Suricata socket: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set Suricata socket deadline: %w", err)
	}

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	if err := enc.Encode(map[string]string{"version": "0.1"}); err != nil {
		return nil, fmt.Errorf("write Suricata version negotiation: %w", err)
	}
	var hello suricata.Response
	if err := dec.Decode(&hello); err != nil {
		return nil, fmt.Errorf("read Suricata version negotiation: %w", err)
	}
	if hello.Return != "OK" {
		return nil, fmt.Errorf("Suricata version negotiation failed: return=%s", hello.Return)
	}
	if err := enc.Encode(cmd); err != nil {
		return nil, fmt.Errorf("write Suricata command: %w", err)
	}
	var resp suricata.Response
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("read Suricata command response: %w", err)
	}
	return &resp, nil
}

func readTokenFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("auth token file path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read auth token file: %w", err)
	}
	token := strings.TrimRight(string(data), "\r\n")
	if token == "" {
		return "", errors.New("auth token file is empty")
	}
	return token, nil
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
	writeJSON(w, status, suricata.Response{Return: "NOK", Message: message})
}

func writeJSON(w http.ResponseWriter, status int, resp suricata.Response) {
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
