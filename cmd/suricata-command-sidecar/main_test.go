package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/security/ids/suricata"
)

func TestSuricataHandlerForwardsAuthenticatedCommand(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("shared-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	var observed []suricata.Command
	socketPath, cleanup := mockSuricataSocket(t, func(cmd suricata.Command) suricata.Response {
		observed = append(observed, cmd)
		switch cmd.Command {
		case "version":
			return suricata.Response{Return: "OK", Message: "7.0.3"}
		default:
			return suricata.Response{Return: "NOK", Message: "unexpected command"}
		}
	})
	defer cleanup()

	handler := buildHandler(sidecarConfig{
		SocketPath:    socketPath,
		AuthTokenFile: tokenFile,
		Timeout:       time.Second,
	})
	body := bytes.NewBufferString(`{"command":"version"}`)
	req := httptest.NewRequest(http.MethodPost, "/suricata-command", body)
	req.Header.Set("X-FOS1-Suricata-Auth", "shared-token")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}
	var decoded suricata.Response
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoded.Message != "7.0.3" {
		t.Fatalf("message = %v, want version", decoded.Message)
	}
	if len(observed) != 1 || observed[0].Command != "version" {
		t.Fatalf("observed commands = %#v, want version only", observed)
	}
}

func TestSuricataHandlerRejectsMissingSharedSecret(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("shared-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	handler := buildHandler(sidecarConfig{
		SocketPath:    "/tmp/suricata-command.sock",
		AuthTokenFile: tokenFile,
		Timeout:       time.Second,
	})
	req := httptest.NewRequest(http.MethodPost, "/suricata-command", bytes.NewBufferString(`{"command":"version"}`))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusUnauthorized)
	}
}

func TestSuricataHandlerRejectsMissingClientCertificate(t *testing.T) {
	handler := buildHandler(sidecarConfig{
		SocketPath: "/tmp/suricata-command.sock",
		AllowedCNs: []string{"ids-controller"},
		Timeout:    time.Second,
	})
	req := httptest.NewRequest(http.MethodPost, "/suricata-command", bytes.NewBufferString(`{"command":"version"}`))
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusForbidden)
	}
}

func mockSuricataSocket(t *testing.T, handler func(cmd suricata.Command) suricata.Response) (string, func()) {
	t.Helper()

	dir := t.TempDir()
	socketPath := filepath.Join(dir, "suricata-command.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix socket listeners unavailable: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				dec := json.NewDecoder(c)
				enc := json.NewEncoder(c)
				var hello map[string]string
				if err := dec.Decode(&hello); err != nil {
					return
				}
				if hello["version"] != "0.1" {
					_ = enc.Encode(suricata.Response{Return: "NOK", Message: "missing version negotiation"})
					return
				}
				if err := enc.Encode(suricata.Response{Return: "OK"}); err != nil {
					return
				}
				for {
					var cmd suricata.Command
					if err := dec.Decode(&cmd); err != nil {
						return
					}
					if err := enc.Encode(handler(cmd)); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return socketPath, func() {
		ln.Close()
		<-done
		os.RemoveAll(dir)
	}
}

func TestRunSuricataCommandHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runSuricataCommand(ctx, sidecarConfig{SocketPath: "/tmp/missing.sock", Timeout: time.Second}, suricata.Command{Command: "version"})
	if err == nil {
		t.Fatal("expected canceled context error")
	}
}
