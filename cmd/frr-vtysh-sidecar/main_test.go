package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVtyshHandlerExecutesCommandAndReturnsOutput(t *testing.T) {
	vtysh := filepath.Join(t.TempDir(), "vtysh")
	script := "#!/usr/bin/env sh\nprintf 'args:%s %s\\n' \"$1\" \"$2\"\n"
	if err := os.WriteFile(vtysh, []byte(script), 0700); err != nil {
		t.Fatalf("write fake vtysh: %v", err)
	}

	handler := buildHandler(sidecarConfig{
		VtyshPath: vtysh,
		Timeout:   time.Second,
	})

	body := bytes.NewBufferString(`{"command":"show version"}`)
	req := httptest.NewRequest(http.MethodPost, "/vtysh", body)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", resp.Code, http.StatusOK, resp.Body.String())
	}

	var decoded vtyshResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoded.Output != "args:-c show version\n" {
		t.Fatalf("output = %q", decoded.Output)
	}
}

func TestVtyshHandlerRejectsNonPostAndEmptyCommands(t *testing.T) {
	handler := buildHandler(sidecarConfig{
		VtyshPath: "/usr/bin/vtysh",
		Timeout:   time.Second,
	})

	req := httptest.NewRequest(http.MethodGet, "/vtysh", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want %d", resp.Code, http.StatusMethodNotAllowed)
	}

	req = httptest.NewRequest(http.MethodPost, "/vtysh", strings.NewReader(`{"command":""}`))
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("empty command status = %d, want %d", resp.Code, http.StatusBadRequest)
	}
}

func TestRunVtyshReturnsStderrOnFailure(t *testing.T) {
	vtysh := filepath.Join(t.TempDir(), "vtysh")
	script := "#!/usr/bin/env sh\nprintf 'bad command\\n' >&2\nexit 7\n"
	if err := os.WriteFile(vtysh, []byte(script), 0700); err != nil {
		t.Fatalf("write fake vtysh: %v", err)
	}

	_, err := runVtysh(context.Background(), vtysh, "show broken", time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "bad command") {
		t.Fatalf("error = %q, want stderr context", err.Error())
	}
}
