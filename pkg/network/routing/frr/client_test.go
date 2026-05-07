package frr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
	if client.config == nil {
		t.Fatal("Client config is nil")
	}
}

func TestNewClientWithConfig(t *testing.T) {
	config := &ClientConfig{
		VTYSHPath:      "/usr/local/bin/vtysh",
		SocketPath:     "/var/run/frr-test",
		ConfigPath:     "/etc/frr-test",
		CommandTimeout: 60,
		MaxRetries:     5,
		RetryDelay:     2,
	}

	client := NewClientWithConfig(config)
	if client == nil {
		t.Fatal("NewClientWithConfig() returned nil")
	}

	if client.config.VTYSHPath != config.VTYSHPath {
		t.Errorf("VTYSHPath mismatch: got %s, want %s", client.config.VTYSHPath, config.VTYSHPath)
	}
	if client.config.CommandTimeout != config.CommandTimeout {
		t.Errorf("CommandTimeout mismatch: got %d, want %d", client.config.CommandTimeout, config.CommandTimeout)
	}
}

func TestDefaultClientConfig(t *testing.T) {
	config := DefaultClientConfig()
	if config == nil {
		t.Fatal("DefaultClientConfig() returned nil")
	}

	if config.VTYSHPath == "" {
		t.Error("VTYSHPath is empty")
	}
	if config.CommandTimeout <= 0 {
		t.Error("CommandTimeout is invalid")
	}
	if config.MaxRetries <= 0 {
		t.Error("MaxRetries is invalid")
	}
}

func TestConfigureBGP(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	neighbors := []BGPNeighbor{
		{
			Address:           "192.0.2.1",
			RemoteASNumber:    65001,
			Description:       "Test Neighbor",
			KeepaliveInterval: 30,
			HoldTime:          90,
			BFDEnabled:        true,
		},
	}

	addressFamilies := []BGPAddressFamily{
		{
			Type:    "ipv4-unicast",
			Enabled: true,
			Networks: []BGPNetwork{
				{
					Prefix: "10.0.0.0/24",
				},
			},
			Redistributions: []Redistribution{
				{
					Protocol: "connected",
				},
			},
		},
	}

	// This will fail without an actual FRR instance, but tests the function signature
	err := client.ConfigureBGP(ctx, 65000, "1.1.1.1", neighbors, addressFamilies)
	// We expect an error since FRR is not running in test environment
	if err == nil {
		t.Log("ConfigureBGP succeeded (FRR must be running)")
	} else {
		t.Logf("ConfigureBGP failed as expected without FRR: %v", err)
	}
}

func TestConfigureOSPF(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	areas := []OSPFArea{
		{
			AreaID: "0.0.0.0",
			Interfaces: []OSPFInterface{
				{
					Name:     "eth0",
					Network:  "10.0.0.0/24",
					Cost:     10,
					Priority: 1,
				},
			},
			StubArea: false,
			NSSAArea: false,
		},
	}

	redistributions := []Redistribution{
		{
			Protocol: "connected",
		},
	}

	// This will fail without an actual FRR instance
	err := client.ConfigureOSPF(ctx, "2.2.2.2", areas, redistributions)
	if err == nil {
		t.Log("ConfigureOSPF succeeded (FRR must be running)")
	} else {
		t.Logf("ConfigureOSPF failed as expected without FRR: %v", err)
	}
}

func TestHealthCheck(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	// This will fail without an actual FRR instance
	err := client.HealthCheck(ctx)
	if err == nil {
		t.Log("HealthCheck succeeded (FRR must be running)")
	} else {
		t.Logf("HealthCheck failed as expected without FRR: %v", err)
	}
}

func TestIsAvailable(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	// This will return false without an actual FRR instance
	available := client.IsAvailable(ctx)
	if available {
		t.Log("FRR is available")
	} else {
		t.Log("FRR is not available (expected in test environment)")
	}
}

func TestExecuteVtyshCommandUsesMutualTLSEndpoint(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vtysh" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Fatal("expected exactly one verified client certificate")
		}
		if got := r.TLS.PeerCertificates[0].Subject.CommonName; got != "routing-controller" {
			t.Fatalf("unexpected client CN: %s", got)
		}

		var req vtyshCommandRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Command != "show version" {
			t.Fatalf("unexpected command: %s", req.Command)
		}

		if err := json.NewEncoder(w).Encode(vtyshCommandResponse{Output: "FRRouting 8.4\n"}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))

	caFile, certFile, keyFile := writeClientTLSMaterial(t, server)
	defer server.Close()

	client := NewClientWithConfig(&ClientConfig{
		VTYSHPath:      "/usr/bin/vtysh",
		SocketPath:     "/var/run/frr",
		ConfigPath:     "/etc/frr",
		CommandTimeout: 5,
		MaxRetries:     1,
		RetryDelay:     1,
		Transport:      VtyshTransportHTTPS,
		TLSEndpoint:    server.URL,
		TLSCAFile:      caFile,
		TLSCertFile:    certFile,
		TLSKeyFile:     keyFile,
		TLSServerName:  "example.com",
	})

	output, err := client.ExecuteVtyshCommand(context.Background(), "show version")
	if err != nil {
		t.Fatalf("ExecuteVtyshCommand returned error: %v", err)
	}
	if output != "FRRouting 8.4\n" {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestExecuteVtyshCommandRequiresClientCertificateForTLSEndpoint(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server handler should not run without a trusted client certificate")
	}))

	clientCA, _, _, err := generateTestClientCertificate("routing-controller")
	if err != nil {
		t.Fatalf("generate client CA: %v", err)
	}
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  x509.NewCertPool(),
	}
	if !server.TLS.ClientCAs.AppendCertsFromPEM(clientCA) {
		t.Fatal("append client CA")
	}
	server.StartTLS()
	defer server.Close()
	caFile := writePEMFile(t, "ca.pem", pemBlock("CERTIFICATE", server.Certificate().Raw))
	client := NewClientWithConfig(&ClientConfig{
		VTYSHPath:      "/usr/bin/vtysh",
		SocketPath:     "/var/run/frr",
		ConfigPath:     "/etc/frr",
		CommandTimeout: 5,
		MaxRetries:     1,
		RetryDelay:     1,
		Transport:      VtyshTransportHTTPS,
		TLSEndpoint:    server.URL,
		TLSCAFile:      caFile,
		TLSServerName:  "example.com",
	})

	if _, err := client.ExecuteVtyshCommand(context.Background(), "show version"); err == nil {
		t.Fatal("expected mTLS endpoint call to fail without a client certificate")
	}
}

func writeClientTLSMaterial(t *testing.T, server *httptest.Server) (string, string, string) {
	t.Helper()

	clientCA, cert, key, err := generateTestClientCertificate("routing-controller")
	if err != nil {
		t.Fatalf("generate client certificate: %v", err)
	}
	if server.TLS == nil {
		server.TLS = &tls.Config{}
	}
	server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	server.TLS.ClientCAs = x509.NewCertPool()
	if !server.TLS.ClientCAs.AppendCertsFromPEM(clientCA) {
		t.Fatal("append client CA")
	}

	server.StartTLS()
	caFile := writePEMFile(t, "ca.pem", pemBlock("CERTIFICATE", server.Certificate().Raw))
	certFile := writePEMFile(t, "client.crt", cert)
	keyFile := writePEMFile(t, "client.key", key)
	return caFile, certFile, keyFile
}

func writePEMFile(t *testing.T, name string, contents []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func generateTestClientCertificate(commonName string) ([]byte, []byte, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-client-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return nil, nil, nil, err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return caPEM, certPEM, keyPEM, nil
}

func pemBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}
