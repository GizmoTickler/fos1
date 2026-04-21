package connectors

import (
	"context"
	"strings"
	"testing"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

type testCiliumClient struct{}

func (t *testCiliumClient) ApplyNetworkPolicy(ctx context.Context, policy *cilium.CiliumPolicy) error {
	return nil
}

func (t *testCiliumClient) DeleteNetworkPolicy(ctx context.Context, policyName string) error {
	return nil
}

func (t *testCiliumClient) ListRoutes(ctx context.Context) ([]cilium.Route, error) {
	return nil, nil
}

func (t *testCiliumClient) ListVRFRoutes(ctx context.Context, vrfID int) ([]cilium.Route, error) {
	return nil, nil
}

func (t *testCiliumClient) AddRoute(route cilium.Route) error {
	return nil
}

func (t *testCiliumClient) DeleteRoute(route cilium.Route) error {
	return nil
}

func (t *testCiliumClient) AddVRFRoute(route cilium.Route, vrfID int) error {
	return nil
}

func (t *testCiliumClient) DeleteVRFRoute(route cilium.Route, vrfID int) error {
	return nil
}

func (t *testCiliumClient) CreateNAT(ctx context.Context, config *cilium.CiliumNATConfig) error {
	return nil
}

func (t *testCiliumClient) RemoveNAT(ctx context.Context, config *cilium.CiliumNATConfig) error {
	return nil
}

func (t *testCiliumClient) CreateNAT64(ctx context.Context, config *cilium.NAT64Config) error {
	return nil
}

func (t *testCiliumClient) RemoveNAT64(ctx context.Context, config *cilium.NAT64Config) error {
	return nil
}

func (t *testCiliumClient) CreatePortForward(ctx context.Context, config *cilium.PortForwardConfig) error {
	return nil
}

func (t *testCiliumClient) RemovePortForward(ctx context.Context, config *cilium.PortForwardConfig) error {
	return nil
}

func (t *testCiliumClient) ConfigureVLANRouting(ctx context.Context, config *cilium.CiliumVLANRoutingConfig) error {
	return nil
}

func (t *testCiliumClient) ConfigureDPIIntegration(ctx context.Context, config *cilium.CiliumDPIIntegrationConfig) error {
	return nil
}

func TestNewZeekConnectorUsesKubernetesLogContract(t *testing.T) {
	connector, err := NewZeekConnector(ZeekOptions{
		CiliumClient:   &testCiliumClient{},
		KubernetesMode: true,
	})
	if err != nil {
		t.Fatalf("NewZeekConnector() error = %v", err)
	}
	defer connector.Stop()

	if connector.logsPath != "/var/log/zeek/current" {
		t.Fatalf("logsPath = %q, want %q", connector.logsPath, "/var/log/zeek/current")
	}
}

func TestZeekConnectorStartFailsForMissingLogContract(t *testing.T) {
	connector, err := NewZeekConnector(ZeekOptions{
		CiliumClient: &testCiliumClient{},
		LogsPath:     "/tmp/fos1-missing-zeek/current",
	})
	if err != nil {
		t.Fatalf("NewZeekConnector() error = %v", err)
	}
	defer connector.Stop()

	err = connector.Start()
	if err == nil {
		t.Fatal("Start() error = nil, want missing log contract error")
	}

	if !strings.Contains(err.Error(), "/tmp/fos1-missing-zeek/current") {
		t.Fatalf("Start() error = %q, want missing path in message", err.Error())
	}
}

func TestSuricataConnectorStartFailsForMissingEveFile(t *testing.T) {
	connector, err := NewSuricataConnector(SuricataOptions{
		CiliumClient: &testCiliumClient{},
		EvePath:      "/tmp/fos1-missing-suricata/eve.json",
	})
	if err != nil {
		t.Fatalf("NewSuricataConnector() error = %v", err)
	}
	defer connector.Stop()

	err = connector.Start()
	if err == nil {
		t.Fatal("Start() error = nil, want missing eve.json error")
	}

	if !strings.Contains(err.Error(), "/tmp/fos1-missing-suricata/eve.json") {
		t.Fatalf("Start() error = %q, want missing path in message", err.Error())
	}
}
