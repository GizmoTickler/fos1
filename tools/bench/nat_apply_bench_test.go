// Package bench holds performance benchmarks for FOS1 hot paths.
//
// The NAT policy apply benchmarks here measure the cost of
// pkg/network/nat/manager.ApplyNATPolicy, isolated from Kubernetes
// API round-trips and real Cilium writes by using a minimal fake
// Cilium client. What's being measured is the manager's apply logic:
// validation, spec hashing, condition bookkeeping, dispatch per NAT
// type, and the per-rule call loop (DNAT port mappings).
//
// Run locally with:
//
//	go test -bench=. -benchmem -count=10 ./tools/bench/...
//
// See docs/performance/README.md for philosophy and regression policy.
package bench

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"testing"

	"k8s.io/klog/v2"

	"github.com/GizmoTickler/fos1/pkg/cilium"
	"github.com/GizmoTickler/fos1/pkg/network/nat"
)

// TestMain silences klog for the whole package. The NAT manager logs
// per-apply at Info level; without this, a `-count=10` run with
// numMappings=1000 produces hundreds of MB of log output that both
// drowns the benchmark numbers and perturbs timing.
func TestMain(m *testing.M) {
	flags := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(flags)
	// -logtostderr=false + SetOutput(io.Discard) routes all klog output
	// to /dev/null without touching process-global stderr.
	_ = flags.Set("logtostderr", "false")
	_ = flags.Set("alsologtostderr", "false")
	_ = flags.Set("stderrthreshold", "FATAL")
	_ = flags.Set("v", "0")
	klog.SetOutput(io.Discard)

	os.Exit(m.Run())
}

// fakeCiliumClient is a zero-work stand-in for the real Cilium client.
// Every method returns nil immediately so the benchmark measures only
// the NAT manager's apply-logic cost. It is intentionally local to
// this package to avoid coupling benchmarks to test helpers in the
// NAT package.
type fakeCiliumClient struct{}

func (fakeCiliumClient) ApplyNetworkPolicy(context.Context, *cilium.CiliumPolicy) error {
	return nil
}
func (fakeCiliumClient) DeleteNetworkPolicy(context.Context, string) error { return nil }
func (fakeCiliumClient) ListRoutes(context.Context) ([]cilium.Route, error) {
	return nil, nil
}
func (fakeCiliumClient) ListVRFRoutes(context.Context, int) ([]cilium.Route, error) {
	return nil, nil
}
func (fakeCiliumClient) AddRoute(cilium.Route) error            { return nil }
func (fakeCiliumClient) DeleteRoute(cilium.Route) error         { return nil }
func (fakeCiliumClient) AddVRFRoute(cilium.Route, int) error    { return nil }
func (fakeCiliumClient) DeleteVRFRoute(cilium.Route, int) error { return nil }
func (fakeCiliumClient) CreateNAT(context.Context, *cilium.CiliumNATConfig) error {
	return nil
}
func (fakeCiliumClient) RemoveNAT(context.Context, *cilium.CiliumNATConfig) error {
	return nil
}
func (fakeCiliumClient) CreateNAT64(context.Context, *cilium.NAT64Config) error {
	return nil
}
func (fakeCiliumClient) RemoveNAT64(context.Context, *cilium.NAT64Config) error {
	return nil
}
func (fakeCiliumClient) CreatePortForward(context.Context, *cilium.PortForwardConfig) error {
	return nil
}
func (fakeCiliumClient) RemovePortForward(context.Context, *cilium.PortForwardConfig) error {
	return nil
}
func (fakeCiliumClient) ConfigureVLANRouting(context.Context, *cilium.CiliumVLANRoutingConfig) error {
	return nil
}
func (fakeCiliumClient) ConfigureDPIIntegration(context.Context, *cilium.CiliumDPIIntegrationConfig) error {
	return nil
}

// buildDNATConfig constructs a DNAT policy with the requested number of
// port mappings. Each mapping targets a distinct port so the per-rule
// apply loop in manager.applyDNAT does real work proportional to
// numMappings.
func buildDNATConfig(name string, numMappings int) nat.Config {
	mappings := make([]nat.PortMapping, numMappings)
	for i := 0; i < numMappings; i++ {
		mappings[i] = nat.PortMapping{
			Protocol:     "tcp",
			ExternalPort: 10000 + i,
			InternalIP:   "10.0.0.5",
			InternalPort: 20000 + i,
			Description:  "bench",
		}
	}
	return nat.Config{
		Name:         name,
		Namespace:    "bench",
		Type:         nat.TypeDNAT,
		Interface:    "eth0",
		ExternalIP:   "203.0.113.1",
		PortMappings: mappings,
	}
}

// benchmarkNATApply runs ApplyNATPolicy once per iteration with a
// unique policy name so each call does a real apply (not the hash-hit
// idempotency shortcut). A fresh manager per iteration keeps the
// internal maps bounded and stops cross-iteration memory growth from
// leaking into allocs/op numbers.
func benchmarkNATApply(b *testing.B, numMappings int) {
	b.Helper()
	cfg := buildDNATConfig("rule", numMappings)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mgr := nat.NewManager(fakeCiliumClient{})
		cfg.Name = fmt.Sprintf("rule-%d", i)
		if _, err := mgr.ApplyNATPolicy(cfg); err != nil {
			b.Fatalf("ApplyNATPolicy failed: %v", err)
		}
	}
}

// BenchmarkNATApply_SingleRule measures the base overhead of applying
// a DNAT policy with a single port mapping.
func BenchmarkNATApply_SingleRule(b *testing.B) {
	benchmarkNATApply(b, 1)
}

// BenchmarkNATApply_HundredRules measures apply cost scaled to 100
// port mappings per policy.
func BenchmarkNATApply_HundredRules(b *testing.B) {
	benchmarkNATApply(b, 100)
}

// BenchmarkNATApply_ThousandRules measures apply cost scaled to 1000
// port mappings per policy. Useful for validating that the per-rule
// apply loop stays linear.
func BenchmarkNATApply_ThousandRules(b *testing.B) {
	benchmarkNATApply(b, 1000)
}
