// FilterPolicy → CiliumPolicy translate benchmarks.
//
// These benchmarks measure the cost of
// pkg/security/policy.CiliumPolicyTranslator.TranslatePolicy, the pure
// (no I/O) function that the policy controller calls on every
// reconcile to turn a FilterPolicy CRD into a slice of
// cilium.CiliumPolicy structs. The apply path is not exercised here:
// this is the pure translate cost only, which is what the NAT-style
// spec-hash idempotency shortcut doesn't save you from when the spec
// actually changes.
//
// Scale is controlled by the number of PortSelectors on the input
// FilterPolicy: each selector becomes its own CiliumRule, so the
// per-selector work in translateCiliumRules dominates at higher
// counts.
//
// Run locally with:
//
//	go test -bench=. -benchmem -count=10 ./tools/bench/...
package bench

import (
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

// buildFilterPolicy constructs a FilterPolicy with `numRules` port
// selectors (each with a single port) plus a fixed source / destination
// selector set. Each selector is a distinct protocol+port combination
// so the translator's per-selector loop does real work proportional to
// numRules.
func buildFilterPolicy(name string, numRules int) *policy.FilterPolicy {
	ports := make([]policy.PortSelector, numRules)
	for i := 0; i < numRules; i++ {
		proto := "tcp"
		if i%2 == 1 {
			proto = "udp"
		}
		ports[i] = policy.PortSelector{
			Protocol: proto,
			Ports:    []int32{int32(1024 + i)},
		}
	}
	return &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "bench",
		},
		Spec: policy.FilterPolicySpec{
			Description: "bench",
			Scope:       "ingress",
			Enabled:     true,
			Priority:    100,
			Selectors: policy.FilterSelectors{
				Sources: []policy.Selector{{
					Type:   "cidr",
					Values: []interface{}{"10.0.0.0/8"},
				}},
				Destinations: []policy.Selector{{
					Type:   "cidr",
					Values: []interface{}{"192.168.0.0/16"},
				}},
				Ports: ports,
			},
			Actions: []policy.PolicyAction{{Type: "allow"}},
		},
	}
}

// benchmarkFilterPolicyTranslate builds a fresh translator per run but
// reuses the same FilterPolicy across iterations: the translator is
// stateless and pure, so measuring the repeated-translate cost is the
// point. A unique name per iteration is not needed here (no cache is
// keyed on it), unlike the NAT apply bench.
func benchmarkFilterPolicyTranslate(b *testing.B, numRules int) {
	b.Helper()
	fp := buildFilterPolicy(fmt.Sprintf("bench-%d", numRules), numRules)
	tr := policy.NewCiliumPolicyTranslator(nil, policy.NewPolicyLogger(false))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		out, err := tr.TranslatePolicy(fp, nil)
		if err != nil {
			b.Fatalf("TranslatePolicy failed: %v", err)
		}
		if len(out) != 1 {
			b.Fatalf("expected 1 CiliumPolicy, got %d", len(out))
		}
	}
}

// BenchmarkFilterPolicyTranslate_SingleRule measures the base overhead
// of translating a FilterPolicy with one port selector.
func BenchmarkFilterPolicyTranslate_SingleRule(b *testing.B) {
	benchmarkFilterPolicyTranslate(b, 1)
}

// BenchmarkFilterPolicyTranslate_HundredRules measures translate cost
// scaled to 100 port selectors.
func BenchmarkFilterPolicyTranslate_HundredRules(b *testing.B) {
	benchmarkFilterPolicyTranslate(b, 100)
}

// BenchmarkFilterPolicyTranslate_ThousandRules measures translate cost
// scaled to 1000 port selectors. Useful for validating that the
// per-selector loop in translateCiliumRules stays linear.
func BenchmarkFilterPolicyTranslate_ThousandRules(b *testing.B) {
	benchmarkFilterPolicyTranslate(b, 1000)
}
