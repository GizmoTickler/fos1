// DPI event → Cilium policy benchmarks.
//
// These benchmarks measure the cost of
// pkg/security/dpi.PolicyPipeline.ProcessEvent, which is the hot path
// that turns a stream of DPI events into CiliumNetworkPolicy applies.
// The apply side effect is isolated with a minimal fake Cilium client
// so what's being measured is the pipeline's per-event logic:
// deduplication lookup, rule match, policy name / hash construction,
// and bookkeeping on activePolicies / recentEvents.
//
// Each event in a burst uses a distinct SourceIP so the dedup and
// "already active" shortcuts don't kick in — every event does a real
// policy build and apply, which is the worst-case that matters for
// regression detection.
//
// Run locally with:
//
//	go test -bench=. -benchmem -count=10 ./tools/bench/...
package bench

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/security/dpi"
	"github.com/GizmoTickler/fos1/pkg/security/dpi/common"
)

// buildDPIEvents constructs `n` synthetic DPI events with distinct
// source IPs so each event takes the create-policy path rather than
// the dedup shortcut. Severity is pinned above the rule threshold so
// every event matches.
func buildDPIEvents(n int) []common.DPIEvent {
	events := make([]common.DPIEvent, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		events[i] = common.DPIEvent{
			Timestamp:   now,
			SourceIP:    fmt.Sprintf("198.51.100.%d", (i%250)+1),
			DestIP:      "10.0.0.1",
			SourcePort:  40000 + (i % 10000),
			DestPort:    443,
			Protocol:    "tcp",
			Category:    "malware",
			EventType:   "alert",
			Severity:    3,
			Description: "synthetic bench event",
			Signature:   fmt.Sprintf("BENCH-%d", i),
		}
		// Ensure each event's source IP is truly unique across the
		// burst so none of them collide on the /32 policy key.
		if n > 250 {
			events[i].SourceIP = fmt.Sprintf("198.%d.%d.%d", (i/65536)%255+1, (i/256)%255, (i%255)+1)
		}
	}
	return events
}

// bpcBuildRule returns a single matching rule the pipeline will apply
// for every event built by buildDPIEvents. AggregateWindow=0 and a
// non-zero Duration exercise the non-dedup, TTL-tracked path.
func bpcBuildRule() dpi.PolicyRule {
	return dpi.PolicyRule{
		Name:        "bench-block",
		MinSeverity: 2,
		Categories:  []string{"malware"},
		Action:      dpi.ActionBlock,
		Duration:    1 * time.Hour,
	}
}

// benchmarkDPIEvent builds a fresh pipeline per iteration so the
// activePolicies map doesn't grow unbounded across b.N iterations.
// Inside a single iteration, `burst` events are processed back-to-back.
func benchmarkDPIEvent(b *testing.B, burst int) {
	b.Helper()
	events := buildDPIEvents(burst)
	rules := []dpi.PolicyRule{bpcBuildRule()}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pipeline := dpi.NewPolicyPipeline(fakeCiliumClient{}, rules)
		for j := 0; j < burst; j++ {
			// Make source IPs unique across iterations too so the
			// policy key in the per-iteration pipeline really is
			// fresh every call. Without this, when b.N > 1 the
			// second-and-later iterations would hit the "already
			// active" shortcut.
			ev := events[j]
			ev.SourceIP = fmt.Sprintf("198.%d.%d.%d", (i%200)+1, (j/250)%255, (j%250)+1)
			if err := pipeline.ProcessEvent(ctx, ev); err != nil {
				b.Fatalf("ProcessEvent failed: %v", err)
			}
		}
	}
}

// BenchmarkDPIEvent_Single measures per-event cost for a single DPI
// event (one apply per iteration).
func BenchmarkDPIEvent_Single(b *testing.B) {
	benchmarkDPIEvent(b, 1)
}

// BenchmarkDPIEvent_Burst100 measures 100 events processed in one
// iteration, each creating a distinct auto-policy.
func BenchmarkDPIEvent_Burst100(b *testing.B) {
	benchmarkDPIEvent(b, 100)
}

// BenchmarkDPIEvent_Burst1000 measures 1000 events processed in one
// iteration. Useful for validating that the per-event apply loop
// scales linearly and that map growth doesn't introduce superlinear
// cost.
func BenchmarkDPIEvent_Burst1000(b *testing.B) {
	benchmarkDPIEvent(b, 1000)
}
