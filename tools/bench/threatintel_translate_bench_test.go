// Threat-intel Indicator → CiliumPolicy translate benchmarks.
//
// These benchmarks measure pkg/security/threatintel.Translator.Translate,
// which turns a slice of Indicator (one per feed row from URLhaus etc.)
// into a deduplicated slice of CiliumPolicy structs. The translator is
// pure (no I/O) and stateless; per-iteration cost is dominated by URL
// parsing, SHA-1 hashing of the host, label sanitization, and policy
// struct allocation.
//
// Scale is controlled by the size of the input indicator slice. Each
// synthetic indicator uses a distinct host so the internal `seen` set
// does not collapse duplicates — every indicator does real translate
// work, which is the worst case that matters for regression detection.
//
// Run locally with:
//
//	go test -bench=. -benchmem -count=10 ./tools/bench/...
package bench

import (
	"fmt"
	"testing"
	"time"

	"github.com/GizmoTickler/fos1/pkg/security/threatintel"
)

// buildIndicators constructs `n` synthetic indicators with unique
// hostnames so none of them collapse into the translator's `seen` dedup
// map. A mix of domain-based and IP-literal indicators (every 4th) is
// included so both the toFQDNs and toCIDR branches of buildPolicy get
// exercised proportionally to what a real URLhaus feed looks like.
func buildIndicators(n int) []threatintel.Indicator {
	out := make([]threatintel.Indicator, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		var raw string
		if i%4 == 0 {
			// IP-literal — exercises the toCIDR branch.
			raw = fmt.Sprintf("http://203.0.%d.%d/bad.exe", (i/256)%255, (i%255)+1)
		} else {
			// FQDN — exercises the toFQDNs branch.
			raw = fmt.Sprintf("http://mal-%d.example.com/evil-%d", i, i)
		}
		out[i] = threatintel.Indicator{
			URL:       raw,
			Threat:    "malware_download",
			DateAdded: now,
			Tags:      "bench",
		}
	}
	return out
}

// benchmarkThreatIntelTranslate runs Translate once per iteration on the
// same indicator slice. A fresh Translator is cheap (zero-value struct
// with one field), so constructing it inside the loop matches the real
// controller usage and keeps the bench honest about per-call overhead.
func benchmarkThreatIntelTranslate(b *testing.B, numIndicators int) {
	b.Helper()
	indicators := buildIndicators(numIndicators)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tr := &threatintel.Translator{FeedName: "bench-feed"}
		res := tr.Translate(indicators)
		if len(res.Policies) == 0 {
			b.Fatalf("expected at least one policy, got 0")
		}
	}
}

// BenchmarkThreatIntelTranslate_SingleIndicator measures the base
// overhead of translating one indicator.
func BenchmarkThreatIntelTranslate_SingleIndicator(b *testing.B) {
	benchmarkThreatIntelTranslate(b, 1)
}

// BenchmarkThreatIntelTranslate_HundredIndicators measures translate
// cost for 100 indicators.
func BenchmarkThreatIntelTranslate_HundredIndicators(b *testing.B) {
	benchmarkThreatIntelTranslate(b, 100)
}

// BenchmarkThreatIntelTranslate_ThousandIndicators measures translate
// cost for 1000 indicators. Useful for validating that the per-indicator
// loop stays linear and that dedup-map growth does not introduce
// superlinear cost.
func BenchmarkThreatIntelTranslate_ThousandIndicators(b *testing.B) {
	benchmarkThreatIntelTranslate(b, 1000)
}
