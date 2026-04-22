package threatintel

import (
	"strings"
	"testing"
	"time"
)

func TestTranslator_ProducesFQDNDenyRule(t *testing.T) {
	tr := &Translator{FeedName: "urlhaus"}
	ind := Indicator{
		URL:       "http://malicious.example.com/bad.exe",
		Threat:    "malware_download",
		DateAdded: time.Now(),
	}
	res := tr.Translate([]Indicator{ind})
	if len(res.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(res.Policies))
	}
	p := res.Policies[0]
	if !strings.HasPrefix(p.Name, "fos1-threatintel-urlhaus-") {
		t.Errorf("unexpected policy name %s", p.Name)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Rules))
	}
	rule := p.Rules[0]
	if !rule.Denied {
		t.Error("rule should be denied")
	}
	if len(rule.ToFQDNs) != 1 || rule.ToFQDNs[0].MatchPattern != "malicious.example.com" {
		t.Errorf("expected toFQDNs matching malicious.example.com, got %+v", rule.ToFQDNs)
	}
	if len(rule.ToCIDR) != 0 {
		t.Errorf("FQDN indicator should not emit ToCIDR, got %+v", rule.ToCIDR)
	}
	if p.Labels["fos1.io/feed"] != "urlhaus" {
		t.Errorf("expected feed label urlhaus, got %q", p.Labels["fos1.io/feed"])
	}
	if p.Labels["fos1.io/threat"] != "malware_download" {
		t.Errorf("expected threat label malware_download, got %q", p.Labels["fos1.io/threat"])
	}
}

func TestTranslator_IPLiteralEmitsCIDR(t *testing.T) {
	tr := &Translator{FeedName: "urlhaus"}
	ind := Indicator{URL: "http://203.0.113.10/"}
	res := tr.Translate([]Indicator{ind})
	if len(res.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(res.Policies))
	}
	rule := res.Policies[0].Rules[0]
	if len(rule.ToCIDR) != 1 || rule.ToCIDR[0] != "203.0.113.10/32" {
		t.Errorf("expected ToCIDR 203.0.113.10/32, got %+v", rule.ToCIDR)
	}
	if len(rule.ToFQDNs) != 0 {
		t.Errorf("IP literal should not emit ToFQDNs, got %+v", rule.ToFQDNs)
	}
}

func TestTranslator_Deduplicates(t *testing.T) {
	tr := &Translator{FeedName: "urlhaus"}
	indicators := []Indicator{
		{URL: "http://foo.example/"},
		{URL: "http://foo.example/different-path"},
		{URL: "https://foo.example:8080/"},
		{URL: "http://bar.example/"},
	}
	res := tr.Translate(indicators)
	if len(res.Policies) != 2 {
		t.Errorf("expected 2 unique policies, got %d", len(res.Policies))
	}
}

func TestTranslator_UnresolvableIndicator(t *testing.T) {
	tr := &Translator{FeedName: "urlhaus"}
	indicators := []Indicator{
		{URL: ""},
		{URL: "   "},
	}
	res := tr.Translate(indicators)
	if len(res.Policies) != 0 {
		t.Errorf("expected 0 policies for empty URLs, got %d", len(res.Policies))
	}
	if res.UnresolvedCount != 2 {
		t.Errorf("expected UnresolvedCount=2, got %d", res.UnresolvedCount)
	}
}

func TestTranslator_DeterministicPolicyName(t *testing.T) {
	tr := &Translator{FeedName: "urlhaus"}
	a := tr.Translate([]Indicator{{URL: "http://evil.example/"}}).Policies[0].Name
	b := tr.Translate([]Indicator{{URL: "http://evil.example/"}}).Policies[0].Name
	if a != b {
		t.Errorf("same indicator should produce same policy name, got %s vs %s", a, b)
	}
	if len(a) > 63 {
		t.Errorf("policy name must fit k8s 63-char limit, got len=%d: %s", len(a), a)
	}
}
