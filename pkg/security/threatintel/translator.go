package threatintel

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/GizmoTickler/fos1/pkg/cilium"
)

// Translator converts parsed Indicator entries into Cilium network policies.
//
// v0 produces one CiliumPolicy per indicator domain that denies egress to the
// FQDN via `toFQDNs`. IP literals are translated into CIDR deny rules instead
// (toFQDNs does not accept raw addresses). Indicators whose host component
// cannot be extracted are skipped and returned to the caller via the
// UnresolvedCount on TranslateResult.
type Translator struct {
	// FeedName is used to namespace the generated policy names so multiple
	// ThreatFeed resources can coexist without colliding.
	FeedName string
}

// TranslateResult summarizes what Translate produced from a batch of indicators.
type TranslateResult struct {
	// Policies is the set of CiliumPolicy structs to apply; one per unique
	// indicator key.
	Policies []*cilium.CiliumPolicy

	// Keys is a parallel slice of stable indicator keys (same length as
	// Policies) used for dedup/expiry tracking. key[i] corresponds to
	// Policies[i].
	Keys []string

	// UnresolvedCount tracks entries that could not be translated (empty
	// host, malformed URLs, etc.). Non-fatal; surfaced via logs/status.
	UnresolvedCount int
}

// Translate converts indicators into Cilium policies. It is deterministic:
// the same indicator always produces the same policy name and labels, and
// duplicate indicators in the input slice collapse into a single policy.
func (t *Translator) Translate(indicators []Indicator) TranslateResult {
	seen := make(map[string]struct{}, len(indicators))
	result := TranslateResult{}

	for _, ind := range indicators {
		host := extractHost(ind.URL)
		if host == "" {
			result.UnresolvedCount++
			continue
		}

		key := indicatorKey(host)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		policy := t.buildPolicy(host, key, ind)
		result.Policies = append(result.Policies, policy)
		result.Keys = append(result.Keys, key)
	}

	return result
}

// PolicyName returns the deterministic CiliumPolicy name for a given
// indicator key. Exported for use by the manager when expiring policies.
func (t *Translator) PolicyName(key string) string {
	feedSlug := sanitizeLabelComponent(t.FeedName)
	if feedSlug == "" {
		feedSlug = "feed"
	}
	return fmt.Sprintf("fos1-threatintel-%s-%s", feedSlug, key)
}

// buildPolicy constructs the CiliumPolicy for a single host/indicator pair.
func (t *Translator) buildPolicy(host, key string, ind Indicator) *cilium.CiliumPolicy {
	policyName := t.PolicyName(key)

	labels := map[string]string{
		"fos1.io/auto-generated": "true",
		"fos1.io/source":         "threatintel",
		"fos1.io/feed":           sanitizeLabelComponent(t.FeedName),
		"fos1.io/indicator-key":  key,
	}
	if ind.Threat != "" {
		labels["fos1.io/threat"] = sanitizeLabelComponent(ind.Threat)
	}

	description := fmt.Sprintf("Auto-generated from threat feed %q (indicator=%s)", t.FeedName, host)
	if ind.Threat != "" {
		description += " threat=" + ind.Threat
	}

	rule := cilium.CiliumRule{
		Denied: true,
		Action: "deny",
	}
	if isIPLiteral(host) {
		cidr := host
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		rule.ToCIDR = []string{cidr}
	} else {
		rule.ToFQDNs = []cilium.MatchFQDN{{MatchPattern: host}}
	}

	return &cilium.CiliumPolicy{
		Name:        policyName,
		Description: description,
		Labels:      labels,
		Rules:       []cilium.CiliumRule{rule},
	}
}

// extractHost parses the URL and returns its host component, lowercased and
// with any port stripped. It falls back to a lenient prefix strip for URLs
// that lack a scheme (URLhaus sometimes publishes these).
func extractHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// If the URL lacks a scheme, url.Parse treats the whole string as a
	// path. Try with a default scheme so Host is populated.
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}

	u, err := url.Parse(candidate)
	if err != nil || u.Host == "" {
		return ""
	}

	host := u.Hostname()
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

// indicatorKey hashes the host into a short, label-safe identifier so the
// resulting policy names fit Kubernetes' 63-character limit even for long
// domains.
func indicatorKey(host string) string {
	sum := sha1.Sum([]byte(host)) //nolint:gosec // not used for security
	return hex.EncodeToString(sum[:8])
}

// isIPLiteral returns true if the host string parses as an IPv4 or IPv6 address.
func isIPLiteral(host string) bool {
	return net.ParseIP(host) != nil
}

// sanitizeLabelComponent lowercases and strips characters invalid in K8s
// label values, falling back to "_" for anything not [a-z0-9-.]. It does not
// truncate; callers that need a length bound should apply one.
func sanitizeLabelComponent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			b = append(b, c)
		case c >= '0' && c <= '9':
			b = append(b, c)
		case c == '-' || c == '.' || c == '_':
			b = append(b, c)
		default:
			b = append(b, '-')
		}
	}
	trimmed := strings.Trim(string(b), "-._")
	if trimmed == "" {
		return "x"
	}
	if len(trimmed) > 40 {
		trimmed = trimmed[:40]
	}
	return trimmed
}
