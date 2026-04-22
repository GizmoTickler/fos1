package policy

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestTranslatePolicy_SimpleAllow covers the happy-path L3/L4 translation
// and the deterministic Cilium policy name scheme added in sprint 29
// ticket 33.
func TestTranslatePolicy_SimpleAllow(t *testing.T) {
	tr := NewCiliumPolicyTranslator(nil, NewPolicyLogger(false))

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-ssh", Namespace: "team-a"},
		Spec: FilterPolicySpec{
			Enabled:  true,
			Priority: 100,
			Scope:    "ingress",
			Selectors: FilterSelectors{
				Ports: []PortSelector{{Protocol: "tcp", Ports: []int32{22}}},
			},
			Actions: []PolicyAction{{Type: "allow"}},
		},
	}

	got, err := tr.TranslatePolicy(policy, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one CiliumPolicy, got %d", len(got))
	}
	if got[0].Name != "fos1-filter-team-a-allow-ssh" {
		t.Errorf("expected deterministic name fos1-filter-team-a-allow-ssh, got %q", got[0].Name)
	}
	if got[0].Labels["app.kubernetes.io/managed-by"] != "fos1-policy-controller" {
		t.Errorf("expected managed-by label, got %+v", got[0].Labels)
	}
	if len(got[0].Rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(got[0].Rules))
	}
	if got[0].Rules[0].Action != "allow" {
		t.Errorf("expected action allow, got %s", got[0].Rules[0].Action)
	}
}

func TestTranslatePolicy_DisabledReturnsNil(t *testing.T) {
	tr := NewCiliumPolicyTranslator(nil, NewPolicyLogger(false))

	policy := &FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "dormant", Namespace: "team-a"},
		Spec:       FilterPolicySpec{Enabled: false},
	}

	got, err := tr.TranslatePolicy(policy, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil slice for disabled policy, got %+v", got)
	}
}

func TestTranslatePolicy_NilPolicyIsError(t *testing.T) {
	tr := NewCiliumPolicyTranslator(nil, NewPolicyLogger(false))

	_, err := tr.TranslatePolicy(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil policy, got nil")
	}
}

// TestSpecHash_StableAcrossFieldOrdering confirms the canonicalizer reorders
// map/slice fields before hashing so the NAT-style idempotency contract
// holds even when the Kubernetes apiserver returns fields in a different
// order.
func TestSpecHash_StableAcrossFieldOrdering(t *testing.T) {
	base := FilterPolicySpec{
		Enabled:  true,
		Priority: 10,
		Scope:    "egress",
		Tags:     []string{"team-a", "critical", "blue"},
		Selectors: FilterSelectors{
			Sources: []Selector{
				{Type: "cidr", Values: []interface{}{"10.0.0.0/8", "192.168.0.0/16"}},
			},
			Ports: []PortSelector{
				{Protocol: "tcp", Ports: []int32{443, 80}},
			},
		},
		Actions: []PolicyAction{{
			Type: "allow",
			Parameters: map[string]interface{}{
				"log":   true,
				"audit": "yes",
			},
		}},
	}

	reordered := FilterPolicySpec{
		Enabled:  true,
		Priority: 10,
		Scope:    "egress",
		Tags:     []string{"blue", "critical", "team-a"},
		Selectors: FilterSelectors{
			Sources: []Selector{
				{Type: "cidr", Values: []interface{}{"192.168.0.0/16", "10.0.0.0/8"}},
			},
			Ports: []PortSelector{
				{Protocol: "tcp", Ports: []int32{80, 443}},
			},
		},
		Actions: []PolicyAction{{
			Type: "allow",
			Parameters: map[string]interface{}{
				"audit": "yes",
				"log":   true,
			},
		}},
	}

	if h1, h2 := specHash(base), specHash(reordered); h1 != h2 {
		t.Fatalf("expected canonical hashes to match; got %s vs %s", h1, h2)
	}
}

func TestSpecHash_DetectsActualChange(t *testing.T) {
	before := FilterPolicySpec{
		Enabled: true,
		Scope:   "ingress",
		Actions: []PolicyAction{{Type: "allow"}},
	}
	after := before
	after.Scope = "egress"

	if specHash(before) == specHash(after) {
		t.Fatal("expected different hashes when spec fields differ")
	}
}

// TestCiliumPolicyName_Deterministic pins the naming scheme so the output
// stays stable across refactors — operators rely on it for kubectl lookups.
func TestCiliumPolicyName_Deterministic(t *testing.T) {
	cases := []struct {
		name     string
		ns       string
		policy   string
		expected string
	}{
		{"namespaced", "team-b", "allow-http", "fos1-filter-team-b-allow-http"},
		{"cluster-wide (no namespace)", "", "block-egress", "fos1-filter-block-egress"},
		{"special-chars sanitized", "Team_A", "Allow HTTPS!", "fos1-filter-team-a-allow-https"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &FilterPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: tc.policy, Namespace: tc.ns},
			}
			if got := ciliumPolicyName(p); got != tc.expected {
				t.Errorf("ciliumPolicyName(%q/%q) = %q, want %q", tc.ns, tc.policy, got, tc.expected)
			}
		})
	}
}
