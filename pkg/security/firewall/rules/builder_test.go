package rules

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/GizmoTickler/fos1/pkg/security/policy"
)

func TestNewRuleBuilder(t *testing.T) {
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: policy.FilterPolicySpec{
			Scope:   "forward",
			Enabled: true,
		},
	}

	builder := NewRuleBuilder(testPolicy)
	require.NotNil(t, builder)
	assert.Equal(t, testPolicy, builder.policy)
}

func TestRuleBuilder_BuildRules_SimpleAccept(t *testing.T) {
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: policy.FilterPolicySpec{
			Scope:   "forward",
			Enabled: true,
			Actions: []policy.PolicyAction{
				{
					Type: "accept",
				},
			},
		},
	}

	builder := NewRuleBuilder(testPolicy)

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}

	chain := &nftables.Chain{
		Name:  "forward",
		Table: table,
	}

	rules, err := builder.BuildRules(table, chain)
	assert.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.NotNil(t, rules[0])
	assert.Equal(t, table, rules[0].Table)
	assert.Equal(t, chain, rules[0].Chain)
	assert.NotEmpty(t, rules[0].Exprs)
}

func TestRuleBuilder_BuildRules_WithSourceIP(t *testing.T) {
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: policy.FilterPolicySpec{
			Scope:   "forward",
			Enabled: true,
			Selectors: policy.FilterSelectors{
				Sources: []policy.Selector{
					{
						Type:   "ip",
						Values: []interface{}{"192.168.1.0/24"},
					},
				},
			},
			Actions: []policy.PolicyAction{
				{
					Type: "accept",
				},
			},
		},
	}

	builder := NewRuleBuilder(testPolicy)

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}

	chain := &nftables.Chain{
		Name:  "forward",
		Table: table,
	}

	rules, err := builder.BuildRules(table, chain)
	assert.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.NotEmpty(t, rules[0].Exprs)
}

func TestRuleBuilder_BuildRules_WithDestinationIP(t *testing.T) {
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: policy.FilterPolicySpec{
			Scope:   "forward",
			Enabled: true,
			Selectors: policy.FilterSelectors{
				Destinations: []policy.Selector{
					{
						Type:   "ip",
						Values: []interface{}{"10.0.0.0/8"},
					},
				},
			},
			Actions: []policy.PolicyAction{
				{
					Type: "drop",
				},
			},
		},
	}

	builder := NewRuleBuilder(testPolicy)

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}

	chain := &nftables.Chain{
		Name:  "forward",
		Table: table,
	}

	rules, err := builder.BuildRules(table, chain)
	assert.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.NotEmpty(t, rules[0].Exprs)
}

func TestRuleBuilder_BuildRules_WithPorts(t *testing.T) {
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: policy.FilterPolicySpec{
			Scope:   "forward",
			Enabled: true,
			Selectors: policy.FilterSelectors{
				Ports: []policy.PortSelector{
					{
						Protocol: "tcp",
						Ports:    []int32{80, 443},
					},
				},
			},
			Actions: []policy.PolicyAction{
				{
					Type: "accept",
				},
			},
		},
	}

	builder := NewRuleBuilder(testPolicy)

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}

	chain := &nftables.Chain{
		Name:  "forward",
		Table: table,
	}

	rules, err := builder.BuildRules(table, chain)
	assert.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.NotEmpty(t, rules[0].Exprs)
}

func TestRuleBuilder_BuildRules_WithInterface(t *testing.T) {
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: policy.FilterPolicySpec{
			Scope:   "forward",
			Enabled: true,
			Selectors: policy.FilterSelectors{
				Sources: []policy.Selector{
					{
						Type:   "interface",
						Values: []interface{}{"eth0"},
					},
				},
			},
			Actions: []policy.PolicyAction{
				{
					Type: "accept",
				},
			},
		},
	}

	builder := NewRuleBuilder(testPolicy)

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}

	chain := &nftables.Chain{
		Name:  "forward",
		Table: table,
	}

	rules, err := builder.BuildRules(table, chain)
	assert.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.NotEmpty(t, rules[0].Exprs)
}

func TestRuleBuilder_BuildRules_WithIPSet(t *testing.T) {
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: policy.FilterPolicySpec{
			Scope:   "forward",
			Enabled: true,
			Selectors: policy.FilterSelectors{
				Sources: []policy.Selector{
					{
						Type:   "ipset",
						Values: []interface{}{"blacklist"},
					},
				},
			},
			Actions: []policy.PolicyAction{
				{
					Type: "drop",
				},
			},
		},
	}

	builder := NewRuleBuilder(testPolicy)

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}

	chain := &nftables.Chain{
		Name:  "forward",
		Table: table,
	}

	rules, err := builder.BuildRules(table, chain)
	assert.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.NotEmpty(t, rules[0].Exprs)
}

func TestRuleBuilder_BuildRules_IPv6(t *testing.T) {
	testPolicy := &policy.FilterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-policy",
		},
		Spec: policy.FilterPolicySpec{
			Scope:   "forward",
			Enabled: true,
			Selectors: policy.FilterSelectors{
				Sources: []policy.Selector{
					{
						Type:   "ip",
						Values: []interface{}{"2001:db8::/32"},
					},
				},
			},
			Actions: []policy.PolicyAction{
				{
					Type: "accept",
				},
			},
		},
	}

	builder := NewRuleBuilder(testPolicy)

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "filter",
	}

	chain := &nftables.Chain{
		Name:  "forward",
		Table: table,
	}

	rules, err := builder.BuildRules(table, chain)
	assert.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.NotEmpty(t, rules[0].Exprs)
}

func TestProtocolToNumber(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		expected uint8
	}{
		{"TCP", "tcp", 6},
		{"UDP", "udp", 17},
		{"ICMP", "icmp", 1},
		{"ICMPv6", "icmpv6", 58},
		{"SCTP", "sctp", 132},
		{"Unknown", "unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := protocolToNumber(tt.protocol)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildNATRule_SNAT(t *testing.T) {
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	}

	chain := &nftables.Chain{
		Name:  "postrouting",
		Table: table,
	}

	rule, err := BuildNATRule(table, chain, "192.168.1.0/24", "203.0.113.1", "snat")
	assert.NoError(t, err)
	assert.NotNil(t, rule)
	assert.Equal(t, table, rule.Table)
	assert.Equal(t, chain, rule.Chain)
	assert.NotEmpty(t, rule.Exprs)
}

func TestBuildNATRule_DNAT(t *testing.T) {
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	}

	chain := &nftables.Chain{
		Name:  "prerouting",
		Table: table,
	}

	rule, err := BuildNATRule(table, chain, "", "192.168.1.100", "dnat")
	assert.NoError(t, err)
	assert.NotNil(t, rule)
	assert.Equal(t, table, rule.Table)
	assert.Equal(t, chain, rule.Chain)
	assert.NotEmpty(t, rule.Exprs)
}

func TestBuildNATRule_Masquerade(t *testing.T) {
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	}

	chain := &nftables.Chain{
		Name:  "postrouting",
		Table: table,
	}

	rule, err := BuildNATRule(table, chain, "192.168.0.0/16", "203.0.113.1", "masquerade")
	assert.NoError(t, err)
	assert.NotNil(t, rule)
	assert.NotEmpty(t, rule.Exprs)
}

func TestBuildNATRule_InvalidIP(t *testing.T) {
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	}

	chain := &nftables.Chain{
		Name:  "postrouting",
		Table: table,
	}

	_, err := BuildNATRule(table, chain, "invalid-ip", "203.0.113.1", "snat")
	assert.Error(t, err)
}
