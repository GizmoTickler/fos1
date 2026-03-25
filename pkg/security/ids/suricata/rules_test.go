package suricata

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ParseRule tests ---

func TestParseRuleBasicAlert(t *testing.T) {
	line := `alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"ET WEB Test"; sid:2000001; rev:1;)`
	rule, err := ParseRule(line)
	require.NoError(t, err)

	assert.Equal(t, "alert", rule.Action)
	assert.Equal(t, "tcp", rule.Protocol)
	assert.Equal(t, "$HOME_NET", rule.SrcAddr)
	assert.Equal(t, "any", rule.SrcPort)
	assert.Equal(t, "->", rule.Direction)
	assert.Equal(t, "$EXTERNAL_NET", rule.DstAddr)
	assert.Equal(t, "80", rule.DstPort)
	assert.Equal(t, 2000001, rule.SID)
	assert.True(t, rule.Enabled)
	assert.Equal(t, "ET WEB Test", rule.Options["msg"])
	assert.Equal(t, "2000001", rule.Options["sid"])
	assert.Equal(t, "1", rule.Options["rev"])
}

func TestParseRuleDrop(t *testing.T) {
	line := `drop udp any any -> any 53 (msg:"Block DNS"; sid:1000001; rev:2; classtype:policy-violation;)`
	rule, err := ParseRule(line)
	require.NoError(t, err)

	assert.Equal(t, "drop", rule.Action)
	assert.Equal(t, "udp", rule.Protocol)
	assert.Equal(t, "any", rule.SrcAddr)
	assert.Equal(t, "any", rule.SrcPort)
	assert.Equal(t, "->", rule.Direction)
	assert.Equal(t, "any", rule.DstAddr)
	assert.Equal(t, "53", rule.DstPort)
	assert.Equal(t, 1000001, rule.SID)
	assert.Equal(t, "policy-violation", rule.Options["classtype"])
}

func TestParseRuleBidirectional(t *testing.T) {
	line := `alert icmp any any <> any any (msg:"ICMP Bidirectional"; sid:3000001; rev:1;)`
	rule, err := ParseRule(line)
	require.NoError(t, err)

	assert.Equal(t, "<>", rule.Direction)
	assert.Equal(t, "icmp", rule.Protocol)
	assert.Equal(t, 3000001, rule.SID)
}

func TestParseRuleDisabled(t *testing.T) {
	line := `# alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Disabled Rule"; sid:5000001; rev:1;)`
	rule, err := ParseRule(line)
	require.NoError(t, err)

	assert.False(t, rule.Enabled)
	assert.Equal(t, "alert", rule.Action)
	assert.Equal(t, 5000001, rule.SID)
}

func TestParseRulePass(t *testing.T) {
	line := `pass tcp 10.0.0.0/8 any -> any any (msg:"Allow internal"; sid:9000001; rev:1;)`
	rule, err := ParseRule(line)
	require.NoError(t, err)

	assert.Equal(t, "pass", rule.Action)
	assert.Equal(t, "10.0.0.0/8", rule.SrcAddr)
	assert.Equal(t, 9000001, rule.SID)
}

func TestParseRuleReject(t *testing.T) {
	line := `reject tcp any any -> any 25 (msg:"Reject SMTP"; sid:7000001; rev:3;)`
	rule, err := ParseRule(line)
	require.NoError(t, err)

	assert.Equal(t, "reject", rule.Action)
	assert.Equal(t, "25", rule.DstPort)
}

func TestParseRuleWithContentOption(t *testing.T) {
	line := `alert http any any -> any any (msg:"HTTP Test"; content:"GET"; http_method; sid:4000001; rev:1;)`
	rule, err := ParseRule(line)
	require.NoError(t, err)

	assert.Equal(t, "http", rule.Protocol)
	assert.Equal(t, "GET", rule.Options["content"])
	assert.Equal(t, "", rule.Options["http_method"])
	assert.Equal(t, 4000001, rule.SID)
}

func TestParseRuleEmptyLine(t *testing.T) {
	_, err := ParseRule("")
	assert.Error(t, err)
}

func TestParseRuleNonRuleComment(t *testing.T) {
	_, err := ParseRule("# This is just a comment")
	assert.Error(t, err)
}

func TestParseRuleInvalidFormat(t *testing.T) {
	_, err := ParseRule("not a valid rule")
	assert.Error(t, err)
}

// --- Rule.String() tests ---

func TestRuleString(t *testing.T) {
	rule := &Rule{
		Action:    "alert",
		Protocol:  "tcp",
		SrcAddr:   "$HOME_NET",
		SrcPort:   "any",
		Direction: "->",
		DstAddr:   "$EXTERNAL_NET",
		DstPort:   "80",
		Options: map[string]string{
			"msg": "Test Rule",
			"sid": "2000001",
			"rev": "1",
		},
		SID:     2000001,
		Enabled: true,
	}

	s := rule.String()
	assert.Contains(t, s, "alert tcp $HOME_NET any -> $EXTERNAL_NET 80")
	assert.Contains(t, s, `msg:"Test Rule"`)
	assert.Contains(t, s, "sid:2000001")
	assert.Contains(t, s, "rev:1")
	assert.NotContains(t, s, "# ")
}

func TestRuleStringDisabled(t *testing.T) {
	rule := &Rule{
		Action:    "drop",
		Protocol:  "udp",
		SrcAddr:   "any",
		SrcPort:   "any",
		Direction: "->",
		DstAddr:   "any",
		DstPort:   "53",
		Options: map[string]string{
			"msg": "Blocked",
			"sid": "1000001",
			"rev": "1",
		},
		SID:     1000001,
		Enabled: false,
	}

	s := rule.String()
	assert.True(t, s[0] == '#', "disabled rule should start with #")
	assert.Contains(t, s, "drop udp")
}

// --- Round-trip test ---

func TestParseRuleRoundTrip(t *testing.T) {
	original := `alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Round Trip"; sid:6000001; rev:1;)`
	rule, err := ParseRule(original)
	require.NoError(t, err)

	serialized := rule.String()
	reparsed, err := ParseRule(serialized)
	require.NoError(t, err)

	assert.Equal(t, rule.Action, reparsed.Action)
	assert.Equal(t, rule.Protocol, reparsed.Protocol)
	assert.Equal(t, rule.SrcAddr, reparsed.SrcAddr)
	assert.Equal(t, rule.SrcPort, reparsed.SrcPort)
	assert.Equal(t, rule.Direction, reparsed.Direction)
	assert.Equal(t, rule.DstAddr, reparsed.DstAddr)
	assert.Equal(t, rule.DstPort, reparsed.DstPort)
	assert.Equal(t, rule.SID, reparsed.SID)
	assert.Equal(t, rule.Enabled, reparsed.Enabled)
	assert.Equal(t, rule.Options["msg"], reparsed.Options["msg"])
	assert.Equal(t, rule.Options["sid"], reparsed.Options["sid"])
	assert.Equal(t, rule.Options["rev"], reparsed.Options["rev"])
}

// --- ParseRuleFile / WriteRuleFile tests ---

func TestParseRuleFileAndWriteRuleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.rules")

	content := `# A comment line
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Rule One"; sid:100001; rev:1;)
# alert tcp any any -> any 443 (msg:"Disabled Rule"; sid:100002; rev:1;)
drop udp any any -> any 53 (msg:"Rule Three"; sid:100003; rev:2;)
`
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)

	rules, err := ParseRuleFile(path)
	require.NoError(t, err)
	require.Len(t, rules, 3)

	assert.Equal(t, 100001, rules[0].SID)
	assert.True(t, rules[0].Enabled)

	assert.Equal(t, 100002, rules[1].SID)
	assert.False(t, rules[1].Enabled)

	assert.Equal(t, 100003, rules[2].SID)
	assert.True(t, rules[2].Enabled)

	// Write rules back to a new file and verify
	outPath := filepath.Join(dir, "output.rules")
	err = WriteRuleFile(outPath, rules)
	require.NoError(t, err)

	reloaded, err := ParseRuleFile(outPath)
	require.NoError(t, err)
	require.Len(t, reloaded, 3)

	for i, rule := range rules {
		assert.Equal(t, rule.SID, reloaded[i].SID)
		assert.Equal(t, rule.Action, reloaded[i].Action)
		assert.Equal(t, rule.Enabled, reloaded[i].Enabled)
	}
}

func TestParseRuleFileNotExists(t *testing.T) {
	_, err := ParseRuleFile("/nonexistent/path/rules.rules")
	assert.Error(t, err)
}

func TestWriteRuleFileCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.rules")

	rules := []*Rule{
		{
			Action:    "alert",
			Protocol:  "tcp",
			SrcAddr:   "any",
			SrcPort:   "any",
			Direction: "->",
			DstAddr:   "any",
			DstPort:   "80",
			Options:   map[string]string{"msg": "New Rule", "sid": "999001", "rev": "1"},
			SID:       999001,
			Enabled:   true,
		},
	}

	err := WriteRuleFile(path, rules)
	require.NoError(t, err)

	// Verify file exists and can be parsed
	loaded, err := ParseRuleFile(path)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, 999001, loaded[0].SID)
}

// --- RuleManager tests ---

func TestRuleManagerAddRule(t *testing.T) {
	dir := t.TempDir()
	mgr := NewRuleManager(nil, dir)

	rule := &Rule{
		Action:    "alert",
		Protocol:  "tcp",
		SrcAddr:   "$HOME_NET",
		SrcPort:   "any",
		Direction: "->",
		DstAddr:   "$EXTERNAL_NET",
		DstPort:   "80",
		Options:   map[string]string{"msg": "Test", "sid": "200001", "rev": "1"},
		SID:       200001,
		Enabled:   true,
	}

	err := mgr.AddRule(rule)
	require.NoError(t, err)

	// Verify rule was written
	rules, err := mgr.ListRules()
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, 200001, rules[0].SID)
}

func TestRuleManagerAddRuleReplacesExisting(t *testing.T) {
	dir := t.TempDir()
	mgr := NewRuleManager(nil, dir)

	rule1 := &Rule{
		Action:    "alert",
		Protocol:  "tcp",
		SrcAddr:   "any",
		SrcPort:   "any",
		Direction: "->",
		DstAddr:   "any",
		DstPort:   "80",
		Options:   map[string]string{"msg": "Original", "sid": "300001", "rev": "1"},
		SID:       300001,
		Enabled:   true,
	}

	rule2 := &Rule{
		Action:    "drop",
		Protocol:  "tcp",
		SrcAddr:   "any",
		SrcPort:   "any",
		Direction: "->",
		DstAddr:   "any",
		DstPort:   "80",
		Options:   map[string]string{"msg": "Updated", "sid": "300001", "rev": "2"},
		SID:       300001,
		Enabled:   true,
	}

	require.NoError(t, mgr.AddRule(rule1))
	require.NoError(t, mgr.AddRule(rule2))

	rules, err := mgr.ListRules()
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "drop", rules[0].Action)
	assert.Equal(t, "Updated", rules[0].Options["msg"])
}

func TestRuleManagerAddRuleRequiresSID(t *testing.T) {
	dir := t.TempDir()
	mgr := NewRuleManager(nil, dir)

	rule := &Rule{
		Action:    "alert",
		Protocol:  "tcp",
		SrcAddr:   "any",
		SrcPort:   "any",
		Direction: "->",
		DstAddr:   "any",
		DstPort:   "80",
		Options:   map[string]string{"msg": "No SID"},
		SID:       0,
		Enabled:   true,
	}

	err := mgr.AddRule(rule)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "non-zero SID")
}

func TestRuleManagerDisableAndEnableRule(t *testing.T) {
	dir := t.TempDir()
	mgr := NewRuleManager(nil, dir)

	rule := &Rule{
		Action:    "alert",
		Protocol:  "tcp",
		SrcAddr:   "any",
		SrcPort:   "any",
		Direction: "->",
		DstAddr:   "any",
		DstPort:   "443",
		Options:   map[string]string{"msg": "Toggle Me", "sid": "400001", "rev": "1"},
		SID:       400001,
		Enabled:   true,
	}

	require.NoError(t, mgr.AddRule(rule))

	// Disable the rule
	require.NoError(t, mgr.DisableRule(400001))
	r, err := mgr.GetRule(400001)
	require.NoError(t, err)
	assert.False(t, r.Enabled)

	// Enable the rule
	require.NoError(t, mgr.EnableRule(400001))
	r, err = mgr.GetRule(400001)
	require.NoError(t, err)
	assert.True(t, r.Enabled)
}

func TestRuleManagerDisableRuleNotFound(t *testing.T) {
	dir := t.TempDir()
	mgr := NewRuleManager(nil, dir)

	err := mgr.DisableRule(999999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRuleManagerEnableRuleNotFound(t *testing.T) {
	dir := t.TempDir()
	mgr := NewRuleManager(nil, dir)

	err := mgr.EnableRule(999999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRuleManagerGetRule(t *testing.T) {
	dir := t.TempDir()
	mgr := NewRuleManager(nil, dir)

	rule := &Rule{
		Action:    "alert",
		Protocol:  "udp",
		SrcAddr:   "any",
		SrcPort:   "any",
		Direction: "->",
		DstAddr:   "any",
		DstPort:   "53",
		Options:   map[string]string{"msg": "DNS Alert", "sid": "500001", "rev": "1"},
		SID:       500001,
		Enabled:   true,
	}

	require.NoError(t, mgr.AddRule(rule))

	found, err := mgr.GetRule(500001)
	require.NoError(t, err)
	assert.Equal(t, "DNS Alert", found.Options["msg"])
}

func TestRuleManagerGetRuleNotFound(t *testing.T) {
	dir := t.TempDir()
	mgr := NewRuleManager(nil, dir)

	_, err := mgr.GetRule(888888)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRuleManagerListRulesMultipleFiles(t *testing.T) {
	dir := t.TempDir()

	// Write rules to two separate files
	rules1 := []*Rule{
		{
			Action: "alert", Protocol: "tcp", SrcAddr: "any", SrcPort: "any",
			Direction: "->", DstAddr: "any", DstPort: "80",
			Options: map[string]string{"msg": "File1 Rule", "sid": "600001", "rev": "1"},
			SID: 600001, Enabled: true,
		},
	}
	rules2 := []*Rule{
		{
			Action: "drop", Protocol: "udp", SrcAddr: "any", SrcPort: "any",
			Direction: "->", DstAddr: "any", DstPort: "53",
			Options: map[string]string{"msg": "File2 Rule", "sid": "600002", "rev": "1"},
			SID: 600002, Enabled: true,
		},
	}

	require.NoError(t, WriteRuleFile(filepath.Join(dir, "first.rules"), rules1))
	require.NoError(t, WriteRuleFile(filepath.Join(dir, "second.rules"), rules2))

	mgr := NewRuleManager(nil, dir)
	all, err := mgr.ListRules()
	require.NoError(t, err)
	require.Len(t, all, 2)

	sids := map[int]bool{}
	for _, r := range all {
		sids[r.SID] = true
	}
	assert.True(t, sids[600001])
	assert.True(t, sids[600002])
}

func TestRuleManagerReloadRulesNoClient(t *testing.T) {
	dir := t.TempDir()
	mgr := NewRuleManager(nil, dir)

	err := mgr.ReloadRules(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no client configured")
}
