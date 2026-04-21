package traffic

import (
	"testing"
)

func TestClassifierReconcilesRules(t *testing.T) {
	c := NewClassifier()

	// Apply a set of rules spanning every match dimension.
	rules := []ClassificationRule{
		{
			Name:                 "voip",
			Priority:             1,
			ClassName:            "gold",
			SourceAddresses:      []string{"10.0.0.0/24"},
			DestinationAddresses: []string{"8.8.8.8"},
			Protocol:             "udp",
			DestinationPorts:     []string{"5000-5010"},
			Applications:         []string{"sip"},
			ApplicationCategories: []string{"voice"},
			DSCP:                 46,
		},
		{
			Name:      "bulk",
			Priority:  10,
			ClassName: "bulk",
			Protocol:  "any",
		},
	}
	for _, r := range rules {
		if err := c.AddClassificationRule(r); err != nil {
			t.Fatalf("AddClassificationRule %s: %v", r.Name, err)
		}
	}

	// Read back the full rule set.
	got, err := c.ListClassificationRules()
	if err != nil {
		t.Fatalf("ListClassificationRules: %v", err)
	}
	if len(got) != len(rules) {
		t.Fatalf("expected %d rules, got %d", len(rules), len(got))
	}

	// Update an existing rule (same name) and verify it replaces in-place.
	updated := rules[0]
	updated.DSCP = 10
	if err := c.AddClassificationRule(updated); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	got, _ = c.ListClassificationRules()
	if len(got) != len(rules) {
		t.Fatalf("update should not add a new rule, got %d", len(got))
	}

	// Remove a rule and check the read-back reflects deletion.
	if err := c.RemoveClassificationRule("bulk"); err != nil {
		t.Fatalf("RemoveClassificationRule: %v", err)
	}
	got, _ = c.ListClassificationRules()
	if len(got) != 1 {
		t.Fatalf("expected 1 rule after delete, got %d", len(got))
	}
	// Removing an unknown rule returns an error.
	if err := c.RemoveClassificationRule("missing"); err == nil {
		t.Fatalf("expected error removing unknown rule")
	}
}

func TestClassifyPacketReturnsHighestPriorityMatch(t *testing.T) {
	c := NewClassifier()

	// Broad fallback
	_ = c.AddClassificationRule(ClassificationRule{Name: "catch-all", Priority: 100, ClassName: "default"})
	// Narrower VoIP match
	_ = c.AddClassificationRule(ClassificationRule{
		Name:             "voip",
		Priority:         1,
		ClassName:        "gold",
		Protocol:         "udp",
		DestinationPorts: []string{"5060"},
	})

	gold, err := c.ClassifyPacket(PacketInfo{
		Protocol:        "udp",
		DestinationPort: 5060,
	})
	if err != nil {
		t.Fatalf("ClassifyPacket: %v", err)
	}
	if gold != "gold" {
		t.Fatalf("expected gold, got %s", gold)
	}

	// Fallback hits catch-all when no specific rule matches.
	def, err := c.ClassifyPacket(PacketInfo{Protocol: "tcp", DestinationPort: 22})
	if err != nil {
		t.Fatalf("ClassifyPacket: %v", err)
	}
	if def != "default" {
		t.Fatalf("expected default, got %s", def)
	}
}

func TestClassifyPacketMatchesAllDimensions(t *testing.T) {
	c := NewClassifier().(*classifier)

	rule := ClassificationRule{
		Name:                  "full",
		Priority:              1,
		ClassName:             "gold",
		SourceAddresses:       []string{"10.0.0.0/24"},
		DestinationAddresses:  []string{"192.168.1.1"},
		Protocol:              "tcp",
		SourcePorts:           []string{"1000-2000"},
		DestinationPorts:      []string{"443"},
		Applications:          []string{"https"},
		ApplicationCategories: []string{"web"},
		DSCP:                  10,
	}

	pkt := PacketInfo{
		SourceIP:            "10.0.0.5",
		DestinationIP:       "192.168.1.1",
		Protocol:            "tcp",
		SourcePort:          1500,
		DestinationPort:     443,
		Application:         "https",
		ApplicationCategory: "web",
		DSCP:                10,
	}
	if !c.matchesRule(pkt, rule) {
		t.Fatalf("expected packet to match full rule")
	}

	// Flip each dimension in turn and confirm the rule no longer matches.
	cases := []struct {
		name   string
		mutate func(p *PacketInfo)
	}{
		{"source ip out of range", func(p *PacketInfo) { p.SourceIP = "192.168.10.1" }},
		{"dest ip mismatch", func(p *PacketInfo) { p.DestinationIP = "10.10.10.10" }},
		{"protocol mismatch", func(p *PacketInfo) { p.Protocol = "udp" }},
		{"source port out", func(p *PacketInfo) { p.SourcePort = 50 }},
		{"dest port out", func(p *PacketInfo) { p.DestinationPort = 80 }},
		{"application mismatch", func(p *PacketInfo) { p.Application = "ftp" }},
		{"application missing", func(p *PacketInfo) { p.Application = "" }},
		{"category mismatch", func(p *PacketInfo) { p.ApplicationCategory = "voice" }},
		{"dscp mismatch", func(p *PacketInfo) { p.DSCP = 0 }},
	}
	for _, tc := range cases {
		p := pkt
		tc.mutate(&p)
		if c.matchesRule(p, rule) {
			t.Fatalf("%s: expected packet NOT to match", tc.name)
		}
	}
}

func TestClassifierIPInNetworkAndPortInRange(t *testing.T) {
	c := &classifier{}

	if !c.ipInNetwork("10.0.0.1", "10.0.0.0/24") {
		t.Fatalf("expected 10.0.0.1 in 10.0.0.0/24")
	}
	if !c.ipInNetwork("10.0.0.1", "10.0.0.1") {
		t.Fatalf("expected 10.0.0.1 to match single IP")
	}
	if c.ipInNetwork("not-an-ip", "10.0.0.0/24") {
		t.Fatalf("expected invalid IP to not match")
	}
	if c.ipInNetwork("10.0.0.1", "bogus") {
		t.Fatalf("expected invalid CIDR to not match")
	}

	if !c.portInRange(80, "80") {
		t.Fatalf("expected 80 in single-port range")
	}
	if c.portInRange(80, "81") {
		t.Fatalf("expected 80 not to match 81")
	}
	if !c.portInRange(1500, "1000-2000") {
		t.Fatalf("expected 1500 in 1000-2000")
	}
	if c.portInRange(50, "1000-2000") {
		t.Fatalf("expected 50 out of 1000-2000")
	}
	if c.portInRange(80, "abc-xyz") {
		t.Fatalf("expected invalid range to not match")
	}
	if c.portInRange(80, "50-xyz") {
		t.Fatalf("expected half-invalid range to not match")
	}
	if c.portInRange(80, "xyz") {
		t.Fatalf("expected invalid single port to not match")
	}
}
