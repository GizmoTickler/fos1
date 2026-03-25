package suricata

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Rule represents a Suricata rule with its parsed components.
type Rule struct {
	Action    string            // alert, pass, drop, reject
	Protocol  string            // tcp, udp, icmp, ip, etc.
	SrcAddr   string            // source address or variable like $HOME_NET
	SrcPort   string            // source port or "any"
	Direction string            // -> or <>
	DstAddr   string            // destination address or variable
	DstPort   string            // destination port or "any"
	Options   map[string]string // sid, msg, rev, classtype, etc.
	SID       int               // signature ID extracted from options
	Enabled   bool              // false if the rule is commented out
	Raw       string            // original raw rule text (without leading # for disabled rules)
}

// ruleHeaderRe matches the header portion of a Suricata rule:
//
//	action protocol src_addr src_port direction dst_addr dst_port
var ruleHeaderRe = regexp.MustCompile(
	`^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.+)\)\s*$`,
)

// ParseRule parses a single Suricata rule line into a Rule struct.
// Lines that are commented out (leading #) are parsed with Enabled=false.
// Blank lines and comment-only lines that do not contain a rule return an error.
func ParseRule(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}

	enabled := true
	raw := line

	// Handle commented-out rules
	if strings.HasPrefix(line, "#") {
		stripped := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		// Check if the remainder looks like a rule (starts with an action keyword)
		if !looksLikeRule(stripped) {
			return nil, fmt.Errorf("not a rule: %s", line)
		}
		enabled = false
		line = stripped
		raw = stripped
	}

	matches := ruleHeaderRe.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("invalid rule format: %s", line)
	}

	options, err := parseOptions(matches[8])
	if err != nil {
		return nil, fmt.Errorf("parse options: %w", err)
	}

	sid := 0
	if sidStr, ok := options["sid"]; ok {
		sid, err = strconv.Atoi(strings.TrimSpace(sidStr))
		if err != nil {
			return nil, fmt.Errorf("invalid sid %q: %w", sidStr, err)
		}
	}

	return &Rule{
		Action:    matches[1],
		Protocol:  matches[2],
		SrcAddr:   matches[3],
		SrcPort:   matches[4],
		Direction: matches[5],
		DstAddr:   matches[6],
		DstPort:   matches[7],
		Options:   options,
		SID:       sid,
		Enabled:   enabled,
		Raw:       raw,
	}, nil
}

// looksLikeRule returns true if the line starts with a known Suricata action keyword.
func looksLikeRule(line string) bool {
	actions := []string{"alert", "pass", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth"}
	lower := strings.ToLower(line)
	for _, a := range actions {
		if strings.HasPrefix(lower, a+" ") {
			return true
		}
	}
	return false
}

// parseOptions parses the options section of a Suricata rule (the part inside parentheses).
// Options are semicolon-delimited key:value pairs.
func parseOptions(raw string) (map[string]string, error) {
	opts := make(map[string]string)
	raw = strings.TrimSpace(raw)

	// Split by semicolons, but be careful with quoted strings
	parts := splitOptions(raw)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Options are either "key:value" or standalone "key"
		idx := strings.Index(part, ":")
		if idx == -1 {
			opts[part] = ""
		} else {
			key := strings.TrimSpace(part[:idx])
			value := strings.TrimSpace(part[idx+1:])
			// Remove surrounding quotes from values like msg
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}
			opts[key] = value
		}
	}

	return opts, nil
}

// splitOptions splits the options string on semicolons, respecting quoted strings.
func splitOptions(s string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	escaped := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			current.WriteByte(ch)
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			current.WriteByte(ch)
			continue
		}
		if ch == ';' && !inQuote {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(ch)
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// String formats the Rule back into Suricata rule syntax.
// If the rule is disabled, the output is prefixed with "# ".
func (r *Rule) String() string {
	var sb strings.Builder

	if !r.Enabled {
		sb.WriteString("# ")
	}

	sb.WriteString(fmt.Sprintf("%s %s %s %s %s %s %s",
		r.Action, r.Protocol, r.SrcAddr, r.SrcPort, r.Direction, r.DstAddr, r.DstPort))

	sb.WriteString(" (")

	// Build options in a deterministic order: msg first, then sorted keys, sid and rev last
	type kv struct {
		key   string
		value string
	}

	priorityFirst := []string{"msg"}
	priorityLast := []string{"sid", "rev"}
	prioritySet := make(map[string]bool)
	for _, k := range priorityFirst {
		prioritySet[k] = true
	}
	for _, k := range priorityLast {
		prioritySet[k] = true
	}

	var ordered []kv

	// First: priority-first keys in order
	for _, k := range priorityFirst {
		if v, ok := r.Options[k]; ok {
			ordered = append(ordered, kv{k, v})
		}
	}

	// Middle: everything else sorted
	var middleKeys []string
	for k := range r.Options {
		if !prioritySet[k] {
			middleKeys = append(middleKeys, k)
		}
	}
	sort.Strings(middleKeys)
	for _, k := range middleKeys {
		ordered = append(ordered, kv{k, r.Options[k]})
	}

	// Last: priority-last keys in order
	for _, k := range priorityLast {
		if v, ok := r.Options[k]; ok {
			ordered = append(ordered, kv{k, v})
		}
	}

	for i, opt := range ordered {
		if i > 0 {
			sb.WriteString(" ")
		}
		if opt.value == "" {
			sb.WriteString(fmt.Sprintf("%s;", opt.key))
		} else {
			// Quote the msg value
			if opt.key == "msg" {
				sb.WriteString(fmt.Sprintf("%s:\"%s\";", opt.key, opt.value))
			} else {
				sb.WriteString(fmt.Sprintf("%s:%s;", opt.key, opt.value))
			}
		}
	}

	sb.WriteString(")")

	return sb.String()
}

// ParseRuleFile reads a Suricata rule file and returns all parsed rules.
// Comment-only lines that do not contain disabled rules and blank lines are skipped.
func ParseRuleFile(path string) ([]*Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open rule file %s: %w", path, err)
	}
	defer f.Close()

	var rules []*Rule
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		rule, err := ParseRule(line)
		if err != nil {
			// Skip non-rule lines (pure comments, etc.)
			continue
		}
		rules = append(rules, rule)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read rule file %s: %w", path, err)
	}

	return rules, nil
}

// WriteRuleFile writes the given rules to a file, one rule per line.
// The file is created with mode 0644 if it does not exist, or truncated if it does.
func WriteRuleFile(path string, rules []*Rule) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create rule file %s: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, rule := range rules {
		if _, err := fmt.Fprintln(w, rule.String()); err != nil {
			return fmt.Errorf("write rule sid=%d: %w", rule.SID, err)
		}
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush rule file %s: %w", path, err)
	}

	return nil
}
