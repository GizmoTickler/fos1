// Package main implements the prometheus-query-validator tool.
//
// extractor.go defines the logic for pulling PromQL expressions out of
// Grafana dashboard JSON and Prometheus alert rule YAML manifests.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
)

// SourceKind identifies where an expression came from.
type SourceKind string

const (
	// SourceDashboardPanel marks expressions that come from a Grafana panel
	// target.
	SourceDashboardPanel SourceKind = "dashboard-panel"
	// SourceDashboardTemplate marks expressions that come from a Grafana
	// template variable query.
	SourceDashboardTemplate SourceKind = "dashboard-template"
	// SourceAlertRule marks expressions that come from a Prometheus alert
	// rule.
	SourceAlertRule SourceKind = "alert-rule"
)

// Expression is a single PromQL expression tied back to the file and
// logical location it came from. Location is an opaque, human-readable
// identifier meant for reporting only.
type Expression struct {
	Expr     string     `json:"expr"`
	Source   SourceKind `json:"source"`
	File     string     `json:"file"`
	Location string     `json:"location"`
}

// ExtractFromDashboard reads a Grafana dashboard JSON file and returns every
// PromQL expression found under the known panel and template shapes.
//
// Supported shapes:
//   - panels[*].targets[*].expr (current Grafana schema)
//   - panels[*].panels[*].targets[*].expr (nested panels inside row panels)
//   - templating.list[*].query when it is a Prometheus-shaped string
//
// Panels that are rows without targets are skipped, and non-string
// template queries are ignored. The function does not reach into
// Grafana-plugin-specific payloads.
func ExtractFromDashboard(path string) ([]Expression, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read dashboard %s: %w", path, err)
	}

	var dash map[string]interface{}
	if err := json.Unmarshal(raw, &dash); err != nil {
		return nil, fmt.Errorf("parse dashboard %s: %w", path, err)
	}

	var out []Expression

	if panels, ok := dash["panels"].([]interface{}); ok {
		out = append(out, walkPanels(path, "", panels)...)
	}

	if templating, ok := dash["templating"].(map[string]interface{}); ok {
		if list, ok := templating["list"].([]interface{}); ok {
			for idx, item := range list {
				entry, ok := item.(map[string]interface{})
				if !ok {
					continue
				}

				name, _ := entry["name"].(string)
				label := name
				if label == "" {
					label = fmt.Sprintf("idx%d", idx)
				}

				// Skip non-Prometheus template variables (datasource
				// vars, constants, etc.).
				if typ, ok := entry["type"].(string); ok && typ != "query" {
					continue
				}

				switch q := entry["query"].(type) {
				case string:
					expr := strings.TrimSpace(q)
					if expr == "" {
						continue
					}
					out = append(out, Expression{
						Expr:     expr,
						Source:   SourceDashboardTemplate,
						File:     path,
						Location: fmt.Sprintf("templating.list[%s]", label),
					})
				case map[string]interface{}:
					if s, ok := q["query"].(string); ok {
						expr := strings.TrimSpace(s)
						if expr == "" {
							continue
						}
						out = append(out, Expression{
							Expr:     expr,
							Source:   SourceDashboardTemplate,
							File:     path,
							Location: fmt.Sprintf("templating.list[%s].query", label),
						})
					}
				}
			}
		}
	}

	return out, nil
}

func walkPanels(file, prefix string, panels []interface{}) []Expression {
	var out []Expression

	for idx, p := range panels {
		panel, ok := p.(map[string]interface{})
		if !ok {
			continue
		}

		label := fmt.Sprintf("%spanels[%d]", prefix, idx)
		if title, ok := panel["title"].(string); ok && title != "" {
			label = fmt.Sprintf("%s(%q)", label, title)
		}

		if nested, ok := panel["panels"].([]interface{}); ok && len(nested) > 0 {
			out = append(out, walkPanels(file, label+".", nested)...)
		}

		targets, ok := panel["targets"].([]interface{})
		if !ok {
			continue
		}

		for tIdx, t := range targets {
			target, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			exprStr, ok := target["expr"].(string)
			if !ok {
				continue
			}
			expr := strings.TrimSpace(exprStr)
			if expr == "" {
				continue
			}

			refID, _ := target["refId"].(string)
			loc := fmt.Sprintf("%s.targets[%d]", label, tIdx)
			if refID != "" {
				loc = fmt.Sprintf("%s.targets[%d:%s]", label, tIdx, refID)
			}

			out = append(out, Expression{
				Expr:     expr,
				Source:   SourceDashboardPanel,
				File:     file,
				Location: loc,
			})
		}
	}

	return out
}

// alertRuleFile is a deliberately lenient YAML shape that covers both the
// raw `groups:` document that `rule_files` inlines and the ConfigMap form
// this repo actually ships. ConfigMaps embed each rule file as a string
// value under `data`, so we walk both top-level groups and string leaves
// under `data`.
type alertRuleFile struct {
	Groups []alertRuleGroup `yaml:"groups"`

	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   map[string]interface{} `yaml:"metadata"`
	Data       map[string]string      `yaml:"data"`
}

type alertRuleGroup struct {
	Name  string               `yaml:"name"`
	Rules []alertRuleRuleEntry `yaml:"rules"`
}

type alertRuleRuleEntry struct {
	Alert  string `yaml:"alert"`
	Record string `yaml:"record"`
	Expr   string `yaml:"expr"`
}

// ExtractFromAlertRules reads a Prometheus alert rule YAML file and returns
// every PromQL expression in `groups[*].rules[*].expr`. The file may either
// be a bare rule file (top-level `groups:`) or a Kubernetes ConfigMap whose
// `data` keys each hold a rule file body as a string.
func ExtractFromAlertRules(path string) ([]Expression, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read alert rules %s: %w", path, err)
	}

	// Prometheus allows multiple YAML documents in a single file. We parse
	// each one independently and union the output.
	docs, err := splitYAMLDocs(raw)
	if err != nil {
		return nil, fmt.Errorf("split YAML %s: %w", path, err)
	}

	var out []Expression

	for docIdx, body := range docs {
		if strings.TrimSpace(string(body)) == "" {
			continue
		}

		var parsed alertRuleFile
		if err := yaml.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("parse alert rules %s doc %d: %w", path, docIdx, err)
		}

		// Top-level groups: extract directly.
		out = append(out, groupsToExpressions(path, docLabel(path, docIdx, -1, ""), parsed.Groups)...)

		// ConfigMap form: walk the data map in stable order and parse each
		// value as its own rule file.
		if len(parsed.Data) > 0 {
			keys := make([]string, 0, len(parsed.Data))
			for k := range parsed.Data {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, key := range keys {
				inner := parsed.Data[key]
				if strings.TrimSpace(inner) == "" {
					continue
				}

				var innerParsed alertRuleFile
				if err := yaml.Unmarshal([]byte(inner), &innerParsed); err != nil {
					return nil, fmt.Errorf("parse alert rules %s data[%s]: %w", path, key, err)
				}

				out = append(out, groupsToExpressions(path, docLabel(path, docIdx, -1, key), innerParsed.Groups)...)
			}
		}
	}

	return out, nil
}

func groupsToExpressions(path, origin string, groups []alertRuleGroup) []Expression {
	var out []Expression

	for _, group := range groups {
		for rIdx, rule := range group.Rules {
			expr := strings.TrimSpace(rule.Expr)
			if expr == "" {
				continue
			}

			ruleName := rule.Alert
			kind := "alert"
			if ruleName == "" {
				ruleName = rule.Record
				kind = "record"
			}
			if ruleName == "" {
				ruleName = fmt.Sprintf("rule%d", rIdx)
			}

			location := fmt.Sprintf("%sgroup=%s,%s=%s", origin, group.Name, kind, ruleName)

			out = append(out, Expression{
				Expr:     expr,
				Source:   SourceAlertRule,
				File:     path,
				Location: location,
			})
		}
	}

	return out
}

func docLabel(path string, docIdx, _ int, dataKey string) string {
	base := filepath.Base(path)
	if dataKey != "" {
		return fmt.Sprintf("%s[data=%s] ", base, dataKey)
	}
	if docIdx > 0 {
		return fmt.Sprintf("%s[doc=%d] ", base, docIdx)
	}
	return ""
}

// splitYAMLDocs splits a YAML file body into its component documents.
// It tolerates a single trailing separator and trims empty chunks.
func splitYAMLDocs(raw []byte) ([][]byte, error) {
	// yaml.v2 doesn't expose a stream splitter, so do a simple line scan
	// for `---` document separators at the start of a line.
	var docs [][]byte
	lines := strings.Split(string(raw), "\n")
	current := strings.Builder{}

	flush := func() {
		body := current.String()
		current.Reset()
		if strings.TrimSpace(body) != "" {
			docs = append(docs, []byte(body))
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "---" {
			flush()
			continue
		}
		current.WriteString(trimmed)
		current.WriteString("\n")
	}
	flush()

	if len(docs) == 0 {
		// Preserve the original buffer so a single-document file with no
		// explicit separator still parses.
		docs = append(docs, raw)
	}

	return docs, nil
}
