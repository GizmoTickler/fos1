package correlation

import (
	"fmt"
	"strings"
	"time"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
)

type CorrelatedEvent struct {
	Rule       securityv1alpha1.CorrelationRule `json:"rule"`
	MatchCount int                              `json:"matchCount"`
	DetectedAt time.Time                        `json:"detectedAt"`
	Events     []map[string]any                 `json:"events"`
}

type Processor struct {
	maxEventsInMemory int
	maxEventAge       time.Duration
	rules             []compiledRule
}

type compiledRule struct {
	rule       securityv1alpha1.CorrelationRule
	timeWindow time.Duration
	events     []matchedEvent
}

type matchedEvent struct {
	timestamp time.Time
	payload   map[string]any
}

func NewProcessor(config eventCorrelatorConfig) (*Processor, error) {
	maxEventAge, err := parseOptionalDuration(config.Runtime.MaxEventAge)
	if err != nil {
		return nil, fmt.Errorf("parse runtime maxEventAge: %w", err)
	}

	processor := &Processor{
		maxEventsInMemory: config.Runtime.MaxEventsInMemory,
		maxEventAge:       maxEventAge,
		rules:             make([]compiledRule, 0, len(config.Rules)),
	}

	for _, rule := range config.Rules {
		timeWindow, parseErr := parseOptionalDuration(rule.TimeWindow)
		if parseErr != nil {
			return nil, fmt.Errorf("parse timeWindow for rule %q: %w", rule.Name, parseErr)
		}

		processor.rules = append(processor.rules, compiledRule{
			rule:       rule,
			timeWindow: timeWindow,
		})
	}

	return processor, nil
}

func (p *Processor) ProcessEvent(event map[string]any) ([]CorrelatedEvent, error) {
	eventTime := extractEventTimestamp(event)
	outputs := make([]CorrelatedEvent, 0)

	for i := range p.rules {
		rule := &p.rules[i]
		p.pruneRuleEvents(rule, eventTime)

		match, err := ruleMatches(rule.rule, event)
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}

		rule.events = append(rule.events, matchedEvent{
			timestamp: eventTime,
			payload:   cloneEvent(event),
		})
		p.pruneRuleEvents(rule, eventTime)

		if thresholdFor(rule.rule) == len(rule.events) {
			outputs = append(outputs, CorrelatedEvent{
				Rule:       rule.rule,
				MatchCount: len(rule.events),
				DetectedAt: eventTime.UTC(),
				Events:     cloneEventSlice(rule.events),
			})
		}
	}

	return outputs, nil
}

func (p *Processor) pruneRuleEvents(rule *compiledRule, current time.Time) {
	cutoff := current.Add(-effectiveRetention(rule.timeWindow, p.maxEventAge))
	if rule.timeWindow == 0 && p.maxEventAge == 0 {
		cutoff = time.Time{}
	}

	if !cutoff.IsZero() {
		filtered := rule.events[:0]
		for _, event := range rule.events {
			if event.timestamp.Before(cutoff) {
				continue
			}
			filtered = append(filtered, event)
		}
		rule.events = filtered
	}

	if p.maxEventsInMemory > 0 && len(rule.events) > p.maxEventsInMemory {
		rule.events = append([]matchedEvent(nil), rule.events[len(rule.events)-p.maxEventsInMemory:]...)
	}
}

func ruleMatches(rule securityv1alpha1.CorrelationRule, event map[string]any) (bool, error) {
	for _, condition := range rule.Conditions {
		value, ok := lookupField(event, condition.Field)
		if !ok {
			return false, nil
		}

		switch strings.ToLower(condition.Operator) {
		case "equals":
			if fmt.Sprint(value) != condition.Value {
				return false, nil
			}
		case "contains":
			if !strings.Contains(fmt.Sprint(value), condition.Value) {
				return false, nil
			}
		default:
			return false, fmt.Errorf("unsupported operator %q for rule %q", condition.Operator, rule.Name)
		}
	}

	return true, nil
}

func lookupField(event map[string]any, field string) (any, bool) {
	current := any(event)
	for _, segment := range strings.Split(field, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func extractEventTimestamp(event map[string]any) time.Time {
	for _, key := range []string{"timestamp", "time", "event_timestamp", "ts"} {
		raw, ok := event[key]
		if !ok {
			continue
		}

		switch value := raw.(type) {
		case string:
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
				parsed, err := time.Parse(layout, value)
				if err == nil {
					return parsed.UTC()
				}
			}
		}
	}

	return time.Now().UTC()
}

func thresholdFor(rule securityv1alpha1.CorrelationRule) int {
	if rule.Threshold <= 0 {
		return 1
	}
	return rule.Threshold
}

func effectiveRetention(timeWindow, maxEventAge time.Duration) time.Duration {
	switch {
	case timeWindow == 0:
		return maxEventAge
	case maxEventAge == 0:
		return timeWindow
	case timeWindow < maxEventAge:
		return timeWindow
	default:
		return maxEventAge
	}
}

func parseOptionalDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	return time.ParseDuration(raw)
}

func cloneEvent(event map[string]any) map[string]any {
	cloned := make(map[string]any, len(event))
	for key, value := range event {
		cloned[key] = value
	}
	return cloned
}

func cloneEventSlice(events []matchedEvent) []map[string]any {
	cloned := make([]map[string]any, 0, len(events))
	for _, event := range events {
		cloned = append(cloned, cloneEvent(event.payload))
	}
	return cloned
}
