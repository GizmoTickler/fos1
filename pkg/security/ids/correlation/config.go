package correlation

import (
	"encoding/json"
	"fmt"
	"os"
)

type ConfigOverrides struct {
	MaxEventsInMemory int
	MaxEventAge       string
	OutputFormat      string
}

func LoadConfig(path string, overrides ConfigOverrides) (eventCorrelatorConfig, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return eventCorrelatorConfig{}, fmt.Errorf("read config: %w", err)
	}

	var config eventCorrelatorConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return eventCorrelatorConfig{}, fmt.Errorf("decode config: %w", err)
	}

	if overrides.MaxEventsInMemory > 0 {
		config.Runtime.MaxEventsInMemory = overrides.MaxEventsInMemory
	}
	if overrides.MaxEventAge != "" {
		config.Runtime.MaxEventAge = overrides.MaxEventAge
	}
	if overrides.OutputFormat != "" {
		config.Sink.Format = overrides.OutputFormat
	}

	if config.Source.Type == "" {
		return eventCorrelatorConfig{}, fmt.Errorf("source.type is required")
	}
	if config.Sink.Type == "" {
		return eventCorrelatorConfig{}, fmt.Errorf("sink.type is required")
	}
	if config.Source.Format == "" {
		config.Source.Format = "jsonl"
	}
	if config.Sink.Format == "" {
		config.Sink.Format = "json"
	}

	return config, nil
}
