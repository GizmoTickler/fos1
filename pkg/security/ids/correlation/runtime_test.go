package correlation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
)

func TestProcessorEmitsCorrelationWhenThresholdReachedWithinWindow(t *testing.T) {
	t.Parallel()

	processor, err := NewProcessor(eventCorrelatorConfig{
		Runtime: eventCorrelatorRuntimeConfig{
			MaxEventsInMemory: 10,
			MaxEventAge:       "1h",
		},
		Rules: []securityv1alpha1.CorrelationRule{
			{
				Name:       "ssh-brute-force",
				Threshold:  2,
				TimeWindow: "5m",
				Severity:   "high",
				Action:     "alert",
				Conditions: []securityv1alpha1.CorrelationCondition{
					{Field: "signature", Operator: "contains", Value: "SSH"},
				},
			},
		},
	})
	require.NoError(t, err)

	first := map[string]any{
		"timestamp": "2026-04-20T12:00:00Z",
		"signature": "SSH brute force attempt",
		"source_ip": "192.0.2.10",
	}
	second := map[string]any{
		"timestamp": "2026-04-20T12:02:00Z",
		"signature": "SSH brute force attempt",
		"source_ip": "192.0.2.10",
	}

	outputs, err := processor.ProcessEvent(first)
	require.NoError(t, err)
	assert.Empty(t, outputs)

	outputs, err = processor.ProcessEvent(second)
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	assert.Equal(t, "ssh-brute-force", outputs[0].Rule.Name)
	assert.Equal(t, 2, outputs[0].MatchCount)
	assert.Len(t, outputs[0].Events, 2)
}

func TestProcessorDropsExpiredEventsBeforeThresholdEvaluation(t *testing.T) {
	t.Parallel()

	processor, err := NewProcessor(eventCorrelatorConfig{
		Runtime: eventCorrelatorRuntimeConfig{
			MaxEventsInMemory: 10,
			MaxEventAge:       "1h",
		},
		Rules: []securityv1alpha1.CorrelationRule{
			{
				Name:       "ssh-brute-force",
				Threshold:  2,
				TimeWindow: "5m",
				Conditions: []securityv1alpha1.CorrelationCondition{
					{Field: "signature", Operator: "contains", Value: "SSH"},
				},
			},
		},
	})
	require.NoError(t, err)

	for _, event := range []map[string]any{
		{
			"timestamp": "2026-04-20T12:00:00Z",
			"signature": "SSH brute force attempt",
		},
		{
			"timestamp": "2026-04-20T12:10:00Z",
			"signature": "SSH brute force attempt",
		},
	} {
		outputs, processErr := processor.ProcessEvent(event)
		require.NoError(t, processErr)
		assert.Empty(t, outputs)
	}
}

func TestLoadConfigAppliesRuntimeAndSinkOverrides(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	rawConfig := eventCorrelatorConfig{
		Source: securityv1alpha1.EventSource{
			Type:   "file",
			Path:   filepath.Join(dir, "events.jsonl"),
			Format: "jsonl",
		},
		Sink: securityv1alpha1.EventSink{
			Type:   "file",
			Path:   filepath.Join(dir, "correlated.json"),
			Format: "json",
		},
		Runtime: eventCorrelatorRuntimeConfig{
			MaxEventsInMemory: 5,
			MaxEventAge:       "15m",
		},
	}
	payload, err := json.Marshal(rawConfig)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, payload, 0o644))

	config, err := LoadConfig(configPath, ConfigOverrides{
		MaxEventsInMemory: 25,
		MaxEventAge:       "1h",
		OutputFormat:      "json",
	})
	require.NoError(t, err)
	assert.Equal(t, 25, config.Runtime.MaxEventsInMemory)
	assert.Equal(t, "1h", config.Runtime.MaxEventAge)
	assert.Equal(t, "json", config.Sink.Format)
}

func TestRuntimeRunsFileSourceToFileSink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "events.jsonl")
	outputPath := filepath.Join(dir, "correlated.json")

	require.NoError(t, os.WriteFile(inputPath, []byte(
		"{\"timestamp\":\"2026-04-20T12:00:00Z\",\"signature\":\"SSH brute force attempt\",\"source_ip\":\"192.0.2.10\"}\n"+
			"{\"timestamp\":\"2026-04-20T12:03:00Z\",\"signature\":\"SSH brute force attempt\",\"source_ip\":\"192.0.2.10\"}\n",
	), 0o644))

	runtime, err := NewRuntime(eventCorrelatorConfig{
		Source: securityv1alpha1.EventSource{
			Type:   "file",
			Path:   inputPath,
			Format: "jsonl",
		},
		Sink: securityv1alpha1.EventSink{
			Type:   "file",
			Path:   outputPath,
			Format: "json",
		},
		Runtime: eventCorrelatorRuntimeConfig{
			MaxEventsInMemory: 10,
			MaxEventAge:       "1h",
		},
		Rules: []securityv1alpha1.CorrelationRule{
			{
				Name:       "ssh-brute-force",
				Threshold:  2,
				TimeWindow: "5m",
				Severity:   "high",
				Action:     "alert",
				Conditions: []securityv1alpha1.CorrelationCondition{
					{Field: "signature", Operator: "contains", Value: "SSH"},
				},
			},
		},
	}, RuntimeOptions{
		PollInterval: 10 * time.Millisecond,
		HTTPAddr:     "127.0.0.1:0",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runtime.Run(ctx)
	}()

	require.Eventually(t, func() bool {
		content, readErr := os.ReadFile(outputPath)
		if readErr != nil {
			return false
		}

		var outputs []CorrelatedEvent
		for _, line := range splitNonEmptyLines(string(content)) {
			var output CorrelatedEvent
			if json.Unmarshal([]byte(line), &output) != nil {
				return false
			}
			outputs = append(outputs, output)
		}

		return len(outputs) == 1 && outputs[0].Rule.Name == "ssh-brute-force" && outputs[0].MatchCount == 2
	}, 3*time.Second, 25*time.Millisecond)

	cancel()
	require.NoError(t, <-errCh)
}

func TestNewRuntimeRejectsFileSourceWithoutPath(t *testing.T) {
	t.Parallel()

	_, err := NewRuntime(eventCorrelatorConfig{
		Source: securityv1alpha1.EventSource{
			Type:   "file",
			Format: "jsonl",
		},
		Sink: securityv1alpha1.EventSink{
			Type:   "stdout",
			Format: "json",
		},
	}, RuntimeOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source.path is required for file source")
}

func TestNewRuntimeRejectsFileSinkWithoutPath(t *testing.T) {
	t.Parallel()

	_, err := NewRuntime(eventCorrelatorConfig{
		Source: securityv1alpha1.EventSource{
			Type:   "file",
			Path:   "/tmp/events.jsonl",
			Format: "jsonl",
		},
		Sink: securityv1alpha1.EventSink{
			Type:   "file",
			Format: "json",
		},
	}, RuntimeOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sink.path is required for file sink")
}

func TestProbeHandlerReportsHealthAndReadiness(t *testing.T) {
	t.Parallel()

	state := NewProbeState()
	handler := NewProbeHandler(state)

	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	assert.Equal(t, http.StatusOK, healthRec.Code)

	readyReq := httptest.NewRequest(http.MethodGet, "/ready", nil)
	readyRec := httptest.NewRecorder()
	handler.ServeHTTP(readyRec, readyReq)
	assert.Equal(t, http.StatusServiceUnavailable, readyRec.Code)

	state.SetReady(true)
	readyRec = httptest.NewRecorder()
	handler.ServeHTTP(readyRec, readyReq)
	assert.Equal(t, http.StatusOK, readyRec.Code)
}

func splitNonEmptyLines(raw string) []string {
	lines := make([]string, 0)
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\n' {
			continue
		}
		if start != i {
			lines = append(lines, raw[start:i])
		}
		start = i + 1
	}
	if start < len(raw) {
		lines = append(lines, raw[start:])
	}
	return lines
}
