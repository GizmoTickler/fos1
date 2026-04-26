package correlation

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
	"github.com/GizmoTickler/fos1/pkg/security/certificates"
)

type RuntimeOptions struct {
	PollInterval time.Duration
	HTTPAddr     string
	Stdout       io.Writer

	// TLSCertDir, when non-empty, switches the probe HTTP listener to
	// HTTPS using cert-manager-rotated material. Sprint 31 / Ticket 49.
	TLSCertDir string
}

type Runtime struct {
	config    eventCorrelatorConfig
	processor *Processor
	sink      correlatedEventSink
	probes    *ProbeState
	options   RuntimeOptions
}

type correlatedEventSink interface {
	Write(CorrelatedEvent) error
	Close() error
}

type fileSink struct {
	mu   sync.Mutex
	file *os.File
}

type writerSink struct {
	mu     sync.Mutex
	writer io.Writer
}

func NewRuntime(config eventCorrelatorConfig, options RuntimeOptions) (*Runtime, error) {
	if err := validateRuntimeConfig(config); err != nil {
		return nil, err
	}

	processor, err := NewProcessor(config)
	if err != nil {
		return nil, err
	}

	if options.PollInterval <= 0 {
		options.PollInterval = 250 * time.Millisecond
	}
	if options.HTTPAddr == "" {
		options.HTTPAddr = ":8080"
	}
	if options.Stdout == nil {
		options.Stdout = os.Stdout
	}

	sink, err := newSink(config.Sink, options.Stdout)
	if err != nil {
		return nil, err
	}

	return &Runtime{
		config:    config,
		processor: processor,
		sink:      sink,
		probes:    NewProbeState(),
		options:   options,
	}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if err := validateRuntimeConfig(r.config); err != nil {
		return err
	}
	defer func() {
		r.probes.SetReady(false)
		r.probes.SetHealthy(false)
		_ = r.sink.Close()
	}()

	listener, err := net.Listen("tcp", r.options.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen for probes: %w", err)
	}

	server := &http.Server{
		Handler: NewProbeHandler(r.probes),
	}

	// Sprint 31 / Ticket 49: when TLS material is mounted, wrap the
	// listener in TLS using the shared rotation-aware loader.
	var tlsCancel context.CancelFunc
	if r.options.TLSCertDir != "" {
		tlsCfg, reloader, lerr := certificates.LoadTLSConfig(r.options.TLSCertDir)
		if lerr != nil {
			_ = listener.Close()
			return fmt.Errorf("load TLS config from %s: %w", r.options.TLSCertDir, lerr)
		}
		server.TLSConfig = tlsCfg
		listener = tls.NewListener(listener, tlsCfg)

		watchCtx, cancel := context.WithCancel(ctx)
		tlsCancel = cancel
		go func() {
			if werr := reloader.WatchAndReload(watchCtx, nil, tlsCfg, nil); werr != nil {
				// Non-fatal — the server keeps using the cert in
				// memory. Logged via stderr because the runtime
				// here doesn't carry a klog handle.
				fmt.Fprintf(os.Stderr, "correlator: TLS watcher exited: %v\n", werr)
			}
		}()
	}
	serverErrCh := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		if tlsCancel != nil {
			tlsCancel()
		}
		<-serverErrCh
	}()

	r.probes.SetReady(true)

	var offset int64
	if err := r.readAvailable(&offset); err != nil {
		return err
	}

	ticker := time.NewTicker(r.options.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serverErrCh:
			if err != nil {
				return fmt.Errorf("serve probes: %w", err)
			}
			return nil
		case <-ticker.C:
			if err := r.readAvailable(&offset); err != nil {
				return err
			}
		}
	}
}

func validateRuntimeConfig(config eventCorrelatorConfig) error {
	if config.Source.Type != "file" {
		return fmt.Errorf("unsupported source type %q", config.Source.Type)
	}
	if config.Source.Path == "" {
		return fmt.Errorf("source.path is required for file source")
	}
	if config.Source.Format != "" && config.Source.Format != "jsonl" {
		return fmt.Errorf("unsupported source format %q", config.Source.Format)
	}
	switch config.Sink.Type {
	case "file", "stdout":
	default:
		return fmt.Errorf("unsupported sink type %q", config.Sink.Type)
	}
	if config.Sink.Type == "file" && config.Sink.Path == "" {
		return fmt.Errorf("sink.path is required for file sink")
	}
	if config.Sink.Format != "" && config.Sink.Format != "json" {
		return fmt.Errorf("unsupported sink format %q", config.Sink.Format)
	}
	return nil
}

func (r *Runtime) readAvailable(offset *int64) error {
	info, err := os.Stat(r.config.Source.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat source file: %w", err)
	}
	if info.Size() < *offset {
		*offset = 0
	}

	file, err := os.Open(r.config.Source.Path)
	if err != nil {
		return fmt.Errorf("open source file: %w", err)
	}
	defer file.Close()

	if _, err := file.Seek(*offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek source file: %w", err)
	}

	reader := bufio.NewReader(file)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			*offset += int64(len(line))
			if err := r.processLine(line); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("read source line: %w", readErr)
		}
	}
}

func (r *Runtime) processLine(line []byte) error {
	line = bytesTrimSpace(line)
	if len(line) == 0 {
		return nil
	}

	var event map[string]any
	if err := json.Unmarshal(line, &event); err != nil {
		return fmt.Errorf("decode source event: %w", err)
	}

	outputs, err := r.processor.ProcessEvent(event)
	if err != nil {
		return err
	}

	for _, output := range outputs {
		if err := r.sink.Write(output); err != nil {
			return err
		}
	}
	return nil
}

func newSink(config securityv1alpha1.EventSink, stdout io.Writer) (correlatedEventSink, error) {
	switch config.Type {
	case "file":
		if config.Path == "" {
			return nil, fmt.Errorf("sink.path is required for file sink")
		}
		if err := os.MkdirAll(filepath.Dir(config.Path), 0o755); err != nil {
			return nil, fmt.Errorf("create sink directory: %w", err)
		}
		file, err := os.OpenFile(config.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open sink file: %w", err)
		}
		return &fileSink{file: file}, nil
	case "stdout":
		return &writerSink{writer: stdout}, nil
	default:
		return nil, fmt.Errorf("unsupported sink type %q", config.Type)
	}
}

func (s *fileSink) Write(event CorrelatedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSONLine(s.file, event)
}

func (s *fileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Close()
}

func (s *writerSink) Write(event CorrelatedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSONLine(s.writer, event)
}

func (s *writerSink) Close() error {
	return nil
}

func writeJSONLine(writer io.Writer, event CorrelatedEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode correlated event: %w", err)
	}
	if _, err := writer.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write correlated event: %w", err)
	}
	return nil
}

func bytesTrimSpace(input []byte) []byte {
	start := 0
	end := len(input)
	for start < end && isSpace(input[start]) {
		start++
	}
	for end > start && isSpace(input[end-1]) {
		end--
	}
	return input[start:end]
}

func isSpace(value byte) bool {
	switch value {
	case ' ', '\n', '\r', '\t':
		return true
	default:
		return false
	}
}
