// Package capture provides functionality for packet capture management.
package capture

import "errors"

// Sentinel errors surfaced by the capture manager. They live in a
// platform-neutral file so both the Linux real path and the non-Linux stub
// return identical sentinels and callers can use errors.Is on every platform.
var (
	// ErrTCPDumpNotAvailable is returned when the tcpdump binary cannot be
	// located on PATH. The real Linux manager refuses to start without it and
	// surfaces this sentinel so callers can downgrade gracefully.
	ErrTCPDumpNotAvailable = errors.New("tcpdump binary not found in PATH")

	// ErrCaptureUnsupported is returned when packet capture is not supported on
	// the current platform (the non-Linux stub).
	ErrCaptureUnsupported = errors.New("packet capture not supported on this platform")

	// ErrCaptureNotFound is returned when the requested capture ID has no
	// corresponding job in the manager.
	ErrCaptureNotFound = errors.New("capture not found")
)
