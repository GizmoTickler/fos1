//go:build !linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// SockOpsLoader is the non-Linux stub of the sockops loader. Every
// method returns ErrEBPFUnsupportedPlatform wrapped with operation
// context so callers can still log a human-readable message via
// errors.Is.
type SockOpsLoader struct{}

// Program returns nil on non-Linux. Callers are expected to treat a nil
// program as "no loader available" and surface the NewSockOpsLoader
// error that produced the stub in the first place.
func (l *SockOpsLoader) Program() *ebpf.Program { return nil }

// CounterMap returns nil on non-Linux.
func (l *SockOpsLoader) CounterMap() *ebpf.Map { return nil }

// SockOpsRedirectObject is a compile-time placeholder so non-Linux
// callers can still type-check against the helper. It always returns
// ErrEBPFUnsupportedPlatform.
func SockOpsRedirectObject() ([]byte, error) {
	return nil, fmt.Errorf("SockOpsRedirectObject: %w", ErrEBPFUnsupportedPlatform)
}

// NewSockOpsLoader is a non-Linux stub. Returns
// ErrEBPFUnsupportedPlatform.
func NewSockOpsLoader(_ []byte) (*SockOpsLoader, error) {
	return nil, fmt.Errorf("NewSockOpsLoader: %w", ErrEBPFUnsupportedPlatform)
}

// AttachToCGroup is a non-Linux stub. Returns
// ErrEBPFUnsupportedPlatform.
//
// The returned `interface{}` is intentionally untyped: the
// cilium/ebpf `link.Link` type is Linux-only, and callers that live on
// both platforms should reach the Linux path before doing anything
// with the handle. The stub never returns a non-nil handle.
func (l *SockOpsLoader) AttachToCGroup(_ string) (interface{}, error) {
	return nil, fmt.Errorf("SockOpsLoader.AttachToCGroup: %w", ErrEBPFUnsupportedPlatform)
}

// DetachFromCGroup is a non-Linux stub. Returns
// ErrEBPFUnsupportedPlatform.
func (l *SockOpsLoader) DetachFromCGroup(_ interface{}) error {
	return fmt.Errorf("SockOpsLoader.DetachFromCGroup: %w", ErrEBPFUnsupportedPlatform)
}

// Close is a no-op on non-Linux platforms.
func (l *SockOpsLoader) Close() error { return nil }

// attachSockOpsProgram is the non-Linux stub used by program_manager.go
// to keep the cross-platform dispatch code identical between Linux and
// darwin builds. It always returns ErrEBPFUnsupportedPlatform.
func attachSockOpsProgram(_ *LoadedProgram) (link.Link, error) {
	return nil, fmt.Errorf("attachSockOpsProgram: %w", ErrEBPFUnsupportedPlatform)
}
