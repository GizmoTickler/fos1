//go:build !linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// XDPLoader is the non-Linux stub of the XDP loader. Every method
// returns ErrEBPFUnsupportedPlatform wrapped with operation context so
// callers can still log a human-readable message via errors.Is.
type XDPLoader struct{}

// Program returns nil on non-Linux. Callers are expected to treat a nil
// program as "no loader available" and surface the NewXDPLoader error
// that produced the stub in the first place.
func (l *XDPLoader) Program() *ebpf.Program {
	return nil
}

// DenylistMap returns nil on non-Linux for the same reason as Program.
func (l *XDPLoader) DenylistMap() *ebpf.Map {
	return nil
}

// XDPDDoSDropObject is a compile-time placeholder so non-Linux callers
// can still type-check against the helper. It always returns
// ErrEBPFUnsupportedPlatform.
func XDPDDoSDropObject() ([]byte, error) {
	return nil, fmt.Errorf("XDPDDoSDropObject: %w", ErrEBPFUnsupportedPlatform)
}

// NewXDPLoader is a non-Linux stub. Returns ErrEBPFUnsupportedPlatform.
func NewXDPLoader(_ []byte) (*XDPLoader, error) {
	return nil, fmt.Errorf("NewXDPLoader: %w", ErrEBPFUnsupportedPlatform)
}

// Attach is a non-Linux stub. Returns ErrEBPFUnsupportedPlatform.
//
// The returned `interface{}` is intentionally untyped: the cilium/ebpf
// `link.Link` type is Linux-only, and callers that live on both
// platforms should reach the Linux path before doing anything with the
// handle. The stub never returns a non-nil handle.
func (l *XDPLoader) Attach(_ string) (interface{}, error) {
	return nil, fmt.Errorf("XDPLoader.Attach: %w", ErrEBPFUnsupportedPlatform)
}

// Detach is a non-Linux stub. Returns ErrEBPFUnsupportedPlatform.
func (l *XDPLoader) Detach(_ interface{}) error {
	return fmt.Errorf("XDPLoader.Detach: %w", ErrEBPFUnsupportedPlatform)
}

// Close is a no-op on non-Linux platforms.
func (l *XDPLoader) Close() error {
	return nil
}
