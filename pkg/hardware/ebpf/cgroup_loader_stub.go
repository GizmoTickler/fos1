//go:build !linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// CGroupLoader is the non-Linux stub of the cgroup loader. Every method
// returns ErrEBPFUnsupportedPlatform wrapped with operation context so
// callers can still log a human-readable message via errors.Is.
type CGroupLoader struct{}

// EgressProgram returns nil on non-Linux. Callers are expected to treat
// a nil program as "no loader available" and surface the NewCGroupLoader
// error that produced the stub in the first place.
func (l *CGroupLoader) EgressProgram() *ebpf.Program { return nil }

// StatsMap returns nil on non-Linux.
func (l *CGroupLoader) StatsMap() *ebpf.Map { return nil }

// CGroupEgressCounterObject is a compile-time placeholder so non-Linux
// callers can still type-check against the helper. It always returns
// ErrEBPFUnsupportedPlatform.
func CGroupEgressCounterObject() ([]byte, error) {
	return nil, fmt.Errorf("CGroupEgressCounterObject: %w", ErrEBPFUnsupportedPlatform)
}

// NewCGroupLoader is a non-Linux stub. Returns
// ErrEBPFUnsupportedPlatform.
func NewCGroupLoader(_ []byte) (*CGroupLoader, error) {
	return nil, fmt.Errorf("NewCGroupLoader: %w", ErrEBPFUnsupportedPlatform)
}

// AttachEgress is a non-Linux stub. Returns ErrEBPFUnsupportedPlatform.
//
// The returned `interface{}` is intentionally untyped: the
// cilium/ebpf `link.Link` type is Linux-only, and callers that live on
// both platforms should reach the Linux path before doing anything
// with the handle. The stub never returns a non-nil handle.
func (l *CGroupLoader) AttachEgress(_ string) (interface{}, error) {
	return nil, fmt.Errorf("CGroupLoader.AttachEgress: %w", ErrEBPFUnsupportedPlatform)
}

// AttachIngress is a non-Linux stub.
func (l *CGroupLoader) AttachIngress(_ string) (interface{}, error) {
	return nil, fmt.Errorf("CGroupLoader.AttachIngress: %w", ErrEBPFUnsupportedPlatform)
}

// Detach is a non-Linux stub. Returns ErrEBPFUnsupportedPlatform.
func (l *CGroupLoader) Detach(_ interface{}) error {
	return fmt.Errorf("CGroupLoader.Detach: %w", ErrEBPFUnsupportedPlatform)
}

// Close is a no-op on non-Linux platforms.
func (l *CGroupLoader) Close() error { return nil }

// attachCGroupProgram is the non-Linux stub used by program_manager.go
// to keep the cross-platform dispatch code identical between Linux and
// darwin builds. It always returns ErrEBPFUnsupportedPlatform.
func attachCGroupProgram(_ *LoadedProgram) (link.Link, error) {
	return nil, fmt.Errorf("attachCGroupProgram: %w", ErrEBPFUnsupportedPlatform)
}
