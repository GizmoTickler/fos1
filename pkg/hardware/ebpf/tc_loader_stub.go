//go:build !linux

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TCLoader is the non-Linux stub of the TC loader. Every method returns
// ErrEBPFUnsupportedPlatform wrapped with operation context so callers
// can still log a human-readable message via errors.Is.
type TCLoader struct{}

// IngressProgram returns nil on non-Linux. Callers are expected to
// treat a nil program as "no loader available" and surface the
// NewTCLoader error that produced the stub in the first place.
func (l *TCLoader) IngressProgram() *ebpf.Program { return nil }

// EgressProgram returns nil on non-Linux.
func (l *TCLoader) EgressProgram() *ebpf.Program { return nil }

// PriorityMap returns nil on non-Linux.
func (l *TCLoader) PriorityMap() *ebpf.Map { return nil }

// TCQoSShapeObject is a compile-time placeholder so non-Linux callers
// can still type-check against the helper. It always returns
// ErrEBPFUnsupportedPlatform.
func TCQoSShapeObject() ([]byte, error) {
	return nil, fmt.Errorf("TCQoSShapeObject: %w", ErrEBPFUnsupportedPlatform)
}

// NewTCLoader is a non-Linux stub. Returns ErrEBPFUnsupportedPlatform.
func NewTCLoader(_ []byte) (*TCLoader, error) {
	return nil, fmt.Errorf("NewTCLoader: %w", ErrEBPFUnsupportedPlatform)
}

// SetPriority is a non-Linux stub. Returns ErrEBPFUnsupportedPlatform.
func (l *TCLoader) SetPriority(_ string, _ uint32) error {
	return fmt.Errorf("TCLoader.SetPriority: %w", ErrEBPFUnsupportedPlatform)
}

// ClearPriority is a non-Linux stub. Returns ErrEBPFUnsupportedPlatform.
func (l *TCLoader) ClearPriority(_ string) error {
	return fmt.Errorf("TCLoader.ClearPriority: %w", ErrEBPFUnsupportedPlatform)
}

// AttachIngress is a non-Linux stub. Returns ErrEBPFUnsupportedPlatform.
//
// The returned `interface{}` is intentionally untyped: the cilium/ebpf
// `link.Link` type is Linux-only, and callers that live on both
// platforms should reach the Linux path before doing anything with the
// handle. The stub never returns a non-nil handle.
func (l *TCLoader) AttachIngress(_ string) (interface{}, error) {
	return nil, fmt.Errorf("TCLoader.AttachIngress: %w", ErrEBPFUnsupportedPlatform)
}

// AttachEgress is a non-Linux stub.
func (l *TCLoader) AttachEgress(_ string) (interface{}, error) {
	return nil, fmt.Errorf("TCLoader.AttachEgress: %w", ErrEBPFUnsupportedPlatform)
}

// Detach is a non-Linux stub. Returns ErrEBPFUnsupportedPlatform.
func (l *TCLoader) Detach(_ interface{}) error {
	return fmt.Errorf("TCLoader.Detach: %w", ErrEBPFUnsupportedPlatform)
}

// Close is a no-op on non-Linux platforms.
func (l *TCLoader) Close() error { return nil }

// attachTCProgram is the non-Linux stub used by program_manager.go to
// keep the cross-platform dispatch code identical between Linux and
// darwin builds. It always returns ErrEBPFUnsupportedPlatform.
func attachTCProgram(_ *LoadedProgram, _ ebpf.AttachType) (link.Link, error) {
	return nil, fmt.Errorf("attachTCProgram: %w", ErrEBPFUnsupportedPlatform)
}
