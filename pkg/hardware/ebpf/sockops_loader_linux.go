//go:build linux

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate sh -c "cd ../../.. && make bpf-objects && cp bpf/out/sockops_redirect.o pkg/hardware/ebpf/bpf/sockops_redirect.o"

// embeddedSockOpsRedirectObject is the compiled ELF for
// bpf/sockops_redirect.c.
//
// Committed alongside the source so the Go tree builds on machines
// without a BPF-capable clang. Regenerate via `make bpf-objects` and
// copy into `pkg/hardware/ebpf/bpf/sockops_redirect.o`.
//
//go:embed bpf/sockops_redirect.o
var embeddedSockOpsRedirectObject []byte

// SockOpsRedirectObject returns the embedded ELF object for the owned
// sockops_redirect program. Returns ErrEBPFObjectMissing if the embed
// slot is empty (i.e. `make bpf-objects` has not been run on a host
// with a BPF-capable clang).
func SockOpsRedirectObject() ([]byte, error) {
	if !hasELFMagic(embeddedSockOpsRedirectObject) {
		return nil, ErrEBPFObjectMissing
	}
	return embeddedSockOpsRedirectObject, nil
}

// SockOpsLoader owns the lifecycle of the compiled sockops_redirect
// program and the cgroup v2 attachment it produces.
//
// Usage:
//
//	loader, err := NewSockOpsLoader(objectBytes)
//	defer loader.Close()
//	lnk, err := loader.AttachToCGroup("/sys/fs/cgroup")
//	defer loader.DetachFromCGroup(lnk)
//
// The zero value is unusable; always go through NewSockOpsLoader. A
// single loader instance can service many cgroups: the `*ebpf.Collection`
// holds one program and each Attach call produces an independent link
// handle.
type SockOpsLoader struct {
	spec       *ebpf.CollectionSpec
	coll       *ebpf.Collection
	prog       *ebpf.Program
	counterMap *ebpf.Map
}

// sockops program / map names. Must match the SEC() and map names in
// bpf/sockops_redirect.c — NewSockOpsLoader fails loudly if either is
// missing rather than silently binding the wrong one.
const (
	sockOpsProgName    = "sockops_redirect"
	sockOpsCounterName = "sockops_established_count"
)

// NewSockOpsLoader parses a compiled sockops BPF ELF, verifies the
// program and counter map are present, bumps RLIMIT_MEMLOCK, and loads
// the collection into the kernel.
//
// Capability gating mirrors the XDP and TC loaders: root, CAP_BPF, or
// CAP_NET_ADMIN is required. The returned loader owns the
// `*ebpf.Collection` and must be released via Close.
func NewSockOpsLoader(objectBytes []byte) (*SockOpsLoader, error) {
	if !hasELFMagic(objectBytes) {
		return nil, ErrEBPFObjectMissing
	}

	if err := ensureBPFCapable(); err != nil {
		return nil, err
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectBytes))
	if err != nil {
		return nil, fmt.Errorf("parse BPF ELF: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection: %w", err)
	}

	prog, ok := coll.Programs[sockOpsProgName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing %q program (have %v)", sockOpsProgName, programNames(coll))
	}

	counter, ok := coll.Maps[sockOpsCounterName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing %q map", sockOpsCounterName)
	}

	// Verify program type — belt-and-braces against a future BPF source
	// edit that would move the program to a different section.
	if t := prog.Type(); t != ebpf.SockOps {
		coll.Close()
		return nil, fmt.Errorf("%q has program type %s, want SockOps", sockOpsProgName, t)
	}

	return &SockOpsLoader{
		spec:       spec,
		coll:       coll,
		prog:       prog,
		counterMap: counter,
	}, nil
}

// Program returns the loaded *ebpf.Program. Nil on a nil receiver or a
// closed loader.
func (l *SockOpsLoader) Program() *ebpf.Program {
	if l == nil {
		return nil
	}
	return l.prog
}

// CounterMap exposes the user-space handle for the per-CPU counter.
// Callers read across all CPUs to get the total established-callback
// count. Returns nil on a nil receiver.
func (l *SockOpsLoader) CounterMap() *ebpf.Map {
	if l == nil || l.coll == nil {
		return nil
	}
	return l.counterMap
}

// AttachToCGroup attaches the sockops program to the given cgroup v2
// path via `link.AttachCgroup` with `ebpf.AttachCGroupSockOps`.
//
// The path must be a directory inside a cgroup2 filesystem (typically
// `/sys/fs/cgroup` on modern distros, or a sub-path for per-workload
// scoping). If the path cannot be opened the loader returns
// ErrCGroupPathNotFound wrapping the underlying os error so operators
// can see both "why" and "what to fix".
//
// The returned link.Link should be passed back to DetachFromCGroup
// when the controller tears down the attachment.
func (l *SockOpsLoader) AttachToCGroup(cgroupPath string) (link.Link, error) {
	if l == nil || l.prog == nil {
		return nil, fmt.Errorf("sockops loader not initialized")
	}

	// Verify the path exists and is a directory before handing it to
	// the cilium/ebpf library — its error path here is a plain
	// `open /path: no such file or directory` which gives operators
	// less context than wrapping with our sentinel.
	if err := checkCGroupPath(cgroupPath); err != nil {
		return nil, err
	}

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: l.prog,
	})
	if err != nil {
		return nil, fmt.Errorf("attach sockops to cgroup %q: %w", cgroupPath, err)
	}
	return lnk, nil
}

// DetachFromCGroup closes the given sockops link.
func (l *SockOpsLoader) DetachFromCGroup(lnk link.Link) error {
	if lnk == nil {
		return nil
	}
	if err := lnk.Close(); err != nil {
		return fmt.Errorf("close sockops link: %w", err)
	}
	return nil
}

// Close releases the loaded program and map handles.
func (l *SockOpsLoader) Close() error {
	if l == nil || l.coll == nil {
		return nil
	}
	l.coll.Close()
	l.coll = nil
	l.prog = nil
	l.counterMap = nil
	return nil
}

// checkCGroupPath verifies that `path` exists and is a directory. It
// does NOT verify that the directory is actually backed by a cgroup2
// filesystem — that check requires a statfs syscall we would duplicate
// between two loaders. The cilium/ebpf library's AttachCgroup call
// surfaces the magic-number mismatch with a specific error, and we
// wrap that at the call site rather than here.
func checkCGroupPath(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCGroupPathNotFound, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %q is not a directory", ErrCGroupPathNotFound, path)
	}
	return nil
}

// attachSockOpsProgram is the ProgramManager-facing helper that handles
// both owned-loader and legacy (Code-based) sockops attach paths
// uniformly.
//
//   - Owned-loader path (prog.sockOpsLoader != nil): delegate to the
//     SockOpsLoader so cgroup-path validation and error wrapping
//     happen in one place.
//   - Legacy path (caller-supplied Code): attach the InnerProg
//     directly to the default cgroup v2 root via link.AttachCgroup
//     with AttachCGroupSockOps. Preserves the pre-Sprint-31 dispatch
//     behaviour.
//
// The default cgroup path is `/sys/fs/cgroup` (the unified v2
// hierarchy root on modern distros). Controllers that need a
// per-workload sub-path should call the loader directly rather than
// going through AttachProgram.
func attachSockOpsProgram(prog *LoadedProgram) (link.Link, error) {
	if prog == nil {
		return nil, fmt.Errorf("sockops attach: nil program")
	}
	const defaultCGroupPath = "/sys/fs/cgroup"
	if prog.sockOpsLoader != nil {
		return prog.sockOpsLoader.AttachToCGroup(defaultCGroupPath)
	}
	return link.AttachCgroup(link.CgroupOptions{
		Path:    defaultCGroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: prog.InnerProg,
	})
}
