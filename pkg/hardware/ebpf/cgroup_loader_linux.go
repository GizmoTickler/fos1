//go:build linux

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate sh -c "cd ../../.. && make bpf-objects && cp bpf/out/cgroup_egress_counter.o pkg/hardware/ebpf/bpf/cgroup_egress_counter.o"

// embeddedCGroupEgressCounterObject is the compiled ELF for
// bpf/cgroup_egress_counter.c.
//
// Committed alongside the source so the Go tree builds on machines
// without a BPF-capable clang. Regenerate via `make bpf-objects` and
// copy into `pkg/hardware/ebpf/bpf/cgroup_egress_counter.o`.
//
//go:embed bpf/cgroup_egress_counter.o
var embeddedCGroupEgressCounterObject []byte

// CGroupEgressCounterObject returns the embedded ELF object for the
// owned cgroup_egress_counter program. Returns ErrEBPFObjectMissing if
// the embed slot is empty (i.e. `make bpf-objects` has not been run on
// a host with a BPF-capable clang).
func CGroupEgressCounterObject() ([]byte, error) {
	if !hasELFMagic(embeddedCGroupEgressCounterObject) {
		return nil, ErrEBPFObjectMissing
	}
	return embeddedCGroupEgressCounterObject, nil
}

// CGroupLoader owns the lifecycle of the compiled cgroup_egress_counter
// program and any cgroup v2 attachments it produces.
//
// Usage:
//
//	loader, err := NewCGroupLoader(objectBytes)
//	defer loader.Close()
//	lnk, err := loader.AttachEgress("/sys/fs/cgroup")
//	defer loader.Detach(lnk)
//
// The zero value is unusable; always go through NewCGroupLoader. The
// loader carries a single cgroup_skb/egress program today; an
// ingress-side companion is an explicit non-goal for v0 (see the C
// source for rationale).
type CGroupLoader struct {
	spec       *ebpf.CollectionSpec
	coll       *ebpf.Collection
	egressProg *ebpf.Program
	statsMap   *ebpf.Map
}

// cgroup program / map names. Must match the SEC() and map names in
// bpf/cgroup_egress_counter.c — NewCGroupLoader fails loudly if either
// is missing rather than silently binding the wrong one.
const (
	cgroupEgressProgName = "cgroup_egress_counter"
	cgroupStatsMapName   = "cgroup_egress_stats"
)

// NewCGroupLoader parses a compiled cgroup_skb BPF ELF, verifies the
// egress program and stats map are present, bumps RLIMIT_MEMLOCK, and
// loads the collection into the kernel.
//
// Capability gating mirrors the XDP / TC / sockops loaders: root,
// CAP_BPF, or CAP_NET_ADMIN is required. The returned loader owns the
// `*ebpf.Collection` and must be released via Close.
func NewCGroupLoader(objectBytes []byte) (*CGroupLoader, error) {
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

	egress, ok := coll.Programs[cgroupEgressProgName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing %q program (have %v)", cgroupEgressProgName, programNames(coll))
	}

	stats, ok := coll.Maps[cgroupStatsMapName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing %q map", cgroupStatsMapName)
	}

	// Verify program type — cgroup_skb programs compile to
	// ProgramType CGroupSKB. Belt-and-braces against a future source
	// edit that moves the program to a different section.
	if t := egress.Type(); t != ebpf.CGroupSKB {
		coll.Close()
		return nil, fmt.Errorf("%q has program type %s, want CGroupSKB", cgroupEgressProgName, t)
	}

	return &CGroupLoader{
		spec:       spec,
		coll:       coll,
		egressProg: egress,
		statsMap:   stats,
	}, nil
}

// EgressProgram returns the loaded egress *ebpf.Program. Nil on a nil
// receiver or a closed loader.
func (l *CGroupLoader) EgressProgram() *ebpf.Program {
	if l == nil {
		return nil
	}
	return l.egressProg
}

// StatsMap exposes the user-space handle for the per-CPU stats map.
// Key 0 holds cumulative bytes; key 1 holds cumulative packet count.
// Callers read across all CPUs and sum. Returns nil on a nil receiver.
func (l *CGroupLoader) StatsMap() *ebpf.Map {
	if l == nil || l.coll == nil {
		return nil
	}
	return l.statsMap
}

// AttachEgress attaches the cgroup_egress_counter program to the given
// cgroup v2 path via `link.AttachCgroup` with
// `ebpf.AttachCGroupInetEgress`.
//
// The path must be a directory inside a cgroup2 filesystem (typically
// `/sys/fs/cgroup` on modern distros, or a sub-path for per-workload
// scoping). If the path cannot be opened the loader returns
// ErrCGroupPathNotFound wrapping the underlying os error.
//
// The returned link.Link should be passed back to Detach when the
// controller tears down the attachment.
func (l *CGroupLoader) AttachEgress(cgroupPath string) (link.Link, error) {
	return l.attach(cgroupPath, ebpf.AttachCGroupInetEgress)
}

// AttachIngress attaches the program to the cgroup ingress hook. The
// v0 program is deliberately egress-only at the C-source level —
// attaching it to the ingress hook will load but produce no counters
// because the kernel passes skbs in the *opposite* direction through
// this hook. Exposed for API symmetry with the TC loader so future
// tickets that add an ingress-side program do not need to widen this
// loader's shape.
func (l *CGroupLoader) AttachIngress(cgroupPath string) (link.Link, error) {
	return l.attach(cgroupPath, ebpf.AttachCGroupInetIngress)
}

func (l *CGroupLoader) attach(cgroupPath string, attach ebpf.AttachType) (link.Link, error) {
	if l == nil || l.egressProg == nil {
		return nil, fmt.Errorf("cgroup loader not initialized")
	}

	if err := checkCGroupPath(cgroupPath); err != nil {
		return nil, err
	}

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  attach,
		Program: l.egressProg,
	})
	if err != nil {
		return nil, fmt.Errorf("attach %s to cgroup %q: %w", cgroupAttachName(attach), cgroupPath, err)
	}
	return lnk, nil
}

// Detach closes the given cgroup link.
func (l *CGroupLoader) Detach(lnk link.Link) error {
	if lnk == nil {
		return nil
	}
	if err := lnk.Close(); err != nil {
		return fmt.Errorf("close cgroup link: %w", err)
	}
	return nil
}

// Close releases the loaded program and map handles.
func (l *CGroupLoader) Close() error {
	if l == nil || l.coll == nil {
		return nil
	}
	l.coll.Close()
	l.coll = nil
	l.egressProg = nil
	l.statsMap = nil
	return nil
}

// cgroupAttachName returns a human-readable name for the cgroup
// AttachType. Used only for error-message construction.
func cgroupAttachName(t ebpf.AttachType) string {
	switch t {
	case ebpf.AttachCGroupInetIngress:
		return "cgroup ingress"
	case ebpf.AttachCGroupInetEgress:
		return "cgroup egress"
	case ebpf.AttachCGroupSockOps:
		return "cgroup sockops"
	default:
		return fmt.Sprintf("cgroup attach(%d)", t)
	}
}

// attachCGroupProgram is the ProgramManager-facing helper that handles
// both owned-loader and legacy (Code-based) cgroup attach paths
// uniformly.
//
//   - Owned-loader path (prog.cgroupLoader != nil): delegate to the
//     CGroupLoader's AttachEgress so cgroup-path validation and error
//     wrapping happen in one place. The v0 program is cgroup_skb/
//     egress, so the INET egress hook is the natural target.
//   - Legacy path (caller-supplied Code): attach the InnerProg
//     directly to the default cgroup v2 root via link.AttachCgroup
//     with AttachCGroupDevice. Preserves the pre-Sprint-31 dispatch
//     behaviour (the old comment called this "a simplified
//     implementation" — we leave the attach type alone rather than
//     silently changing it for Code-based loads, which would break
//     any caller that set InnerProg to a device-type program).
func attachCGroupProgram(prog *LoadedProgram) (link.Link, error) {
	if prog == nil {
		return nil, fmt.Errorf("cgroup attach: nil program")
	}
	const defaultCGroupPath = "/sys/fs/cgroup"
	if prog.cgroupLoader != nil {
		return prog.cgroupLoader.AttachEgress(defaultCGroupPath)
	}
	return link.AttachCgroup(link.CgroupOptions{
		Path:    defaultCGroupPath,
		Attach:  ebpf.AttachCGroupDevice,
		Program: prog.InnerProg,
	})
}
