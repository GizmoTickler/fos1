//go:build linux

package ebpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate sh -c "cd ../../.. && make bpf-objects && cp bpf/out/tc_qos_shape.o pkg/hardware/ebpf/bpf/tc_qos_shape.o"

// embeddedTCQoSShapeObject is the compiled ELF for bpf/tc_qos_shape.c.
//
// Committed alongside the source so the Go tree builds on machines
// without a BPF-capable clang. Regenerate via `make bpf-objects` and
// copy into `pkg/hardware/ebpf/bpf/tc_qos_shape.o`.
//
//go:embed bpf/tc_qos_shape.o
var embeddedTCQoSShapeObject []byte

// TCQoSShapeObject returns the embedded ELF object for the owned
// tc_qos_shape program. Returns ErrEBPFObjectMissing if the embed slot
// is empty (i.e. `make bpf-objects` has not been run on a host with a
// BPF-capable clang).
func TCQoSShapeObject() ([]byte, error) {
	if !hasELFMagic(embeddedTCQoSShapeObject) {
		return nil, ErrEBPFObjectMissing
	}
	return embeddedTCQoSShapeObject, nil
}

// TCLoader owns the lifecycle of the compiled tc_qos_shape program and
// the per-interface `clsact` qdiscs it attaches to.
//
// Usage:
//
//	loader, err := NewTCLoader(objectBytes)
//	defer loader.Close()
//	lnk, err := loader.AttachIngress("eth0")
//	defer loader.Detach(lnk)
//
// The zero value is unusable; always go through NewTCLoader. A single
// loader instance can service many interfaces: the `*ebpf.Collection`
// holds one program per section (ingress + egress) and each Attach*
// call produces an independent link handle.
type TCLoader struct {
	spec         *ebpf.CollectionSpec
	coll         *ebpf.Collection
	ingressProg  *ebpf.Program
	egressProg   *ebpf.Program
	priorityMap  *ebpf.Map
}

// TC program / section names. These must match the section names in
// bpf/tc_qos_shape.c — verified by NewTCLoader, which fails loudly if
// either program is missing rather than silently binding the wrong one.
const (
	tcIngressProgName = "tc_qos_ingress"
	tcEgressProgName  = "tc_qos_egress"
	tcPriorityMapName = "qos_iface_priority"
)

// NewTCLoader parses a compiled TC BPF ELF, verifies both the ingress
// and egress programs are present, bumps RLIMIT_MEMLOCK, and loads the
// collection into the kernel.
//
// Capability gating mirrors the XDP loader: root, CAP_BPF, or
// CAP_NET_ADMIN is required. The returned loader owns the
// `*ebpf.Collection` and must be released via Close.
func NewTCLoader(objectBytes []byte) (*TCLoader, error) {
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

	ingress, ok := coll.Programs[tcIngressProgName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing %q program (have %v)", tcIngressProgName, programNames(coll))
	}
	egress, ok := coll.Programs[tcEgressProgName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing %q program (have %v)", tcEgressProgName, programNames(coll))
	}

	// Verify the priority map is present — NewCollection will have
	// already loaded it, but failing here with a named error is kinder
	// to operators than a later "map not found" during SetPriority.
	prio, ok := coll.Maps[tcPriorityMapName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing %q map", tcPriorityMapName)
	}

	// Verify both programs are of SchedCLS type — belt-and-braces
	// against a future BPF source edit that would move them to a
	// different section.
	if t := ingress.Type(); t != ebpf.SchedCLS {
		coll.Close()
		return nil, fmt.Errorf("%q has program type %s, want SchedCLS", tcIngressProgName, t)
	}
	if t := egress.Type(); t != ebpf.SchedCLS {
		coll.Close()
		return nil, fmt.Errorf("%q has program type %s, want SchedCLS", tcEgressProgName, t)
	}

	return &TCLoader{
		spec:        spec,
		coll:        coll,
		ingressProg: ingress,
		egressProg:  egress,
		priorityMap: prio,
	}, nil
}

// IngressProgram returns the loaded ingress *ebpf.Program. Nil on a
// nil receiver or a closed loader. Callers that want to attach via a
// non-TCX path can use this handle directly.
func (l *TCLoader) IngressProgram() *ebpf.Program {
	if l == nil {
		return nil
	}
	return l.ingressProg
}

// EgressProgram returns the loaded egress *ebpf.Program.
func (l *TCLoader) EgressProgram() *ebpf.Program {
	if l == nil {
		return nil
	}
	return l.egressProg
}

// PriorityMap exposes the user-space handle for the `qos_iface_priority`
// map. Callers populate it via Put(ifindex → priority) before attaching
// (the BPF program only reads). Returns nil on a nil receiver.
func (l *TCLoader) PriorityMap() *ebpf.Map {
	if l == nil || l.coll == nil {
		return nil
	}
	return l.priorityMap
}

// SetPriority is a convenience wrapper around PriorityMap().Put that
// accepts a user-friendly interface name rather than a raw ifindex.
// It is idempotent (BPF_ANY flag): existing entries are overwritten.
func (l *TCLoader) SetPriority(ifaceName string, priority uint32) error {
	if l == nil || l.priorityMap == nil {
		return fmt.Errorf("tc loader not initialized")
	}
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("resolve interface %q: %w", ifaceName, err)
	}
	ifindex := uint32(iface.Attrs().Index)
	if err := l.priorityMap.Put(&ifindex, &priority); err != nil {
		return fmt.Errorf("update priority map for %q: %w", ifaceName, err)
	}
	return nil
}

// ClearPriority removes the priority entry for the given interface.
// Returns nil when the entry was absent — the caller's intent is "the
// interface should have no override", which is already satisfied.
func (l *TCLoader) ClearPriority(ifaceName string) error {
	if l == nil || l.priorityMap == nil {
		return fmt.Errorf("tc loader not initialized")
	}
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("resolve interface %q: %w", ifaceName, err)
	}
	ifindex := uint32(iface.Attrs().Index)
	if err := l.priorityMap.Delete(&ifindex); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("delete priority map entry for %q: %w", ifaceName, err)
	}
	return nil
}

// AttachIngress attaches the tc_qos_ingress program to the named
// interface via a clsact qdisc. The returned link.Link should be passed
// back to Detach when the controller tears down the attachment.
//
// Qdisc handling: a clsact qdisc is ensured via netlink. EEXIST is
// tolerated (another controller or manual `tc qdisc` may have already
// installed one). Any other qdisc error is wrapped with
// ErrTCQdiscUnsupported so callers can distinguish environment failures
// from attach-side failures.
func (l *TCLoader) AttachIngress(ifaceName string) (link.Link, error) {
	return l.attach(ifaceName, l.ingressProg, ebpf.AttachTCXIngress)
}

// AttachEgress attaches the tc_qos_egress program to the named
// interface via a clsact qdisc. Symmetric with AttachIngress.
func (l *TCLoader) AttachEgress(ifaceName string) (link.Link, error) {
	return l.attach(ifaceName, l.egressProg, ebpf.AttachTCXEgress)
}

func (l *TCLoader) attach(ifaceName string, prog *ebpf.Program, attach ebpf.AttachType) (link.Link, error) {
	if l == nil || prog == nil {
		return nil, fmt.Errorf("tc loader not initialized")
	}

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("resolve interface %q: %w", ifaceName, err)
	}

	if err := ensureClsactQdisc(iface.Attrs().Index); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTCQdiscUnsupported, err)
	}

	// AttachTCX requires kernel >= 6.6 (the TCX hook landed in v6.6).
	// Older kernels that only support the classic tc filter API would
	// need the netlink-tc path; keeping that as a non-goal for v1
	// because TCX is the long-term upstream direction and avoids the
	// fragile filter-priority bookkeeping tc(8) requires.
	lnk, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Interface: iface.Attrs().Index,
		Attach:    attach,
	})
	if err != nil {
		return nil, fmt.Errorf("attach TCX %s to %q: %w", attachTypeName(attach), ifaceName, err)
	}
	return lnk, nil
}

// Detach closes the given TC link.
func (l *TCLoader) Detach(lnk link.Link) error {
	if lnk == nil {
		return nil
	}
	if err := lnk.Close(); err != nil {
		return fmt.Errorf("close TC link: %w", err)
	}
	return nil
}

// Close releases the loaded programs and map handles.
func (l *TCLoader) Close() error {
	if l == nil || l.coll == nil {
		return nil
	}
	l.coll.Close()
	l.coll = nil
	l.ingressProg = nil
	l.egressProg = nil
	l.priorityMap = nil
	return nil
}

// ensureClsactQdisc adds a clsact qdisc to the given link index and
// tolerates EEXIST. clsact supersedes the old ingress+egress qdisc
// pair (kernel >= 4.5) and is what AttachTCX expects to find when
// binding a scheduler-classifier program.
func ensureClsactQdisc(linkIndex int) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkIndex,
			Parent:    netlink.HANDLE_CLSACT,
			// Handle 0xFFFF:0 is the conventional clsact handle —
			// matches what `tc qdisc add dev X clsact` would produce.
			Handle: netlink.MakeHandle(0xFFFF, 0),
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return fmt.Errorf("add clsact qdisc on ifindex %d: %w", linkIndex, err)
	}
	return nil
}

// attachTypeName returns a human-readable name for the AttachType. Used
// only for error-message construction.
func attachTypeName(t ebpf.AttachType) string {
	switch t {
	case ebpf.AttachTCXIngress:
		return "ingress"
	case ebpf.AttachTCXEgress:
		return "egress"
	default:
		return fmt.Sprintf("attach(%d)", t)
	}
}

// attachTCProgram is the ProgramManager-facing helper that handles both
// owned-loader and legacy (Code-based) TC attach paths uniformly.
//
//   - Owned-loader path (prog.tcLoader != nil): delegate to the
//     TCLoader so the clsact bootstrap and map wiring happen in one
//     place.
//   - Legacy path (caller-supplied Code): resolve the interface, ensure
//     a clsact qdisc exists, then AttachTCX directly. This preserves
//     the pre-Ticket-39 behaviour of `AttachProgram` but adds the
//     missing qdisc bootstrap — without it the attach would fail on a
//     fresh interface with ENOENT.
func attachTCProgram(prog *LoadedProgram, attach ebpf.AttachType) (link.Link, error) {
	if prog == nil {
		return nil, fmt.Errorf("tc attach: nil program")
	}
	if prog.tcLoader != nil {
		if attach == ebpf.AttachTCXIngress {
			return prog.tcLoader.AttachIngress(prog.Interface)
		}
		return prog.tcLoader.AttachEgress(prog.Interface)
	}

	iface, err := netlink.LinkByName(prog.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", prog.Interface, err)
	}
	if err := ensureClsactQdisc(iface.Attrs().Index); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTCQdiscUnsupported, err)
	}
	return link.AttachTCX(link.TCXOptions{
		Program:   prog.InnerProg,
		Interface: iface.Attrs().Index,
		Attach:    attach,
	})
}
