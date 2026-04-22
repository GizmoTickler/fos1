//go:build linux

package ebpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate sh -c "cd ../../.. && make bpf-objects && cp bpf/out/xdp_ddos_drop.o pkg/hardware/ebpf/bpf/xdp_ddos_drop.o"

// embeddedXDPDDoSDropObject is the compiled ELF for bpf/xdp_ddos_drop.c.
//
// The file is committed alongside the source so the Go tree builds on
// machines without a BPF-capable clang. Regenerate via `make bpf-objects`
// and copy into `pkg/hardware/ebpf/bpf/xdp_ddos_drop.o`.
//
//go:embed bpf/xdp_ddos_drop.o
var embeddedXDPDDoSDropObject []byte

// XDPDDoSDropObject returns the embedded ELF object for the owned
// xdp_ddos_drop program. It returns ErrEBPFObjectMissing if the embed
// slot is empty (i.e. `make bpf-objects` has not been run on a host with
// a BPF-capable clang).
func XDPDDoSDropObject() ([]byte, error) {
	if !hasELFMagic(embeddedXDPDDoSDropObject) {
		return nil, ErrEBPFObjectMissing
	}
	return embeddedXDPDDoSDropObject, nil
}

// elfMagic is the 4-byte prefix that every ELF file (including BPF
// objects produced by clang) begins with: 0x7f 'E' 'L' 'F'.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

func hasELFMagic(buf []byte) bool {
	if len(buf) < len(elfMagic) {
		return false
	}
	return bytes.Equal(buf[:len(elfMagic)], elfMagic)
}

// XDPLoader owns the lifecycle of a single compiled XDP program.
//
// Usage:
//
//	loader, err := NewXDPLoader(objectBytes)
//	defer loader.Close()
//	link, err := loader.Attach("eth0")
//	defer loader.Detach(link)
//
// The zero value is unusable; always go through NewXDPLoader.
type XDPLoader struct {
	spec *ebpf.CollectionSpec
	coll *ebpf.Collection
	prog *ebpf.Program
}

// NewXDPLoader parses an ELF object, checks environmental capability,
// bumps RLIMIT_MEMLOCK, and instantiates the program in the kernel.
// The returned loader owns `*ebpf.Collection` resources and must be
// released with Close when no longer needed.
func NewXDPLoader(objectBytes []byte) (*XDPLoader, error) {
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

	prog, ok := coll.Programs["xdp_ddos_drop"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("BPF object missing xdp_ddos_drop program (have %v)", programNames(coll))
	}

	return &XDPLoader{spec: spec, coll: coll, prog: prog}, nil
}

// Program exposes the loaded *ebpf.Program for callers that need to
// attach via a non-standard path (e.g. tests that use generic XDP).
func (l *XDPLoader) Program() *ebpf.Program {
	if l == nil {
		return nil
	}
	return l.prog
}

// DenylistMap returns the user-space handle for the LPM-trie map that
// drives drop decisions. Returns nil if the loader is unusable.
func (l *XDPLoader) DenylistMap() *ebpf.Map {
	if l == nil || l.coll == nil {
		return nil
	}
	return l.coll.Maps["ipv4_denylist"]
}

// Attach attaches the XDP program to the named interface. The returned
// link.Link should be passed back to Detach. The loader does not track
// link handles internally; callers that need lifecycle management on
// top of the raw link handle should wrap this in their own controller.
func (l *XDPLoader) Attach(ifaceName string) (link.Link, error) {
	if l == nil || l.prog == nil {
		return nil, fmt.Errorf("xdp loader not initialized")
	}

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("resolve interface %q: %w", ifaceName, err)
	}

	// XDPGenericMode works inside network namespaces created by test
	// harnesses (e.g. `netlink.Dummy`) where the driver has no native
	// XDP support. Production code paths that want driver-native XDP
	// can wrap this and pass their own flags.
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   l.prog,
		Interface: iface.Attrs().Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return nil, fmt.Errorf("attach XDP to %q: %w", ifaceName, err)
	}
	return lnk, nil
}

// Detach closes the given XDP link.
func (l *XDPLoader) Detach(lnk link.Link) error {
	if lnk == nil {
		return nil
	}
	if err := lnk.Close(); err != nil {
		return fmt.Errorf("close XDP link: %w", err)
	}
	return nil
}

// Close releases the loaded program and map handles.
func (l *XDPLoader) Close() error {
	if l == nil || l.coll == nil {
		return nil
	}
	l.coll.Close()
	l.coll = nil
	l.prog = nil
	return nil
}

// ensureBPFCapable returns nil if the current process has some way to
// load BPF programs: either effective UID 0, or CAP_BPF / CAP_NET_ADMIN
// in the effective set. It does not distinguish "no BPF support" (older
// kernels without CAP_BPF) from "insufficient capabilities" — callers
// are expected to surface the wrapped error to the operator.
func ensureBPFCapable() error {
	if os.Geteuid() == 0 {
		return nil
	}
	if hasEffectiveCap(unix.CAP_BPF) || hasEffectiveCap(unix.CAP_NET_ADMIN) {
		return nil
	}
	return ErrEBPFInsufficientCaps
}

// hasEffectiveCap performs a raw capget syscall and checks for the
// requested capability in the effective set. Kernels that do not
// recognise CAP_BPF (pre-5.8) treat that bit as unknown, in which case
// we return false and fall back to the CAP_NET_ADMIN check.
func hasEffectiveCap(capability uintptr) bool {
	hdr := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	// Capability IDs 0..31 are in data[0].Effective; 32..63 are in data[1].
	if capability < 32 {
		return data[0].Effective&(1<<capability) != 0
	}
	return data[1].Effective&(1<<(capability-32)) != 0
}

func programNames(coll *ebpf.Collection) []string {
	if coll == nil {
		return nil
	}
	names := make([]string, 0, len(coll.Programs))
	for k := range coll.Programs {
		names = append(names, k)
	}
	return names
}

// isPermissionErr returns true when an error reflects a capability or
// permission failure from the kernel (EPERM / EACCES). Keeps the call
// sites free from go-unix-specific imports.
func isPermissionErr(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
}
