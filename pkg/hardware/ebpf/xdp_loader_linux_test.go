//go:build linux

package ebpf

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestXDPLoader_RejectsEmptyObject verifies that the loader refuses to
// instantiate with a non-ELF payload. Runs on every Linux host — no
// kernel privileges required.
func TestXDPLoader_RejectsEmptyObject(t *testing.T) {
	_, err := NewXDPLoader(nil)
	if !errors.Is(err, ErrEBPFObjectMissing) {
		t.Fatalf("expected ErrEBPFObjectMissing, got %v", err)
	}

	_, err = NewXDPLoader([]byte{0x00, 0x01, 0x02})
	if !errors.Is(err, ErrEBPFObjectMissing) {
		t.Fatalf("expected ErrEBPFObjectMissing for short buffer, got %v", err)
	}
}

// TestXDPLoader_AttachToDummyInterface is the end-to-end proof that
// the owned compile-and-load pipeline actually works: load the
// embedded xdp_ddos_drop object, attach it to a dummy interface,
// verify the link is non-nil, detach, and tear down the interface.
//
// Skip conditions:
//   - No embedded BPF object: `make bpf-objects` has not been run on a
//     BPF-capable clang host, so there is nothing to load.
//   - No root AND no CAP_BPF / CAP_NET_ADMIN: we cannot mutate the
//     network stack or load BPF, so there is nothing meaningful to
//     prove here.
func TestXDPLoader_AttachToDummyInterface(t *testing.T) {
	obj, err := XDPDDoSDropObject()
	if errors.Is(err, ErrEBPFObjectMissing) {
		t.Skip("no embedded BPF object; run `make bpf-objects` on a host with a BPF-capable clang")
	}
	if err != nil {
		t.Fatalf("XDPDDoSDropObject: %v", err)
	}

	if err := ensureBPFCapable(); err != nil {
		t.Skipf("skipping: %v", err)
	}

	const ifaceName = "fos1testxdp"
	// Clean any stale interface from a previous run first.
	if l, err := netlink.LinkByName(ifaceName); err == nil {
		_ = netlink.LinkDel(l)
	}

	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: ifaceName, MTU: 1500}}
	if err := netlink.LinkAdd(dummy); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("skipping: insufficient privileges to create dummy interface: %v", err)
		}
		t.Fatalf("create dummy interface: %v", err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(ifaceName); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	if err := netlink.LinkSetUp(dummy); err != nil {
		t.Fatalf("bring dummy up: %v", err)
	}

	loader, err := NewXDPLoader(obj)
	if err != nil {
		if isPermissionErr(err) || errors.Is(err, ErrEBPFInsufficientCaps) {
			t.Skipf("skipping: insufficient privileges to load BPF: %v", err)
		}
		t.Fatalf("NewXDPLoader: %v", err)
	}
	t.Cleanup(func() { _ = loader.Close() })

	if loader.Program() == nil {
		t.Fatal("loader.Program() returned nil after successful load")
	}
	if loader.DenylistMap() == nil {
		t.Fatal("loader.DenylistMap() returned nil; BPF object is missing `ipv4_denylist` map")
	}

	lnk, err := loader.Attach(ifaceName)
	if err != nil {
		if isPermissionErr(err) {
			t.Skipf("skipping: insufficient privileges to attach XDP: %v", err)
		}
		t.Fatalf("Attach: %v", err)
	}
	if lnk == nil {
		t.Fatal("Attach returned nil link on success")
	}
	t.Cleanup(func() { _ = lnk.Close() })

	// Detach explicitly and assert no error; Cleanup will run again but
	// link.Close is idempotent in practice for cilium/ebpf.
	if err := loader.Detach(lnk); err != nil {
		t.Fatalf("Detach: %v", err)
	}
}

// TestXDPLoader_ProgramAndMapAccessors_NilReceiver guards against a
// regression where callers dereference a nil loader.
func TestXDPLoader_ProgramAndMapAccessors_NilReceiver(t *testing.T) {
	var l *XDPLoader
	if l.Program() != nil {
		t.Fatal("Program() on nil receiver must return nil")
	}
	if l.DenylistMap() != nil {
		t.Fatal("DenylistMap() on nil receiver must return nil")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close on nil receiver must be a no-op, got %v", err)
	}
}

// Ensure the test file still builds when the link package is unused
// after t.Skip paths — reference link.XDPGenericMode here so the
// import is always live.
var _ = link.XDPGenericMode

// Keep the os import live: some build variants may strip unused
// references in the test after heavy use of t.Skip.
var _ = os.Geteuid
