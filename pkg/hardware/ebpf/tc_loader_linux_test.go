//go:build linux

package ebpf

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestTCLoader_RejectsEmptyObject verifies that the loader refuses to
// instantiate with a non-ELF payload. Runs on every Linux host — no
// kernel privileges required.
func TestTCLoader_RejectsEmptyObject(t *testing.T) {
	_, err := NewTCLoader(nil)
	if !errors.Is(err, ErrEBPFObjectMissing) {
		t.Fatalf("expected ErrEBPFObjectMissing, got %v", err)
	}

	_, err = NewTCLoader([]byte{0x00, 0x01, 0x02})
	if !errors.Is(err, ErrEBPFObjectMissing) {
		t.Fatalf("expected ErrEBPFObjectMissing for short buffer, got %v", err)
	}
}

// TestTCLoader_AttachToDummyInterface is the end-to-end proof that the
// owned compile-and-load pipeline works for TC: load the embedded
// tc_qos_shape object, attach both ingress and egress to a dummy
// interface, populate the priority map, verify the link handles are
// non-nil, detach, and tear down the interface.
//
// Skip conditions:
//   - No embedded BPF object: `make bpf-objects` has not been run on a
//     BPF-capable clang host.
//   - No root AND no CAP_BPF / CAP_NET_ADMIN.
//   - Kernel pre-6.6 (no TCX support) — the attach call fails with
//     ENOTSUP / EINVAL and we skip rather than fail.
//   - The clsact qdisc cannot be added (misconfigured netns, etc.) —
//     surfaced as ErrTCQdiscUnsupported which we treat as a skip.
func TestTCLoader_AttachToDummyInterface(t *testing.T) {
	obj, err := TCQoSShapeObject()
	if errors.Is(err, ErrEBPFObjectMissing) {
		t.Skip("no embedded BPF object; run `make bpf-objects` on a host with a BPF-capable clang")
	}
	if err != nil {
		t.Fatalf("TCQoSShapeObject: %v", err)
	}

	if err := ensureBPFCapable(); err != nil {
		t.Skipf("skipping: %v", err)
	}

	const ifaceName = "fos1testtc"
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

	loader, err := NewTCLoader(obj)
	if err != nil {
		if isPermissionErr(err) || errors.Is(err, ErrEBPFInsufficientCaps) {
			t.Skipf("skipping: insufficient privileges to load BPF: %v", err)
		}
		t.Fatalf("NewTCLoader: %v", err)
	}
	t.Cleanup(func() { _ = loader.Close() })

	if loader.IngressProgram() == nil {
		t.Fatal("loader.IngressProgram() returned nil after successful load")
	}
	if loader.EgressProgram() == nil {
		t.Fatal("loader.EgressProgram() returned nil after successful load")
	}
	if loader.PriorityMap() == nil {
		t.Fatal("loader.PriorityMap() returned nil; BPF object is missing `qos_iface_priority` map")
	}

	// Populate and clear the priority map to prove the map handle works.
	if err := loader.SetPriority(ifaceName, 3); err != nil {
		t.Fatalf("SetPriority: %v", err)
	}
	if err := loader.ClearPriority(ifaceName); err != nil {
		t.Fatalf("ClearPriority: %v", err)
	}

	lnkIn, err := loader.AttachIngress(ifaceName)
	if err != nil {
		if isPermissionErr(err) {
			t.Skipf("skipping: insufficient privileges to attach TCX ingress: %v", err)
		}
		if errors.Is(err, ErrTCQdiscUnsupported) {
			t.Skipf("skipping: clsact qdisc unsupported in this environment: %v", err)
		}
		// AttachTCX returns ENOTSUP / EINVAL on pre-6.6 kernels.
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) {
			t.Skipf("skipping: kernel does not support TCX (needs >= 6.6): %v", err)
		}
		t.Fatalf("AttachIngress: %v", err)
	}
	if lnkIn == nil {
		t.Fatal("AttachIngress returned nil link on success")
	}
	t.Cleanup(func() { _ = lnkIn.Close() })

	lnkOut, err := loader.AttachEgress(ifaceName)
	if err != nil {
		t.Fatalf("AttachEgress: %v", err)
	}
	if lnkOut == nil {
		t.Fatal("AttachEgress returned nil link on success")
	}
	t.Cleanup(func() { _ = lnkOut.Close() })

	// Detach explicitly and assert no error.
	if err := loader.Detach(lnkIn); err != nil {
		t.Fatalf("Detach ingress: %v", err)
	}
	if err := loader.Detach(lnkOut); err != nil {
		t.Fatalf("Detach egress: %v", err)
	}
}

// TestTCLoader_AccessorsNilReceiver guards against a regression where
// callers dereference a nil loader.
func TestTCLoader_AccessorsNilReceiver(t *testing.T) {
	var l *TCLoader
	if l.IngressProgram() != nil {
		t.Fatal("IngressProgram() on nil receiver must return nil")
	}
	if l.EgressProgram() != nil {
		t.Fatal("EgressProgram() on nil receiver must return nil")
	}
	if l.PriorityMap() != nil {
		t.Fatal("PriorityMap() on nil receiver must return nil")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close on nil receiver must be a no-op, got %v", err)
	}
}

// TestEnsureClsactQdisc_Idempotent proves the clsact qdisc bootstrap is
// tolerant of EEXIST: adding twice must succeed both times.
func TestEnsureClsactQdisc_Idempotent(t *testing.T) {
	if err := ensureBPFCapable(); err != nil {
		t.Skipf("skipping: %v", err)
	}

	const ifaceName = "fos1testclsact"
	if l, err := netlink.LinkByName(ifaceName); err == nil {
		_ = netlink.LinkDel(l)
	}
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: ifaceName, MTU: 1500}}
	if err := netlink.LinkAdd(dummy); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("skipping: insufficient privileges: %v", err)
		}
		t.Fatalf("create dummy interface: %v", err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(ifaceName); err == nil {
			_ = netlink.LinkDel(l)
		}
	})

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		t.Fatalf("look up dummy: %v", err)
	}
	idx := link.Attrs().Index

	if err := ensureClsactQdisc(idx); err != nil {
		t.Fatalf("first ensureClsactQdisc: %v", err)
	}
	if err := ensureClsactQdisc(idx); err != nil {
		t.Fatalf("second ensureClsactQdisc (must tolerate EEXIST): %v", err)
	}
}
