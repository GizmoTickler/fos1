//go:build linux

package ebpf

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCGroupLoader_RejectsEmptyObject verifies that the loader refuses
// to instantiate with a non-ELF payload. Runs on every Linux host — no
// kernel privileges required.
func TestCGroupLoader_RejectsEmptyObject(t *testing.T) {
	_, err := NewCGroupLoader(nil)
	if !errors.Is(err, ErrEBPFObjectMissing) {
		t.Fatalf("expected ErrEBPFObjectMissing, got %v", err)
	}

	_, err = NewCGroupLoader([]byte{0x00, 0x01, 0x02})
	if !errors.Is(err, ErrEBPFObjectMissing) {
		t.Fatalf("expected ErrEBPFObjectMissing for short buffer, got %v", err)
	}
}

// TestCGroupLoader_AttachEgress is the end-to-end proof that the owned
// compile-and-load pipeline works for cgroup_skb/egress: load the
// embedded cgroup_egress_counter object, attach it to a cgroup v2
// path, verify the link handle is non-nil, detach cleanly.
//
// Skip conditions match the sockops test (missing object / caps /
// cgroup2 mount) plus EINVAL on environments that reject the attach
// for reasons outside our control.
func TestCGroupLoader_AttachEgress(t *testing.T) {
	obj, err := CGroupEgressCounterObject()
	if errors.Is(err, ErrEBPFObjectMissing) {
		t.Skip("no embedded BPF object; run `make bpf-objects` on a host with a BPF-capable clang")
	}
	if err != nil {
		t.Fatalf("CGroupEgressCounterObject: %v", err)
	}

	if err := ensureBPFCapable(); err != nil {
		t.Skipf("skipping: %v", err)
	}

	cgroupPath := findCGroupV2Root(t)
	if cgroupPath == "" {
		t.Skip("no cgroup v2 filesystem mounted; cgroup_skb attach requires a unified cgroup hierarchy")
	}

	loader, err := NewCGroupLoader(obj)
	if err != nil {
		if isPermissionErr(err) || errors.Is(err, ErrEBPFInsufficientCaps) {
			t.Skipf("skipping: insufficient privileges to load BPF: %v", err)
		}
		t.Fatalf("NewCGroupLoader: %v", err)
	}
	t.Cleanup(func() { _ = loader.Close() })

	if loader.EgressProgram() == nil {
		t.Fatal("loader.EgressProgram() returned nil after successful load")
	}
	if loader.StatsMap() == nil {
		t.Fatal("loader.StatsMap() returned nil; BPF object is missing `cgroup_egress_stats` map")
	}

	lnk, err := loader.AttachEgress(cgroupPath)
	if err != nil {
		if isPermissionErr(err) {
			t.Skipf("skipping: insufficient privileges to attach cgroup_skb: %v", err)
		}
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			t.Skipf("skipping: environment does not support cgroup_skb attach: %v", err)
		}
		t.Fatalf("AttachEgress: %v", err)
	}
	if lnk == nil {
		t.Fatal("AttachEgress returned nil link on success")
	}
	t.Cleanup(func() { _ = lnk.Close() })

	// Detach explicitly and assert no error.
	if err := loader.Detach(lnk); err != nil {
		t.Fatalf("Detach: %v", err)
	}
}

// TestCGroupLoader_AttachEgress_PathNotFound proves the loader returns
// ErrCGroupPathNotFound for a missing path without touching the kernel.
func TestCGroupLoader_AttachEgress_PathNotFound(t *testing.T) {
	obj, err := CGroupEgressCounterObject()
	if errors.Is(err, ErrEBPFObjectMissing) {
		t.Skip("no embedded BPF object; run `make bpf-objects` on a host with a BPF-capable clang")
	}
	if err != nil {
		t.Fatalf("CGroupEgressCounterObject: %v", err)
	}
	if err := ensureBPFCapable(); err != nil {
		t.Skipf("skipping: %v", err)
	}

	loader, err := NewCGroupLoader(obj)
	if err != nil {
		if isPermissionErr(err) || errors.Is(err, ErrEBPFInsufficientCaps) {
			t.Skipf("skipping: insufficient privileges to load BPF: %v", err)
		}
		t.Fatalf("NewCGroupLoader: %v", err)
	}
	t.Cleanup(func() { _ = loader.Close() })

	_, err = loader.AttachEgress("/does/not/exist/fos1")
	if !errors.Is(err, ErrCGroupPathNotFound) {
		t.Fatalf("expected ErrCGroupPathNotFound, got %v", err)
	}
}

// TestCGroupLoader_AccessorsNilReceiver guards against a regression
// where callers dereference a nil loader.
func TestCGroupLoader_AccessorsNilReceiver(t *testing.T) {
	var l *CGroupLoader
	if l.EgressProgram() != nil {
		t.Fatal("EgressProgram() on nil receiver must return nil")
	}
	if l.StatsMap() != nil {
		t.Fatal("StatsMap() on nil receiver must return nil")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close on nil receiver must be a no-op, got %v", err)
	}
}
