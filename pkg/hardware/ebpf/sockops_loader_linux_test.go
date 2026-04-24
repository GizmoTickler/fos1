//go:build linux

package ebpf

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSockOpsLoader_RejectsEmptyObject verifies that the loader refuses
// to instantiate with a non-ELF payload. Runs on every Linux host — no
// kernel privileges required.
func TestSockOpsLoader_RejectsEmptyObject(t *testing.T) {
	_, err := NewSockOpsLoader(nil)
	if !errors.Is(err, ErrEBPFObjectMissing) {
		t.Fatalf("expected ErrEBPFObjectMissing, got %v", err)
	}

	_, err = NewSockOpsLoader([]byte{0x00, 0x01, 0x02})
	if !errors.Is(err, ErrEBPFObjectMissing) {
		t.Fatalf("expected ErrEBPFObjectMissing for short buffer, got %v", err)
	}
}

// TestSockOpsLoader_AttachToCGroup is the end-to-end proof that the
// owned compile-and-load pipeline works for sockops: load the embedded
// sockops_redirect object, attach it to a cgroup v2 path, verify the
// link handle is non-nil, detach cleanly.
//
// Skip conditions:
//   - No embedded BPF object: `make bpf-objects` has not been run on a
//     BPF-capable clang host.
//   - No root AND no CAP_BPF / CAP_NET_ADMIN.
//   - No cgroup v2 filesystem mounted at `/sys/fs/cgroup` — hybrid v1/v2
//     setups typically have the unified hierarchy elsewhere. We probe
//     the magic via `statfs` and skip rather than fail.
//   - The attach call returns EPERM / EACCES / EINVAL for reasons
//     outside our control (restricted test runner, locked-down kernel,
//     missing sockops support).
func TestSockOpsLoader_AttachToCGroup(t *testing.T) {
	obj, err := SockOpsRedirectObject()
	if errors.Is(err, ErrEBPFObjectMissing) {
		t.Skip("no embedded BPF object; run `make bpf-objects` on a host with a BPF-capable clang")
	}
	if err != nil {
		t.Fatalf("SockOpsRedirectObject: %v", err)
	}

	if err := ensureBPFCapable(); err != nil {
		t.Skipf("skipping: %v", err)
	}

	cgroupPath := findCGroupV2Root(t)
	if cgroupPath == "" {
		t.Skip("no cgroup v2 filesystem mounted; sockops attach requires a unified cgroup hierarchy")
	}

	loader, err := NewSockOpsLoader(obj)
	if err != nil {
		if isPermissionErr(err) || errors.Is(err, ErrEBPFInsufficientCaps) {
			t.Skipf("skipping: insufficient privileges to load BPF: %v", err)
		}
		t.Fatalf("NewSockOpsLoader: %v", err)
	}
	t.Cleanup(func() { _ = loader.Close() })

	if loader.Program() == nil {
		t.Fatal("loader.Program() returned nil after successful load")
	}
	if loader.CounterMap() == nil {
		t.Fatal("loader.CounterMap() returned nil; BPF object is missing `sockops_established_count` map")
	}

	lnk, err := loader.AttachToCGroup(cgroupPath)
	if err != nil {
		if isPermissionErr(err) {
			t.Skipf("skipping: insufficient privileges to attach sockops: %v", err)
		}
		// Some restricted environments (containers without privileged
		// mode, older kernels) refuse the attach with EINVAL.
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			t.Skipf("skipping: environment does not support cgroup sockops attach: %v", err)
		}
		t.Fatalf("AttachToCGroup: %v", err)
	}
	if lnk == nil {
		t.Fatal("AttachToCGroup returned nil link on success")
	}
	t.Cleanup(func() { _ = lnk.Close() })

	// Detach explicitly and assert no error; Cleanup will run again but
	// link.Close is idempotent in practice for cilium/ebpf.
	if err := loader.DetachFromCGroup(lnk); err != nil {
		t.Fatalf("DetachFromCGroup: %v", err)
	}
}

// TestSockOpsLoader_AttachToCGroup_PathNotFound proves the loader
// returns ErrCGroupPathNotFound for a missing path without touching
// the kernel. This covers the operator-facing error path independent
// of capabilities.
func TestSockOpsLoader_AttachToCGroup_PathNotFound(t *testing.T) {
	obj, err := SockOpsRedirectObject()
	if errors.Is(err, ErrEBPFObjectMissing) {
		t.Skip("no embedded BPF object; run `make bpf-objects` on a host with a BPF-capable clang")
	}
	if err != nil {
		t.Fatalf("SockOpsRedirectObject: %v", err)
	}
	if err := ensureBPFCapable(); err != nil {
		t.Skipf("skipping: %v", err)
	}

	loader, err := NewSockOpsLoader(obj)
	if err != nil {
		if isPermissionErr(err) || errors.Is(err, ErrEBPFInsufficientCaps) {
			t.Skipf("skipping: insufficient privileges to load BPF: %v", err)
		}
		t.Fatalf("NewSockOpsLoader: %v", err)
	}
	t.Cleanup(func() { _ = loader.Close() })

	_, err = loader.AttachToCGroup("/does/not/exist/fos1")
	if !errors.Is(err, ErrCGroupPathNotFound) {
		t.Fatalf("expected ErrCGroupPathNotFound, got %v", err)
	}
}

// TestSockOpsLoader_AccessorsNilReceiver guards against a regression
// where callers dereference a nil loader.
func TestSockOpsLoader_AccessorsNilReceiver(t *testing.T) {
	var l *SockOpsLoader
	if l.Program() != nil {
		t.Fatal("Program() on nil receiver must return nil")
	}
	if l.CounterMap() != nil {
		t.Fatal("CounterMap() on nil receiver must return nil")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close on nil receiver must be a no-op, got %v", err)
	}
}

// findCGroupV2Root returns a path to the cgroup v2 unified hierarchy,
// or "" if one cannot be located. It checks the conventional mount at
// `/sys/fs/cgroup` via `unix.Statfs` against the CGROUP2_SUPER_MAGIC
// constant — on a pure-v2 system the root itself is v2, while on a
// hybrid system the v2 hierarchy is often at `/sys/fs/cgroup/unified`.
func findCGroupV2Root(t *testing.T) string {
	t.Helper()
	const cgroup2Magic = 0x63677270

	for _, path := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		var st unix.Statfs_t
		if err := unix.Statfs(path, &st); err != nil {
			continue
		}
		if int64(st.Type) == cgroup2Magic {
			return path
		}
	}
	return ""
}
