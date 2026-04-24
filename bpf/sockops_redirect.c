// SPDX-License-Identifier: GPL-2.0
//
// sockops_redirect — minimal sockops program that counts active
// established TCP connections. Sprint 31 / Ticket 51.
//
// Behaviour:
//   - Runs in the cgroup sockops hook.
//   - On every BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB callback, increments a
//     single-entry PERCPU_ARRAY counter (key = 0). Every other op is
//     ignored.
//   - Always returns 0 — the hook is informational in v0 and never
//     vetoes a socket state transition. A real perf-oriented sockops
//     redirect would sockhash-redirect established pairs; that is
//     explicitly out of scope for v0 (documented in the ticket).
//
// Non-goals (v0, intentional):
//   - sk_msg / sockhash-backed redirect — Sprint 32+.
//   - BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB tracking — the caller wanted
//     the simplest-possible counter; passive side can be added when a
//     consumer actually needs it.
//   - Per-cgroup / per-5-tuple state — the counter is a single global
//     value so the integration test can assert it is readable without
//     faking a network stack.
//
// Dependencies:
//   - bpf/headers/vmlinux_minimal.h — extended for this ticket with
//     `struct bpf_sock_ops` and the `BPF_SOCK_OPS_*` op codes we use.
//   - bpf/headers/bpf_helpers.h — pinned subset of libbpf helpers.
//
// Related:
//   - pkg/hardware/ebpf/sockops_loader_linux.go loads and attaches
//     this object via `link.AttachCgroup(AttachCGroupSockOps)`.
//   - Build via `make bpf-objects` (requires BPF-capable clang/LLVM).

#include "vmlinux_minimal.h"
#include "bpf_helpers.h"

// sockops_established_count — per-CPU counter of active established
// callbacks seen. Single entry (key = 0). Per-CPU avoids the cross-CPU
// atomic write overhead and, more importantly, avoids the need for
// BPF_F_NO_PREALLOC juggling on older kernels.
//
// Readers sum across CPUs in user space via `Map.Lookup` with a slice
// of length `possibleCPUs`.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} sockops_established_count SEC(".maps");

SEC("sockops")
int sockops_redirect(struct bpf_sock_ops *ops) {
    if (ops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return 0;
    }

    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&sockops_established_count, &key);
    if (cnt) {
        // Per-CPU map — plain increment is safe; no cross-CPU race.
        *cnt += 1;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
