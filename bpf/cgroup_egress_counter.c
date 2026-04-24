// SPDX-License-Identifier: GPL-2.0
//
// cgroup_egress_counter — minimal cgroup-skb egress program that counts
// outbound bytes per cgroup attachment. Sprint 31 / Ticket 51.
//
// Behaviour:
//   - Attaches to a cgroup v2 via `BPF_CGROUP_INET_EGRESS`.
//   - On every outbound skb, adds `skb->len` to a single-entry PERCPU
//     counter (key = 0). Also increments a per-entry packet counter at
//     key = 1 so the test can distinguish "no packets" from "zero-byte
//     packet storm".
//   - Always returns 1 (allow). This program does not filter; it is a
//     pure accounting primitive. A future ticket can compose a filter
//     on top by consulting a verdict map.
//
// Non-goals (v0, intentional):
//   - Per-5-tuple / per-process accounting — out of scope; user-space
//     can add a map keyed by sport/dport if a use case emerges.
//   - Ingress counterpart — this is egress-only per the ticket; adding
//     the SEC("cgroup_skb/ingress") mirror is a trivial follow-up.
//   - Byte/packet limiting with drop — see above, verdict remains 1.
//
// Dependencies:
//   - bpf/headers/vmlinux_minimal.h — `struct __sk_buff` is already
//     present from Ticket 39's TC work; no further UAPI additions
//     needed.
//   - bpf/headers/bpf_helpers.h — pinned subset of libbpf helpers.
//
// Related:
//   - pkg/hardware/ebpf/cgroup_loader_linux.go loads and attaches this
//     object via `link.AttachCgroup(AttachCGroupInetEgress)`.
//   - Build via `make bpf-objects` (requires BPF-capable clang/LLVM).

#include "vmlinux_minimal.h"
#include "bpf_helpers.h"

// cgroup_egress_bytes / cgroup_egress_packets — two-entry per-CPU
// counter. Index 0 = cumulative bytes, index 1 = cumulative packets.
// Single map keeps the loader code simple (one handle to verify) at
// the cost of a slightly weaker type — still safe because both values
// are __u64 and the user-space side always reads both.
//
// The PERCPU_ARRAY form matches the sockops counter choice for the
// same reason: avoid cross-CPU atomics in the hot path and sum in
// user-space.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} cgroup_egress_stats SEC(".maps");

SEC("cgroup_skb/egress")
int cgroup_egress_counter(struct __sk_buff *skb) {
    __u32 bytes_key = 0;
    __u64 *bytes = bpf_map_lookup_elem(&cgroup_egress_stats, &bytes_key);
    if (bytes) {
        *bytes += skb->len;
    }

    __u32 pkts_key = 1;
    __u64 *pkts = bpf_map_lookup_elem(&cgroup_egress_stats, &pkts_key);
    if (pkts) {
        *pkts += 1;
    }

    // 1 = allow. cgroup_skb programs use 0 = drop, 1 = allow — not the
    // XDP_* or TC_ACT_* conventions from earlier programs.
    return 1;
}

char _license[] SEC("license") = "GPL";
