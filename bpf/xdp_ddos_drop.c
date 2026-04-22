// SPDX-License-Identifier: GPL-2.0
//
// xdp_ddos_drop — minimal, self-contained XDP program used as the
// compile-and-load prototype for Sprint 30 / Ticket 38.
//
// Behaviour:
//   - Parses the Ethernet + IPv4 header.
//   - Looks the source IPv4 address up in an LPM-trie denylist map.
//   - Returns XDP_DROP on hit, XDP_PASS otherwise.
//   - Non-IPv4 traffic is passed unmodified.
//
// This is intentionally small:
//   - No Cilium integration (owned, not forked from the xdp_template).
//   - No rate limiting, state tracking, or hardware-offload helpers.
//   - IPv6 handling is deliberately out of scope for v1.
//
// Dependencies are minimal on purpose:
//   - bpf/headers/vmlinux_minimal.h vendors only the kernel UAPI types
//     we actually need (xdp_md, ethhdr, iphdr). This keeps the build
//     working without a full `linux-headers` install.
//   - bpf/headers/bpf_helpers.h is a pinned subset of libbpf's helper
//     header.
//
// Related:
//   - pkg/hardware/ebpf/xdp_loader_linux.go loads and attaches this object.
//   - Build via `make bpf-objects` (requires BPF-capable clang/LLVM).

#include "vmlinux_minimal.h"
#include "bpf_helpers.h"

// Denylist key: LPM trie keys carry an explicit prefix length.
struct denylist_key {
    __u32 prefixlen; // bits of `addr` that are significant
    __u32 addr;      // network-order IPv4 address
};

// LPM_TRIE map holding denied source addresses / CIDRs.
// The user-space loader populates this map; the program only reads it.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct denylist_key);
    __type(value, __u8);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_denylist SEC(".maps");

static __always_inline int parse_ipv4(void *data, void *data_end, __u32 *src) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP)) {
        return 1; // not IPv4 — caller should pass.
    }
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return -1;
    }
    *src = iph->saddr; // network order
    return 0;
}

SEC("xdp")
int xdp_ddos_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 src = 0;
    int rc = parse_ipv4(data, data_end, &src);
    if (rc != 0) {
        // rc < 0: malformed; rc > 0: not IPv4. Pass in both cases;
        // the denylist only covers IPv4 for v1.
        return XDP_PASS;
    }

    struct denylist_key key = {
        .prefixlen = 32,
        .addr = src,
    };
    __u8 *hit = bpf_map_lookup_elem(&ipv4_denylist, &key);
    if (hit) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
