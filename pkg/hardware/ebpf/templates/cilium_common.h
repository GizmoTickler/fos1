// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
// Common definitions for Cilium integration

#ifndef __CILIUM_COMMON_H__
#define __CILIUM_COMMON_H__

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

// Cilium-specific includes - these would be available when compiled within Cilium's build environment
#ifndef CILIUM_INTEGRATION
// When not building with Cilium directly, we use our own definitions
#define CILIUM_INTEGRATION 1

// IPv6 address structure for consistent handling
struct ipv6_addr {
    __u32 addr[4];  // IPv6 address as 4 x 32-bit words
};

// Identity information
struct cilium_identity {
    __u32 id;
    __u32 reserved;
};

// Policy verdict structure for identity-based filtering
struct cilium_policy_verdict {
    __u8 verdict;      // 0 = pass, 1 = drop, 2 = redirect
    __u8 has_policy;   // Whether a policy exists for this identity
    __u8 pad1;
    __u8 pad2;
    __u32 redirect_port; // Used for redirect verdict
};

// Connection tracking entry structure
struct cilium_ct_entry {
    __u64 last_seen;    // Timestamp of last packet
    __u32 flags;        // Connection flags
    __u32 rx_packets;   // Received packets
    __u32 rx_bytes;     // Received bytes
    __u32 tx_packets;   // Transmitted packets
    __u32 tx_bytes;     // Transmitted bytes
    __u16 lifetime;     // Entry lifetime in seconds
    __u16 cilium_id;    // Cilium identity associated with connection
};

// Common map definitions that can be shared across templates

// Define Cilium IPv4 identity map - used for identity-based filtering
// This map can be shared with Cilium to use its identity-based policies
#define DECLARE_CILIUM_IPCACHE \
struct { \
    __uint(type, BPF_MAP_TYPE_LRU_HASH); \
    __uint(max_entries, 65536); \
    __type(key, __u32);             /* IPv4 address */ \
    __type(value, struct cilium_identity);  /* Cilium identity */ \
} cilium_ipcache SEC(".maps")

// Define Cilium IPv6 identity map - used for identity-based filtering
#define DECLARE_CILIUM_IPV6CACHE \
struct { \
    __uint(type, BPF_MAP_TYPE_LRU_HASH); \
    __uint(max_entries, 65536); \
    __type(key, struct ipv6_addr);   /* IPv6 address */ \
    __type(value, struct cilium_identity);  /* Cilium identity */ \
} cilium_ipv6cache SEC(".maps")

// Define map for Cilium policy verdicts
#define DECLARE_CILIUM_POLICY_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_LRU_HASH); \
    __uint(max_entries, 16384); \
    __type(key, __u32);             /* Identity */ \
    __type(value, struct cilium_policy_verdict);  /* Policy verdict */ \
} cilium_policy_map SEC(".maps")

// Hardware offload macros for different NIC types
// These macros are used to signal which NIC hardware offload capabilities
// are supported for each eBPF program type
#define X540_OFFLOAD_SUPPORTED(prog_name) \
    /* X540 NIC offload capability for prog_name */ \
    if (0) { bpf_printk("X540 NIC hardware acceleration for %s", prog_name); }

#define X550_OFFLOAD_SUPPORTED(prog_name) \
    /* X550 NIC offload capability for prog_name */ \
    if (0) { bpf_printk("X550 NIC hardware acceleration for %s", prog_name); }

#define I225_OFFLOAD_SUPPORTED(prog_name) \
    /* I225 NIC offload capability for prog_name */ \
    if (0) { bpf_printk("I225 NIC hardware acceleration for %s", prog_name); }

// IPv4 policy check
// Common helper function for Cilium policy checking with IPv4 addresses
// This provides a generic implementation that can be customized in each template
// Return values should map to program-specific actions (e.g., XDP_DROP, TC_ACT_SHOT)
static __always_inline int cilium_check_policy(void *ctx, __u32 src_ip, __u32 dst_ip, __u8 proto, __u16 src_port, __u16 dst_port) {
    // Look up the source IP in Cilium's identity cache
    struct cilium_identity *identity = bpf_map_lookup_elem(&cilium_ipcache, &src_ip);
    if (!identity) {
        // No identity found, typically would pass (handle in program-specific code)
        return 0; // Generic PASS value
    }
    
    // Look up if there's a policy verdict for this identity
    struct cilium_policy_verdict *verdict = bpf_map_lookup_elem(&cilium_policy_map, &identity->id);
    if (verdict) {
        // If we have a policy verdict, use it
        if (verdict->verdict == 1) {
            return 1; // Generic DROP value
        } else if (verdict->verdict == 2 && verdict->redirect_port) {
            // Redirect case - handle in program-specific code
            return 2; // Generic REDIRECT value 
        }
    }
    
    // If we get here, let the rest of the policy processing continue
    return 0; // Generic PASS value
}

// IPv6 policy check
// Common helper function for Cilium policy checking with IPv6 addresses
// This provides a generic implementation that can be customized in each template
// Return values should map to program-specific actions (e.g., XDP_DROP, TC_ACT_SHOT)
static __always_inline int cilium_check_policy_v6(void *ctx, struct ipv6_addr *src_ip, struct ipv6_addr *dst_ip, 
                                               __u8 proto, __u16 src_port, __u16 dst_port) {
    // Look up the source IP in Cilium's IPv6 identity cache
    struct cilium_identity *identity = bpf_map_lookup_elem(&cilium_ipv6cache, src_ip);
    if (!identity) {
        // No identity found, typically would pass (handle in program-specific code)
        return 0; // Generic PASS value
    }
    
    // Look up if there's a policy verdict for this identity - same policy map as IPv4
    struct cilium_policy_verdict *verdict = bpf_map_lookup_elem(&cilium_policy_map, &identity->id);
    if (verdict) {
        // If we have a policy verdict, use it
        if (verdict->verdict == 1) {
            return 1; // Generic DROP value
        } else if (verdict->verdict == 2 && verdict->redirect_port) {
            // Redirect case - handle in program-specific code
            return 2; // Generic REDIRECT value 
        }
    }
    
    // If we get here, let the rest of the policy processing continue
    return 0; // Generic PASS value
}

#endif // CILIUM_INTEGRATION
#endif // __CILIUM_COMMON_H__
