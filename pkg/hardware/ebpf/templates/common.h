#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Common IP address union for IPv4/IPv6
union ip_addr {
    __u32 v4;
    struct in6_addr v6;
};

// Generic IP header info structure
struct ip_info {
    union ip_addr src;
    union ip_addr dst;
    __u8 version;
    __u8 protocol;
    __u16 src_port;
    __u16 dst_port;
};

// Common monitoring configuration
struct monitoring_config {
    __u8 enable_monitoring;   // Enable monitoring
    __u8 enable_tracing;      // Enable tracing
    __u8 cilium_integration;  // Enable Cilium integration
    __u8 hw_offload;          // Enable hardware offload
    __u16 cilium_policy_index; // Cilium policy reference
};

// Common connection event structure
struct conn_event {
    __u64 timestamp;         // Event timestamp
    __u32 pid;              // Process ID
    union {
        struct {
            __u32 sip4;     // Source IPv4
            __u32 dip4;     // Destination IPv4
        };
        struct {
            struct in6_addr sip6;  // Source IPv6
            struct in6_addr dip6;  // Destination IPv6
        };
    };
    __u16 sport;            // Source port
    __u16 dport;            // Destination port
    __u8 protocol;          // Protocol
    __u8 type;              // Event type
    __u8 family;            // Address family (1 = IPv4, 2 = IPv6)
};

// Common IPv6 comparison function
static __always_inline int compare_ipv6(struct in6_addr *a, struct in6_addr *b) {
    for (int i = 0; i < 4; i++) {
        if (a->in6_u.u6_addr32[i] != b->in6_u.u6_addr32[i])
            return 0;
    }
    return 1;
}

// Common connection tuple hash function
static __always_inline __u64 conn_hash(struct ip_info *info, int reverse) {
    __u64 hash;
    if (info->version == 4) {
        if (!reverse) {
            hash = info->src.v4 ^ info->dst.v4;
            hash = hash ^ ((__u64)info->src_port << 16 | info->dst_port);
        } else {
            hash = info->dst.v4 ^ info->src.v4;
            hash = hash ^ ((__u64)info->dst_port << 16 | info->src_port);
        }
    } else {
        // IPv6 hash
        if (!reverse) {
            hash = info->src.v6.in6_u.u6_addr32[0] ^ info->dst.v6.in6_u.u6_addr32[0];
            hash ^= info->src.v6.in6_u.u6_addr32[1] ^ info->dst.v6.in6_u.u6_addr32[1];
            hash ^= info->src.v6.in6_u.u6_addr32[2] ^ info->dst.v6.in6_u.u6_addr32[2];
            hash ^= info->src.v6.in6_u.u6_addr32[3] ^ info->dst.v6.in6_u.u6_addr32[3];
            hash = hash ^ ((__u64)info->src_port << 16 | info->dst_port);
        } else {
            hash = info->dst.v6.in6_u.u6_addr32[0] ^ info->src.v6.in6_u.u6_addr32[0];
            hash ^= info->dst.v6.in6_u.u6_addr32[1] ^ info->src.v6.in6_u.u6_addr32[1];
            hash ^= info->dst.v6.in6_u.u6_addr32[2] ^ info->src.v6.in6_u6_addr32[2];
            hash ^= info->dst.v6.in6_u.u6_addr32[3] ^ info->src.v6.in6_u.u6_addr32[3];
            hash = hash ^ ((__u64)info->dst_port << 16 | info->src_port);
        }
    }
    return hash;
}

#endif /* __COMMON_H__ */
