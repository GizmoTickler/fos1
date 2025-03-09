// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
// Common definitions for Cilium integration

#ifndef __CILIUM_COMMON_H__
#define __CILIUM_COMMON_H__

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Maximum entries for maps
#define MAX_MAP_ENTRIES 65536
#define MAX_BLACKLIST_ENTRIES 10240
#define MAX_CONN_ENTRIES 131072
#define DEFAULT_RATE_LIMIT 1000000  // packets per second

// Define IPv6 flow label mask
#define IPV6_FLOWLABEL_MASK 0x000FFFFF

// Cilium-specific includes - these would be available when compiled within Cilium's build environment
#ifndef CILIUM_INTEGRATION
// When not building with Cilium directly, we use our own definitions
#define CILIUM_INTEGRATION 1

// IPv6 address structure for consistent handling
struct ipv6_addr {
    union {
        __u8 bytes[16];    // IPv6 address as 16 bytes
        __u32 words[4];    // IPv6 address as 4 x 32-bit words
    };
};

// LPM Trie key structures for CIDR matching
struct bpf_lpm_trie_key4 {
    __u32 prefixlen;
    __u32 data;
};

struct bpf_lpm_trie_key6 {
    __u32 prefixlen;
    struct ipv6_addr data;
};

// Flow keys for connection tracking
struct flow_key4 {
    __u32 src_addr;
    __u32 dst_addr;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
};

struct flow_key6 {
    struct ipv6_addr src_addr;
    struct ipv6_addr dst_addr;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
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
    __uint(max_entries, MAX_MAP_ENTRIES); \
    __type(key, __u32);             /* IPv4 address */ \
    __type(value, struct cilium_identity);  /* Cilium identity */ \
} cilium_ipcache SEC(".maps")

// Define Cilium IPv6 identity map - used for identity-based filtering
#define DECLARE_CILIUM_IPCACHE6 \
struct { \
    __uint(type, BPF_MAP_TYPE_LRU_HASH); \
    __uint(max_entries, MAX_MAP_ENTRIES); \
    __type(key, struct ipv6_addr);   /* IPv6 address */ \
    __type(value, struct cilium_identity);  /* Cilium identity */ \
} cilium_ipcache6 SEC(".maps")

// Define map for Cilium policy verdicts
#define DECLARE_CILIUM_POLICY_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_LRU_HASH); \
    __uint(max_entries, 16384); \
    __type(key, __u32);             /* Identity */ \
    __type(value, struct cilium_policy_verdict);  /* Policy verdict */ \
} cilium_policy_map SEC(".maps")

// Generic blacklist map declarations
#define DECLARE_IPV4_BLACKLIST_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE); \
    __uint(max_entries, MAX_BLACKLIST_ENTRIES); \
    __type(key, struct bpf_lpm_trie_key4); \
    __type(value, __u32); \
    __uint(map_flags, BPF_F_NO_PREALLOC); \
} ipv4_blacklist SEC(".maps")

#define DECLARE_IPV6_BLACKLIST_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE); \
    __uint(max_entries, MAX_BLACKLIST_ENTRIES); \
    __type(key, struct bpf_lpm_trie_key6); \
    __type(value, __u32); \
    __uint(map_flags, BPF_F_NO_PREALLOC); \
} ipv6_blacklist SEC(".maps")

// Generic rate limit map declarations
#define DECLARE_IPV4_RATE_LIMIT_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_LRU_HASH); \
    __uint(max_entries, MAX_CONN_ENTRIES); \
    __type(key, __u32); \
    __type(value, __u64); \
} ipv4_rate_limit SEC(".maps")

#define DECLARE_IPV6_RATE_LIMIT_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_LRU_HASH); \
    __uint(max_entries, MAX_CONN_ENTRIES); \
    __type(key, struct ipv6_addr); \
    __type(value, __u64); \
} ipv6_rate_limit SEC(".maps")

// Generic state tracking map declarations
#define DECLARE_IPV4_STATE_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_LRU_HASH); \
    __uint(max_entries, MAX_CONN_ENTRIES); \
    __type(key, struct flow_key4); \
    __type(value, __u8); \
} ipv4_state_map SEC(".maps")

#define DECLARE_IPV6_STATE_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_LRU_HASH); \
    __uint(max_entries, MAX_CONN_ENTRIES); \
    __type(key, struct flow_key6); \
    __type(value, __u8); \
} ipv6_state_map SEC(".maps")

// Traffic class structure for QoS and rate limiting
struct traffic_class {
    __u32 priority;         // Class priority
    __u32 mark;             // Mark to apply
    __u32 rate_limit_bps;   // Rate limit in bytes per second
    __u32 ceiling_bps;      // Ceiling in bytes per second
    __u8 dscp;              // DSCP value to set (used in egress)
};

// Map macro for traffic classes
#define DECLARE_TRAFFIC_CLASS_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_HASH); \
    __uint(max_entries, 64); \
    __type(key, __u32);     /* Class ID */ \
    __type(value, struct traffic_class); \
} classes_map SEC(".maps")

// Filter rule structure for traffic classification
struct filter_rule {
    __u32 priority;         // Rule priority
    __u32 class_id;         // Target class ID
    __u32 src_ip;           // Source IP (0 = any)
    __u32 dst_ip;           // Destination IP (0 = any)
    __u16 src_port;         // Source port (0 = any)
    __u16 dst_port;         // Destination port (0 = any)
    __u8 protocol;          // Protocol (0 = any)
    __u8 action;            // Action: 0 = pass, 1 = drop, 2 = mark
};

// Map macro for filter rules
#define DECLARE_FILTER_RULES_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_HASH); \
    __uint(max_entries, 1024); \
    __type(key, __u32);     /* Rule ID */ \
    __type(value, struct filter_rule); \
} rules_map SEC(".maps")

// Map macro for rate limiting
#define DECLARE_RATE_LIMIT_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_LRU_HASH); \
    __uint(max_entries, 1024); \
    __type(key, __u32);    /* Class ID or IP */ \
    __type(value, __u64);  /* Bytes + timestamp */ \
} rate_map SEC(".maps")

// Configuration map structure
struct config {
    __u32 rate_limit;         // Packets per second threshold
    __u32 rate_period;        // Rate limiting period in milliseconds
    __u8 enable_blacklist;    // Enable blacklist
    __u8 enable_rate_limit;   // Enable rate limiting
    __u8 enable_stateful;     // Enable stateful tracking
    __u8 default_action;      // Default action: 0 = pass, 1 = drop
    __u8 cilium_integration;  // Enable Cilium integration
    __u8 hw_offload;          // Enable hardware offload optimizations
    __u16 cilium_policy_index;// Reference to Cilium policy to apply
    __u8 enable_ipv6;         // Enable IPv6 support
};

#define DECLARE_CONFIG_MAP \
struct { \
    __uint(type, BPF_MAP_TYPE_ARRAY); \
    __uint(max_entries, 1); \
    __type(key, __u32); \
    __type(value, struct config); \
} config_map SEC(".maps")

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

/* Helper functions for IPv4/IPv6 address comparison */
static __always_inline int ipv6_addr_equals(const struct ipv6_addr *a, const struct ipv6_addr *b) {
    return (a->words[0] == b->words[0] &&
            a->words[1] == b->words[1] &&
            a->words[2] == b->words[2] &&
            a->words[3] == b->words[3]);
}

/* Helper function to check IPv4 address in blacklist */
static __always_inline int check_ipv4_blacklist(__u32 addr) {
    struct bpf_lpm_trie_key4 key = {};
    key.prefixlen = 32;
    key.data = addr;
    
    __u32 *action = bpf_map_lookup_elem(&ipv4_blacklist, &key);
    if (action && *action == 1) {
        return 1; // Blacklisted
    }
    
    return 0; // Not blacklisted
}

/* Helper function to check IPv6 address in blacklist */
static __always_inline int check_ipv6_blacklist(struct ipv6_addr *addr) {
    struct bpf_lpm_trie_key6 key = {};
    key.prefixlen = 128;
    __builtin_memcpy(&key.data, addr, sizeof(struct ipv6_addr));
    
    __u32 *action = bpf_map_lookup_elem(&ipv6_blacklist, &key);
    if (action && *action == 1) {
        return 1; // Blacklisted
    }
    
    return 0; // Not blacklisted
}

/* Helper function to apply IPv4 rate limiting */
static __always_inline int check_ipv4_rate_limit(__u32 addr, struct config *cfg) {
    __u64 now = bpf_ktime_get_ns() / 1000000; // Convert to milliseconds
    __u64 *counter = bpf_map_lookup_elem(&ipv4_rate_limit, &addr);
    __u64 new_value = 1 | (now << 32); // First packet in this period
    
    if (counter) {
        __u64 count = *counter & 0xFFFFFFFF;
        __u64 timestamp = *counter >> 32;
        
        // Check if we're in a new period
        if (now - timestamp > cfg->rate_period) {
            // Reset for new period
            new_value = 1 | (now << 32);
        } else {
            // Increment counter for same period
            count++;
            new_value = count | (timestamp << 32);
            
            // Check if rate limit exceeded
            if (count > cfg->rate_limit) {
                return 1; // Drop packet
            }
        }
    }
    
    // Update counter
    bpf_map_update_elem(&ipv4_rate_limit, &addr, &new_value, BPF_ANY);
    
    return 0; // Allow packet
}

/* Helper function to apply IPv6 rate limiting */
static __always_inline int check_ipv6_rate_limit(struct ipv6_addr *addr, struct config *cfg) {
    __u64 now = bpf_ktime_get_ns() / 1000000; // Convert to milliseconds
    __u64 *counter = bpf_map_lookup_elem(&ipv6_rate_limit, addr);
    __u64 new_value = 1 | (now << 32); // First packet in this period
    
    if (counter) {
        __u64 count = *counter & 0xFFFFFFFF;
        __u64 timestamp = *counter >> 32;
        
        // Check if we're in a new period
        if (now - timestamp > cfg->rate_period) {
            // Reset for new period
            new_value = 1 | (now << 32);
        } else {
            // Increment counter for same period
            count++;
            new_value = count | (timestamp << 32);
            
            // Check if rate limit exceeded
            if (count > cfg->rate_limit) {
                return 1; // Drop packet
            }
        }
    }
    
    // Update counter
    bpf_map_update_elem(&ipv6_rate_limit, addr, &new_value, BPF_ANY);
    
    return 0; // Allow packet
}

// IPv4 policy check
// Common helper function for Cilium policy checking with IPv4 addresses
// This provides a generic implementation that can be customized in each template
// Return values should map to program-specific actions (e.g., XDP_DROP, TC_ACT_SHOT)
static __always_inline int cilium_check_policy(void *ctx, __u32 src_ip, __u32 dst_ip, __u8 proto, __u16 src_port, __u16 dst_port) {
    // Check source and destination identities
    struct cilium_identity *src_identity = bpf_map_lookup_elem(&cilium_ipcache, &src_ip);
    struct cilium_identity *dst_identity = bpf_map_lookup_elem(&cilium_ipcache, &dst_ip);
    
    // Apply identity-based rules if identities are found
    if (src_identity && dst_identity) {
        // Block connections from non-local to local identities
        if (src_identity->id >= 32768 && dst_identity->id < 32768) {
            return 1; // DROP
        }
        
        // Check policy verdict based on source identity
        struct cilium_policy_verdict *verdict = bpf_map_lookup_elem(&cilium_policy_map, &src_identity->id);
        if (verdict && verdict->has_policy) {
            if (verdict->verdict == 1) {
                return 1; // DROP
            } else if (verdict->verdict == 2 && verdict->redirect_port) {
                return 2; // REDIRECT
            }
        }
        
        // Check policy verdict based on destination identity
        verdict = bpf_map_lookup_elem(&cilium_policy_map, &dst_identity->id);
        if (verdict && verdict->has_policy) {
            if (verdict->verdict == 1) {
                return 1; // DROP
            } else if (verdict->verdict == 2 && verdict->redirect_port) {
                return 2; // REDIRECT
            }
        }
    }
    
    return 0; // PASS
}

// IPv6 policy check
// Common helper function for Cilium policy checking with IPv6 addresses
// This provides a generic implementation that can be customized in each template
// Return values should map to program-specific actions (e.g., XDP_DROP, TC_ACT_SHOT)
static __always_inline int cilium_check_policy_v6(void *ctx, struct ipv6_addr *src_ip, struct ipv6_addr *dst_ip, 
                                               __u8 proto, __u16 src_port, __u16 dst_port) {
    // Check source and destination identities
    struct cilium_identity *src_identity = bpf_map_lookup_elem(&cilium_ipcache6, src_ip);
    struct cilium_identity *dst_identity = bpf_map_lookup_elem(&cilium_ipcache6, dst_ip);
    
    // Apply identity-based rules if identities are found
    if (src_identity && dst_identity) {
        // Block connections from non-local to local identities
        if (src_identity->id >= 32768 && dst_identity->id < 32768) {
            return 1; // DROP
        }
        
        // Check policy verdict based on source identity
        struct cilium_policy_verdict *verdict = bpf_map_lookup_elem(&cilium_policy_map, &src_identity->id);
        if (verdict && verdict->has_policy) {
            if (verdict->verdict == 1) {
                return 1; // DROP
            } else if (verdict->verdict == 2 && verdict->redirect_port) {
                return 2; // REDIRECT
            }
        }
        
        // Check policy verdict based on destination identity
        verdict = bpf_map_lookup_elem(&cilium_policy_map, &dst_identity->id);
        if (verdict && verdict->has_policy) {
            if (verdict->verdict == 1) {
                return 1; // DROP
            } else if (verdict->verdict == 2 && verdict->redirect_port) {
                return 2; // REDIRECT
            }
        }
    }
    
    return 0; // PASS
}

/* Helper function to create IPv4 flow key for stateful tracking */
static __always_inline struct flow_key4 create_flow_key4(struct iphdr *iph, __u16 src_port, __u16 dst_port) {
    struct flow_key4 key = {};
    
    key.src_addr = iph->saddr;
    key.dst_addr = iph->daddr;
    key.proto = iph->protocol;
    key.src_port = src_port;
    key.dst_port = dst_port;
    
    return key;
}

/* Helper function to create IPv6 flow key for stateful tracking */
static __always_inline struct flow_key6 create_flow_key6(struct ipv6hdr *ip6h, __u16 src_port, __u16 dst_port) {
    struct flow_key6 key = {};
    
    __builtin_memcpy(&key.src_addr, &ip6h->saddr, sizeof(struct ipv6_addr));
    __builtin_memcpy(&key.dst_addr, &ip6h->daddr, sizeof(struct ipv6_addr));
    key.proto = ip6h->nexthdr;
    key.src_port = src_port;
    key.dst_port = dst_port;
    
    return key;
}

/* Helper function to extract ports from TCP header */
static __always_inline int extract_tcp_ports(void *data, void *data_end, struct tcphdr **tcph, __u16 *src_port, __u16 *dst_port) {
    *tcph = data;
    
    if ((void*)(*tcph + 1) > data_end)
        return 0; // Header incomplete
    
    *src_port = bpf_ntohs((*tcph)->source);
    *dst_port = bpf_ntohs((*tcph)->dest);
    
    return 1; // Success
}

/* Helper function to extract ports from UDP header */
static __always_inline int extract_udp_ports(void *data, void *data_end, struct udphdr **udph, __u16 *src_port, __u16 *dst_port) {
    *udph = data;
    
    if ((void*)(*udph + 1) > data_end)
        return 0; // Header incomplete
    
    *src_port = bpf_ntohs((*udph)->source);
    *dst_port = bpf_ntohs((*udph)->dest);
    
    return 1; // Success
}

/* Helper function to extract IP header information */
static __always_inline int extract_ip_info(struct __sk_buff *skb, struct ip_info *info) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    
    // Validate packet size
    if (data + sizeof(*eth) > data_end)
        return -1;
    
    // Check IP version
    switch (bpf_ntohs(eth->h_proto)) {
        case ETH_P_IP: {
            struct iphdr *iph = (struct iphdr *)(eth + 1);
            if ((void *)(iph + 1) > data_end)
                return -1;
            
            info->version = 4;
            info->protocol = iph->protocol;
            info->src.v4 = iph->saddr;
            info->dst.v4 = iph->daddr;
            
            // Extract ports for TCP/UDP
            void *l4_header = (void *)iph + (iph->ihl * 4);
            if (l4_header > data_end)
                return -1;
            
            if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph;
                if (!extract_tcp_ports(l4_header, data_end, &tcph, &info->src_port, &info->dst_port))
                    return -1;
            } else if (iph->protocol == IPPROTO_UDP) {
                struct udphdr *udph;
                if (!extract_udp_ports(l4_header, data_end, &udph, &info->src_port, &info->dst_port))
                    return -1;
            }
            return 0;
        }
        case ETH_P_IPV6: {
            struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
            if ((void *)(ip6h + 1) > data_end)
                return -1;
            
            info->version = 6;
            info->protocol = ip6h->nexthdr;
            __builtin_memcpy(&info->src.v6, &ip6h->saddr, sizeof(struct ipv6_addr));
            __builtin_memcpy(&info->dst.v6, &ip6h->daddr, sizeof(struct ipv6_addr));
            
            // Extract ports for TCP/UDP
            void *l4_header = (void *)ip6h + sizeof(struct ipv6hdr);
            if (l4_header > data_end)
                return -1;
            
            if (ip6h->nexthdr == IPPROTO_TCP) {
                struct tcphdr *tcph;
                if (!extract_tcp_ports(l4_header, data_end, &tcph, &info->src_port, &info->dst_port))
                    return -1;
            } else if (ip6h->nexthdr == IPPROTO_UDP) {
                struct udphdr *udph;
                if (!extract_udp_ports(l4_header, data_end, &udph, &info->src_port, &info->dst_port))
                    return -1;
            }
            return 0;
        }
        default:
            return -1; // Unsupported protocol
    }
}

// Common rate limiting function for traffic classes
static __always_inline int apply_traffic_class_rate_limit(struct traffic_class *class, __u32 class_id, __u32 pkt_len, struct bpf_map_def *rate_map) {
    if (!class->rate_limit_bps)
        return 0; // No rate limiting, return success (0)
    
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(rate_map, &class_id);
    __u64 val = now;
    
    if (last) {
        // Check if within rate limit window (1 second)
        __u64 bytes = (*last & 0xFFFFFFFF) + pkt_len;
        __u64 ts = *last >> 32;
        
        if (now - ts < 1000000000) { // Within 1 second
            // Convert bytes per second to bits per nanosecond for precise comparison
            __u64 rate_bits_ns = class->rate_limit_bps * 8ULL;
            __u64 elapsed_ns = now - ts;
            __u64 allowed_bits = (rate_bits_ns * elapsed_ns) / 1000000000ULL;
            
            if ((bytes * 8) > allowed_bits)
                return 1; // Rate limit exceeded
            
            val = (ts << 32) | bytes;
        } else {
            // Reset counter for new interval
            val = (now << 32) | pkt_len;
        }
    } else {
        // First packet in this class
        val = (now << 32) | pkt_len;
    }
    
    bpf_map_update_elem(rate_map, &class_id, &val, BPF_ANY);
    return 0; // Success
}

#endif // CILIUM_INTEGRATION
#endif // __CILIUM_COMMON_H__
