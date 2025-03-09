// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
// Compatible with Cilium Network Policies
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Include common Cilium definitions
#include "cilium_common.h"

// Declare all maps using the common macros
DECLARE_IPV4_BLACKLIST_MAP;
DECLARE_IPV6_BLACKLIST_MAP;
DECLARE_IPV4_RATE_LIMIT_MAP;
DECLARE_IPV6_RATE_LIMIT_MAP;
DECLARE_IPV4_STATE_MAP;
DECLARE_IPV6_STATE_MAP;
DECLARE_CONFIG_MAP;

// Cilium identity maps
DECLARE_CILIUM_IPCACHE;
DECLARE_CILIUM_IPCACHE6;
DECLARE_CILIUM_POLICY_MAP;

// Helper function to calculate IPv4 flow hash for more granular state tracking
static __always_inline __u64 flow_hash(struct iphdr *iph, __u16 src_port, __u16 dst_port) {
    __u64 hash;
    
    // Base hash using addresses and protocol
    hash = (((__u64)iph->saddr << 32) | ((__u64)iph->daddr)) ^
           ((__u64)iph->protocol << 56);
    
    // Add port information if available
    if (src_port && dst_port) {
        hash ^= (((__u64)src_port << 32) | ((__u64)dst_port));
    }
    
    return hash;
}

// Helper function to calculate IPv6 flow hash for more granular state tracking
static __always_inline __u64 flow_hash_v6(struct ipv6hdr *ip6h, __u16 src_port, __u16 dst_port) {
    __u64 hash;
    __u32 *src_addr = (__u32 *)&ip6h->saddr;
    __u32 *dst_addr = (__u32 *)&ip6h->daddr;
    
    // Use first and last 32 bits of IPv6 addresses for hash calculation
    hash = (((__u64)src_addr[0] << 32) | ((__u64)src_addr[3])) ^
           (((__u64)dst_addr[0] << 32) | ((__u64)dst_addr[3]));
    
    // Add protocol information
    hash ^= ((__u64)ip6h->nexthdr << 56);
    
    // Add port information if available
    if (src_port && dst_port) {
        hash ^= (((__u64)src_port << 32) | ((__u64)dst_port));
    }
    
    // Include flow label for additional entropy
    hash ^= (bpf_ntohl(ip6h->flow_lbl[0] << 16 | ip6h->flow_lbl[1] << 8 | 
                      ip6h->flow_lbl[2]) & IPV6_FLOWLABEL_MASK);
    
    return hash;
}

// Process IPv4 packet
static __always_inline int process_ipv4(struct xdp_md *ctx, void *data, void *data_end, 
                                        struct ethhdr *eth, struct iphdr *iph, struct config *cfg) {
    __u16 src_port = 0, dst_port = 0;
    struct tcphdr *tcph;
    struct udphdr *udph;
    void *l4_header = (void *)iph + (iph->ihl * 4);
    
    // Check if L4 header is accessible
    if (l4_header > data_end) {
        return XDP_PASS; // Malformed packet
    }
    
    // Extract ports for TCP or UDP
    if (iph->protocol == IPPROTO_TCP) {
        if (!extract_tcp_ports(l4_header, data_end, &tcph, &src_port, &dst_port)) {
            return XDP_PASS; // Malformed TCP header
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        if (!extract_udp_ports(l4_header, data_end, &udph, &src_port, &dst_port)) {
            return XDP_PASS; // Malformed UDP header
        }
    }
    
    // Check Cilium integration first if enabled (priority over local rules)
    if (cfg->cilium_integration) {
        int verdict = cilium_check_policy(NULL, iph->saddr, iph->daddr, iph->protocol, src_port, dst_port);
        if (verdict != 0) { // If Cilium has made a non-pass decision
            switch (verdict) {
                case 1:
                    return XDP_DROP;
                case 2:
                    return XDP_REDIRECT; // If supported by Cilium integration
                default:
                    return XDP_PASS;
            }
        }
    }
    
    // Check blacklist if enabled
    if (cfg->enable_blacklist && check_ipv4_blacklist(iph->saddr)) {
        return XDP_DROP;
    }
    
    // Check rate limit if enabled
    if (cfg->enable_rate_limit && check_ipv4_rate_limit(iph->saddr, cfg)) {
        return XDP_DROP;
    }
    
    // Stateful tracking if enabled
    if (cfg->enable_stateful) {
        struct flow_key4 flow_key = create_flow_key4(iph, src_port, dst_port);
        __u8 new_state = 1;  // Mark as seen
        
        // Update state map
        bpf_map_update_elem(&ipv4_state_map, &flow_key, &new_state, BPF_ANY);
    }
    
    // Default action based on configuration
    return cfg->default_action ? XDP_DROP : XDP_PASS;
}

// Process IPv6 packet
static __always_inline int process_ipv6(struct xdp_md *ctx, void *data, void *data_end, 
                                        struct ethhdr *eth, struct ipv6hdr *ip6h, struct config *cfg) {
    __u16 src_port = 0, dst_port = 0;
    struct tcphdr *tcph;
    struct udphdr *udph;
    void *l4_header = (void *)ip6h + sizeof(struct ipv6hdr);
    struct ipv6_addr src_addr;
    
    // Check if L4 header is accessible
    if (l4_header > data_end) {
        return XDP_PASS; // Malformed packet
    }
    
    // Extract ports for TCP or UDP
    if (ip6h->nexthdr == IPPROTO_TCP) {
        if (!extract_tcp_ports(l4_header, data_end, &tcph, &src_port, &dst_port)) {
            return XDP_PASS; // Malformed TCP header
        }
    } else if (ip6h->nexthdr == IPPROTO_UDP) {
        if (!extract_udp_ports(l4_header, data_end, &udph, &src_port, &dst_port)) {
            return XDP_PASS; // Malformed UDP header
        }
    }
    
    // Extract source IPv6 address
    __builtin_memcpy(&src_addr, &ip6h->saddr, sizeof(struct ipv6_addr));
    
    // Check Cilium integration first if enabled
    if (cfg->cilium_integration) {
        struct ipv6_addr dst_addr;
        __builtin_memcpy(&dst_addr, &ip6h->daddr, sizeof(struct ipv6_addr));
        
        int verdict = cilium_check_policy_v6(NULL, &src_addr, &dst_addr, ip6h->nexthdr, src_port, dst_port);
        if (verdict != 0) { // If Cilium has made a non-pass decision
            switch (verdict) {
                case 1:
                    return XDP_DROP;
                case 2:
                    return XDP_REDIRECT; // If supported by Cilium integration
                default:
                    return XDP_PASS;
            }
        }
    }
    
    // Check blacklist if enabled
    if (cfg->enable_blacklist && check_ipv6_blacklist(&src_addr)) {
        return XDP_DROP;
    }
    
    // Check rate limit if enabled
    if (cfg->enable_rate_limit && check_ipv6_rate_limit(&src_addr, cfg)) {
        return XDP_DROP;
    }
    
    // Stateful tracking if enabled
    if (cfg->enable_stateful) {
        struct flow_key6 flow_key = create_flow_key6(ip6h, src_port, dst_port);
        __u8 new_state = 1;  // Mark as seen
        
        // Update state map
        bpf_map_update_elem(&ipv6_state_map, &flow_key, &new_state, BPF_ANY);
    }
    
    // Default action based on configuration
    return cfg->default_action ? XDP_DROP : XDP_PASS;
}

// XDP program - main entry point
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    // Check if packet is too small for Ethernet header
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;  // Pass malformed packets
    
    // Get configuration
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg) {
        // Default configuration if none exists
        struct config default_cfg = {
            .rate_limit = DEFAULT_RATE_LIMIT,
            .rate_period = 1000, // 1 second in milliseconds
            .enable_blacklist = 1,
            .enable_rate_limit = 1,
            .enable_stateful = 1,
            .default_action = 0, // XDP_PASS
            .cilium_integration = 0,
            .hw_offload = 0, 
            .enable_ipv6 = 1  // IPv6 enabled by default
        };
        
        // We can't modify the config map directly, so we just use our default
        cfg = &default_cfg;
    }
    
    // Hardware offload optimizations using common macros
    if (cfg->hw_offload) {
        // Use the appropriate hardware offload macro based on NIC type
        X540_OFFLOAD_SUPPORTED("xdp");
        X550_OFFLOAD_SUPPORTED("xdp");
        I225_OFFLOAD_SUPPORTED("xdp");
    }
    
    // Process packet based on protocol
    __u16 eth_type = bpf_ntohs(eth->h_proto);
    
    // Check for IPv4 packet
    if (eth_type == ETH_P_IP) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void*)(iph + 1) > data_end)
            return XDP_PASS;  // Pass malformed packets
        
        return process_ipv4(ctx, data, data_end, eth, iph, cfg);
    }
    // Check for IPv6 packet if IPv6 support is enabled
    else if (eth_type == ETH_P_IPV6 && cfg->enable_ipv6) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void*)(ip6h + 1) > data_end)
            return XDP_PASS;  // Pass malformed packets
        
        return process_ipv6(ctx, data, data_end, eth, ip6h, cfg);
    }
    
    // Default pass for other packet types
    return XDP_PASS;
}

// Define Cilium tail calls program to enable integration with Cilium's datapath
SEC("cilium_xdp_entry")
int cilium_xdp_entry(struct xdp_md *ctx) {
    // This is a specialized entry point for Cilium integration
    // When used with Cilium, this will be called through their tail call mechanism
    return xdp_filter(ctx);
}

char _license[] SEC("license") = "GPL";
