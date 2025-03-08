// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define map for rate limiting
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // Source IP
    __type(value, __u64);  // Timestamp + counter
} ratelimit_map SEC(".maps");

// Define map for blacklisted IPs
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // Source IP
    __type(value, __u8);   // 1 = blacklisted
} blacklist_map SEC(".maps");

// Define map for stateful tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, __u64);    // Connection tuple hash
    __type(value, __u8);   // Connection state
} state_map SEC(".maps");

// Define map for configuration
struct config {
    __u32 ratelimit_pps;   // Packets per second threshold
    __u8 enable_blacklist; // Enable blacklist
    __u8 enable_ratelimit; // Enable rate limiting
    __u8 enable_stateful;  // Enable stateful tracking
    __u8 default_action;   // Default action: 0 = pass, 1 = drop
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

// Helper function to calculate flow hash
static __always_inline __u64 flow_hash(struct iphdr *iph) {
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(iph + 1);
        return (((__u64)iph->saddr << 32) | ((__u64)iph->daddr)) ^
               (((__u64)tcp->source << 32) | ((__u64)tcp->dest)) ^
               ((__u64)iph->protocol << 56);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(iph + 1);
        return (((__u64)iph->saddr << 32) | ((__u64)iph->daddr)) ^
               (((__u64)udp->source << 32) | ((__u64)udp->dest)) ^
               ((__u64)iph->protocol << 56);
    } else {
        return (((__u64)iph->saddr << 32) | ((__u64)iph->daddr)) ^
               ((__u64)iph->protocol << 56);
    }
}

// XDP program - main entry point
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    // Check if packet is too small
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;  // Pass malformed packets
    
    // Check for IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;  // Non-IPv4 packets pass
    
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;  // Pass malformed packets
    
    // Get configuration
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return XDP_PASS;  // No config, pass the packet
    
    // Check blacklist if enabled
    if (cfg->enable_blacklist) {
        __u8 *blocked = bpf_map_lookup_elem(&blacklist_map, &iph->saddr);
        if (blocked && *blocked)
            return XDP_DROP;  // Drop blacklisted packets
    }
    
    // Check rate limit if enabled
    if (cfg->enable_ratelimit) {
        __u64 now = bpf_ktime_get_ns();
        __u64 *last = bpf_map_lookup_elem(&ratelimit_map, &iph->saddr);
        __u64 val = now;
        
        if (last) {
            // Check if within rate limit window (1 second)
            __u64 count = (*last & 0xFFFFFFFF) + 1;
            __u64 ts = *last >> 32;
            
            if (now - ts < 1000000000) { // Within 1 second
                if (count > cfg->ratelimit_pps)
                    return XDP_DROP;  // Exceeds rate limit
                val = (ts << 32) | count;
            }
        }
        
        bpf_map_update_elem(&ratelimit_map, &iph->saddr, &val, BPF_ANY);
    }
    
    // Stateful tracking if enabled
    if (cfg->enable_stateful) {
        __u64 hash = flow_hash(iph);
        __u8 *state = bpf_map_lookup_elem(&state_map, &hash);
        __u8 new_state = 1;  // Mark as seen
        
        // Update state map
        bpf_map_update_elem(&state_map, &hash, &new_state, BPF_ANY);
    }
    
    // Default action based on configuration
    return cfg->default_action ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
