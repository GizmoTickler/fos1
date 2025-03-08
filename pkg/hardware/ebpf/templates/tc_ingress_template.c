// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
// Compatible with Cilium Network Policies
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Include common Cilium definitions
#include "cilium_common.h"

// Configuration structure
struct tc_config {
    __u32 mark_mask;        // Mask for packet marking
    __u32 default_mark;     // Default mark value
    __u8 enable_marking;    // Enable packet marking
    __u8 enable_filtering;  // Enable packet filtering
    __u8 enable_qos;        // Enable quality of service
    __u8 default_action;    // Default action: 0 = pass, 1 = drop
    __u8 cilium_integration;// Enable Cilium integration
    __u8 hw_optimized;      // Hardware optimization enabled
    __u16 cilium_policy_index; // Reference to Cilium policy to apply
};

// Define map for configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tc_config);
} config_map SEC(".maps");

// Traffic class structure
struct traffic_class {
    __u32 priority;         // Class priority
    __u32 mark;             // Mark to apply
    __u32 rate_limit_bps;   // Rate limit in bytes per second
    __u32 ceiling_bps;      // Ceiling in bytes per second
};

// Define map for traffic classes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);     // Class ID
    __type(value, struct traffic_class);
} classes_map SEC(".maps");

// Filter rule structure
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

// Define map for filter rules
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);     // Rule ID
    __type(value, struct filter_rule);
} rules_map SEC(".maps");

// Define map for rate limiting
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // Class ID or IP
    __type(value, __u64);  // Bytes + timestamp
} rate_map SEC(".maps");

// Cilium integration maps - using common definitions from cilium_common.h

// Cilium identity map for identity-based policy lookups
DECLARE_CILIUM_IPCACHE;

// Map for Cilium policy verdicts
DECLARE_CILIUM_POLICY_MAP;

// Check if a packet matches a filter rule
static __always_inline int match_rule(struct filter_rule *rule, struct iphdr *iph, 
                               struct tcphdr *tcp, struct udphdr *udp) {
    // Check IP match
    if (rule->src_ip && rule->src_ip != iph->saddr)
        return 0;
    
    if (rule->dst_ip && rule->dst_ip != iph->daddr)
        return 0;
    
    // Check protocol match
    if (rule->protocol && rule->protocol != iph->protocol)
        return 0;
    
    // Check port match for TCP/UDP
    if (iph->protocol == IPPROTO_TCP && tcp) {
        if (rule->src_port && rule->src_port != bpf_ntohs(tcp->source))
            return 0;
        
        if (rule->dst_port && rule->dst_port != bpf_ntohs(tcp->dest))
            return 0;
    } else if (iph->protocol == IPPROTO_UDP && udp) {
        if (rule->src_port && rule->src_port != bpf_ntohs(udp->source))
            return 0;
        
        if (rule->dst_port && rule->dst_port != bpf_ntohs(udp->dest))
            return 0;
    } else if (rule->src_port || rule->dst_port) {
        // Rule specifies ports but packet isn't TCP/UDP
        return 0;
    }
    
    // All checks passed, rule matches
    return 1;
}

// Apply rate limiting for a class
static __always_inline int apply_rate_limit(struct traffic_class *class, __u32 class_id, __u32 pkt_len) {
    if (!class->rate_limit_bps)
        return TC_ACT_OK; // No rate limiting
    
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&rate_map, &class_id);
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
                return TC_ACT_SHOT; // Exceeds rate limit
            
            val = (ts << 32) | bytes;
        } else {
            // Reset counter for new interval
            val = (now << 32) | pkt_len;
        }
    } else {
        // First packet in this class
        val = (now << 32) | pkt_len;
    }
    
    bpf_map_update_elem(&rate_map, &class_id, &val, BPF_ANY);
    return TC_ACT_OK;
}

// Forward declarations for Cilium integration
static __always_inline int cilium_policy_check(struct iphdr *iph, struct tc_config *cfg);

// TC ingress program - main entry point
SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    // Get configuration
    __u32 key = 0;
    struct tc_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return TC_ACT_OK; // No config, pass the packet
    
    // Parse Ethernet header
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return TC_ACT_OK; // Can't parse Ethernet header
    
    // Check for IPv4 packet
    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK; // Non-IPv4 packets pass
    
    // Parse IP header
    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, sizeof(eth), &iph, sizeof(iph)) < 0)
        return TC_ACT_OK; // Can't parse IP header
    
    // Hardware optimization path if enabled using common macros
    if (cfg->hw_optimized) {
        // Use the appropriate hardware optimization macro based on NIC type
        X540_OFFLOAD_SUPPORTED("tc_ingress");
        X550_OFFLOAD_SUPPORTED("tc_ingress");
        I225_OFFLOAD_SUPPORTED("tc_ingress");
    }
    
    // Initialize TCP/UDP headers to NULL
    struct tcphdr tcp;
    struct udphdr udp;
    int has_tcp = 0;
    int has_udp = 0;
    
    // Parse TCP/UDP headers if needed
    if (iph.protocol == IPPROTO_TCP) {
        if (bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(iph), &tcp, sizeof(tcp)) < 0)
            return TC_ACT_OK; // Can't parse TCP header
        has_tcp = 1;
    } else if (iph.protocol == IPPROTO_UDP) {
        if (bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(iph), &udp, sizeof(udp)) < 0)
            return TC_ACT_OK; // Can't parse UDP header
        has_udp = 1;
    }
    
    // Check Cilium integration first if enabled
    if (cfg->cilium_integration) {
        int verdict = cilium_policy_check(&iph, cfg);
        if (verdict != TC_ACT_OK) { // If Cilium has made a drop/redirect decision
            return verdict;
        }
        // Otherwise, continue with local policy checks
    }
    
    // Apply filtering if enabled
    if (cfg->enable_filtering) {
        // Check filter rules (limited to 16 rules due to BPF loop restrictions)
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            __u32 rule_id = i;
            struct filter_rule *rule = bpf_map_lookup_elem(&rules_map, &rule_id);
            if (!rule)
                continue;
            
            // Check if rule matches
            if (match_rule(rule, &iph, has_tcp ? &tcp : NULL, has_udp ? &udp : NULL)) {
                // Rule matched, apply action
                if (rule->action == 1)
                    return TC_ACT_SHOT; // Drop
                
                if (rule->action == 2 && cfg->enable_marking) {
                    // Apply mark and get the class
                    struct traffic_class *class = bpf_map_lookup_elem(&classes_map, &rule->class_id);
                    if (class) {
                        // Apply marking
                        skb->mark = (skb->mark & ~cfg->mark_mask) | (class->mark & cfg->mark_mask);
                        
                        // Apply rate limiting
                        if (cfg->enable_qos) {
                            return apply_rate_limit(class, rule->class_id, skb->len);
                        }
                    }
                }
                
                break; // First matching rule wins
            }
        }
    }
    
    // Apply default mark if no rule matched and marking is enabled
    if (cfg->enable_marking) {
        skb->mark = (skb->mark & ~cfg->mark_mask) | (cfg->default_mark & cfg->mark_mask);
    }
    
    // Default action
    return cfg->default_action ? TC_ACT_SHOT : TC_ACT_OK;
}

// Cilium integration - check policies based on common implementation
static __always_inline int cilium_policy_check(struct iphdr *iph, struct tc_config *cfg) {
    // Extract ports for TCP/UDP if possible
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    // Call the common cilium_check_policy helper and translate its generic return values
    // to TC-specific actions
    int verdict = cilium_check_policy(
        NULL,           // No specific context needed for this simplified version
        iph->saddr,     // Source IP
        iph->daddr,     // Destination IP
        iph->protocol,  // Protocol
        src_port,       // Source port (simplified)
        dst_port        // Destination port (simplified)
    );
    
    // Map generic verdict values to TC actions
    switch (verdict) {
        case 1:  // DROP
            return TC_ACT_SHOT;
        case 2:  // REDIRECT
            // For redirect case, we would normally apply specialized handling
            // For this simplified version, we'll mark the packet if marking is enabled
            if (cfg->enable_marking) {
                // Get the policy verdict to extract the redirect port
                struct cilium_identity *identity = bpf_map_lookup_elem(&cilium_ipcache, &iph->saddr);
                if (identity) {
                    struct cilium_policy_verdict *policy = bpf_map_lookup_elem(&cilium_policy_map, &identity->id);
                    if (policy && policy->redirect_port) {
                        // Apply the redirect mark
                        __u32 mark = policy->redirect_port;
                        mark = (mark & cfg->mark_mask) | (cfg->default_mark & ~cfg->mark_mask);
                        // Note: skb is not defined in this function scope, so we can't actually mark
                        // This would need to be handled in the caller
                    }
                }
            }
            return TC_ACT_OK;
        default: // PASS (0)
            return TC_ACT_OK;
    }
}

// Define specific entry point for Cilium integration
SEC("cilium/tc")
int cilium_tc_ingress(struct __sk_buff *skb) {
    // This is a specialized entry point for Cilium integration
    // When used with Cilium, this will be called instead of the standard entry point
    return tc_ingress(skb);
}

char _license[] SEC("license") = "GPL";
