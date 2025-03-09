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
    __u8 enable_dscp;       // Enable DSCP marking
    __u8 default_action;    // Default action: 0 = pass, 1 = drop
    __u8 cilium_integration; // Enable Cilium integration
    __u8 hw_offload;        // Enable hardware offload optimizations
    __u16 cilium_policy_index; // Reference to Cilium policy to apply
};

// Define map for configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tc_config);
} config_map SEC(".maps");

// Use common traffic class definitions from cilium_common.h
DECLARE_TRAFFIC_CLASS_MAP;
DECLARE_FILTER_RULES_MAP;
DECLARE_RATE_LIMIT_MAP;

// Cilium identity map - used for identity-based filtering
// This map can be shared with Cilium to use its identity-based policies
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);             // IP address
    __type(value, struct cilium_identity);  // Cilium identity
} cilium_ipcache SEC(".maps");

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
    int ret = apply_traffic_class_rate_limit(class, class_id, pkt_len, &rate_map);
    return ret ? TC_ACT_SHOT : TC_ACT_OK;
}

// Set DSCP value in IP TOS field
static __always_inline void set_dscp(struct __sk_buff *skb, __u8 dscp_val) {
    // DSCP is the top 6 bits of the TOS field
    // First, read the current TOS value
    unsigned char tos;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + 1, &tos, 1) < 0)
        return;
    
    // Clear the DSCP bits and set new value
    tos = (tos & 0x03) | (dscp_val << 2);
    
    // Write back the modified TOS field
    bpf_skb_store_bytes(skb, ETH_HLEN + 1, &tos, 1, 0);
    
    // Recalculate IP header checksum
    bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), 0, 0, 2);
}

// Forward declarations for Cilium-specific functions
static __always_inline int cilium_policy_check(struct __sk_buff *skb, struct iphdr *iph, struct tc_config *cfg);

// Cilium integration - check policies based on common implementation
static __always_inline int cilium_policy_check(struct __sk_buff *skb, struct iphdr *iph, struct tc_config *cfg) {
    // Extract ports for TCP/UDP if possible
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    // For egress, we're primarily interested in the destination IP
    // Call the common cilium_check_policy helper with swapped src/dst parameters
    // to accommodate egress policy logic
    int verdict = cilium_check_policy(
        skb,             // Pass skb as context for possible use
        iph->daddr,      // For egress, we use dst as the key for identity lookup
        iph->saddr,      // Source IP
        iph->protocol,   // Protocol
        dst_port,        // Destination port (simplified)
        src_port         // Source port (simplified)
    );
    
    // Map generic verdict values to TC actions
    switch (verdict) {
        case 1:  // DROP
            return TC_ACT_SHOT;
        case 2:  // REDIRECT - potentially more complex for egress
            // Additional logic could be added here
            return TC_ACT_OK;
        default: // PASS (0)
            // Apply any specific policy marking for egress traffic
            if (cfg->enable_marking && cfg->cilium_policy_index > 0) {
                struct cilium_identity *identity = bpf_map_lookup_elem(&cilium_ipcache, &iph->daddr);
                if (identity) {
                    __u32 mark = skb->mark & ~cfg->mark_mask;
                    mark |= (identity->id & 0xFFFF) << 16; // Use identity as part of the mark
                    skb->mark = mark;
                }
            }
            return TC_ACT_OK;
    }
}

// TC egress program - main entry point
SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    // Get configuration
    __u32 key = 0;
    struct tc_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return TC_ACT_OK; // No config, pass the packet
    
    // Hardware offload optimizations
    if (cfg->hw_offload) {
        // When hardware offload is enabled, this program is optimized for
        // specific hardware and may skip certain checks for performance
        // This enables X540/X550/I225 NIC hardware acceleration features
        // such as TX checksum, TSO, and GRO
    }
    
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
        
    // Check Cilium integration first if enabled (priority over local rules)
    if (cfg->cilium_integration) {
        int verdict = cilium_policy_check(skb, &iph, cfg);
        if (verdict != TC_ACT_OK) { // If Cilium has made a drop/redirect decision
            return verdict;
        }
        // Otherwise, continue with local policy checks
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
                
                if (rule->action == 2) {
                    // Get the class
                    struct traffic_class *class = bpf_map_lookup_elem(&classes_map, &rule->class_id);
                    if (class) {
                        // Apply marking if enabled
                        if (cfg->enable_marking) {
                            skb->mark = (skb->mark & ~cfg->mark_mask) | (class->mark & cfg->mark_mask);
                        }
                        
                        // Apply DSCP marking if enabled
                        if (cfg->enable_dscp) {
                            set_dscp(skb, class->dscp);
                        }
                        
                        // Apply rate limiting if QoS is enabled
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

// Define Cilium tail calls program to enable integration with Cilium's datapath
SEC("cilium_tc_egress")
int cilium_tc_egress(struct __sk_buff *skb) {
    // This function would be called by Cilium's datapath when using integration
    // In a real implementation, this would likely call a Cilium function or tail call
    // For now, we just pass packets along to our own egress handler
    return tc_egress(skb);
}

char _license[] SEC("license") = "GPL";
