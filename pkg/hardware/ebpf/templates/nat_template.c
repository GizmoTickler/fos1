// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
// Compatible with Cilium Network Policies
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Include common Cilium definitions
#include "cilium_common.h"

// NAT Configuration structure
struct nat_config {
    __u32 external_ip;     // External IP address for SNAT/DNAT
    __u8 nat_type;         // 0 = SNAT, 1 = DNAT, 2 = Both
    __u8 enable_masquerade; // Enable masquerading (use interface address)
    __u8 enable_portmap;   // Enable port mapping
    __u8 enable_tracking;  // Enable connection tracking
    __u8 default_action;   // Default action: 0 = pass, 1 = drop
    __u8 cilium_integration; // Enable Cilium integration
    __u8 hw_offload;        // Enable hardware offload optimizations
    __u16 cilium_policy_index; // Reference to Cilium policy to apply
};

// Define map for configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct nat_config);
} config_map SEC(".maps");

// NAT Translation Entry structure
struct nat_entry {
    __u32 internal_ip;     // Internal IP
    __u32 external_ip;     // External IP
    __u16 internal_port;   // Internal port
    __u16 external_port;   // External port
    __u8 protocol;         // Protocol
};

// Define map for NAT translation entries
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);     // Connection tuple hash
    __type(value, struct nat_entry);
} translations_map SEC(".maps");

// Port Mapping Entry structure
struct port_mapping {
    __u32 internal_ip;     // Internal IP
    __u16 internal_port;   // Internal port
    __u16 external_port;   // External port
    __u8 protocol;         // Protocol
};

// Define map for port mappings
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);     // External port + protocol
    __type(value, struct port_mapping);
} portmap_map SEC(".maps");

// Connection tracking is available in cilium_common.h as cilium_ct_entry
// but we use a simpler version here for NAT-specific tracking
struct conn_track {
    __u64 last_seen;       // Timestamp
    __u8 state;            // Connection state
};

// Define map for connection tracking
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);     // Connection tuple hash
    __type(value, struct conn_track);
} conntrack_map SEC(".maps");

// Cilium identity map - using common definition
DECLARE_CILIUM_IPCACHE;

// Cilium to local NAT policy for service redirection
struct cilium_nat_policy {
    __u32 from_identity;    // Source identity
    __u32 to_identity;      // Destination identity
    __u32 nat_target_ip;    // NAT target IP
    __u16 nat_target_port;  // NAT target port
    __u8 protocol;          // Protocol
};

// Define map for Cilium NAT policies
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);     // Policy index
    __type(value, struct cilium_nat_policy);
} cilium_nat_map SEC(".maps");

// Helper function for checksum calculation
static __always_inline void update_checksum(struct __sk_buff *skb, __u16 old_val, __u16 new_val, __u16 checksum_offset) {
    bpf_l4_csum_replace(skb, checksum_offset, old_val, new_val, sizeof(new_val));
}

// Check Cilium identity-based NAT policies
static __always_inline int check_cilium_nat_policy(struct __sk_buff *skb, struct iphdr *iph, 
                                          __u16 src_port, __u16 dst_port,
                                          struct nat_config *cfg) {
    // Skip if Cilium integration is not enabled
    if (!cfg->cilium_integration || !cfg->cilium_policy_index) {
        return 0; // Continue with regular NAT
    }
    
    // Use the common cilium_check_policy helper to determine if the connection is allowed
    int verdict = cilium_check_policy(
        skb,            // Context
        iph->saddr,      // Source IP
        iph->daddr,      // Destination IP
        iph->protocol,   // Protocol
        src_port,        // Source port
        dst_port         // Destination port
    );
    
    // If the policy check indicates DROP, don't perform NAT
    if (verdict == 1) { // DROP
        return -1; // Return -1 to indicate policy check failed, don't NAT
    }
    
    // For custom NAT rules based on Cilium identities, we still need some specialized logic
    __u32 policy_key = cfg->cilium_policy_index;
    struct cilium_nat_policy *policy = bpf_map_lookup_elem(&cilium_nat_map, &policy_key);
    
    if (policy) {
        struct cilium_identity *src_identity = bpf_map_lookup_elem(&cilium_ipcache, &iph->saddr);
        struct cilium_identity *dst_identity = bpf_map_lookup_elem(&cilium_ipcache, &iph->daddr);
        
        if (src_identity && dst_identity && 
            (policy->from_identity == 0 || policy->from_identity == src_identity->id) &&
            (policy->to_identity == 0 || policy->to_identity == dst_identity->id) &&
            (policy->protocol == 0 || policy->protocol == iph->protocol)) {
            
            // This connection matches the Cilium NAT policy
            return 1; // Indicates a Cilium policy match occurred
        }
    }
    
    return 0; // No Cilium policy match, use regular NAT
}

// Helper function to calculate connection tuple hash for TCP/UDP
static __always_inline __u64 conn_hash(struct iphdr *iph, __u16 src_port, __u16 dst_port, int reverse) {
    if (reverse) {
        return (((__u64)iph->daddr << 32) | ((__u64)iph->saddr)) ^
               (((__u64)dst_port << 32) | ((__u64)src_port)) ^
               ((__u64)iph->protocol << 56);
    } else {
        return (((__u64)iph->saddr << 32) | ((__u64)iph->daddr)) ^
               (((__u64)src_port << 32) | ((__u64)dst_port)) ^
               ((__u64)iph->protocol << 56);
    }
}

// Helper function to calculate connection tuple hash for ICMP
static __always_inline __u64 icmp_hash(struct iphdr *iph, __u16 id, int reverse) {
    if (reverse) {
        return (((__u64)iph->daddr << 32) | ((__u64)iph->saddr)) ^
               ((__u64)id << 32) ^
               ((__u64)iph->protocol << 56);
    } else {
        return (((__u64)iph->saddr << 32) | ((__u64)iph->daddr)) ^
               ((__u64)id << 32) ^
               ((__u64)iph->protocol << 56);
    }
}

// SNAT for TCP/UDP
static __always_inline int do_snat(struct __sk_buff *skb, struct iphdr *iph, __u16 *src_port, __u16 *dst_port,
                           __u16 l4_off, __u16 csum_off, struct nat_config *cfg) {
    // Create hash for the connection
    __u64 hash = conn_hash(iph, *src_port, *dst_port, 0);
    
    // Check if this is an established connection
    struct nat_entry *entry = bpf_map_lookup_elem(&translations_map, &hash);
    if (entry) {
        // Update timestamps if connection tracking is enabled
        if (cfg->enable_tracking) {
            struct conn_track track = {
                .last_seen = bpf_ktime_get_ns(),
                .state = 1 // Established
            };
            bpf_map_update_elem(&conntrack_map, &hash, &track, BPF_ANY);
        }
    } else {
        // New connection, create NAT entry
        struct nat_entry new_entry = {
            .internal_ip = iph->saddr,
            .external_ip = cfg->external_ip,
            .internal_port = *src_port,
            .external_port = *src_port, // Use same port by default
            .protocol = iph->protocol
        };
        
        // For masquerading, external IP is dynamically assigned
        if (cfg->enable_masquerade) {
            // In a real implementation, we would get the interface's IP
            // For now, just use the configured external IP
            new_entry.external_ip = cfg->external_ip;
        }
        
        // Create a new translation entry
        bpf_map_update_elem(&translations_map, &hash, &new_entry, BPF_ANY);
        
        // Create reverse mapping for incoming packets
        __u64 rev_hash = conn_hash(iph, *src_port, *dst_port, 1);
        bpf_map_update_elem(&translations_map, &rev_hash, &new_entry, BPF_ANY);
        
        // Update connection tracking if enabled
        if (cfg->enable_tracking) {
            struct conn_track track = {
                .last_seen = bpf_ktime_get_ns(),
                .state = 1 // Established
            };
            bpf_map_update_elem(&conntrack_map, &hash, &track, BPF_ANY);
        }
        
        entry = &new_entry;
    }
    
    // Apply SNAT - change source IP and port if needed
    __u32 old_addr = iph->saddr;
    iph->saddr = entry->external_ip;
    bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_addr, entry->external_ip, 4);
    
    // Replace source port if needed
    if (*src_port != entry->external_port) {
        update_checksum(skb, *src_port, entry->external_port, csum_off);
        bpf_skb_store_bytes(skb, l4_off, &entry->external_port, 2, 0);
    }
    
    return TC_ACT_OK;
}

// DNAT for TCP/UDP
static __always_inline int do_dnat(struct __sk_buff *skb, struct iphdr *iph, __u16 *src_port, __u16 *dst_port,
                           __u16 l4_off, __u16 csum_off, struct nat_config *cfg) {
    // Check port mapping
    if (cfg->enable_portmap) {
        // Create portmap key: the destination port and protocol
        __u32 portmap_key = ((__u32)*dst_port << 8) | iph->protocol;
        struct port_mapping *port_map = bpf_map_lookup_elem(&portmap_map, &portmap_key);
        
        if (port_map) {
            // Found a port mapping, apply DNAT
            __u32 old_addr = iph->daddr;
            iph->daddr = port_map->internal_ip;
            bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_addr, port_map->internal_ip, 4);
            
            // Replace destination port if needed
            if (*dst_port != port_map->internal_port) {
                update_checksum(skb, *dst_port, port_map->internal_port, csum_off);
                bpf_skb_store_bytes(skb, l4_off + 2, &port_map->internal_port, 2, 0);
            }
            
            // Create translation entry if tracking is enabled
            if (cfg->enable_tracking) {
                // Create hash for the connection
                __u64 hash = conn_hash(iph, *src_port, *dst_port, 0);
                
                struct nat_entry entry = {
                    .internal_ip = port_map->internal_ip,
                    .external_ip = iph->daddr,
                    .internal_port = port_map->internal_port,
                    .external_port = *dst_port,
                    .protocol = iph->protocol
                };
                
                // Create a new translation entry
                bpf_map_update_elem(&translations_map, &hash, &entry, BPF_ANY);
                
                // Create connection tracking entry
                struct conn_track track = {
                    .last_seen = bpf_ktime_get_ns(),
                    .state = 1 // Established
                };
                bpf_map_update_elem(&conntrack_map, &hash, &track, BPF_ANY);
            }
            
            return TC_ACT_OK;
        }
    }
    
    // Look for an existing translation
    __u64 hash = conn_hash(iph, *src_port, *dst_port, 0);
    struct nat_entry *entry = bpf_map_lookup_elem(&translations_map, &hash);
    
    if (entry) {
        // Apply existing DNAT translation
        __u32 old_addr = iph->daddr;
        iph->daddr = entry->internal_ip;
        bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_addr, entry->internal_ip, 4);
        
        // Replace destination port if needed
        if (*dst_port != entry->internal_port) {
            update_checksum(skb, *dst_port, entry->internal_port, csum_off);
            bpf_skb_store_bytes(skb, l4_off + 2, &entry->internal_port, 2, 0);
        }
        
        // Update connection tracking if enabled
        if (cfg->enable_tracking) {
            struct conn_track track = {
                .last_seen = bpf_ktime_get_ns(),
                .state = 1 // Established
            };
            bpf_map_update_elem(&conntrack_map, &hash, &track, BPF_ANY);
        }
        
        return TC_ACT_OK;
    }
    
    return TC_ACT_OK;
}

// TC program for NAT - main entry point
SEC("tc")
int tc_nat(struct __sk_buff *skb) {
    // Get configuration
    __u32 key = 0;
    struct nat_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return TC_ACT_OK; // No config, pass the packet
        
    // Hardware offload optimizations using common macros
    if (cfg->hw_offload) {
        // Use the appropriate hardware offload macro based on NIC type
        X540_OFFLOAD_SUPPORTED("nat");
        X550_OFFLOAD_SUPPORTED("nat");
        I225_OFFLOAD_SUPPORTED("nat");
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
    
    // Calculate IP header length
    __u32 ip_header_size = iph.ihl << 2;
    __u16 l4_offset = sizeof(eth) + ip_header_size;
    
    // Handle TCP
    if (iph.protocol == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
            return TC_ACT_OK; // Can't parse TCP header
        
        __u16 src_port = tcp.source;
        __u16 dst_port = tcp.dest;
        __u16 csum_offset = l4_offset + offsetof(struct tcphdr, check);
        
        // Perform SNAT or DNAT based on configuration
        if (cfg->nat_type == 0 || cfg->nat_type == 2) {
            // SNAT for outgoing packets (internal -> external)
            return do_snat(skb, &iph, &src_port, &dst_port, l4_offset, csum_offset, cfg);
        } else if (cfg->nat_type == 1 || cfg->nat_type == 2) {
            // DNAT for incoming packets (external -> internal)
            return do_dnat(skb, &iph, &src_port, &dst_port, l4_offset, csum_offset, cfg);
        }
    }
    // Handle UDP
    else if (iph.protocol == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) < 0)
            return TC_ACT_OK; // Can't parse UDP header
        
        __u16 src_port = udp.source;
        __u16 dst_port = udp.dest;
        __u16 csum_offset = l4_offset + offsetof(struct udphdr, check);
        
        // Perform SNAT or DNAT based on configuration
        if (cfg->nat_type == 0 || cfg->nat_type == 2) {
            // SNAT for outgoing packets (internal -> external)
            return do_snat(skb, &iph, &src_port, &dst_port, l4_offset, csum_offset, cfg);
        } else if (cfg->nat_type == 1 || cfg->nat_type == 2) {
            // DNAT for incoming packets (external -> internal)
            return do_dnat(skb, &iph, &src_port, &dst_port, l4_offset, csum_offset, cfg);
        }
    }
    // Handle ICMP
    else if (iph.protocol == IPPROTO_ICMP) {
        // For ICMP, NAT implementations would handle special cases for ICMP errors
        // This is a simplified implementation focusing on ICMP Echo/Reply
        struct icmphdr icmp;
        if (bpf_skb_load_bytes(skb, l4_offset, &icmp, sizeof(icmp)) < 0)
            return TC_ACT_OK; // Can't parse ICMP header
        
        // Only handle Echo and Reply types
        if (icmp.type != ICMP_ECHO && icmp.type != ICMP_ECHOREPLY)
            return TC_ACT_OK;
        
        // Use identifier as a port equivalent
        __u16 id = icmp.un.echo.id;
        __u64 hash;
        
        if (icmp.type == ICMP_ECHO && (cfg->nat_type == 0 || cfg->nat_type == 2)) {
            // SNAT for outgoing ICMP Echo
            hash = icmp_hash(&iph, id, 0);
            
            // Check if this is an established connection
            struct nat_entry *entry = bpf_map_lookup_elem(&translations_map, &hash);
            if (!entry) {
                // New connection, create NAT entry
                struct nat_entry new_entry = {
                    .internal_ip = iph->saddr,
                    .external_ip = cfg->external_ip,
                    .internal_port = id,
                    .external_port = id,
                    .protocol = iph->protocol
                };
                
                // Create a new translation entry
                bpf_map_update_elem(&translations_map, &hash, &new_entry, BPF_ANY);
                
                // Create reverse mapping for incoming packets
                __u64 rev_hash = icmp_hash(&iph, id, 1);
                bpf_map_update_elem(&translations_map, &rev_hash, &new_entry, BPF_ANY);
                
                entry = &new_entry;
            }
            
            // Apply SNAT - change source IP
            __u32 old_addr = iph->saddr;
            iph->saddr = entry->external_ip;
            bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_addr, entry->external_ip, 4);
            
            // Update ICMP checksum
            bpf_l4_csum_replace(skb, l4_offset + offsetof(struct icmphdr, checksum), 0, 0, BPF_F_MARK_MANGLED_0);
        }
        else if (icmp.type == ICMP_ECHOREPLY && (cfg->nat_type == 1 || cfg->nat_type == 2)) {
            // DNAT for incoming ICMP Echo Reply
            hash = icmp_hash(&iph, id, 0);
            
            // Look for an existing translation
            struct nat_entry *entry = bpf_map_lookup_elem(&translations_map, &hash);
            if (entry) {
                // Apply existing DNAT translation
                __u32 old_addr = iph->daddr;
                iph->daddr = entry->internal_ip;
                bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_addr, entry->internal_ip, 4);
                
                // Update ICMP checksum
                bpf_l4_csum_replace(skb, l4_offset + offsetof(struct icmphdr, checksum), 0, 0, BPF_F_MARK_MANGLED_0);
            }
        }
    }
    
    // Default action
    return cfg->default_action ? TC_ACT_SHOT : TC_ACT_OK;
}

// Define Cilium tail call program to enable integration with Cilium's datapath
SEC("cilium_nat")
int cilium_nat(struct __sk_buff *skb) {
    // This function would be called by Cilium's datapath when using integration
    // In a real implementation, this would likely call a Cilium function or tail call
    // For now, we just pass packets to our own NAT handler
    return tc_nat(skb);
}

char _license[] SEC("license") = "GPL";
