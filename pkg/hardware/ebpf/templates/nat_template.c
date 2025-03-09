// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
// Compatible with Cilium Network Policies
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/pkt_cls.h>

// Include common definitions
#include "common.h"
#include "cilium_common.h"

// NAT Configuration structure
struct nat_config {
    union ip_addr external_ip;  // External IP address for SNAT/DNAT
    __u8 nat_type;              // 0 = SNAT, 1 = DNAT, 2 = Both
    __u8 enable_masquerade;     // Enable masquerading (use interface address)
    __u8 enable_portmap;        // Enable port mapping
    __u8 enable_tracking;       // Enable connection tracking
    __u8 default_action;        // Default action: 0 = pass, 1 = drop
    __u8 cilium_integration;    // Enable Cilium integration
    __u8 hw_offload;           // Enable hardware offload optimizations
    __u8 ip_version;           // IP version: 4 or 6
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
    union ip_addr internal_ip;  // Internal IP
    union ip_addr external_ip;  // External IP
    __u16 internal_port;       // Internal port
    __u16 external_port;       // External port
    __u8 protocol;             // Protocol
    __u8 ip_version;           // IP version: 4 or 6
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
    union ip_addr internal_ip;  // Internal IP
    __u16 internal_port;       // Internal port
    __u16 external_port;       // External port
    __u8 protocol;             // Protocol
    __u8 ip_version;           // IP version: 4 or 6
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
    union ip_addr nat_target_ip;  // NAT target IP (v4 or v6)
    __u16 nat_target_port;  // NAT target port
    __u8 protocol;          // Protocol
    __u8 ip_version;        // IP version: 4 or 6
};

// Define map for Cilium NAT policies
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);     // Policy index
    __type(value, struct cilium_nat_policy);
} cilium_nat_map SEC(".maps");

// Extract IP header information
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
            if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
                if (iph->protocol == IPPROTO_TCP) {
                    struct tcphdr *tcp = (struct tcphdr *)((void *)iph + sizeof(*iph));
                    if ((void *)(tcp + 1) > data_end)
                        return -1;
                    info->src_port = tcp->source;
                    info->dst_port = tcp->dest;
                } else {
                    struct udphdr *udp = (struct udphdr *)((void *)iph + sizeof(*iph));
                    if ((void *)(udp + 1) > data_end)
                        return -1;
                    info->src_port = udp->source;
                    info->dst_port = udp->dest;
                }
            }
            break;
        }
        case ETH_P_IPV6: {
            struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
            if ((void *)(ip6h + 1) > data_end)
                return -1;
            
            info->version = 6;
            info->protocol = ip6h->nexthdr;
            __builtin_memcpy(&info->src.v6, &ip6h->saddr, sizeof(struct in6_addr));
            __builtin_memcpy(&info->dst.v6, &ip6h->daddr, sizeof(struct in6_addr));
            
            // Extract ports for TCP/UDP
            if (ip6h->nexthdr == IPPROTO_TCP || ip6h->nexthdr == IPPROTO_UDP) {
                if (ip6h->nexthdr == IPPROTO_TCP) {
                    struct tcphdr *tcp = (struct tcphdr *)((void *)ip6h + sizeof(*ip6h));
                    if ((void *)(tcp + 1) > data_end)
                        return -1;
                    info->src_port = tcp->source;
                    info->dst_port = tcp->dest;
                } else {
                    struct udphdr *udp = (struct udphdr *)((void *)ip6h + sizeof(*ip6h));
                    if ((void *)(udp + 1) > data_end)
                        return -1;
                    info->src_port = udp->source;
                    info->dst_port = udp->dest;
                }
            }
            break;
        }
        default:
            return -1;
    }
    return 0;
}

// Helper function for checksum calculation
static __always_inline void update_checksum(struct __sk_buff *skb, __u16 old_val, __u16 new_val, __u16 checksum_offset) {
    bpf_l4_csum_replace(skb, checksum_offset, old_val, new_val, sizeof(new_val));
}

// Helper function for IPv6 checksum calculation
static __always_inline void update_ipv6_checksum(struct __sk_buff *skb, struct in6_addr *old_addr,
                                                struct in6_addr *new_addr, __u16 checksum_offset) {
    // Update checksum for each 16-bit segment of the IPv6 address
    for (int i = 0; i < 8; i++) {
        __u16 old_val = *((__u16 *)old_addr + i);
        __u16 new_val = *((__u16 *)new_addr + i);
        if (old_val != new_val) {
            bpf_l4_csum_replace(skb, checksum_offset, old_val, new_val, sizeof(new_val));
        }
    }
}

// Check Cilium identity-based NAT policies
static __always_inline int check_cilium_nat_policy(struct __sk_buff *skb, struct ip_info *info,
                                          struct nat_config *cfg) {
    // Skip if Cilium integration is not enabled
    if (!cfg->cilium_integration || !cfg->cilium_policy_index) {
        return 0; // Continue with regular NAT
    }
    
    // Use the common cilium_check_policy helper to determine if the connection is allowed
    int verdict;
    if (info->version == 4) {
        verdict = cilium_check_policy(
            skb,            // Context
            info->src.v4,    // Source IP
            info->dst.v4,    // Destination IP
            info->protocol,  // Protocol
            info->src_port,  // Source port
            info->dst_port   // Destination port
        );
    } else {
        // TODO: Update when Cilium adds native IPv6 policy check
        verdict = cilium_check_policy6(
            skb,                // Context
            &info->src.v6,      // Source IPv6
            &info->dst.v6,      // Destination IPv6
            info->protocol,     // Protocol
            info->src_port,     // Source port
            info->dst_port      // Destination port
        );
    }
    
    // If the policy check indicates DROP, don't perform NAT
    if (verdict == 1) { // DROP
        return -1; // Return -1 to indicate policy check failed, don't NAT
    }
    
    // For custom NAT rules based on Cilium identities, we still need some specialized logic
    __u32 policy_key = cfg->cilium_policy_index;
    struct cilium_nat_policy *policy = bpf_map_lookup_elem(&cilium_nat_map, &policy_key);
    
    if (policy) {
        // Skip if IP version doesn't match policy
        if (policy->ip_version != 0 && policy->ip_version != info->version)
            return 0;
        
        struct cilium_identity *src_identity, *dst_identity;
        if (info->version == 4) {
            src_identity = bpf_map_lookup_elem(&cilium_ipcache, &info->src.v4);
            dst_identity = bpf_map_lookup_elem(&cilium_ipcache, &info->dst.v4);
        } else {
            src_identity = bpf_map_lookup_elem(&cilium_ipcache6, &info->src.v6);
            dst_identity = bpf_map_lookup_elem(&cilium_ipcache6, &info->dst.v6);
        }
        
        if (src_identity && dst_identity && 
            (policy->from_identity == 0 || policy->from_identity == src_identity->id) &&
            (policy->to_identity == 0 || policy->to_identity == dst_identity->id) &&
            (policy->protocol == 0 || policy->protocol == info->protocol)) {
            
            // This connection matches the Cilium NAT policy
            return 1; // Indicates a Cilium policy match occurred
        }
    }
    
    return 0; // No Cilium policy match, use regular NAT
}

// Compare IPv6 addresses
static __always_inline int compare_ipv6(struct in6_addr *a, struct in6_addr *b) {
    return (a->s6_addr32[0] == b->s6_addr32[0] &&
            a->s6_addr32[1] == b->s6_addr32[1] &&
            a->s6_addr32[2] == b->s6_addr32[2] &&
            a->s6_addr32[3] == b->s6_addr32[3]);
}

// Helper function to calculate connection tuple hash for TCP/UDP
static __always_inline __u64 conn_hash(struct ip_info *info, int reverse) {
    __u64 addr_hash;
    if (info->version == 4) {
        if (reverse) {
            addr_hash = (((__u64)info->dst.v4 << 32) | ((__u64)info->src.v4));
        } else {
            addr_hash = (((__u64)info->src.v4 << 32) | ((__u64)info->dst.v4));
        }
    } else {
        // For IPv6, use all 4 32-bit segments
        if (reverse) {
            addr_hash = ((__u64)info->dst.v6.s6_addr32[0] << 32 | (__u64)info->dst.v6.s6_addr32[1]) ^
                        ((__u64)info->dst.v6.s6_addr32[2] << 32 | (__u64)info->dst.v6.s6_addr32[3]) ^
                        ((__u64)info->src.v6.s6_addr32[0] << 32 | (__u64)info->src.v6.s6_addr32[1]) ^
                        ((__u64)info->src.v6.s6_addr32[2] << 32 | (__u64)info->src.v6.s6_addr32[3]);
        } else {
            addr_hash = ((__u64)info->src.v6.s6_addr32[0] << 32 | (__u64)info->src.v6.s6_addr32[1]) ^
                        ((__u64)info->src.v6.s6_addr32[2] << 32 | (__u64)info->src.v6.s6_addr32[3]) ^
                        ((__u64)info->dst.v6.s6_addr32[0] << 32 | (__u64)info->dst.v6.s6_addr32[1]) ^
                        ((__u64)info->dst.v6.s6_addr32[2] << 32 | (__u64)info->dst.v6.s6_addr32[3]);
        }
    }
    
    // Add ports and protocol to hash
    if (reverse) {
        return addr_hash ^ (((__u64)info->dst_port << 32) | ((__u64)info->src_port)) ^
               ((__u64)info->protocol << 56);
    } else {
        return addr_hash ^ (((__u64)info->src_port << 32) | ((__u64)info->dst_port)) ^
               ((__u64)info->protocol << 56);
    }
}

// Helper function to calculate connection tuple hash for ICMP/ICMPv6
static __always_inline __u64 icmp_hash(struct ip_info *info, __u16 id, int reverse) {
    __u64 addr_hash;
    if (info->version == 4) {
        if (reverse) {
            addr_hash = (((__u64)info->dst.v4 << 32) | ((__u64)info->src.v4));
        } else {
            addr_hash = (((__u64)info->src.v4 << 32) | ((__u64)info->dst.v4));
        }
    } else {
        // For IPv6, use all 4 32-bit segments
        if (reverse) {
            addr_hash = ((__u64)info->dst.v6.s6_addr32[0] << 32 | (__u64)info->dst.v6.s6_addr32[1]) ^
                        ((__u64)info->dst.v6.s6_addr32[2] << 32 | (__u64)info->dst.v6.s6_addr32[3]) ^
                        ((__u64)info->src.v6.s6_addr32[0] << 32 | (__u64)info->src.v6.s6_addr32[1]) ^
                        ((__u64)info->src.v6.s6_addr32[2] << 32 | (__u64)info->src.v6.s6_addr32[3]);
        } else {
            addr_hash = ((__u64)info->src.v6.s6_addr32[0] << 32 | (__u64)info->src.v6.s6_addr32[1]) ^
                        ((__u64)info->src.v6.s6_addr32[2] << 32 | (__u64)info->src.v6.s6_addr32[3]) ^
                        ((__u64)info->dst.v6.s6_addr32[0] << 32 | (__u64)info->dst.v6.s6_addr32[1]) ^
                        ((__u64)info->dst.v6.s6_addr32[2] << 32 | (__u64)info->dst.v6.s6_addr32[3]);
        }
    }
    
    return addr_hash ^ ((__u64)id << 32) ^ ((__u64)info->protocol << 56);
}

// SNAT for TCP/UDP/ICMP
static __always_inline int do_snat(struct __sk_buff *skb, struct ip_info *info, __u16 l4_off, __u16 csum_off, struct nat_config *cfg) {
    // Create hash for the connection
    __u64 hash = conn_hash(info, 0);
    
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
        
        // Apply existing translation
        if (info->version == 4) {
            // Update IPv4 source address
            bpf_l3_csum_replace(skb, l4_off - 8, info->src.v4, entry->external_ip.v4, 4);
            info->src.v4 = entry->external_ip.v4;
        } else {
            // Update IPv6 source address
            update_ipv6_checksum(skb, &info->src.v6, &entry->external_ip.v6, csum_off);
            __builtin_memcpy(&info->src.v6, &entry->external_ip.v6, sizeof(struct in6_addr));
        }
        
        // Update source port if needed
        if (info->protocol == IPPROTO_TCP || info->protocol == IPPROTO_UDP) {
            if (info->src_port != entry->external_port) {
                update_checksum(skb, info->src_port, entry->external_port, csum_off);
                info->src_port = entry->external_port;
            }
        }
        
        return 0;
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
    
    // Extract IP information using our generic parser
    struct ip_info info = {};
    if (extract_ip_info(skb, &info) < 0)
        return TC_ACT_OK; // Can't parse packet
    
    // Skip if IP version doesn't match configuration
    if (cfg->ip_version != 0 && cfg->ip_version != info.version)
        return TC_ACT_OK;
    
    // Calculate L4 header offset based on IP version
    __u16 l4_offset = sizeof(struct ethhdr);
    l4_offset += (info.version == 4) ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
    __u16 csum_offset = 0;
    
    // Handle TCP/UDP packets
    if (info.protocol == IPPROTO_TCP || info.protocol == IPPROTO_UDP) {
        // Set checksum offset based on protocol
        if (info.protocol == IPPROTO_TCP) {
            csum_offset = l4_offset + offsetof(struct tcphdr, check);
        } else {
            csum_offset = l4_offset + offsetof(struct udphdr, check);
        }
        
        // Check Cilium policies if enabled
        if (cfg->cilium_integration) {
            // TODO: Update Cilium policy check for IPv6
            if (info.version == 4) {
                int verdict = check_cilium_nat_policy(skb, (struct iphdr *)((void *)(long)skb->data + sizeof(struct ethhdr)),
                                                    info.src_port, info.dst_port, cfg);
                if (verdict < 0)
                    return TC_ACT_SHOT; // Drop packet based on policy
            }
        }
        
        // Perform NAT based on direction
        if (cfg->nat_type == 0 || cfg->nat_type == 2) { // SNAT or Both
            if (do_snat(skb, &info, l4_offset, csum_offset, cfg) < 0)
                return TC_ACT_SHOT;
        }
        if (cfg->nat_type == 1 || cfg->nat_type == 2) { // DNAT or Both
            if (do_dnat(skb, &info, l4_offset, csum_offset, cfg) < 0)
                return TC_ACT_SHOT;
        }
    }
    // Handle ICMP/ICMPv6 packets
    else if ((info.version == 4 && info.protocol == IPPROTO_ICMP) ||
             (info.version == 6 && info.protocol == IPPROTO_ICMPV6)) {
        __u16 icmp_id;
        __u8 icmp_type;
        
        // Parse ICMP/ICMPv6 header
        if (info.version == 4) {
            struct icmphdr icmp;
            if (bpf_skb_load_bytes(skb, l4_offset, &icmp, sizeof(icmp)) < 0)
                return TC_ACT_OK;
            
            // Only handle Echo and Reply types
            if (icmp.type != ICMP_ECHO && icmp.type != ICMP_ECHOREPLY)
                return TC_ACT_OK;
            
            icmp_id = icmp.un.echo.id;
            icmp_type = icmp.type;
        } else {
            struct icmp6hdr icmp6;
            if (bpf_skb_load_bytes(skb, l4_offset, &icmp6, sizeof(icmp6)) < 0)
                return TC_ACT_OK;
            
            // Only handle Echo and Reply types
            if (icmp6.icmp6_type != ICMPV6_ECHO_REQUEST && icmp6.icmp6_type != ICMPV6_ECHO_REPLY)
                return TC_ACT_OK;
            
            icmp_id = icmp6.icmp6_dataun.u_echo.identifier;
            icmp_type = icmp6.icmp6_type;
        }
        
        // Handle ICMP NAT based on direction
        __u64 hash = icmp_hash(&info, icmp_id, 0);
        
        if ((info.version == 4 && icmp_type == ICMP_ECHO) ||
            (info.version == 6 && icmp_type == ICMPV6_ECHO_REQUEST)) {
            // SNAT for outgoing ICMP Echo
            if (cfg->nat_type == 0 || cfg->nat_type == 2) {
                if (do_snat(skb, &info, l4_offset, l4_offset + offsetof(struct icmphdr, checksum), cfg) < 0)
                    return TC_ACT_SHOT;
            }
        } else {
            // DNAT for incoming ICMP Echo Reply
            if (cfg->nat_type == 1 || cfg->nat_type == 2) {
                if (do_dnat(skb, &info, l4_offset, l4_offset + offsetof(struct icmphdr, checksum), cfg) < 0)
                    return TC_ACT_SHOT;
            }
        }
    }
    
    // Default action
    return cfg->default_action ? TC_ACT_SHOT : TC_ACT_OK;
}

// Define Cilium tail call programs to enable integration with Cilium's datapath
SEC("cilium_nat")
int cilium_nat(struct __sk_buff *skb) {
    // Extract IP information
    struct ip_info info = {};
    if (extract_ip_info(skb, &info) < 0)
        return TC_ACT_OK; // Can't parse packet
    
    // Get configuration
    __u32 key = 0;
    struct nat_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return TC_ACT_OK; // No config, pass the packet
    
    // Check Cilium policies
    if (cfg->cilium_integration) {
        int verdict = check_cilium_nat_policy(skb, &info, cfg);
        if (verdict < 0)
            return TC_ACT_SHOT; // Drop packet based on policy
        
        // If policy matched, apply NAT based on direction
        if (verdict == 1) {
            __u16 l4_offset = sizeof(struct ethhdr);
            l4_offset += (info.version == 4) ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
            __u16 csum_offset = 0;
            
            if (info.protocol == IPPROTO_TCP) {
                csum_offset = l4_offset + offsetof(struct tcphdr, check);
            } else if (info.protocol == IPPROTO_UDP) {
                csum_offset = l4_offset + offsetof(struct udphdr, check);
            }
            
            // Apply NAT based on policy direction
            if (cfg->nat_type == 0 || cfg->nat_type == 2) { // SNAT or Both
                if (do_snat(skb, &info, l4_offset, csum_offset, cfg) < 0)
                    return TC_ACT_SHOT;
            }
            if (cfg->nat_type == 1 || cfg->nat_type == 2) { // DNAT or Both
                if (do_dnat(skb, &info, l4_offset, csum_offset, cfg) < 0)
                    return TC_ACT_SHOT;
            }
        }
    }
    
    // Pass packet to regular NAT handler
    return tc_nat(skb);
}

// Define IPv6-specific Cilium tail call
SEC("cilium_nat6")
int cilium_nat6(struct __sk_buff *skb) {
    return cilium_nat(skb); // Use the same handler for both IPv4 and IPv6
}

char _license[] SEC("license") = "GPL";
