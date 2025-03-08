// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
// Compatible with Cilium Network Policies
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Include common Cilium definitions
#include "cilium_common.h"

// CGroup configuration structure
struct cgroup_config {
    __u8 enable_accounting;    // Enable resource accounting
    __u8 enable_egress_ctrl;   // Enable egress control
    __u8 enable_device_ctrl;   // Enable device control
    __u8 enable_container_pol; // Enable per-container policies
    __u8 default_action;       // Default action: 0 = allow, 1 = deny
    __u8 cilium_integration;   // Enable Cilium integration
    __u8 hw_offload;           // Enable hardware offload optimizations
    __u16 cilium_policy_index; // Reference to Cilium policy to apply
};

// Define map for configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cgroup_config);
} config_map SEC(".maps");

// Container policy structure
struct container_policy {
    __u32 cgroup_id;         // CGroup ID
    __u32 max_bandwidth;     // Maximum bandwidth in bytes/sec
    __u32 max_connections;   // Maximum number of connections
    __u8 action;             // Action: 0 = allow, 1 = deny
};

// Define map for container policies
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);       // CGroup ID
    __type(value, struct container_policy);
} cgroup_policies_map SEC(".maps");

// Resource usage structure
struct resource_usage {
    __u64 bytes_in;           // Bytes ingress
    __u64 bytes_out;          // Bytes egress
    __u32 conn_count;         // Connection count
    __u64 last_update;        // Last update timestamp
};

// Define map for resource accounting
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);       // CGroup ID
    __type(value, struct resource_usage);
} accounting_map SEC(".maps");

// CGroup allowed devices map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);      // Device ID (major:minor)
    __type(value, __u8);     // 1 = allowed
} allowed_devices_map SEC(".maps");

// Cilium identity map - used for identity-based filtering
// This map can be shared with Cilium to use its identity-based policies
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);             // IP address
    __type(value, struct cilium_identity);  // Cilium identity
} cilium_ipcache SEC(".maps");

// Cilium-specific cgroup policies that relate cgroups to identities
struct cilium_cgroup_policy {
    __u64 cgroup_id;         // CGroup ID to match
    __u32 identity;         // Cilium identity to assign/match
    __u8 direction;         // 0 = ingress, 1 = egress, 2 = both
    __u8 action;            // 0 = allow, 1 = deny
};

// Define map for Cilium cgroup policies
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);     // Policy index
    __type(value, struct cilium_cgroup_policy);
} cilium_cgroup_map SEC(".maps");

// CGroup resource accounting
static __always_inline int update_accounting(struct __sk_buff *skb, int egress) {
    __u64 cgroup_id = bpf_skb_cgroup_id(skb);
    if (!cgroup_id)
        return 1; // Allow if can't determine cgroup
    
    // Get or create resource usage entry
    struct resource_usage *usage = bpf_map_lookup_elem(&accounting_map, &cgroup_id);
    if (!usage) {
        struct resource_usage new_usage = {
            .bytes_in = 0,
            .bytes_out = 0,
            .conn_count = 0,
            .last_update = bpf_ktime_get_ns()
        };
        
        if (egress) {
            new_usage.bytes_out = skb->len;
        } else {
            new_usage.bytes_in = skb->len;
        }
        
        bpf_map_update_elem(&accounting_map, &cgroup_id, &new_usage, BPF_ANY);
    } else {
        // Update existing usage
        __u64 now = bpf_ktime_get_ns();
        usage->last_update = now;
        
        if (egress) {
            usage->bytes_out += skb->len;
        } else {
            usage->bytes_in += skb->len;
        }
        
        bpf_map_update_elem(&accounting_map, &cgroup_id, usage, BPF_ANY);
    }
    
    return 1; // Continue processing
}

// Check Cilium cgroup-identity mappings
static __always_inline int check_cilium_cgroup_policy(struct __sk_buff *skb, int egress, struct cgroup_config *cfg) {
    // Skip if Cilium integration is not enabled
    if (!cfg->cilium_integration || !cfg->cilium_policy_index) {
        return -1; // Not a match, continue with regular policy
    }
    
    // Get cgroup ID
    __u64 cgroup_id = bpf_skb_cgroup_id(skb);
    if (!cgroup_id) {
        return -1; // Can't determine cgroup
    }
    
    // Extract IP addresses for identity lookups
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    
    // Validate packet size
    if (data + sizeof(*eth) > data_end) {
        return -1; // Malformed packet
    }
    
    // Check if IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return -1; // Non-IP packet
    }
    
    // Parse IP header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return -1; // Malformed packet
    }
    
    // Look up policy by index
    __u32 policy_key = cfg->cilium_policy_index;
    struct cilium_cgroup_policy *policy = bpf_map_lookup_elem(&cilium_cgroup_map, &policy_key);
    
    if (policy && 
        (policy->cgroup_id == 0 || policy->cgroup_id == cgroup_id) && 
        (policy->direction == 2 || (egress && policy->direction == 1) || (!egress && policy->direction == 0))) {
        
        // Process source/destination based on traffic direction
        __u32 src_ip = egress ? iph->saddr : iph->daddr;
        __u32 dst_ip = egress ? iph->daddr : iph->saddr;
        
        // For egress traffic, record source identity based on cgroup
        if (egress && policy->identity > 0) {
            struct cilium_identity identity = {
                .id = policy->identity,
                .reserved = 0
            };
            bpf_map_update_elem(&cilium_ipcache, &iph->saddr, &identity, BPF_ANY);
            
            // After setting identity, we can use the common policy check
            // to determine if this traffic is allowed based on additional rules
            int common_verdict = cilium_check_policy(
                skb,           // Context
                src_ip,         // Source IP
                dst_ip,         // Destination IP
                iph->protocol,  // Protocol
                0,              // Source port (simplified)
                0               // Destination port (simplified)
            );
            
            // If common check returns DROP, override cgroup policy
            if (common_verdict == 1) { // DROP
                return 1; // Deny
            }
        }
        
        // Policy matched, return the action from cgroup policy
        return policy->action;
    }
    
    return -1; // No Cilium policy match
}

// Check if a connection is allowed based on container policy
static __always_inline int check_connection_policy(struct __sk_buff *skb) {
    __u64 cgroup_id = bpf_skb_cgroup_id(skb);
    if (!cgroup_id)
        return 1; // Allow if can't determine cgroup
    
    // Check for policy
    struct container_policy *policy = bpf_map_lookup_elem(&cgroup_policies_map, &cgroup_id);
    if (!policy)
        return 1; // No policy, allow
    
    // Check for connection limits
    if (policy->max_connections > 0) {
        struct resource_usage *usage = bpf_map_lookup_elem(&accounting_map, &cgroup_id);
        if (usage && usage->conn_count >= policy->max_connections) {
            return 0; // Deny, over connection limit
        }
    }
    
    // Check for bandwidth limits
    if (policy->max_bandwidth > 0) {
        struct resource_usage *usage = bpf_map_lookup_elem(&accounting_map, &cgroup_id);
        if (usage) {
            __u64 now = bpf_ktime_get_ns();
            __u64 elapsed_ns = now - usage->last_update;
            
            // Only check if at least 1 second has passed
            if (elapsed_ns > 1000000000) {
                __u64 bytes_per_sec = (usage->bytes_in + usage->bytes_out) * 1000000000 / elapsed_ns;
                if (bytes_per_sec > policy->max_bandwidth) {
                    return 0; // Deny, over bandwidth limit
                }
            }
        }
    }
    
    return policy->action == 0 ? 1 : 0; // Return based on policy action
}

// CGroup egress control - main entry point
SEC("cgroup_skb/egress")
int cgroup_egress(struct __sk_buff *skb) {
    // Get configuration
    __u32 key = 0;
    struct cgroup_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 1; // No config, allow packet
        
    // Hardware offload optimizations using common macros
    if (cfg->hw_offload) {
        // Use the appropriate hardware offload macro based on NIC type
        X540_OFFLOAD_SUPPORTED("cgroup");
        X550_OFFLOAD_SUPPORTED("cgroup");
        I225_OFFLOAD_SUPPORTED("cgroup");
    }
    
    // Update accounting if enabled
    if (cfg->enable_accounting) {
        update_accounting(skb, 1); // 1 = egress
    }
    
    // Check Cilium integration first
    if (cfg->cilium_integration) {
        int cilium_verdict = check_cilium_cgroup_policy(skb, 1, cfg); // 1 = egress
        if (cilium_verdict == 0) {
            return 1; // Allow
        } else if (cilium_verdict == 1) {
            return 0; // Deny
        }
        // Otherwise continue with regular policies
    }
    
    // Apply container policies if enabled
    if (cfg->enable_container_pol) {
        int action = check_connection_policy(skb);
        if (!action)
            return 0; // Deny
    }
    
    // Apply egress control if enabled
    if (cfg->enable_egress_ctrl) {
        // Parse Ethernet header
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;
        struct ethhdr *eth = data;
        
        // Check packet size
        if (data + sizeof(*eth) > data_end)
            return 1; // Allow malformed packet (let kernel handle it)
        
        // Check if IP packet
        if (eth->h_proto != bpf_htons(ETH_P_IP))
            return 1; // Non-IP packet, allow
        
        // Parse IP header
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return 1; // Allow malformed packet
        
        // Example: Block specific destination (e.g., block access to 1.2.3.4)
        if (iph->daddr == 0x04030201) // 1.2.3.4 in network byte order
            return 0; // Deny
    }
    
    // Default action
    return cfg->default_action ? 0 : 1; // 0 = deny, 1 = allow
}

// CGroup ingress control - main entry point
SEC("cgroup_skb/ingress")
int cgroup_ingress(struct __sk_buff *skb) {
    // Get configuration
    __u32 key = 0;
    struct cgroup_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 1; // No config, allow packet
        
    // Hardware offload optimizations for ingress
    if (cfg->hw_offload) {
        // Similar to egress, but tuned for ingress traffic on X540/X550/I225 NICs
        // - Hardware filtering of unwanted ingress traffic
        // - Accelerated packet inspection using NIC capabilities
        // - GRO and RSS optimization for improved performance
    }
    
    // Update accounting if enabled
    if (cfg->enable_accounting) {
        update_accounting(skb, 0); // 0 = ingress
    }
    
    // Check Cilium integration first
    if (cfg->cilium_integration) {
        int cilium_verdict = check_cilium_cgroup_policy(skb, 0, cfg); // 0 = ingress
        if (cilium_verdict == 0) {
            return 1; // Allow
        } else if (cilium_verdict == 1) {
            return 0; // Deny
        }
        // Otherwise continue with regular policies
    }
    
    // Apply container policies if enabled
    if (cfg->enable_container_pol) {
        int action = check_connection_policy(skb);
        if (!action)
            return 0; // Deny
    }
    
    // Default action
    return cfg->default_action ? 0 : 1; // 0 = deny, 1 = allow
}

// CGroup device control - main entry point
SEC("cgroup/dev")
int cgroup_device(struct bpf_cgroup_dev_ctx *ctx) {
    // Get configuration
    __u32 key = 0;
    struct cgroup_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 1; // No config, allow device
    
    // Apply device control if enabled
    if (cfg->enable_device_ctrl) {
        // Create device ID from major:minor
        __u64 device_id = ((__u64)ctx->major << 32) | ctx->minor;
        
        // Check if device is allowed
        __u8 *allowed = bpf_map_lookup_elem(&allowed_devices_map, &device_id);
        if (!allowed || *allowed != 1)
            return 0; // Deny if not explicitly allowed
    }
    
    // Default action
    return cfg->default_action ? 0 : 1; // 0 = deny, 1 = allow
}

// Define Cilium integration hooks for cgroup programs
SEC("cilium_cgroup/egress")
int cilium_cgroup_egress(struct __sk_buff *skb) {
    // This function would be called by Cilium's datapath when using integration
    return cgroup_egress(skb);
}

SEC("cilium_cgroup/ingress")
int cilium_cgroup_ingress(struct __sk_buff *skb) {
    // This function would be called by Cilium's datapath when using integration
    return cgroup_ingress(skb);
}

char _license[] SEC("license") = "GPL";
