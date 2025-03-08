// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// CGroup configuration structure
struct cgroup_config {
    __u8 enable_accounting;    // Enable resource accounting
    __u8 enable_egress_ctrl;   // Enable egress control
    __u8 enable_device_ctrl;   // Enable device control
    __u8 enable_container_pol; // Enable per-container policies
    __u8 default_action;       // Default action: 0 = allow, 1 = deny
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
    
    // Update accounting if enabled
    if (cfg->enable_accounting) {
        update_accounting(skb, 1); // 1 = egress
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
    
    // Update accounting if enabled
    if (cfg->enable_accounting) {
        update_accounting(skb, 0); // 0 = ingress
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

char _license[] SEC("license") = "GPL";
