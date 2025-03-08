// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
// Compatible with Cilium Network Policies
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Include common Cilium definitions
#include "cilium_common.h"

// Socket operations configuration structure
struct sockops_config {
    __u8 enable_monitoring;   // Enable socket monitoring
    __u8 enable_redirection;  // Enable socket redirection
    __u8 enable_tracing;      // Enable socket tracing
    __u8 enable_app_gateway;  // Enable application-layer gateway
    __u8 default_action;      // Default action: 0 = pass, 1 = drop
    __u8 cilium_integration;  // Enable Cilium integration
    __u8 hw_offload;          // Enable hardware offload optimizations
    __u16 cilium_policy_index; // Reference to Cilium policy to apply
};

// Define map for configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sockops_config);
} config_map SEC(".maps");

// Socket connection structure
struct sock_key {
    union {
        // IPv4 addresses
        struct {
            __u32 sip4;      // Source IPv4
            __u32 dip4;      // Destination IPv4
        };
        // IPv6 addresses
        struct {
            struct ipv6_addr sip6;  // Source IPv6
            struct ipv6_addr dip6;  // Destination IPv6
        };
    };
    __u16 sport;             // Source port
    __u16 dport;             // Destination port
    __u8 family;             // Address family (1 = IPv4, 2 = IPv6)
    __u8 protocol;           // Protocol
} __attribute__((packed));

// Socket policy structure
struct sock_policy {
    __u32 policy_id;         // Policy ID
    __u8 action;             // Action: 0 = allow, 1 = deny, 2 = redirect
    __u32 redirect_ip;       // Redirect IP (if action is redirect)
    __u16 redirect_port;     // Redirect port (if action is redirect)
};

// Define map for socket connections
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct sock_key);
    __type(value, __u64);    // Connection flags and timestamp
} sockets_map SEC(".maps");

// Define map for socket policies
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);      // Policy ID
    __type(value, struct sock_policy);
} policy_map SEC(".maps");

// Cilium IPv4 identity map - used for identity-based filtering
// This map can be shared with Cilium to use its identity-based policies
DECLARE_CILIUM_IPCACHE;

// Cilium IPv6 identity map - used for identity-based filtering
// This map can be shared with Cilium to use its identity-based policies
DECLARE_CILIUM_IPV6CACHE;

// Connection event structure for monitoring
struct conn_event {
    __u64 timestamp;         // Event timestamp
    __u32 pid;               // Process ID
    union {
        struct {
            __u32 sip4;      // Source IPv4
            __u32 dip4;      // Destination IPv4
        };
        struct {
            struct ipv6_addr sip6;  // Source IPv6
            struct ipv6_addr dip6;  // Destination IPv6
        };
    };
    __u16 sport;             // Source port
    __u16 dport;             // Destination port
    __u8 protocol;           // Protocol
    __u8 type;               // Event type
    __u8 family;             // Address family (1 = IPv4, 2 = IPv6)
};

// Define map for connection events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Parse IPv4 addresses from socket operations context
static __always_inline void extract_key4_from_ops(struct bpf_sock_ops *ops, struct sock_key *key) {
    key->sip4 = ops->local_ip4;
    key->dip4 = ops->remote_ip4;
    key->sport = ops->local_port;
    key->dport = bpf_ntohl(ops->remote_port);
    key->family = 1; // AF_INET
    key->protocol = ops->protocol;
}

// Parse IPv6 addresses from socket operations context
static __always_inline void extract_key6_from_ops(struct bpf_sock_ops *ops, struct sock_key *key) {
    // Copy local IPv6 address (source)
    for (int i = 0; i < 4; i++) {
        key->sip6.addr[i] = ops->local_ip6[i];
    }
    
    // Copy remote IPv6 address (destination)
    for (int i = 0; i < 4; i++) {
        key->dip6.addr[i] = ops->remote_ip6[i];
    }
    
    key->sport = ops->local_port;
    key->dport = bpf_ntohl(ops->remote_port);
    key->family = 2; // AF_INET6
    key->protocol = ops->protocol;
}

// Record a connection event to the events map
static __always_inline void record_event(struct bpf_sock_ops *ops, __u8 event_type) {
    struct conn_event event = {
        .timestamp = bpf_ktime_get_ns(),
        .pid = bpf_get_current_pid_tgid() >> 32,
        .protocol = ops->protocol,
        .type = event_type,
        .sport = ops->local_port,
        .dport = bpf_ntohl(ops->remote_port)
    };
    
    // Handle IPv4 or IPv6 based on the family
    if (ops->family == AF_INET) {
        event.sip4 = ops->local_ip4;
        event.dip4 = ops->remote_ip4;
        event.family = 1; // IPv4
    } else if (ops->family == AF_INET6) {
        // Copy IPv6 addresses
        for (int i = 0; i < 4; i++) {
            event.sip6.addr[i] = ops->local_ip6[i];
            event.dip6.addr[i] = ops->remote_ip6[i];
        }
        event.family = 2; // IPv6
    }
    
    bpf_perf_event_output(ops, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

// Check for socket policy matches
static __always_inline int check_policy(struct sock_key *key) {
    // In a real implementation, we would check against multiple policies
    // For now, simplify and check just a single policy
    __u32 policy_id = 0;
    struct sock_policy *policy = bpf_map_lookup_elem(&policy_map, &policy_id);
    
    if (policy) {
        return policy->action;
    }
    
    return 0; // Default to allow
}

// Check Cilium-based identity policy for IPv4 using common implementation
static __always_inline int check_cilium_policy_v4(struct sock_key *key, struct sockops_config *cfg) {
    // Skip if Cilium integration is not enabled
    if (!cfg->cilium_integration || cfg->cilium_policy_index <= 0) {
        return cfg->default_action;
    }
    
    // Use the common cilium_check_policy helper to determine if the connection is allowed
    int verdict = cilium_check_policy(
        NULL,           // No specific context needed for this
        key->sip4,      // Source IP
        key->dip4,      // Destination IP
        key->protocol,  // Protocol
        key->sport,     // Source port
        key->dport      // Destination port
    );
    
    // Map the generic policy verdict to sockops-specific actions
    switch (verdict) {
        case 1:  // DROP
            return 1;  // Deny
        case 2:  // REDIRECT
            // For a sockops implementation, we might want to handle redirects specially
            // For now, we'll allow the connection
            return 0;  // Allow
        default: // PASS (0)
            return 0;  // Allow
    }
}

// Check Cilium-based identity policy for IPv6 using common implementation
static __always_inline int check_cilium_policy_v6(struct sock_key *key, struct sockops_config *cfg) {
    // Skip if Cilium integration is not enabled
    if (!cfg->cilium_integration || cfg->cilium_policy_index <= 0) {
        return cfg->default_action;
    }
    
    // Use the common cilium_check_policy_v6 helper to determine if the connection is allowed
    int verdict = cilium_check_policy_v6(
        NULL,           // No specific context needed for this
        &key->sip6,     // Source IPv6 address
        &key->dip6,     // Destination IPv6 address
        key->protocol,  // Protocol
        key->sport,     // Source port
        key->dport      // Destination port
    );
    
    // Map the generic policy verdict to sockops-specific actions
    switch (verdict) {
        case 1:  // DROP
            return 1;  // Deny
        case 2:  // REDIRECT
            // For a sockops implementation, we might want to handle redirects specially
            // For now, we'll allow the connection
            return 0;  // Allow
        default: // PASS (0)
            return 0;  // Allow
    }
}

// Check Cilium-based identity policy - dispatches to IPv4/IPv6 implementation
static __always_inline int check_cilium_policy(struct sock_key *key, struct sockops_config *cfg) {
    if (key->family == 1) { // IPv4
        return check_cilium_policy_v4(key, cfg);
    } else if (key->family == 2) { // IPv6
        return check_cilium_policy_v6(key, cfg);
    }
    
    // Unknown family
    return cfg->default_action;
}

// Socket operations handler - main entry point
SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops) {
    // Get configuration
    __u32 key = 0;
    struct sockops_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 0; // No config, do nothing
        
    // Hardware offload optimizations using common macros
    if (cfg->hw_offload) {
        // Use the appropriate hardware offload macro based on NIC type
        X540_OFFLOAD_SUPPORTED("sockops");
        X550_OFFLOAD_SUPPORTED("sockops");
        I225_OFFLOAD_SUPPORTED("sockops");
    }
    
    // Extract the connection key
    struct sock_key sock_key = {};
    
    // Only process TCP for now
    if (skops->protocol != IPPROTO_TCP)
        return 0;
        
    // Handle both IPv4 and IPv6
    if (skops->family != AF_INET && skops->family != AF_INET6)
        return 0;
    
    // Handle socket operations based on the operation type
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            // Connection established
            if (skops->family == AF_INET) {
                extract_key4_from_ops(skops, &sock_key);
            } else if (skops->family == AF_INET6) {
                extract_key6_from_ops(skops, &sock_key);
            }
            
            // Store connection info
            __u64 val = bpf_ktime_get_ns();
            bpf_map_update_elem(&sockets_map, &sock_key, &val, BPF_ANY);
            
            // Check Cilium policy first if enabled
            int action = 0;
            if (cfg->cilium_integration) {
                action = check_cilium_policy(&sock_key, cfg);
            }
            
            // If Cilium allowed or not enabled, check local policy
            if (action == 0 && !cfg->cilium_integration) {
                action = check_policy(&sock_key);
            }
            
            if (action == 1) {
                // Deny connection - close the socket
                bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RST_CB_FLAG);
                return 1;
            }
            else if (action == 2 && cfg->enable_redirection) {
                // Redirect connection - not directly supported in sockops
                // Would require integration with socket redirect BPF programs
            }
            
            // Record event if monitoring is enabled
            if (cfg->enable_monitoring) {
                record_event(skops, 1); // 1 = established
            }
            
            break;
            
        case BPF_SOCK_OPS_CONNECTION_TIMEOUT_CB:
            // Connection timeout
            if (cfg->enable_monitoring) {
                extract_key4_from_ops(skops, &sock_key);
                record_event(skops, 2); // 2 = timeout
            }
            break;
            
        case BPF_SOCK_OPS_STATE_CB:
            // State change
            if (cfg->enable_monitoring && skops->args[1] == BPF_TCP_CLOSE) {
                extract_key4_from_ops(skops, &sock_key);
                record_event(skops, 3); // 3 = closed
                
                // Remove from connections map
                bpf_map_delete_elem(&sockets_map, &sock_key);
            }
            break;
    }
    
    return 0;
}

// TCP congestion control overrides could be added here
// This is a placeholder for TCP CC optimizations
SEC("sockops")
int bpf_tcp_cc(struct bpf_sock_ops *skops) {
    // Get configuration
    __u32 key = 0;
    struct sockops_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 0; // No config, do nothing
    
    if (skops->op == BPF_SOCK_OPS_TCP_CONNECT_CB) {
        // Set initial congestion control parameters
        // Example: can customize the congestion control algorithm
        // bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, "bbr", 3);
    }
    
    return 0;
}

// Define Cilium integration hooks
SEC("cilium_sockops")
int cilium_sockops(struct bpf_sock_ops *skops) {
    // This function would be called by Cilium's datapath when using integration
    // For now, we just pass operations to our own handler
    return bpf_sockops(skops);
}

char _license[] SEC("license") = "GPL";
