// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Socket operations configuration structure
struct sockops_config {
    __u8 enable_monitoring;   // Enable socket monitoring
    __u8 enable_redirection;  // Enable socket redirection
    __u8 enable_tracing;      // Enable socket tracing
    __u8 enable_app_gateway;  // Enable application-layer gateway
    __u8 default_action;      // Default action: 0 = pass, 1 = drop
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
    __u32 sip4;              // Source IPv4
    __u32 dip4;              // Destination IPv4
    __u16 sport;             // Source port
    __u16 dport;             // Destination port
    __u8 family;             // Address family
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

// Connection event structure for monitoring
struct conn_event {
    __u64 timestamp;         // Event timestamp
    __u32 pid;               // Process ID
    __u32 sip4;              // Source IPv4
    __u32 dip4;              // Destination IPv4
    __u16 sport;             // Source port
    __u16 dport;             // Destination port
    __u8 protocol;           // Protocol
    __u8 type;               // Event type
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

// Record a connection event to the events map
static __always_inline void record_event(struct bpf_sock_ops *ops, __u8 event_type) {
    struct conn_event event = {
        .timestamp = bpf_ktime_get_ns(),
        .pid = bpf_get_current_pid_tgid() >> 32,
        .sip4 = ops->local_ip4,
        .dip4 = ops->remote_ip4,
        .sport = ops->local_port,
        .dport = bpf_ntohl(ops->remote_port),
        .protocol = ops->protocol,
        .type = event_type
    };
    
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

// Socket operations handler - main entry point
SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops) {
    // Get configuration
    __u32 key = 0;
    struct sockops_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 0; // No config, do nothing
    
    // Extract the connection key
    struct sock_key sock_key = {};
    
    // Only process TCP IPv4 for now
    if (skops->family != AF_INET)
        return 0;
    
    if (skops->protocol != IPPROTO_TCP)
        return 0;
    
    // Handle socket operations based on the operation type
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            // Connection established
            extract_key4_from_ops(skops, &sock_key);
            
            // Store connection info
            __u64 val = bpf_ktime_get_ns();
            bpf_map_update_elem(&sockets_map, &sock_key, &val, BPF_ANY);
            
            // Check policy for this connection
            int action = check_policy(&sock_key);
            
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

char _license[] SEC("license") = "GPL";
