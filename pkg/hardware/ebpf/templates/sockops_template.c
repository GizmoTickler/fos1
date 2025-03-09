// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Your Organization
// Compatible with Cilium Network Policies
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/socket.h>

// Include common definitions
#include "common.h"
#include "cilium_common.h"

// Socket operations configuration structure
struct sockops_config {
    struct monitoring_config base;  // Common monitoring configuration
    __u8 enable_redirection;       // Enable socket redirection
    __u8 enable_app_gateway;       // Enable application-layer gateway
    __u8 default_action;           // Default action: 0 = pass, 1 = drop
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
    struct ip_info info;     // Common IP info structure
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



// Define map for connection events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Parse IPv4 addresses from socket operations context
static __always_inline void extract_key4_from_ops(struct bpf_sock_ops *ops, struct sock_key *key) {
    key->info.src.v4 = ops->local_ip4;
    key->info.dst.v4 = ops->remote_ip4;
    key->info.src_port = ops->local_port;
    key->info.dst_port = bpf_ntohl(ops->remote_port);
    key->info.version = 4;
    key->info.protocol = ops->protocol;
}

// Parse IPv6 addresses from socket operations context
static __always_inline void extract_key6_from_ops(struct bpf_sock_ops *ops, struct sock_key *key) {
    // Copy local IPv6 address (source)
    for (int i = 0; i < 4; i++) {
        key->info.src.v6.in6_u.u6_addr32[i] = ops->local_ip6[i];
    }
    
    // Copy remote IPv6 address (destination)
    for (int i = 0; i < 4; i++) {
        key->info.dst.v6.in6_u.u6_addr32[i] = ops->remote_ip6[i];
    }
    
    key->info.src_port = ops->local_port;
    key->info.dst_port = bpf_ntohl(ops->remote_port);
    key->info.version = 6;
    key->info.protocol = ops->protocol;
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
        event.family = 4; // IPv4
    } else if (ops->family == AF_INET6) {
        // Copy IPv6 addresses
        for (int i = 0; i < 4; i++) {
            event.sip6.in6_u.u6_addr32[i] = ops->local_ip6[i];
            event.dip6.in6_u.u6_addr32[i] = ops->remote_ip6[i];
        }
        event.family = 6; // IPv6
    }
    
    bpf_perf_event_output(ops, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

// Check for socket policy matches
static __always_inline int check_policy(struct sock_key *key) {
    // In a real implementation, we would check against multiple policies
    // For now, simplify and check just a single policy
    __u32 policy_id = 0;
    struct sock_policy *policy = bpf_map_lookup_elem(&policy_map, &policy_id);
    
    if (!policy)
        return 0; // Default to allow
    
    // Check if policy matches the connection
    if (key->info.version == 4) {
        // IPv4 policy check
        if (policy->redirect_ip == key->info.dst.v4) {
            return policy->action;
        }
    } else {
        // IPv6 policy check
        if (compare_ipv6((struct in6_addr *)&policy->redirect_ip, &key->info.dst.v6)) {
            return policy->action;
        }
    }
    
    return 0; // Default to allow
}

// Check Cilium-based identity policy for IPv4 using common implementation
static __always_inline int check_cilium_policy_v4(struct sock_key *key, struct sockops_config *cfg) {
    // Skip if Cilium integration is not enabled
    if (!cfg->base.cilium_integration || cfg->base.cilium_policy_index <= 0) {
        return cfg->default_action;
    }
    
    // Use the common cilium_check_policy helper to determine if the connection is allowed
    int verdict = cilium_check_policy(
        NULL,                       // No specific context needed for this
        key->info.src.v4,           // Source IP
        key->info.dst.v4,           // Destination IP
        key->info.protocol,         // Protocol
        key->info.src_port,         // Source port
        key->info.dst_port          // Destination port
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
    if (!cfg->base.cilium_integration || cfg->base.cilium_policy_index <= 0) {
        return cfg->default_action;
    }
    
    // Use the common cilium_check_policy_v6 helper to determine if the connection is allowed
    int verdict = cilium_check_policy_v6(
        NULL,                       // No specific context needed for this
        &key->info.src.v6,          // Source IPv6 address
        &key->info.dst.v6,          // Destination IPv6 address
        key->info.protocol,         // Protocol
        key->info.src_port,         // Source port
        key->info.dst_port          // Destination port
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
    if (key->info.version == 4) { // IPv4
        return check_cilium_policy_v4(key, cfg);
    } else if (key->info.version == 6) { // IPv6
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
    if (cfg->base.hw_offload) {
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
    
    // Extract connection key based on address family
    if (skops->family == AF_INET) {
        extract_key4_from_ops(skops, &sock_key);
    } else {
        extract_key6_from_ops(skops, &sock_key);
    }
    
    // Handle socket operations based on the operation type
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
            // Check Cilium policy first if enabled
            int action = 0;
            if (cfg->base.cilium_integration) {
                action = check_cilium_policy(&sock_key, cfg);
                
                // Record policy decision if monitoring is enabled
                if (cfg->base.enable_monitoring && action == 1) {
                    record_event(skops, 3); // 3 = denied by Cilium policy
                }
            }
            
            // If Cilium allowed or not enabled, check local policy
            if (action == 0) {
                action = check_policy(&sock_key);
                
                // Record policy decision if monitoring is enabled
                if (cfg->base.enable_monitoring && action == 1) {
                    record_event(skops, 4); // 4 = denied by local policy
                }
            }
            
            if (action == 1) {
                // Deny connection - close the socket
                bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RST_CB_FLAG);
                return 1;
            }
            
            // Store connection info with metadata
            __u64 val = bpf_ktime_get_ns();
            if (sock_key.info.version == 6) {
                val |= (1ULL << 63); // Set IPv6 flag in high bit
            }
            if (action == 2) {
                val |= (1ULL << 62); // Set redirect flag
            }
            
            bpf_map_update_elem(&sockets_map, &sock_key, &val, BPF_ANY);
            
            // Record connection event if monitoring is enabled
            if (cfg->base.enable_monitoring) {
                record_event(skops, 1); // 1 = established
            }
            
            break;
        }
            
        case BPF_SOCK_OPS_CONNECTION_TIMEOUT_CB: {
            // Connection timeout
            if (cfg->base.enable_monitoring) {
                record_event(skops, 8); // 8 = timeout
            }
            
            // Clean up connection tracking
            bpf_map_delete_elem(&sockets_map, &sock_key);
            break;
        }
            
        case BPF_SOCK_OPS_STATE_CB: {
            // Connection state change
            __u32 old_state = skops->args[1];
            __u32 new_state = skops->args[2];
            
            // Handle connection closure states
            if (new_state == BPF_TCP_CLOSE ||
                new_state == BPF_TCP_CLOSE_WAIT ||
                new_state == BPF_TCP_FIN_WAIT1 ||
                new_state == BPF_TCP_FIN_WAIT2) {
                
                // Record event if monitoring is enabled
                if (cfg->base.enable_monitoring) {
                    record_event(skops, 2); // 2 = closed
                }
                
                // Remove from tracking map
                bpf_map_delete_elem(&sockets_map, &sock_key);
            }
            // Handle retransmission events for congestion monitoring
            else if (new_state == BPF_TCP_RETRANS) {
                if (cfg->base.enable_monitoring) {
                    record_event(skops, 5); // 5 = retransmission
                }
            }
            // Handle connection reset
            else if (new_state == BPF_TCP_RESET) {
                if (cfg->base.enable_monitoring) {
                    record_event(skops, 9); // 9 = reset
                }
                bpf_map_delete_elem(&sockets_map, &sock_key);
            }
            break;
        }
            
        case BPF_SOCK_OPS_TCP_CONNECT_CB: {
            // New outgoing connection attempt
            if (cfg->enable_monitoring) {
                record_event(skops, 6); // 6 = connection attempt
            }
            break;
        }
            
        case BPF_SOCK_OPS_TCP_LISTEN_CB: {
            // New listening socket
            if (cfg->enable_monitoring) {
                record_event(skops, 7); // 7 = listen started
            }
            break;
        }
    }
    
    return 0;
}

// TCP congestion control handler
SEC("sockops")
int bpf_tcp_cc(struct bpf_sock_ops *skops) {
    // Get configuration
    __u32 key = 0;
    struct sockops_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 0; // No config, do nothing
    
    // Extract connection key for tracking
    struct sock_key sock_key = {};
    if (skops->family == AF_INET) {
        extract_key4_from_ops(skops, &sock_key);
    } else if (skops->family == AF_INET6) {
        extract_key6_from_ops(skops, &sock_key);
    } else {
        return 0; // Unknown family
    }
    
    switch (skops->op) {
        case BPF_SOCK_OPS_INIT: {
            // Initialize congestion control parameters
            // Set initial window size based on IP version
            __u32 init_cwnd = (sock_key.info.version == 6) ? 10 : 8;
            bpf_setsockopt(skops, SOL_TCP, TCP_INIT_CWND, &init_cwnd, sizeof(init_cwnd));
            
            // Enable TCP timestamps for better RTT measurements
            __u32 ts_enabled = 1;
            bpf_setsockopt(skops, SOL_TCP, TCP_TIMESTAMPS, &ts_enabled, sizeof(ts_enabled));
            break;
        }
        
        case BPF_SOCK_OPS_RTT_CB: {
            // RTT update callback
            if (cfg->base.enable_monitoring) {
                // Record RTT event with the new RTT value
                record_event(skops, 10); // 10 = RTT update
            }
            break;
        }
        
        case BPF_SOCK_OPS_DUPACK_CB: {
            // Duplicate ACK received
            if (cfg->base.enable_monitoring) {
                record_event(skops, 11); // 11 = duplicate ACK
            }
            break;
        }
        
        case BPF_SOCK_OPS_RTO_CB: {
            // RTO timer expired
            if (cfg->base.enable_monitoring) {
                record_event(skops, 12); // 12 = RTO timeout
            }
            break;
        }
        
        case BPF_SOCK_OPS_STATE_CB: {
            // State change in congestion control
            __u32 old_state = skops->args[1];
            __u32 new_state = skops->args[2];
            
            if (new_state == TCP_CA_Recovery || new_state == TCP_CA_Loss) {
                // Connection is experiencing congestion
                if (cfg->base.enable_monitoring) {
                    record_event(skops, 13); // 13 = congestion event
                }
            }
            break;
        }
    }
    
    return 0;
}
        // bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, "bbr", 3);
    }
    
    return 0;
}

// Define Cilium integration hooks
SEC("cilium_sockops")
int cilium_sockops(struct bpf_sock_ops *skops) {
    // Get configuration
    __u32 key = 0;
    struct sockops_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || !cfg->base.cilium_integration)
        return 0; // No config or Cilium not enabled
    
    // Extract connection key for policy checks
    struct sock_key sock_key = {};
    if (skops->family == AF_INET) {
        extract_key4_from_ops(skops, &sock_key);
    } else if (skops->family == AF_INET6) {
        extract_key6_from_ops(skops, &sock_key);
    } else {
        return 0; // Unknown family
    }
    
    // Check Cilium policy
    int verdict = check_cilium_policy(&sock_key, cfg);
    
    if (verdict == 1) { // DROP
        // Record denied connection if monitoring is enabled
        if (cfg->base.enable_monitoring) {
            record_event(skops, 3); // 3 = denied by Cilium policy
        }
        return 1; // Deny connection
    } else if (verdict == 2) { // REDIRECT
        // Store redirection flag in connection metadata
        __u64 val = bpf_ktime_get_ns();
        val |= (1ULL << 62); // Set redirect flag
        if (sock_key.info.version == 6) {
            val |= (1ULL << 63); // Set IPv6 flag
        }
        bpf_map_update_elem(&sockets_map, &sock_key, &val, BPF_ANY);
    }
    
    // Pass to regular sockops handler for additional processing
    return bpf_sockops(skops);
}

char _license[] SEC("license") = "GPL";
