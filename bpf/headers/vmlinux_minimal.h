/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * vmlinux_minimal.h — the smallest subset of kernel UAPI definitions
 * we need to compile `xdp_ddos_drop.c` without pulling in the full
 * kernel-headers tree. This avoids a hard dependency on
 * `linux-headers` being installed on the build host.
 *
 * If we add a second BPF program later that needs larger pieces of the
 * kernel UAPI (for example, `bpf_sock` or tail-call maps), switch to
 * a real BTF-extracted `vmlinux.h` rather than extending this file.
 */

#ifndef __FOS1_VMLINUX_MINIMAL_H
#define __FOS1_VMLINUX_MINIMAL_H

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u16 __le16;
typedef __u32 __le32;

/* XDP return codes — see include/uapi/linux/bpf.h */
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP    = 1,
    XDP_PASS    = 2,
    XDP_TX      = 3,
    XDP_REDIRECT = 4,
};

/* XDP context. Must match the kernel's struct xdp_md layout. */
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

/* TC (classifier) context — minimal subset of struct __sk_buff used by
 * bpf/tc_qos_shape.c. Ordering and sizes must match the kernel's UAPI
 * layout (include/uapi/linux/bpf.h); additions here should preserve the
 * preceding fields so offsets stay correct.
 *
 * We carry the fields up to `priority` (which is what the QoS shaper
 * mutates). The kernel's struct continues past this point with
 * ingress_ifindex, ifindex, tc_index, cb[5], hash, tc_classid, etc. —
 * we deliberately omit them because the shaper does not read them.
 */
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
};

/* TC classifier return codes — see include/uapi/linux/pkt_cls.h. The
 * common set used by sched_cls/action programs. */
#define TC_ACT_UNSPEC   (-1)
#define TC_ACT_OK       0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT     2
#define TC_ACT_PIPE     3

/* Map-type IDs (subset). */
#define BPF_MAP_TYPE_HASH     1
#define BPF_MAP_TYPE_ARRAY    2
#define BPF_MAP_TYPE_LPM_TRIE 11

/* Map flags. */
#define BPF_F_NO_PREALLOC (1U << 0)

/* Ethernet header — matches linux/if_ether.h. */
#define ETH_P_IP 0x0800
struct ethhdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __be16 h_proto;
} __attribute__((packed));

/* Minimal IPv4 header. */
struct iphdr {
    __u8  ihl:4, version:4;
    __u8  tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __be32 saddr;
    __be32 daddr;
};

#endif /* __FOS1_VMLINUX_MINIMAL_H */
