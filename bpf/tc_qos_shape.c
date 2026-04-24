// SPDX-License-Identifier: GPL-2.0
//
// tc_qos_shape — owned TC classifier that marks skb->priority per
// interface for VLAN / NIC-scoped QoS shaping.
//
// Sprint 30 / Ticket 39.
//
// Behaviour:
//   - Indexed by ifindex via the BPF_MAP_TYPE_HASH map `qos_iface_priority`
//     (key: __u32 ifindex, value: __u32 priority).
//   - On each packet (ingress or egress) the program looks up the skb's
//     ifindex in the map; if present, it writes the configured priority
//     onto skb->priority. This is the same socket-priority channel the
//     kernel uses for VLAN egress priority mapping (802.1p) and for the
//     prio qdisc's band selection, so downstream classful qdiscs (HTB,
//     pfifo_fast) will honour the classification without further filter
//     glue.
//   - Returns TC_ACT_OK in all cases — the program never drops; it is a
//     pure classifier. Callers that want drop/redirect behaviour should
//     compose a separate program rather than overloading this one.
//
// Non-goals for v1 (intentional):
//   - Per-flow or per-5-tuple classification (QoSProfile-style). That
//     belongs to the user-space controller that populates the map before
//     attaching — the program only reads.
//   - Per-CPU counters / statistics. The Bandwidth Manager path
//     (Ticket 45) already exposes Cilium's counters for per-pod egress;
//     classful TC shaping counters come from the tc(8) side.
//   - IPv6 vs IPv4 distinction. skb->priority is protocol-agnostic; the
//     program treats all frames uniformly.
//
// Composition with Ticket 45:
//   - Ticket 45's BandwidthManager annotates pods so Cilium's in-kernel
//     Bandwidth Manager enforces per-pod egress rate limits on the
//     pod's netdev (typically `lxc*` in Cilium deployments).
//   - This TC program attaches to VLAN / physical uplink NICs via clsact
//     and provides a coarse priority marking that a classful qdisc
//     further down the pipeline (configured by pkg/network/vlan/qos.go)
//     can steer into HTB classes.
//   - Both paths are composable: per-pod egress still flows through
//     Bandwidth Manager on the pod's side, and the uplink-side shaper
//     can add a second level of fairness without re-implementing the
//     pod-level limiter.
//
// Related:
//   - pkg/hardware/ebpf/tc_loader_linux.go loads and attaches this object.
//   - bpf/headers/vmlinux_minimal.h extended for Ticket 39 with the
//     __sk_buff subset and TC_ACT_* return codes.
//   - Build via `make bpf-objects` (requires BPF-capable clang/LLVM).

#include "vmlinux_minimal.h"
#include "bpf_helpers.h"

// qos_iface_priority — user-space populates this before attach. The key
// is the ifindex of the interface under management, the value is the
// 802.1p / socket priority to stamp onto traversing skbs.
//
// max_entries is modest: router/firewall uplink + VLAN trunks rarely
// exceed a handful of interfaces. Grow user-side if the deployment
// needs it; the kernel will reject updates that would push past this.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} qos_iface_priority SEC(".maps");

// Shared implementation for both ingress and egress sections. Ingress
// classification is unusual for shaping (most shaping is egress), but
// we expose both so callers that use IFB redirects for ingress shaping
// can attach the same program on the IFB side without duplicating C.
static __always_inline int tc_qos_classify(struct __sk_buff *skb) {
    __u32 ifindex = skb->ifindex;
    __u32 *prio = bpf_map_lookup_elem(&qos_iface_priority, &ifindex);
    if (prio) {
        skb->priority = *prio;
    }
    return TC_ACT_OK;
}

SEC("classifier/ingress")
int tc_qos_ingress(struct __sk_buff *skb) {
    return tc_qos_classify(skb);
}

SEC("classifier/egress")
int tc_qos_egress(struct __sk_buff *skb) {
    return tc_qos_classify(skb);
}

char _license[] SEC("license") = "GPL";
