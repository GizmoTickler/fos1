# Sprint 30 / Ticket 39: Extend eBPF Loading To A TC-Attached QoS Shaping Program

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans.

**Goal:** Produce one owned TC classifier program, extend the Ticket 38 loader to support `BPF_PROG_TYPE_SCHED_CLS` attach via `clsact` qdisc, and route `QoSProfile` CRD output through it. Replace `pkg/network/vlan/qos.go:73` "not implemented" return with either the real path or explicit non-goal.

**Architecture:** Same Linux-only build-tag split as Ticket 38. `clsact` qdisc ensured via `netlink.QdiscAdd`. Program attached on `BPF_TC_INGRESS` and/or `BPF_TC_EGRESS` depending on QoSProfile shape.

**Tech Stack:** C (BPF), Go, `github.com/cilium/ebpf`, `github.com/vishvananda/netlink`, `tc-bpf`.

**Prerequisite:** Ticket 38 merged — shares the loader foundation.

---

## Context

- `pkg/controllers/qos_controller.go` reconciles `QoSProfile` CRs; currently outputs go to `pkg/security/qos/manager.go` which is stub.
- `pkg/network/vlan/qos.go:73` returns `"sysfs VLAN priority setting not implemented, will use ip command"`.
- Ticket 38 establishes the compile-and-load pattern; this ticket replicates it for TC.

---

## File Map

- Create: `bpf/tc_qos_shape.c` — classifier that reads a map-backed `{iface → class_id → bandwidth}` table and marks `__sk_buff->priority` or returns a TC action.
- Modify: `Makefile` — extend `bpf-objects` target to compile TC program.
- Create: `pkg/hardware/ebpf/tc_loader_linux.go` — `TCLoader` with `AttachIngress(iface)` / `AttachEgress(iface)`, handles `clsact` qdisc bootstrap.
- Create: `pkg/hardware/ebpf/tc_loader_stub.go` — non-Linux stub.
- Modify: `pkg/hardware/ebpf/program_manager.go` — dispatch `ProgramTypeTC` → `TCLoader`.
- Modify: `pkg/controllers/qos_controller.go` — on reconcile, call TC loader through the existing eBPF manager seam.
- Modify: `pkg/security/qos/manager.go` — remove stub, delegate to controller.
- Decide and execute on `pkg/network/vlan/qos.go:73` — either implement via netlink tc or mark explicit non-goal.
- Create: `pkg/hardware/ebpf/tc_loader_linux_test.go` — capability-gated integration test.
- Modify: `Status.md` — QoS row from stub to real.
- Modify: `docs/design/ebpf-implementation.md` — TC section.

---

## Task 1: TC BPF Program And Build

- [ ] Author `bpf/tc_qos_shape.c`: `SEC("classifier/ingress") int tc_qos_ingress(struct __sk_buff *skb)` + `SEC("classifier/egress") int tc_qos_egress(...)`. Simple map lookup on `skb->ifindex` → class; set `skb->priority`.
- [ ] Extend `make bpf-objects` to compile this file.

## Task 2: Loader Implementation

- [ ] `TCLoader` constructor accepts compiled object; stores spec.
- [ ] `AttachIngress(iface)`:
  - `netlink.LinkByName(iface)` → link index
  - ensure `clsact` qdisc exists (`netlink.QdiscAdd(&netlink.GenericQdisc{QdiscAttrs: {LinkIndex, Parent: netlink.HANDLE_CLSACT}, QdiscType: "clsact"})`), tolerate `EEXIST`
  - `link.AttachTCX` with `ebpf.AttachTCXIngress`
- [ ] Analogous for `AttachEgress`.
- [ ] Sentinel error `ErrTCQdiscUnsupported` if clsact bootstrap fails.

## Task 3: QoS Controller Integration

- [ ] `qos_controller.go` reconcile: translate `QoSProfile.Spec.Classes` into the map content, call loader attach.
- [ ] Status reflects attached/detached/degraded conditions.

## Task 4: Resolve `pkg/network/vlan/qos.go:73`

- [ ] Decide: real implementation via tc, or explicit non-goal.
- [ ] If non-goal: return `ErrVLANPrioritySysfsUnsupported` with actionable message pointing at the tc-bpf alternative.

## Task 5: Docs And Status

- [ ] `Status.md` QoS row → "Complete via TC-attached eBPF classifier and clsact qdisc" on Linux.
- [ ] `docs/design/ebpf-implementation.md` TC section + state machine.

---

## Verification

- [ ] `make bpf-objects` produces `tc_qos_shape.o`
- [ ] `make verify-mainline` green
- [ ] Linux integration test passes or skips based on capabilities
- [ ] One QoSProfile CR produces a live tc-bpf attachment in Kind

## Out Of Scope

- HTB/tbf classful shaping (stays as target architecture)
- Multi-queue NIC-specific tuning
- sockops / cgroup programs

## Suggested Branch

`sprint-30/ticket-39-ebpf-tc-qos`
