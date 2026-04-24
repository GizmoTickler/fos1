# Sprint 31 / Ticket 51: eBPF sockops + cgroup Program Types

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** `pkg/hardware/ebpf/program_manager.go` currently routes XDP and TC to real loaders and returns `ErrEBPFProgramTypeUnsupported` for sockops and cgroup. This ticket adds loaders for both.

**Tech Stack:** C (BPF), Go, `github.com/cilium/ebpf`, LLVM/Clang.

**Prerequisite:** Tickets 38 and 39 merged (they are — Sprint 30).

---

## Architecture

Same Linux-only build-tag split as Tickets 38 + 39. Two new program files under `bpf/`, two new loader pairs (`*_loader_linux.go` + `*_loader_stub.go`). Capability-gated integration tests.

- `sockops` program: attach to a cgroup v2 path, redirect established TCP connections between pods on the same node for perf (simple v0 — just count connection events). Attach via `link.AttachCgroup` with `ebpf.AttachCGroupSockOps`.
- `cgroup` program: attach egress skb at the cgroup, count outbound bytes per cgroup. Attach via `link.AttachCgroup` with `ebpf.AttachCGroupInetEgress`.

## File Map

- Create: `bpf/sockops_redirect.c` — `SEC("sockops")` program counting `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` events
- Create: `bpf/cgroup_egress_counter.c` — `SEC("cgroup_skb/egress")` program counting bytes per skb
- Modify: `bpf/headers/vmlinux_minimal.h` — add `bpf_sock_ops`, `__sk_buff` (already present from Ticket 39), any other minimal types needed
- Modify: `Makefile` `bpf-objects` target — compile both new files to `bpf/out/` and copy to `pkg/hardware/ebpf/bpf/`
- Create: `pkg/hardware/ebpf/sockops_loader_linux.go`, `sockops_loader_stub.go`
- Create: `pkg/hardware/ebpf/cgroup_loader_linux.go`, `cgroup_loader_stub.go`
- Create: `pkg/hardware/ebpf/sockops_loader_linux_test.go`, `cgroup_loader_linux_test.go`
- Modify: `pkg/hardware/ebpf/program_manager.go` — dispatch `ProgramTypeSockOps` → SockOpsLoader, `ProgramTypeCGroupEgress` → CGroupLoader
- Modify: `pkg/hardware/ebpf/errors.go` — add `ErrCGroupPathNotFound` sentinel
- Modify: `docs/design/ebpf-implementation.md` — §Compile and Load Pipeline extended with sockops + cgroup
- Modify: `Status.md` — eBPF row updates to "XDP + TC + sockops + cgroup compile + load verified on Linux"

## Tasks

### Task 1: BPF Source + Build

- [ ] Author `bpf/sockops_redirect.c`:
  ```c
  SEC("sockops")
  int sockops_redirect(struct bpf_sock_ops *ops) {
      // count active established; no actual redirect in v0
      if (ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
          // increment a per-cpu counter map
      }
      return 0;
  }
  ```
- [ ] Author `bpf/cgroup_egress_counter.c`:
  ```c
  SEC("cgroup_skb/egress")
  int cgroup_egress_counter(struct __sk_buff *skb) {
      // increment a per-cgroup byte counter
      return 1; // allow
  }
  ```
- [ ] Extend `Makefile` to compile both.
- [ ] If LLVM 21 is available at `/opt/homebrew/opt/llvm@21/bin/clang`, pre-compile and commit the `.o` files to `pkg/hardware/ebpf/bpf/`. Otherwise document.

### Task 2: Loaders

- [ ] `SockOpsLoader`:
  - `NewSockOpsLoader() (*SockOpsLoader, error)` — loads embedded object
  - `AttachToCGroup(cgroupPath string) (link.Link, error)` — opens cgroup FD via `os.Open`, calls `link.AttachCgroup`
  - `DetachFromCGroup(l link.Link) error`
  - stub returns `ErrEBPFUnsupportedPlatform` for every method
- [ ] `CGroupLoader`: parallel shape with `AttachEgress(cgroupPath)` / `AttachIngress(cgroupPath)`.
- [ ] `program_manager.go` dispatch table extended.

### Task 3: Integration Tests

- [ ] Linux-only tests create a throwaway cgroup via `unix.Mount` or by reusing a system cgroup; skip if unable.
- [ ] Assert `Attach*` returns a valid link handle; `Detach*` returns cleanly.

### Task 4: Docs + Status

- [ ] `docs/design/ebpf-implementation.md` §Compile and Load Pipeline gains sockops + cgroup subsections with example attach calls.
- [ ] `Status.md` eBPF row: "XDP + TC + sockops + cgroup compile + load verified on Linux".

## Verification

- [ ] `make verify-mainline` green
- [ ] `make bpf-objects` produces all four `.o` files
- [ ] Integration tests pass or skip cleanly

## Out Of Scope

- sk_msg / sk_lookup / etc. program types — Sprint 32+
- Actual perf-redirect behavior — v0 counts events, does not redirect
- Production cgroup management (creating/destroying cgroups) — tests reuse existing ones

## Suggested Branch

`sprint-31/ticket-51-ebpf-sockops-cgroup`
