# Embedded BPF Objects

This directory holds pre-compiled BPF ELF objects that are embedded into the
Go binary via `//go:embed`. Commit the compiled `.o` files here so the binary
ships with working eBPF programs without requiring `clang` on every build
machine.

Currently embedded:

- `xdp_ddos_drop.o` — XDP denylist drop (Sprint 30 Ticket 38).
- `tc_qos_shape.o` — TC classifier that marks `skb->priority` per
  interface (Sprint 30 Ticket 39).
- `sockops_redirect.o` — cgroup sockops program that counts active
  established TCP callbacks (Sprint 31 Ticket 51).
- `cgroup_egress_counter.o` — cgroup_skb/egress program that counts
  outbound bytes + packets per cgroup attachment (Sprint 31 Ticket 51).

## Regenerating

From the repository root:

```
make bpf-objects
```

The `bpf-objects` target discovers every `bpf/*.c` source, compiles each
into `bpf/out/*.o`, and copies the result into this directory. It requires
an LLVM-based `clang` with a `bpf` target (Apple's bundled clang does not
include the BPF backend; install the LLVM Homebrew formula — e.g.
`brew install llvm@21` — or run on a Linux host with a stock `clang`, then
pass `BPF_CLANG=/opt/homebrew/opt/llvm@21/bin/clang`).

## Missing object

If an expected `.o` file is absent, the matching loader (`NewXDPLoader` /
`NewTCLoader`) returns `ErrEBPFObjectMissing` and callers see an explicit,
actionable failure rather than a silent success. This lets the Go tree
build on platforms where a BPF-capable clang is not installed, while still
preventing the runtime from pretending it has loaded a program.
