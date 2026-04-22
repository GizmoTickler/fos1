# Embedded BPF Objects

This directory holds pre-compiled BPF ELF objects that are embedded into the
Go binary via `//go:embed`. Commit the compiled `.o` files here so the binary
ships with a working eBPF program without requiring `clang` on every build
machine.

## Regenerating

From the repository root:

```
make bpf-objects
cp bpf/out/xdp_ddos_drop.o pkg/hardware/ebpf/bpf/xdp_ddos_drop.o
```

The `bpf-objects` target requires an LLVM-based `clang` with a `bpf` target
(Apple's bundled clang does not include the BPF backend; install the LLVM
Homebrew formula or run on a Linux host with a stock `clang`).

## Missing object

If `xdp_ddos_drop.o` does not exist here, `NewXDPLoader` returns
`ErrEBPFObjectMissing` and callers see an explicit, actionable failure rather
than a silent success. This lets the Go tree build on platforms where a
BPF-capable clang is not installed, while still preventing the runtime from
pretending it has loaded a program.
