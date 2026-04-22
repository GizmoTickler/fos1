# Sprint 30 / Ticket 38: Prototype eBPF XDP Program Compilation And Attachment

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Produce one owned eBPF XDP program, compile it as part of the build, load it via `github.com/cilium/ebpf` on Linux, and attach it to a target interface. End-state: `pkg/network/ebpf/manager.go`'s `LoadProgram`/`AttachProgram` calls the real path for XDP programs and returns explicit "type not yet supported" for others.

**Architecture:** Linux-only real path behind build tags; non-Linux returns explicit unsupported. LLVM/Clang produces the object file from C source. Go loader uses the `cilium/ebpf` library. Attachment target interface is configured via CRD (reuse existing `EBPFProgram` spec).

**Tech Stack:** C (BPF), LLVM/Clang, Go, `github.com/cilium/ebpf`, Kubernetes CRDs, Linux-only test with privilege skip.

**Independence:** Self-contained once the build chain lands; Ticket 39 builds on this.

---

## Context

- `pkg/hardware/ebpf/program_manager.go` already manages program lifecycle state but does not invoke the kernel.
- `pkg/network/ebpf/manager.go` wraps `pkg/hardware/ebpf.Manager` with an interface the reconciliation tests (Ticket 36) now mock.
- `docs/design/ebpf-implementation.md` describes the target architecture.
- `github.com/cilium/ebpf` is already an indirect dependency; promote to direct.
- Current `Status.md` §eBPF Framework lists "Map structure exists, but no BPF compilation/loading" as the critical gap.

---

## File Map

- Create: `bpf/xdp_ddos_drop.c` — minimal XDP program: drop packets whose source IP is in a map-backed denylist, pass others.
- Create: `bpf/headers/` — pinned copies of `bpf_helpers.h`, `vmlinux.h`, etc., or wire `libbpf` via a submodule / vendor dir.
- Create: `Makefile` target `bpf-objects` invoking `clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I bpf/headers -c bpf/xdp_ddos_drop.c -o bpf/out/xdp_ddos_drop.o`.
- Create: `pkg/hardware/ebpf/xdp_loader_linux.go` — loads compiled object via `ebpf.LoadCollection`, attaches to interface via `link.AttachXDP`.
- Create: `pkg/hardware/ebpf/xdp_loader_stub.go` — non-Linux stub returning `ErrEBPFUnsupportedPlatform`.
- Create: `pkg/hardware/ebpf/errors.go` — sentinel errors: `ErrEBPFUnsupportedPlatform`, `ErrEBPFInsufficientCaps`, `ErrEBPFProgramTypeUnsupported`.
- Modify: `pkg/hardware/ebpf/program_manager.go` — dispatch to XDP loader on `ProgramTypeXDP`; return explicit unsupported for other types.
- Modify: `pkg/network/ebpf/manager.go` — delegate through the seam introduced in Ticket 36.
- Create: `pkg/hardware/ebpf/xdp_loader_linux_test.go` — skip when not root or missing `CAP_BPF`/`CAP_NET_ADMIN`; otherwise load the real object into a test namespace interface and assert attachment.
- Modify: `docs/design/ebpf-implementation.md` — describe the real loader path; label the rest as non-goals for v1.
- Modify: `docs/design/hardware-integration.md` — cross-reference.
- Modify: `Status.md` — move eBPF framework row from "Partial/Placeholder" to "XDP compile + load verified on Linux".

---

## Task 1: BPF C Source And Build Wiring

- [ ] Author `bpf/xdp_ddos_drop.c` with a single `SEC("xdp") int xdp_ddos_drop(struct xdp_md *ctx)` that looks up `ctx->data` source IP in an LPM-trie map and returns `XDP_DROP` on hit, `XDP_PASS` otherwise.
- [ ] Pin `bpf_helpers.h` or add a vendored BTF header path. Decide: submodule `libbpf` vs. copy headers. Prefer copy headers for reproducibility.
- [ ] Add `bpf/out/` to `.gitignore`.
- [ ] Add `make bpf-objects` target. Verify `clang --version` availability; fail fast with actionable error if missing.
- [ ] Commit the compiled `.o` under `pkg/hardware/ebpf/bpf/` via `//go:embed` (so the Go binary ships with a pre-compiled program) OR run `bpf-objects` as a `go generate` step.

## Task 2: Linux Loader Implementation

- [ ] `xdp_loader_linux.go`:
  - `type XDPLoader struct { spec *ebpf.CollectionSpec }`
  - `func NewXDPLoader(objectBytes []byte) (*XDPLoader, error)` — `ebpf.LoadCollectionSpec`
  - `func (l *XDPLoader) Attach(ifaceName string) (link.Link, error)` — resolve `netlink.LinkByName`, `link.AttachXDP`
  - `func (l *XDPLoader) Detach(link link.Link) error`
- [ ] `xdp_loader_stub.go`:
  - every method returns `ErrEBPFUnsupportedPlatform` wrapped with operation context.
- [ ] `program_manager.go` dispatch:
  - on `LoadProgram` with `ProgramTypeXDP`, construct XDPLoader, transition state to `Loaded`
  - on `AttachProgram`, call `Attach(iface)`, store `link.Link`, transition to `Attached`
  - on `DetachProgram`, call `Detach(link)`, transition to `Loaded`
  - on `UnloadProgram`, discard spec, transition to `Unloaded`
  - every other `ProgramType` → `ErrEBPFProgramTypeUnsupported`.

## Task 3: Linux-Only Integration Test

- [ ] `xdp_loader_linux_test.go` (build tag `//go:build linux`):
  - skip when `os.Geteuid() != 0` AND no `CAP_BPF`/`CAP_NET_ADMIN`
  - create a dummy interface via `netlink.LinkAdd(&netlink.Dummy{LinkAttrs: {Name: "fos1testxdp"}})`
  - load the program, attach, assert link handle is valid
  - detach, remove dummy interface
  - cleanup via `t.Cleanup` trap

## Task 4: Docs And Status

- [ ] `docs/design/ebpf-implementation.md` — new §"Compile and Load Pipeline" with the `bpf-objects` target, embed strategy, and loader seam.
- [ ] `Status.md` §eBPF — "XDP compile + load verified on Linux via `github.com/cilium/ebpf`; other program types return explicit unsupported."
- [ ] `docs/project-tracker.md` — mirror.
- [ ] `docs/design/implementation_caveats.md` — capture: TC/sockops/cgroup loaders remain non-goals until Ticket 39.

---

## Verification

- [ ] `make bpf-objects` produces `bpf/out/xdp_ddos_drop.o` on a machine with clang
- [ ] `go build ./...` green (no-BPF hosts still build via stub)
- [ ] `go test ./pkg/hardware/ebpf/... ./pkg/network/ebpf/...` passes; Linux integration test skips or passes depending on capabilities
- [ ] `make verify-mainline` passes

## Out Of Scope

- TC / sockops / cgroup attach (Ticket 39 extends to TC)
- Packet-level DDoS intelligence (the denylist is populated elsewhere)
- BTF-based CO-RE vs. legacy compile — pick one and document
- User-space map population controller (future ticket)

## Suggested Branch

`sprint-30/ticket-38-ebpf-xdp-compile-load`
