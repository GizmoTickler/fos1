package ebpf

import "errors"

// Sentinel errors for the owned XDP loader and program-type dispatch.
// These are exported so callers (and tests) can use errors.Is to match.
var (
	// ErrEBPFUnsupportedPlatform is returned by non-Linux builds of the
	// XDP loader. Callers should treat this as a permanent, environmental
	// failure — not as a retryable condition.
	ErrEBPFUnsupportedPlatform = errors.New("eBPF: operation is only supported on Linux")

	// ErrEBPFInsufficientCaps is returned when the process lacks the
	// capabilities (CAP_BPF / CAP_NET_ADMIN) or effective UID required to
	// load or attach eBPF programs.
	ErrEBPFInsufficientCaps = errors.New("eBPF: insufficient capabilities (CAP_BPF/CAP_NET_ADMIN or root required)")

	// ErrEBPFProgramTypeUnsupported is returned when the program-manager
	// dispatch receives a program type that the owned loader does not
	// implement yet. V1 covers XDP only; TC, sockops, and cgroup are
	// tracked by Sprint 30 ticket 39 and follow-ups.
	ErrEBPFProgramTypeUnsupported = errors.New("eBPF: program type not supported by owned loader")

	// ErrEBPFObjectMissing is returned when the embedded BPF ELF object
	// is not present (for example, because `make bpf-objects` has not
	// been run on a machine with a BPF-capable clang). This keeps the
	// Go tree buildable on non-BPF hosts without shipping placeholder
	// success paths.
	ErrEBPFObjectMissing = errors.New("eBPF: embedded BPF object missing; run `make bpf-objects`")
)
