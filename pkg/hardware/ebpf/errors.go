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
	// implement. XDP, TC, sockops, and cgroup have owned loaders (Sprint
	// 30 tickets 38/39 + Sprint 31 ticket 51). Other program types —
	// sk_msg, sk_lookup, lirc, etc. — are explicitly out of scope and
	// return this error.
	ErrEBPFProgramTypeUnsupported = errors.New("eBPF: program type not supported by owned loader")

	// ErrEBPFObjectMissing is returned when the embedded BPF ELF object
	// is not present (for example, because `make bpf-objects` has not
	// been run on a machine with a BPF-capable clang). This keeps the
	// Go tree buildable on non-BPF hosts without shipping placeholder
	// success paths.
	ErrEBPFObjectMissing = errors.New("eBPF: embedded BPF object missing; run `make bpf-objects`")

	// ErrTCQdiscUnsupported is returned when the TC loader cannot
	// bootstrap a `clsact` qdisc on the target interface (missing kernel
	// support, insufficient privileges, or an incompatible existing
	// qdisc). Callers should surface the wrapped error to operators —
	// clsact is supported on every kernel >= 4.5 so a failure here
	// almost always reflects environment, not the loader.
	ErrTCQdiscUnsupported = errors.New("eBPF: clsact qdisc bootstrap failed")

	// ErrCGroupPathNotFound is returned when the sockops or cgroup
	// loader cannot open the requested cgroup v2 path. The most common
	// cause is a missing or un-mounted `cgroup2` filesystem — sockops
	// and cgroup_skb programs both require a unified cgroup v2 hierarchy
	// (hybrid v1/v2 will not work). Callers should surface the wrapped
	// error to operators so the "mount cgroup2 on /sys/fs/cgroup"
	// remediation is obvious.
	ErrCGroupPathNotFound = errors.New("eBPF: cgroup v2 path not found or not a cgroup fs")
)
