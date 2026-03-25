package firewall

// TableFamily represents an nftables table address family.
type TableFamily string

const (
	// FamilyINET represents dual-stack IPv4+IPv6 (inet family).
	FamilyINET TableFamily = "inet"
	// FamilyIPv4 represents IPv4 only (ip family).
	FamilyIPv4 TableFamily = "ip"
	// FamilyIPv6 represents IPv6 only (ip6 family).
	FamilyIPv6 TableFamily = "ip6"
)

// ChainType represents the type of an nftables chain.
type ChainType string

const (
	// ChainTypeFilter is used for packet filtering chains.
	ChainTypeFilter ChainType = "filter"
	// ChainTypeNAT is used for network address translation chains.
	ChainTypeNAT ChainType = "nat"
	// ChainTypeRoute is used for routing decision chains.
	ChainTypeRoute ChainType = "route"
)

// ChainHook represents the netfilter hook point for a chain.
type ChainHook string

const (
	// HookInput is the input hook for locally destined packets.
	HookInput ChainHook = "input"
	// HookOutput is the output hook for locally originated packets.
	HookOutput ChainHook = "output"
	// HookForward is the forward hook for routed packets.
	HookForward ChainHook = "forward"
	// HookPrerouting is the prerouting hook before routing decisions.
	HookPrerouting ChainHook = "prerouting"
	// HookPostrouting is the postrouting hook after routing decisions.
	HookPostrouting ChainHook = "postrouting"
)

// Verdict represents the action taken on a matched packet.
type Verdict string

const (
	// VerdictAccept accepts the packet.
	VerdictAccept Verdict = "accept"
	// VerdictDrop silently drops the packet.
	VerdictDrop Verdict = "drop"
	// VerdictReject rejects the packet with an ICMP error.
	VerdictReject Verdict = "reject"
	// VerdictJump jumps to another chain.
	VerdictJump Verdict = "jump"
	// VerdictReturn returns from the current chain.
	VerdictReturn Verdict = "return"
	// VerdictLog logs the packet (non-terminal, continues processing).
	VerdictLog Verdict = "log"
)

// Protocol represents a network protocol for rule matching.
type Protocol string

const (
	// ProtocolTCP matches TCP packets.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP matches UDP packets.
	ProtocolUDP Protocol = "udp"
	// ProtocolICMP matches ICMP packets.
	ProtocolICMP Protocol = "icmp"
	// ProtocolAny matches any protocol.
	ProtocolAny Protocol = "any"
)

// ChainRef identifies a chain by its table and chain name.
type ChainRef struct {
	// Table is the name of the table containing the chain.
	Table string
	// Chain is the name of the chain.
	Chain string
}

// RuleMatch defines matching criteria for a firewall rule.
type RuleMatch struct {
	// Protocol specifies the L4 protocol to match.
	Protocol Protocol
	// SourceAddr is the source address to match (CIDR or single IP).
	SourceAddr string
	// DestAddr is the destination address to match (CIDR or single IP).
	DestAddr string
	// SourcePort is the source port to match.
	SourcePort uint16
	// DestPort is the destination port to match.
	DestPort uint16
	// InInterface is the input interface name to match.
	InInterface string
	// OutInterface is the output interface name to match.
	OutInterface string
	// CTState is a list of connection tracking states to match (e.g., "new", "established", "related").
	CTState []string
	// SetRef is the name of an nftables set to match against.
	SetRef string
	// Negate inverts the match condition when true.
	Negate bool
}

// NFTFirewallRule defines a firewall rule with match criteria and an action.
// This replaces the old FirewallRule type used by the exec.Command-based implementation.
type NFTFirewallRule struct {
	// Chain identifies the table and chain this rule belongs to.
	Chain ChainRef
	// Matches is a list of match criteria that must all be satisfied.
	Matches []RuleMatch
	// Verdict is the action to take when the rule matches.
	Verdict Verdict
	// JumpTarget is the chain name to jump to when Verdict is VerdictJump.
	JumpTarget string
	// Log enables logging for matched packets.
	Log bool
	// LogPrefix is the prefix string for log messages.
	LogPrefix string
	// Counter enables packet and byte counting for the rule.
	Counter bool
	// Comment is a human-readable description of the rule.
	Comment string
	// Priority controls the ordering of rules within a chain (lower = earlier).
	Priority int
	// Handle is the kernel-assigned handle for an existing rule (set after AddRule).
	Handle uint64
}

// RuleCounters holds packet and byte counters for a rule.
type RuleCounters struct {
	// Packets is the number of packets that matched the rule.
	Packets uint64
	// Bytes is the number of bytes that matched the rule.
	Bytes uint64
}

// FirewallManager defines the interface for managing nftables firewall rules.
type FirewallManager interface {
	// Initialize sets up the nftables connection and creates the default table structure.
	Initialize() error
	// Close releases all resources held by the firewall manager.
	Close() error

	// EnsureTable creates a table if it does not already exist.
	EnsureTable(name string, family TableFamily) error
	// EnsureChain creates a base chain if it does not already exist.
	EnsureChain(table string, chain string, chainType ChainType, hook ChainHook, priority int) error
	// DeleteChain deletes a chain and all its rules.
	DeleteChain(ref ChainRef) error
	// FlushChain removes all rules from a chain without deleting it.
	FlushChain(ref ChainRef) error

	// AddRule appends a rule to the end of a chain and returns the kernel-assigned handle.
	AddRule(rule NFTFirewallRule) (uint64, error)
	// InsertRule inserts a rule at the beginning of a chain and returns the kernel-assigned handle.
	InsertRule(rule NFTFirewallRule) (uint64, error)
	// DeleteRule deletes a rule identified by its chain reference and kernel handle.
	DeleteRule(ref ChainRef, handle uint64) error
	// ListRules returns all rules in a given chain.
	ListRules(ref ChainRef) ([]NFTFirewallRule, error)

	// CreateSet creates a new nftables set for address or port matching.
	CreateSet(table string, name string, keyType uint32, interval bool) error
	// AddSetElements adds elements to an existing nftables set.
	AddSetElements(table string, setName string, elements [][]byte) error
	// DeleteSet removes an nftables set and all its elements.
	DeleteSet(table string, name string) error

	// Commit atomically applies all pending changes to the kernel.
	Commit() error

	// GetRuleCounters returns packet and byte counters for a specific rule.
	GetRuleCounters(ref ChainRef, handle uint64) (*RuleCounters, error)
}
