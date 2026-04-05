//go:build !linux

package policy

// KernelRuleManager handles Linux IP rules via netlink.
type KernelRuleManager struct{}

// NewKernelRuleManager creates a new kernel rule manager.
func NewKernelRuleManager() *KernelRuleManager {
	return &KernelRuleManager{}
}

// AddRule adds an IP rule to the kernel.
func (k *KernelRuleManager) AddRule(rule IPRule) error {
	return nil
}

// DeleteRule deletes an IP rule from the kernel.
func (k *KernelRuleManager) DeleteRule(rule IPRule) error {
	return nil
}

// ListRules lists all IP rules in the kernel.
func (k *KernelRuleManager) ListRules(family int) ([]IPRule, error) {
	return []IPRule{}, nil
}

// CreateRoutingTable creates a custom routing table.
func (k *KernelRuleManager) CreateRoutingTable(tableID int, tableName string) error {
	return nil
}

// DeleteRoutingTable deletes all routes from a routing table.
func (k *KernelRuleManager) DeleteRoutingTable(tableID int) error {
	return nil
}
