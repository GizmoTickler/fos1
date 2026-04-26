package qos

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	networkv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/network/v1alpha1"
)

// fakeTCBackend records every call made through the TCBackend interface
// so assertions can verify both the call shape and ordering. It satisfies
// the apply / remove flows without any kernel involvement, mirroring the
// pattern in qos_controller_test.go for the Bandwidth Manager path.
type fakeTCBackend struct {
	setPriorityCalls   []setPriorityCall
	clearPriorityCalls []string
	attachCalls        []attachCall
	detachCalls        []string

	setPriorityErr   error
	clearPriorityErr error
	attachErr        error
	detachErr        error
}

type setPriorityCall struct {
	iface    string
	priority uint32
}

type attachCall struct {
	iface     string
	direction networkv1alpha1.TrafficShaperDirection
}

func (f *fakeTCBackend) SetPriority(iface string, priority uint32) error {
	f.setPriorityCalls = append(f.setPriorityCalls, setPriorityCall{iface: iface, priority: priority})
	return f.setPriorityErr
}

func (f *fakeTCBackend) ClearPriority(iface string) error {
	f.clearPriorityCalls = append(f.clearPriorityCalls, iface)
	return f.clearPriorityErr
}

func (f *fakeTCBackend) EnsureAttached(iface string, dir networkv1alpha1.TrafficShaperDirection) error {
	f.attachCalls = append(f.attachCalls, attachCall{iface: iface, direction: dir})
	return f.attachErr
}

func (f *fakeTCBackend) EnsureDetached(iface string) error {
	f.detachCalls = append(f.detachCalls, iface)
	return f.detachErr
}

// TestTranslate_HappyPath drives the canonical CIDR + DSCP rule fan-out
// and asserts the translator picks the lowest priority value, defaults the
// direction to egress, and computes a stable hash.
func TestTrafficShaperTranslate_HappyPath(t *testing.T) {
	spec := &networkv1alpha1.TrafficShaperSpec{
		Interface: "eth0",
		Rules: []networkv1alpha1.TrafficShaperRule{
			{MatchCIDR: "10.0.0.0/8", Priority: 5, Rate: "100Mbit"},
			{MatchDSCP: 46, Priority: 1},
		},
	}

	plan, err := TranslateTrafficShaper(spec)
	require.NoError(t, err)
	require.NotNil(t, plan)

	assert.Equal(t, "eth0", plan.Interface)
	assert.Equal(t, networkv1alpha1.TrafficShaperDirectionEgress, plan.Direction,
		"empty direction must default to egress")
	assert.Equal(t, uint32(1), plan.Priority,
		"translator must collapse to the lowest priority across rules")
	assert.Equal(t, int32(2), plan.AppliedRuleCount)
	assert.NotEmpty(t, plan.Hash)
}

// TestTranslate_RuleOrder_StableHash verifies that two specs with the
// same rules in different orders produce the same hash. This is what
// makes the controller's spec-hash short-circuit safe under YAML
// re-formatting.
func TestTrafficShaperTranslate_RuleOrder_StableHash(t *testing.T) {
	a := &networkv1alpha1.TrafficShaperSpec{
		Interface: "eth0",
		Direction: networkv1alpha1.TrafficShaperDirectionEgress,
		Rules: []networkv1alpha1.TrafficShaperRule{
			{MatchCIDR: "10.0.0.0/8", Priority: 5},
			{MatchDSCP: 46, Priority: 1},
		},
	}
	b := &networkv1alpha1.TrafficShaperSpec{
		Interface: "eth0",
		Direction: networkv1alpha1.TrafficShaperDirectionEgress,
		Rules: []networkv1alpha1.TrafficShaperRule{
			{MatchDSCP: 46, Priority: 1},
			{MatchCIDR: "10.0.0.0/8", Priority: 5},
		},
	}

	planA, err := TranslateTrafficShaper(a)
	require.NoError(t, err)
	planB, err := TranslateTrafficShaper(b)
	require.NoError(t, err)

	assert.Equal(t, planA.Hash, planB.Hash, "rule order must not affect hash")
}

// TestTranslate_DirectionVariants exercises every legal direction value
// and the empty default.
func TestTrafficShaperTranslate_DirectionVariants(t *testing.T) {
	cases := []struct {
		in   networkv1alpha1.TrafficShaperDirection
		want networkv1alpha1.TrafficShaperDirection
	}{
		{"", networkv1alpha1.TrafficShaperDirectionEgress},
		{networkv1alpha1.TrafficShaperDirectionEgress, networkv1alpha1.TrafficShaperDirectionEgress},
		{networkv1alpha1.TrafficShaperDirectionIngress, networkv1alpha1.TrafficShaperDirectionIngress},
		{networkv1alpha1.TrafficShaperDirectionBoth, networkv1alpha1.TrafficShaperDirectionBoth},
	}
	for _, tc := range cases {
		spec := &networkv1alpha1.TrafficShaperSpec{
			Interface: "eth0",
			Direction: tc.in,
			Rules: []networkv1alpha1.TrafficShaperRule{
				{MatchCIDR: "10.0.0.0/8", Priority: 3},
			},
		}
		plan, err := TranslateTrafficShaper(spec)
		require.NoError(t, err, "direction=%q", tc.in)
		assert.Equal(t, tc.want, plan.Direction, "direction=%q", tc.in)
	}
}

// TestTranslate_BadDirection ensures unknown direction values reject.
func TestTrafficShaperTranslate_BadDirection(t *testing.T) {
	spec := &networkv1alpha1.TrafficShaperSpec{
		Interface: "eth0",
		Direction: "downstream", // not a legal value
		Rules: []networkv1alpha1.TrafficShaperRule{
			{MatchCIDR: "10.0.0.0/8", Priority: 3},
		},
	}
	_, err := TranslateTrafficShaper(spec)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrafficShaperBadDirection),
		"unknown direction must return ErrTrafficShaperBadDirection")
}

// TestTranslate_NoInterface is the empty-spec.Interface invalid branch.
func TestTrafficShaperTranslate_NoInterface(t *testing.T) {
	spec := &networkv1alpha1.TrafficShaperSpec{
		Rules: []networkv1alpha1.TrafficShaperRule{
			{MatchCIDR: "10.0.0.0/8", Priority: 3},
		},
	}
	_, err := TranslateTrafficShaper(spec)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrafficShaperNoInterface))
}

// TestTranslate_NoRules ensures an empty rules slice is rejected.
func TestTrafficShaperTranslate_NoRules(t *testing.T) {
	spec := &networkv1alpha1.TrafficShaperSpec{Interface: "eth0"}
	_, err := TranslateTrafficShaper(spec)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrafficShaperNoRules))
}

// TestTranslate_EmptyRule rejects rules without any match field.
func TestTrafficShaperTranslate_EmptyRule(t *testing.T) {
	spec := &networkv1alpha1.TrafficShaperSpec{
		Interface: "eth0",
		Rules: []networkv1alpha1.TrafficShaperRule{
			{Priority: 3}, // no MatchCIDR, no MatchDSCP
		},
	}
	_, err := TranslateTrafficShaper(spec)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTrafficShaperEmptyRule))
}

// TestTranslate_BadPriority covers both ends of the 1-7 range.
func TestTrafficShaperTranslate_BadPriority(t *testing.T) {
	cases := []uint32{0, 8, 100}
	for _, p := range cases {
		spec := &networkv1alpha1.TrafficShaperSpec{
			Interface: "eth0",
			Rules: []networkv1alpha1.TrafficShaperRule{
				{MatchCIDR: "10.0.0.0/8", Priority: p},
			},
		}
		_, err := TranslateTrafficShaper(spec)
		require.Error(t, err, "priority=%d", p)
		assert.True(t, errors.Is(err, ErrTrafficShaperBadPriority), "priority=%d", p)
	}
}

// TestTranslate_HashChangesOnSpecMutation guards against an accidental
// hash that ignores some spec fields. Mutating each field in turn must
// change the hash.
func TestTrafficShaperTranslate_HashChangesOnSpecMutation(t *testing.T) {
	base := &networkv1alpha1.TrafficShaperSpec{
		Interface: "eth0",
		Direction: networkv1alpha1.TrafficShaperDirectionEgress,
		Rules: []networkv1alpha1.TrafficShaperRule{
			{MatchCIDR: "10.0.0.0/8", Priority: 5, Rate: "100Mbit"},
		},
	}
	basePlan, err := TranslateTrafficShaper(base)
	require.NoError(t, err)

	// Mutate interface
	mut := *base
	mut.Interface = "eth1"
	plan, err := TranslateTrafficShaper(&mut)
	require.NoError(t, err)
	assert.NotEqual(t, basePlan.Hash, plan.Hash, "interface change must perturb hash")

	// Mutate direction
	mut = *base
	mut.Direction = networkv1alpha1.TrafficShaperDirectionBoth
	plan, err = TranslateTrafficShaper(&mut)
	require.NoError(t, err)
	assert.NotEqual(t, basePlan.Hash, plan.Hash, "direction change must perturb hash")

	// Mutate rule priority
	mut = *base
	mut.Rules = []networkv1alpha1.TrafficShaperRule{
		{MatchCIDR: "10.0.0.0/8", Priority: 3, Rate: "100Mbit"},
	}
	plan, err = TranslateTrafficShaper(&mut)
	require.NoError(t, err)
	assert.NotEqual(t, basePlan.Hash, plan.Hash, "priority change must perturb hash")

	// Mutate rule rate
	mut = *base
	mut.Rules = []networkv1alpha1.TrafficShaperRule{
		{MatchCIDR: "10.0.0.0/8", Priority: 5, Rate: "200Mbit"},
	}
	plan, err = TranslateTrafficShaper(&mut)
	require.NoError(t, err)
	assert.NotEqual(t, basePlan.Hash, plan.Hash, "rate change must perturb hash")
}

// TestApply_HappyPath asserts the translator's plan flows into SetPriority
// then EnsureAttached, in that order.
func TestTrafficShaperApply_HappyPath(t *testing.T) {
	plan := &TrafficShaperPlan{
		Interface: "eth0",
		Direction: networkv1alpha1.TrafficShaperDirectionEgress,
		Priority:  3,
	}
	backend := &fakeTCBackend{}

	require.NoError(t, ApplyTrafficShaper(backend, plan))

	require.Len(t, backend.setPriorityCalls, 1)
	assert.Equal(t, "eth0", backend.setPriorityCalls[0].iface)
	assert.Equal(t, uint32(3), backend.setPriorityCalls[0].priority)

	require.Len(t, backend.attachCalls, 1)
	assert.Equal(t, "eth0", backend.attachCalls[0].iface)
	assert.Equal(t, networkv1alpha1.TrafficShaperDirectionEgress, backend.attachCalls[0].direction)
}

// TestApply_SetPriorityFails surfaces the SetPriority error and skips the
// attach step (no half-applied state on this side of the seam).
func TestTrafficShaperApply_SetPriorityFails(t *testing.T) {
	plan := &TrafficShaperPlan{
		Interface: "eth0",
		Direction: networkv1alpha1.TrafficShaperDirectionEgress,
		Priority:  3,
	}
	backend := &fakeTCBackend{setPriorityErr: errors.New("map full")}

	err := ApplyTrafficShaper(backend, plan)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set priority")
	assert.Empty(t, backend.attachCalls, "attach must not run after SetPriority failure")
}

// TestApply_AttachFails leaves the priority map populated. This is by
// design: an unattached map entry is invisible to packets, and the next
// reconcile retries idempotently.
func TestTrafficShaperApply_AttachFails(t *testing.T) {
	plan := &TrafficShaperPlan{
		Interface: "eth0",
		Direction: networkv1alpha1.TrafficShaperDirectionEgress,
		Priority:  3,
	}
	backend := &fakeTCBackend{attachErr: errors.New("kernel < 6.6")}

	err := ApplyTrafficShaper(backend, plan)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attach TC program")
	assert.Len(t, backend.setPriorityCalls, 1, "SetPriority must have run before attach failure")
}

// TestApply_NilGuards: nil backend / nil plan are programmer errors and
// must surface as errors rather than panics.
func TestTrafficShaperApply_NilGuards(t *testing.T) {
	require.Error(t, ApplyTrafficShaper(nil, &TrafficShaperPlan{Interface: "eth0"}))
	require.Error(t, ApplyTrafficShaper(&fakeTCBackend{}, nil))
}

// TestRemove_HappyPath asserts the detach happens before the clear and
// both calls run on the right interface.
func TestTrafficShaperRemove_HappyPath(t *testing.T) {
	backend := &fakeTCBackend{}
	require.NoError(t, RemoveTrafficShaper(backend, "eth0"))
	require.Len(t, backend.detachCalls, 1)
	assert.Equal(t, "eth0", backend.detachCalls[0])
	require.Len(t, backend.clearPriorityCalls, 1)
	assert.Equal(t, "eth0", backend.clearPriorityCalls[0])
}

// TestRemove_DetachFails: a detach error short-circuits the clear so the
// next reconcile retries from the top.
func TestTrafficShaperRemove_DetachFails(t *testing.T) {
	backend := &fakeTCBackend{detachErr: errors.New("link gone")}
	err := RemoveTrafficShaper(backend, "eth0")
	require.Error(t, err)
	assert.Empty(t, backend.clearPriorityCalls, "clear must not run after detach failure")
}

// TestRemove_NilGuards: nil backend / empty interface are programmer
// errors.
func TestTrafficShaperRemove_NilGuards(t *testing.T) {
	require.Error(t, RemoveTrafficShaper(nil, "eth0"))
	require.Error(t, RemoveTrafficShaper(&fakeTCBackend{}, ""))
}
