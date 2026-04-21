//go:build linux

package nic

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

// fakeEthtoolClient implements the unexported ethtoolClient seam so tests can
// drive the NIC manager without touching real ethtool netlink sockets.
type fakeEthtoolClient struct {
	features     map[string]bool
	featuresErr  error
	changeErr    error
	changedCalls []map[string]bool
	stats        map[string]uint64
	statsErr     error
	driver       string
	driverErr    error
	closed       bool
}

func (f *fakeEthtoolClient) Features(string) (map[string]bool, error) {
	if f.featuresErr != nil {
		return nil, f.featuresErr
	}
	if f.features == nil {
		return map[string]bool{}, nil
	}
	out := make(map[string]bool, len(f.features))
	for k, v := range f.features {
		out[k] = v
	}
	return out, nil
}

func (f *fakeEthtoolClient) Change(_ string, cfg map[string]bool) error {
	if f.changeErr != nil {
		return f.changeErr
	}
	copied := make(map[string]bool, len(cfg))
	for k, v := range cfg {
		copied[k] = v
	}
	f.changedCalls = append(f.changedCalls, copied)
	return nil
}

func (f *fakeEthtoolClient) Stats(string) (map[string]uint64, error) {
	if f.statsErr != nil {
		return nil, f.statsErr
	}
	if f.stats == nil {
		return map[string]uint64{}, nil
	}
	out := make(map[string]uint64, len(f.stats))
	for k, v := range f.stats {
		out[k] = v
	}
	return out, nil
}

func (f *fakeEthtoolClient) DriverName(string) (string, error) {
	return f.driver, f.driverErr
}

func (f *fakeEthtoolClient) Close() { f.closed = true }

// fakeLink is a minimal netlink.Link implementation. We only ever read Attrs()
// so the rest of the interface is stubbed with zero values.
type fakeLink struct {
	attrs *netlink.LinkAttrs
}

func (l *fakeLink) Attrs() *netlink.LinkAttrs { return l.attrs }
func (l *fakeLink) Type() string              { return "device" }

type fakeLinkProvider struct {
	links map[string]netlink.Link
	err   error
}

func (f *fakeLinkProvider) LinkByName(name string) (netlink.Link, error) {
	if f.err != nil {
		return nil, f.err
	}
	link, ok := f.links[name]
	if !ok {
		return nil, errors.New("link not found")
	}
	return link, nil
}

func newLinkWithStats(name string, stats *netlink.LinkStatistics) netlink.Link {
	return &fakeLink{attrs: &netlink.LinkAttrs{Name: name, Statistics: stats}}
}

func TestGetStatisticsPopulatesFromNetlink(t *testing.T) {
	t.Parallel()

	linkStats := &netlink.LinkStatistics{
		RxPackets:  100,
		TxPackets:  200,
		RxBytes:    3000,
		TxBytes:    4000,
		RxErrors:   1,
		TxErrors:   2,
		RxDropped:  3,
		TxDropped:  4,
		Multicast:  5,
		Collisions: 6,
	}

	m := &Manager{
		interfaces:     make(map[string]*types.NetworkInterface),
		monitoringDone: make(chan struct{}),
		ethtool:        &fakeEthtoolClient{},
		links: &fakeLinkProvider{
			links: map[string]netlink.Link{"eth0": newLinkWithStats("eth0", linkStats)},
		},
	}

	stats, err := m.GetStatistics("eth0")
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.EqualValues(t, 100, stats.RxPackets)
	assert.EqualValues(t, 200, stats.TxPackets)
	assert.EqualValues(t, 3000, stats.RxBytes)
	assert.EqualValues(t, 4000, stats.TxBytes)
	assert.EqualValues(t, 5, stats.Multicast)
	assert.EqualValues(t, 6, stats.Collisions)
}

func TestGetStatisticsReturnsSentinelWhenUnsupported(t *testing.T) {
	t.Parallel()

	// Netlink reports zero counters and ethtool reports nothing — emulating a
	// driver that does not expose statistics. Manager must surface the
	// ErrNICStatisticsNotSupported sentinel rather than return zeroes silently.
	m := &Manager{
		interfaces:     make(map[string]*types.NetworkInterface),
		monitoringDone: make(chan struct{}),
		ethtool:        &fakeEthtoolClient{stats: map[string]uint64{}},
		links: &fakeLinkProvider{
			links: map[string]netlink.Link{"eth0": newLinkWithStats("eth0", &netlink.LinkStatistics{})},
		},
	}

	stats, err := m.GetStatistics("eth0")
	require.Error(t, err)
	assert.Nil(t, stats)
	assert.ErrorIs(t, err, ErrNICStatisticsNotSupported)
}

func TestGetStatisticsPropagatesLinkError(t *testing.T) {
	t.Parallel()

	m := &Manager{
		interfaces:     make(map[string]*types.NetworkInterface),
		monitoringDone: make(chan struct{}),
		ethtool:        &fakeEthtoolClient{},
		links:          &fakeLinkProvider{err: errors.New("netlink boom")},
	}

	stats, err := m.GetStatistics("eth0")
	require.Error(t, err)
	assert.Nil(t, stats)
	assert.Contains(t, err.Error(), "eth0")
	assert.Contains(t, err.Error(), "netlink boom")
}

func TestGetStatisticsPropagatesEthtoolErrorWhenNoNetlinkData(t *testing.T) {
	t.Parallel()

	m := &Manager{
		interfaces:     make(map[string]*types.NetworkInterface),
		monitoringDone: make(chan struct{}),
		ethtool:        &fakeEthtoolClient{statsErr: errors.New("eth boom")},
		links: &fakeLinkProvider{
			links: map[string]netlink.Link{"eth0": newLinkWithStats("eth0", &netlink.LinkStatistics{})},
		},
	}

	stats, err := m.GetStatistics("eth0")
	require.Error(t, err)
	assert.Nil(t, stats)
	assert.Contains(t, err.Error(), "eth0")
	assert.Contains(t, err.Error(), "eth boom")
}

func TestGetOffloadFeaturesReturnsSentinelWhenEmpty(t *testing.T) {
	t.Parallel()

	m := &Manager{
		interfaces:     make(map[string]*types.NetworkInterface),
		monitoringDone: make(chan struct{}),
		ethtool:        &fakeEthtoolClient{features: map[string]bool{}},
		links:          &fakeLinkProvider{},
	}

	_, err := m.getOffloadFeatures("eth0")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNICFeatureNotSupported)
}

func TestGetOffloadFeaturesPropagatesEthtoolError(t *testing.T) {
	t.Parallel()

	m := &Manager{
		interfaces:     make(map[string]*types.NetworkInterface),
		monitoringDone: make(chan struct{}),
		ethtool:        &fakeEthtoolClient{featuresErr: errors.New("boom")},
		links:          &fakeLinkProvider{},
	}

	_, err := m.getOffloadFeatures("eth0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "eth0")
	assert.Contains(t, err.Error(), "boom")
}

func TestGetOffloadFeaturesMapsFeatures(t *testing.T) {
	t.Parallel()

	m := &Manager{
		interfaces:     make(map[string]*types.NetworkInterface),
		monitoringDone: make(chan struct{}),
		ethtool: &fakeEthtoolClient{features: map[string]bool{
			"tx-checksumming":              true,
			"rx-checksumming":              true,
			"tcp-segmentation-offload":     true,
			"generic-segmentation-offload": false,
			"generic-receive-offload":      true,
			"large-receive-offload":        false,
		}},
		links: &fakeLinkProvider{},
	}

	features, err := m.getOffloadFeatures("eth0")
	require.NoError(t, err)
	assert.True(t, features.TxChecksum)
	assert.True(t, features.RxChecksum)
	assert.True(t, features.TSO)
	assert.False(t, features.GSO)
	assert.True(t, features.GRO)
	assert.False(t, features.LRO)
}
