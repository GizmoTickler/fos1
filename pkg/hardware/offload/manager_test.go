//go:build linux

package offload

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GizmoTickler/fos1/pkg/hardware/types"
)

type fakeEthtoolClient struct {
	stats    map[string]uint64
	statsErr error
}

func (f *fakeEthtoolClient) Features(string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

func (f *fakeEthtoolClient) Change(string, map[string]bool) error {
	return nil
}

func (f *fakeEthtoolClient) Stats(string) (map[string]uint64, error) {
	if f.statsErr != nil {
		return nil, f.statsErr
	}

	return f.stats, nil
}

func (f *fakeEthtoolClient) Close() {}

func TestGetOffloadStatisticsPopulatesAvailableCounters(t *testing.T) {
	t.Parallel()

	manager := &Manager{
		ethtool: &fakeEthtoolClient{
			stats: map[string]uint64{
				"tx_checksum_ipv4":  11,
				"rx-checksum-tcp":   22,
				"tx_tcp_seg_good":   33,
				"gro_packets":       44,
				"lro-aggregated":    55,
				"unrelated_counter": 999,
			},
		},
		capabilities: make(map[string]*types.OffloadCapabilities),
	}

	stats, err := manager.GetOffloadStatistics("eth0")
	require.NoError(t, err)

	assert.Equal(t, "eth0", stats.Interface)
	assert.EqualValues(t, 11, stats.TxChecksumIPv4)
	assert.EqualValues(t, 22, stats.RxChecksumTCP)
	assert.EqualValues(t, 33, stats.TxTCPSegmentation)
	assert.EqualValues(t, 44, stats.RxGRO)
	assert.EqualValues(t, 55, stats.RxLRO)
	assert.Contains(t, stats.UnsupportedCounters, "TxChecksumIPv6")
	assert.Contains(t, stats.UnsupportedCounters, "TxChecksumUDP")
	assert.NotContains(t, stats.UnsupportedCounters, "TxChecksumIPv4")
	assert.NotContains(t, stats.UnsupportedCounters, "RxChecksumTCP")
	assert.NotContains(t, stats.UnsupportedCounters, "TxTCPSegmentation")
	assert.NotContains(t, stats.UnsupportedCounters, "RxGRO")
	assert.NotContains(t, stats.UnsupportedCounters, "RxLRO")
}

func TestGetOffloadStatisticsReturnsExplicitUnsupportedError(t *testing.T) {
	t.Parallel()

	manager := &Manager{
		ethtool: &fakeEthtoolClient{
			stats: map[string]uint64{
				"rx_packets": 10,
				"tx_packets": 20,
			},
		},
		capabilities: make(map[string]*types.OffloadCapabilities),
	}

	stats, err := manager.GetOffloadStatistics("eth0")
	require.Error(t, err)
	assert.Nil(t, stats)
	assert.ErrorIs(t, err, ErrOffloadStatisticsNotSupported)
}

func TestGetOffloadStatisticsPropagatesStatsErrors(t *testing.T) {
	t.Parallel()

	manager := &Manager{
		ethtool: &fakeEthtoolClient{
			statsErr: errors.New("boom"),
		},
		capabilities: make(map[string]*types.OffloadCapabilities),
	}

	stats, err := manager.GetOffloadStatistics("eth0")
	require.Error(t, err)
	assert.Nil(t, stats)
	assert.Contains(t, err.Error(), "failed to get offload statistics")
	assert.Contains(t, err.Error(), "boom")
}
