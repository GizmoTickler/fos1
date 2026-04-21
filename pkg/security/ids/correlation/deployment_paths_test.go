package correlation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
)

func TestBuildRuntimeFileMountPlanAddsSourceAndFileSinkMounts(t *testing.T) {
	t.Parallel()

	plan, err := buildRuntimeFileMountPlan(
		securityv1alpha1.EventSource{
			Type:   "file",
			Path:   "/var/run/fos1/events/security-events.jsonl",
			Format: "jsonl",
		},
		securityv1alpha1.EventSink{
			Type:   "file",
			Path:   "/var/log/correlator/correlated-events.json",
			Format: "json",
		},
	)
	require.NoError(t, err)
	require.Len(t, plan.volumes, 2)
	require.Len(t, plan.mounts, 2)

	assert.Equal(t, "/var/run/fos1/events", plan.volumes[0].HostPath.Path)
	assert.Equal(t, "/var/run/fos1/events", plan.mounts[0].MountPath)
	assert.True(t, plan.mounts[0].ReadOnly)

	assert.Equal(t, "/var/log/correlator", plan.volumes[1].HostPath.Path)
	assert.Equal(t, "/var/log/correlator", plan.mounts[1].MountPath)
	assert.False(t, plan.mounts[1].ReadOnly)
}

func TestBuildRuntimeFileMountPlanRejectsSourcePathOutsideApprovedPrefixes(t *testing.T) {
	t.Parallel()

	_, err := buildRuntimeFileMountPlan(
		securityv1alpha1.EventSource{
			Type:   "file",
			Path:   "/tmp/security-events.jsonl",
			Format: "jsonl",
		},
		securityv1alpha1.EventSink{
			Type:   "stdout",
			Format: "json",
		},
	)
	require.Error(t, err)
	assert.ErrorContains(t, err, `source.path "/tmp/security-events.jsonl"`)
}

func TestBuildRuntimeFileMountPlanReusesSharedParentDirectory(t *testing.T) {
	t.Parallel()

	plan, err := buildRuntimeFileMountPlan(
		securityv1alpha1.EventSource{
			Type:   "file",
			Path:   "/var/log/fos1/correlation/security-events.jsonl",
			Format: "jsonl",
		},
		securityv1alpha1.EventSink{
			Type:   "file",
			Path:   "/var/log/fos1/correlation/correlated-events.json",
			Format: "json",
		},
	)
	require.NoError(t, err)
	require.Len(t, plan.volumes, 1)
	require.Len(t, plan.mounts, 1)
	assert.Equal(t, "/var/log/fos1/correlation", plan.volumes[0].HostPath.Path)
	assert.False(t, plan.mounts[0].ReadOnly)
}
