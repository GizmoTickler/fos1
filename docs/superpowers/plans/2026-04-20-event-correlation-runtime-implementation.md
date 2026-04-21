# Event-Correlation Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the `EventCorrelation` runtime on a repo-owned, buildable, file-based contract that the controller can actually mount and run.

**Architecture:** Keep the current `EventCorrelation` CRD and correlator runtime deliberately small. The runtime continues to support only file input plus file or stdout output, while the controller becomes responsible for validating allowed host paths and wiring the source and sink parent directories into the pod with explicit read/write semantics. The repo also adds an owned Docker build path so `fos1/event-correlator:latest` is no longer an unspecified external artifact.

**Tech Stack:** Go, controller-runtime, Kubernetes core API types, Docker, Go unit tests, fake Kubernetes client tests

---

## File Map

- Modify: `pkg/security/ids/correlation/runtime.go`
  - tighten runtime config validation so the owned file contract fails early and clearly
- Modify: `pkg/security/ids/correlation/runtime_test.go`
  - lock in the validation behavior with targeted tests
- Create: `pkg/security/ids/correlation/deployment_paths.go`
  - keep path-prefix validation and volume/mount derivation out of `controller.go`
- Create: `pkg/security/ids/correlation/deployment_paths_test.go`
  - unit-test allowed prefixes, mount read/write semantics, and shared-directory reuse
- Modify: `pkg/security/ids/correlation/controller.go`
  - replace the current sink-only `EmptyDir` deployment shape with derived hostPath-backed source/sink mounts
- Modify: `pkg/security/ids/correlation/controller_test.go`
  - verify the controller uses the new runtime mount plan and rejects invalid paths
- Create: `build/event-correlator/Dockerfile`
  - provide the repo-owned build path for `fos1/event-correlator:latest`
- Modify: `docs/observability-architecture.md`
  - reflect the new repo-owned build and mount contract without over-claiming live event proof

## Task 1: Tighten Runtime Validation For The Owned File Contract

**Files:**
- Modify: `pkg/security/ids/correlation/runtime.go`
- Modify: `pkg/security/ids/correlation/runtime_test.go`

- [ ] **Step 1: Write the failing validation test**

Add these tests to `pkg/security/ids/correlation/runtime_test.go`:

```go
func TestNewRuntimeRejectsFileSourceWithoutPath(t *testing.T) {
	t.Parallel()

	_, err := NewRuntime(eventCorrelatorConfig{
		Source: securityv1alpha1.EventSource{
			Type:   "file",
			Format: "jsonl",
		},
		Sink: securityv1alpha1.EventSink{
			Type:   "stdout",
			Format: "json",
		},
	}, RuntimeOptions{
		HTTPAddr: "127.0.0.1:0",
	})

	require.Error(t, err)
	assert.ErrorContains(t, err, "source.path is required for file source")
}

func TestNewRuntimeRejectsFileSinkWithoutPath(t *testing.T) {
	t.Parallel()

	_, err := NewRuntime(eventCorrelatorConfig{
		Source: securityv1alpha1.EventSource{
			Type:   "file",
			Path:   "/var/run/fos1/events/security-events.jsonl",
			Format: "jsonl",
		},
		Sink: securityv1alpha1.EventSink{
			Type:   "file",
			Format: "json",
		},
	}, RuntimeOptions{
		HTTPAddr: "127.0.0.1:0",
	})

	require.Error(t, err)
	assert.ErrorContains(t, err, "sink.path is required for file sink")
}
```

- [ ] **Step 2: Run the targeted tests to verify the first one fails**

Run:

```bash
go test ./pkg/security/ids/correlation -run 'TestNewRuntimeRejectsFileSourceWithoutPath|TestNewRuntimeRejectsFileSinkWithoutPath' -count=1
```

Expected:

- `TestNewRuntimeRejectsFileSourceWithoutPath` fails because `validateRuntimeConfig()` does not currently require `source.path`
- `TestNewRuntimeRejectsFileSinkWithoutPath` may already pass via `newSink()`, which is acceptable because it locks in existing behavior

- [ ] **Step 3: Add the minimal validation in `runtime.go`**

Update `validateRuntimeConfig()` in `pkg/security/ids/correlation/runtime.go` to this shape:

```go
func validateRuntimeConfig(config eventCorrelatorConfig) error {
	if config.Source.Type != "file" {
		return fmt.Errorf("unsupported source type %q", config.Source.Type)
	}
	if config.Source.Path == "" {
		return fmt.Errorf("source.path is required for file source")
	}
	if config.Source.Format != "" && config.Source.Format != "jsonl" {
		return fmt.Errorf("unsupported source format %q", config.Source.Format)
	}

	switch config.Sink.Type {
	case "file", "stdout":
	default:
		return fmt.Errorf("unsupported sink type %q", config.Sink.Type)
	}
	if config.Sink.Type == "file" && config.Sink.Path == "" {
		return fmt.Errorf("sink.path is required for file sink")
	}
	if config.Sink.Format != "" && config.Sink.Format != "json" {
		return fmt.Errorf("unsupported sink format %q", config.Sink.Format)
	}

	return nil
}
```

- [ ] **Step 4: Run the runtime package tests**

Run:

```bash
go test ./pkg/security/ids/correlation -count=1
```

Expected:

- all tests in `pkg/security/ids/correlation` pass

- [ ] **Step 5: Commit the runtime validation change**

Run:

```bash
git add pkg/security/ids/correlation/runtime.go pkg/security/ids/correlation/runtime_test.go
git commit -m "test: tighten event correlator runtime validation"
```

## Task 2: Add Path Validation And Mount-Plan Helpers

**Files:**
- Create: `pkg/security/ids/correlation/deployment_paths.go`
- Create: `pkg/security/ids/correlation/deployment_paths_test.go`

- [ ] **Step 1: Write the failing helper tests**

Create `pkg/security/ids/correlation/deployment_paths_test.go` with these tests:

```go
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
```

- [ ] **Step 2: Run the helper tests to watch them fail**

Run:

```bash
go test ./pkg/security/ids/correlation -run 'TestBuildRuntimeFileMountPlanAddsSourceAndFileSinkMounts|TestBuildRuntimeFileMountPlanRejectsSourcePathOutsideApprovedPrefixes|TestBuildRuntimeFileMountPlanReusesSharedParentDirectory' -count=1
```

Expected:

- build fails because `buildRuntimeFileMountPlan` does not exist yet

- [ ] **Step 3: Implement the helper file**

Create `pkg/security/ids/correlation/deployment_paths.go` with this implementation:

```go
package correlation

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
)

var allowedCorrelatorSourcePrefixes = []string{
	"/var/run/fos1/events/",
	"/var/log/fos1/",
}

var allowedCorrelatorSinkPrefixes = []string{
	"/var/log/fos1/",
	"/var/log/correlator/",
}

type runtimeFileMountPlan struct {
	volumes []corev1.Volume
	mounts  []corev1.VolumeMount
}

func buildRuntimeFileMountPlan(source securityv1alpha1.EventSource, sink securityv1alpha1.EventSink) (runtimeFileMountPlan, error) {
	plan := runtimeFileMountPlan{}
	seen := map[string]int{}

	if err := addRuntimeDirectoryMount(&plan, seen, "source", source.Path, allowedCorrelatorSourcePrefixes, true); err != nil {
		return runtimeFileMountPlan{}, err
	}
	if sink.Type == "file" {
		if err := addRuntimeDirectoryMount(&plan, seen, "sink", sink.Path, allowedCorrelatorSinkPrefixes, false); err != nil {
			return runtimeFileMountPlan{}, err
		}
	}

	return plan, nil
}

func addRuntimeDirectoryMount(plan *runtimeFileMountPlan, seen map[string]int, role, filePath string, allowedPrefixes []string, readOnly bool) error {
	cleanedPath := filepath.Clean(filePath)
	if err := validateApprovedPath(role, cleanedPath, allowedPrefixes); err != nil {
		return err
	}

	directory := filepath.Dir(cleanedPath)
	if mountIndex, ok := seen[directory]; ok {
		if !readOnly {
			plan.mounts[mountIndex].ReadOnly = false
		}
		return nil
	}

	volumeName := fmt.Sprintf("runtime-%s-%d", role, len(plan.volumes))
	plan.volumes = append(plan.volumes, corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: directory,
				Type: hostPathDirectoryOrCreate(),
			},
		},
	})
	plan.mounts = append(plan.mounts, corev1.VolumeMount{
		Name:      volumeName,
		MountPath: directory,
		ReadOnly:  readOnly,
	})
	seen[directory] = len(plan.mounts) - 1

	return nil
}

func validateApprovedPath(role, filePath string, allowedPrefixes []string) error {
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(filePath, prefix) {
			return nil
		}
	}

	sorted := append([]string(nil), allowedPrefixes...)
	sort.Strings(sorted)
	return fmt.Errorf("%s.path %q must be under one of %v", role, filePath, sorted)
}

func hostPathDirectoryOrCreate() *corev1.HostPathType {
	value := corev1.HostPathDirectoryOrCreate
	return &value
}
```

- [ ] **Step 4: Run the helper tests and full package tests**

Run:

```bash
go test ./pkg/security/ids/correlation -run 'TestBuildRuntimeFileMountPlanAddsSourceAndFileSinkMounts|TestBuildRuntimeFileMountPlanRejectsSourcePathOutsideApprovedPrefixes|TestBuildRuntimeFileMountPlanReusesSharedParentDirectory' -count=1
go test ./pkg/security/ids/correlation -count=1
```

Expected:

- the three new helper tests pass
- the full package still passes

- [ ] **Step 5: Commit the path helper change**

Run:

```bash
git add pkg/security/ids/correlation/deployment_paths.go pkg/security/ids/correlation/deployment_paths_test.go
git commit -m "feat: add event correlator mount plan helpers"
```

## Task 3: Wire The Controller To The Runtime Mount Plan

**Files:**
- Modify: `pkg/security/ids/correlation/controller.go`
- Modify: `pkg/security/ids/correlation/controller_test.go`

- [ ] **Step 1: Write the failing controller tests**

Add these tests to `pkg/security/ids/correlation/controller_test.go`:

```go
func TestReconcileAddsSourceHostPathMountForStdoutSink(t *testing.T) {
	t.Parallel()

	correlation := newTestEventCorrelation(true)
	controller, kubeClient := newTestController(t, correlation)

	_, err := controller.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: correlation.Name, Namespace: correlation.Namespace},
	})
	require.NoError(t, err)

	deployment := &appsv1.Deployment{}
	require.NoError(t, kubeClient.Get(context.Background(), types.NamespacedName{
		Name: correlation.Name, Namespace: correlation.Namespace,
	}, deployment))

	container := deployment.Spec.Template.Spec.Containers[0]
	assert.Contains(t, container.VolumeMounts, corev1.VolumeMount{
		Name:      "runtime-source-0",
		MountPath: "/var/run/fos1/events",
		ReadOnly:  true,
	})
	assert.Equal(t, "/var/run/fos1/events", deployment.Spec.Template.Spec.Volumes[1].HostPath.Path)
}

func TestReconcileAddsWritableSinkMountForFileSink(t *testing.T) {
	t.Parallel()

	correlation := newTestEventCorrelation(true)
	correlation.Spec.Sink = securityv1alpha1.EventSink{
		Type:   "file",
		Path:   "/var/log/correlator/correlated-events.json",
		Format: "json",
	}
	controller, kubeClient := newTestController(t, correlation)

	_, err := controller.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: correlation.Name, Namespace: correlation.Namespace},
	})
	require.NoError(t, err)

	deployment := &appsv1.Deployment{}
	require.NoError(t, kubeClient.Get(context.Background(), types.NamespacedName{
		Name: correlation.Name, Namespace: correlation.Namespace,
	}, deployment))

	container := deployment.Spec.Template.Spec.Containers[0]
	assert.Contains(t, container.VolumeMounts, corev1.VolumeMount{
		Name:      "runtime-sink-1",
		MountPath: "/var/log/correlator",
		ReadOnly:  false,
	})
	assert.Equal(t, "/var/log/correlator", deployment.Spec.Template.Spec.Volumes[2].HostPath.Path)
}

func TestReconcileRejectsPathsOutsideApprovedPrefixes(t *testing.T) {
	t.Parallel()

	correlation := newTestEventCorrelation(true)
	correlation.Spec.Source.Path = "/tmp/security-events.jsonl"
	controller, _ := newTestController(t, correlation)

	_, err := controller.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: correlation.Name, Namespace: correlation.Namespace},
	})

	require.Error(t, err)
	assert.ErrorContains(t, err, `source.path "/tmp/security-events.jsonl"`)
}

func TestReconcileUpdatesDeploymentWhenSinkContractChanges(t *testing.T) {
	t.Parallel()

	correlation := newTestEventCorrelation(true)
	controller, kubeClient := newTestController(t, correlation)
	request := ctrl.Request{
		NamespacedName: types.NamespacedName{Name: correlation.Name, Namespace: correlation.Namespace},
	}

	_, err := controller.Reconcile(context.Background(), request)
	require.NoError(t, err)

	stored := &securityv1alpha1.EventCorrelation{}
	require.NoError(t, kubeClient.Get(context.Background(), client.ObjectKeyFromObject(correlation), stored))
	stored.Spec.Sink = securityv1alpha1.EventSink{
		Type:   "file",
		Path:   "/var/log/correlator/correlated-events.json",
		Format: "json",
	}
	require.NoError(t, kubeClient.Update(context.Background(), stored))

	_, err = controller.Reconcile(context.Background(), request)
	require.NoError(t, err)

	deployment := &appsv1.Deployment{}
	require.NoError(t, kubeClient.Get(context.Background(), types.NamespacedName{
		Name: correlation.Name, Namespace: correlation.Namespace,
	}, deployment))

	container := deployment.Spec.Template.Spec.Containers[0]
	assert.Contains(t, container.VolumeMounts, corev1.VolumeMount{
		Name:      "runtime-sink-1",
		MountPath: "/var/log/correlator",
		ReadOnly:  false,
	})
}
```

- [ ] **Step 2: Run the targeted controller tests to verify they fail**

Run:

```bash
go test ./pkg/security/ids/correlation -run 'TestReconcileAddsSourceHostPathMountForStdoutSink|TestReconcileAddsWritableSinkMountForFileSink|TestReconcileRejectsPathsOutsideApprovedPrefixes|TestReconcileUpdatesDeploymentWhenSinkContractChanges' -count=1
```

Expected:

- the mount tests fail because the Deployment still uses the hard-coded `config` volume plus `EmptyDir`
- the invalid-path test fails because the controller does not call any path validation yet
- the update-path test fails because the controller only compares image, command, resources, and node selector when deciding whether to update an existing Deployment

- [ ] **Step 3: Replace the hard-coded runtime volumes in `controller.go`**

Update `reconcileDeployment()` in `pkg/security/ids/correlation/controller.go` so the volume logic looks like this:

```go
	runtimePlan, err := buildRuntimeFileMountPlan(instance.Spec.Source, instance.Spec.Sink)
	if err != nil {
		return nil, err
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "config",
			MountPath: "/etc/correlator",
		},
	}
	volumeMounts = append(volumeMounts, runtimePlan.mounts...)

	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: configMap.Name,
					},
				},
			},
		},
	}
	volumes = append(volumes, runtimePlan.volumes...)
```

Then replace the existing `VolumeMounts` and `Volumes` blocks with:

```go
							VolumeMounts: volumeMounts,
```

and:

```go
					Volumes:      volumes,
```

Delete the old `logs` `EmptyDir` volume and its mount entirely.

Also update the existing Deployment-update branch so it compares and copies the runtime volumes and mounts:

```go
	if !reflect.DeepEqual(found.Spec.Template.Spec.Containers[0].Image, deployment.Spec.Template.Spec.Containers[0].Image) ||
		!reflect.DeepEqual(found.Spec.Template.Spec.Containers[0].Command, deployment.Spec.Template.Spec.Containers[0].Command) ||
		!reflect.DeepEqual(found.Spec.Template.Spec.Containers[0].VolumeMounts, deployment.Spec.Template.Spec.Containers[0].VolumeMounts) ||
		!reflect.DeepEqual(found.Spec.Template.Spec.Containers[0].Resources, deployment.Spec.Template.Spec.Containers[0].Resources) ||
		!reflect.DeepEqual(found.Spec.Template.Spec.Volumes, deployment.Spec.Template.Spec.Volumes) ||
		!reflect.DeepEqual(found.Spec.Template.Spec.NodeSelector, deployment.Spec.Template.Spec.NodeSelector) {
		found.Spec.Template.Spec.Containers[0].Image = deployment.Spec.Template.Spec.Containers[0].Image
		found.Spec.Template.Spec.Containers[0].Command = deployment.Spec.Template.Spec.Containers[0].Command
		found.Spec.Template.Spec.Containers[0].VolumeMounts = deployment.Spec.Template.Spec.Containers[0].VolumeMounts
		found.Spec.Template.Spec.Containers[0].Resources = deployment.Spec.Template.Spec.Containers[0].Resources
		found.Spec.Template.Spec.Volumes = deployment.Spec.Template.Spec.Volumes
		found.Spec.Template.Spec.NodeSelector = deployment.Spec.Template.Spec.NodeSelector
	}
```

- [ ] **Step 4: Run the controller tests and full package tests**

Run:

```bash
go test ./pkg/security/ids/correlation -run 'TestReconcileAddsSourceHostPathMountForStdoutSink|TestReconcileAddsWritableSinkMountForFileSink|TestReconcileRejectsPathsOutsideApprovedPrefixes|TestReconcileUpdatesDeploymentWhenSinkContractChanges|TestReconcileCreatesRuntimeResourcesAndPendingStatusUntilDeploymentIsReady|TestReconcileTransitionsToRunningWhenDeploymentReportsReadyReplicas' -count=1
go test ./pkg/security/ids/correlation -count=1
```

Expected:

- the new controller tests pass
- the existing controller status tests still pass

- [ ] **Step 5: Commit the controller wiring change**

Run:

```bash
git add pkg/security/ids/correlation/controller.go pkg/security/ids/correlation/controller_test.go
git commit -m "feat: wire event correlator deployment mounts"
```

## Task 4: Add The Repo-Owned Event-Correlator Image Build Path

**Files:**
- Create: `build/event-correlator/Dockerfile`

- [ ] **Step 1: Verify the Docker build path is currently missing**

Run:

```bash
docker build -f build/event-correlator/Dockerfile .
```

Expected:

- Docker fails immediately because `build/event-correlator/Dockerfile` does not exist

- [ ] **Step 2: Add the Dockerfile**

Create `build/event-correlator/Dockerfile` with this content:

```dockerfile
FROM golang:1.26 AS builder

WORKDIR /workspace
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o /workspace/event-correlator ./cmd/event-correlator

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /workspace/event-correlator /usr/bin/event-correlator

ENTRYPOINT ["/usr/bin/event-correlator"]
```

- [ ] **Step 3: Build the image and smoke-test the binary path**

Run:

```bash
docker build -t fos1/event-correlator:latest -f build/event-correlator/Dockerfile .
docker run --rm --entrypoint /usr/bin/event-correlator fos1/event-correlator:latest -h
```

Expected:

- Docker build succeeds
- the second command prints the Go flag usage for `event-correlator`, including `-config string`

- [ ] **Step 4: Run the command package and runtime package tests**

Run:

```bash
go test ./cmd/event-correlator ./pkg/security/ids/correlation/... -count=1
```

Expected:

- the command package and correlation packages pass

- [ ] **Step 5: Commit the build artifact**

Run:

```bash
git add build/event-correlator/Dockerfile
git commit -m "build: add event correlator image"
```

## Task 5: Update Observability Docs And Run Full Verification

**Files:**
- Modify: `docs/observability-architecture.md`

- [ ] **Step 1: Mark the stale external-only wording**

Run:

```bash
rg -n 'the image `fos1/event-correlator:latest` must exist and be pullable|must have the referenced source file available' docs/observability-architecture.md
```

Expected:

- the grep finds the stale wording that still treats the correlator image and mounted source path as purely external assumptions

- [ ] **Step 2: Rewrite the event-correlation doc section**

Update `docs/observability-architecture.md` so the event-correlation section says all of the following:

```md
- the repository now owns a Docker build path for `fos1/event-correlator:latest`
- the controller validates `spec.source.path` and file-based `spec.sink.path` against approved prefixes before reconciling the Deployment
- the controller mounts the source parent directory read-only and the file sink parent directory read-write using hostPath volumes
- the repository still does not prove live security-event ingestion into the correlator end to end
```

Also update the "External runtime dependencies" subsection so it no longer claims the image itself is unspecified, but it still keeps the non-goal boundary around live event proof and durable downstream sinks.

- [ ] **Step 3: Verify the doc now states the repo-owned contract clearly**

Run:

```bash
rg -n 'repo.*Docker build path|validates `spec.source.path`|mounts the source parent directory read-only|does not prove live security-event ingestion' docs/observability-architecture.md
```

Expected:

- all four phrases are found in the updated doc

- [ ] **Step 4: Run the full verification sweep**

Run:

```bash
go test ./cmd/event-correlator ./pkg/security/ids/correlation/... -count=1
make verify-mainline
```

Expected:

- targeted event-correlator tests pass
- `make verify-mainline` exits successfully

- [ ] **Step 5: Commit the documentation and verification-complete tree**

Run:

```bash
git add docs/observability-architecture.md
git commit -m "docs: record owned event correlator runtime contract"
```
