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
