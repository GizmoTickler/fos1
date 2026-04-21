package correlation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
)

var testSecurityGroupVersion = schema.GroupVersion{Group: "security.fos1.io", Version: "v1alpha1"}

func TestReconcileDisabledSetsDisabledStatusWithoutRuntimeObjects(t *testing.T) {
	t.Parallel()

	correlation := newTestEventCorrelation(false)
	controller, kubeClient := newTestController(t, correlation)

	result, err := controller.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: correlation.Name, Namespace: correlation.Namespace},
	})
	require.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)

	stored := &securityv1alpha1.EventCorrelation{}
	require.NoError(t, kubeClient.Get(context.Background(), client.ObjectKeyFromObject(correlation), stored))
	assert.Equal(t, "Disabled", stored.Status.Phase)

	ready := findCondition(t, stored.Status.Conditions, "Ready")
	assert.Equal(t, "False", ready.Status)
	assert.Equal(t, "Disabled", ready.Reason)

	assertConfigMapAbsent(t, kubeClient, correlation.Name+"-config", correlation.Namespace)
	assertDeploymentAbsent(t, kubeClient, correlation.Name, correlation.Namespace)
	assertServiceAbsent(t, kubeClient, correlation.Name, correlation.Namespace)
}

func TestReconcileCreatesRuntimeResourcesAndPendingStatusUntilDeploymentIsReady(t *testing.T) {
	t.Parallel()

	correlation := newTestEventCorrelation(true)
	controller, kubeClient := newTestController(t, correlation)

	result, err := controller.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: correlation.Name, Namespace: correlation.Namespace},
	})
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, result.RequeueAfter)

	configMap := &corev1.ConfigMap{}
	require.NoError(t, kubeClient.Get(context.Background(), types.NamespacedName{
		Name:      correlation.Name + "-config",
		Namespace: correlation.Namespace,
	}, configMap))
	config := decodeCorrelatorConfig(t, configMap.Data["config.json"])
	assert.Equal(t, correlation.Spec.Source, config.Source)
	assert.Equal(t, correlation.Spec.Sink, config.Sink)
	assert.Equal(t, correlation.Spec.MaxEventsInMemory, config.Runtime.MaxEventsInMemory)
	assert.Equal(t, correlation.Spec.MaxEventAge, config.Runtime.MaxEventAge)
	require.Len(t, config.Rules, 1)
	assert.Equal(t, "ssh-brute-force", config.Rules[0].Name)
	require.Len(t, config.Rules[0].Conditions, 1)
	assert.Equal(t, "contains", config.Rules[0].Conditions[0].Operator)

	deployment := &appsv1.Deployment{}
	require.NoError(t, kubeClient.Get(context.Background(), types.NamespacedName{
		Name:      correlation.Name,
		Namespace: correlation.Namespace,
	}, deployment))
	require.Len(t, deployment.Spec.Template.Spec.Containers, 1)
	container := deployment.Spec.Template.Spec.Containers[0]
	assert.Equal(t, "fos1/event-correlator:latest", container.Image)
	assert.Equal(t, []string{
		"/usr/bin/event-correlator",
		"--config", "/etc/correlator/config.json",
		"--max-events", "100000",
		"--max-age", "1h",
		"--output-format", "json",
	}, container.Command)
	assert.Equal(t, map[string]string{"kubernetes.io/os": "linux"}, deployment.Spec.Template.Spec.NodeSelector)
	assert.Equal(t, correlation.Name+"-config", deployment.Spec.Template.Spec.Volumes[0].ConfigMap.Name)

	service := &corev1.Service{}
	require.NoError(t, kubeClient.Get(context.Background(), types.NamespacedName{
		Name:      correlation.Name,
		Namespace: correlation.Namespace,
	}, service))
	require.Len(t, service.Spec.Ports, 1)
	assert.Equal(t, int32(8080), service.Spec.Ports[0].Port)
	assert.Equal(t, "api", service.Spec.Ports[0].TargetPort.StrVal)

	stored := &securityv1alpha1.EventCorrelation{}
	require.NoError(t, kubeClient.Get(context.Background(), client.ObjectKeyFromObject(correlation), stored))
	assert.Equal(t, "Pending", stored.Status.Phase)

	assertCondition(t, stored.Status.Conditions, "ConfigMapReady", "True", "ConfigMapCreated")
	assertCondition(t, stored.Status.Conditions, "ServiceReady", "True", "ServiceCreated")
	assertCondition(t, stored.Status.Conditions, "DeploymentReady", "False", "DeploymentNotReady")
	assertCondition(t, stored.Status.Conditions, "Ready", "False", "NotRunning")
}

func TestReconcileTransitionsToRunningWhenDeploymentReportsReadyReplicas(t *testing.T) {
	t.Parallel()

	correlation := newTestEventCorrelation(true)
	controller, kubeClient := newTestController(t, correlation)
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: correlation.Name, Namespace: correlation.Namespace}}

	_, err := controller.Reconcile(context.Background(), request)
	require.NoError(t, err)

	deployment := &appsv1.Deployment{}
	require.NoError(t, kubeClient.Get(context.Background(), types.NamespacedName{
		Name:      correlation.Name,
		Namespace: correlation.Namespace,
	}, deployment))
	deployment.Status.ReadyReplicas = 1
	require.NoError(t, kubeClient.Status().Update(context.Background(), deployment))

	result, err := controller.Reconcile(context.Background(), request)
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, result.RequeueAfter)

	stored := &securityv1alpha1.EventCorrelation{}
	require.NoError(t, kubeClient.Get(context.Background(), client.ObjectKeyFromObject(correlation), stored))
	assert.Equal(t, "Running", stored.Status.Phase)
	assertCondition(t, stored.Status.Conditions, "DeploymentReady", "True", "DeploymentReady")
	assertCondition(t, stored.Status.Conditions, "Ready", "True", "Running")
}

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
		Name:      correlation.Name,
		Namespace: correlation.Namespace,
	}, deployment))

	container := deployment.Spec.Template.Spec.Containers[0]
	assert.Contains(t, container.VolumeMounts, corev1.VolumeMount{
		Name:      "runtime-source-0",
		MountPath: "/var/run/fos1/events",
		ReadOnly:  true,
	})
	require.Len(t, deployment.Spec.Template.Spec.Volumes, 2)
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
		Name:      correlation.Name,
		Namespace: correlation.Namespace,
	}, deployment))

	container := deployment.Spec.Template.Spec.Containers[0]
	assert.Contains(t, container.VolumeMounts, corev1.VolumeMount{
		Name:      "runtime-sink-1",
		MountPath: "/var/log/correlator",
		ReadOnly:  false,
	})
	require.Len(t, deployment.Spec.Template.Spec.Volumes, 3)
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
		Name:      correlation.Name,
		Namespace: correlation.Namespace,
	}, deployment))

	container := deployment.Spec.Template.Spec.Containers[0]
	assert.Contains(t, container.VolumeMounts, corev1.VolumeMount{
		Name:      "runtime-sink-1",
		MountPath: "/var/log/correlator",
		ReadOnly:  false,
	})
	assert.Contains(t, deployment.Spec.Template.Spec.Volumes, corev1.Volume{
		Name: "runtime-sink-1",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/var/log/correlator",
				Type: hostPathDirectoryOrCreate(),
			},
		},
	})
}

func newTestController(t *testing.T, objects ...client.Object) (*EventCorrelationController, client.Client) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, appsv1.AddToScheme(scheme))
	scheme.AddKnownTypes(testSecurityGroupVersion, &securityv1alpha1.EventCorrelation{}, &securityv1alpha1.EventCorrelationList{})
	metav1.AddToGroupVersion(scheme, testSecurityGroupVersion)

	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.EventCorrelation{}, &appsv1.Deployment{}).
		WithObjects(objects...).
		Build()

	return &EventCorrelationController{
		Client: kubeClient,
		Scheme: scheme,
	}, kubeClient
}

func newTestEventCorrelation(enabled bool) *securityv1alpha1.EventCorrelation {
	return &securityv1alpha1.EventCorrelation{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "security.fos1.io/v1alpha1",
			Kind:       "EventCorrelation",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example-correlation",
			Namespace: "security",
		},
		Spec: securityv1alpha1.EventCorrelationSpec{
			Enabled: enabled,
			Source: securityv1alpha1.EventSource{
				Type:   "file",
				Path:   "/var/run/fos1/events/security-events.jsonl",
				Format: "jsonl",
			},
			Sink: securityv1alpha1.EventSink{
				Type:   "stdout",
				Format: "json",
			},
			MaxEventsInMemory: 100000,
			MaxEventAge:       "1h",
			NodeSelector: map[string]string{
				"kubernetes.io/os": "linux",
			},
			Rules: []securityv1alpha1.CorrelationRule{
				{
					Name:        "ssh-brute-force",
					Description: "Detect SSH brute force attacks",
					Threshold:   5,
					TimeWindow:  "5m",
					Severity:    "high",
					Action:      "alert",
					Conditions: []securityv1alpha1.CorrelationCondition{
						{
							Field:    "signature",
							Operator: "contains",
							Value:    "SSH",
						},
					},
				},
			},
		},
	}
}

func assertCondition(t *testing.T, conditions []securityv1alpha1.EventCorrelationCondition, conditionType, status, reason string) {
	t.Helper()

	condition := findCondition(t, conditions, conditionType)
	assert.Equal(t, status, condition.Status)
	assert.Equal(t, reason, condition.Reason)
}

func findCondition(t *testing.T, conditions []securityv1alpha1.EventCorrelationCondition, conditionType string) securityv1alpha1.EventCorrelationCondition {
	t.Helper()

	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition
		}
	}

	t.Fatalf("condition %q not found", conditionType)
	return securityv1alpha1.EventCorrelationCondition{}
}

func assertConfigMapAbsent(t *testing.T, kubeClient client.Client, name, namespace string) {
	t.Helper()

	configMap := &corev1.ConfigMap{}
	err := kubeClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: namespace}, configMap)
	assert.True(t, client.IgnoreNotFound(err) == nil && err != nil, "expected ConfigMap %s/%s to be absent", namespace, name)
}

func assertDeploymentAbsent(t *testing.T, kubeClient client.Client, name, namespace string) {
	t.Helper()

	deployment := &appsv1.Deployment{}
	err := kubeClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: namespace}, deployment)
	assert.True(t, client.IgnoreNotFound(err) == nil && err != nil, "expected Deployment %s/%s to be absent", namespace, name)
}

func assertServiceAbsent(t *testing.T, kubeClient client.Client, name, namespace string) {
	t.Helper()

	service := &corev1.Service{}
	err := kubeClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: namespace}, service)
	assert.True(t, client.IgnoreNotFound(err) == nil && err != nil, "expected Service %s/%s to be absent", namespace, name)
}

func decodeCorrelatorConfig(t *testing.T, raw string) eventCorrelatorConfig {
	t.Helper()

	var config eventCorrelatorConfig
	require.NoError(t, json.Unmarshal([]byte(raw), &config))
	return config
}
