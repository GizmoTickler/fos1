package suricata

import (
	"context"
	"fmt"
	"reflect"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	securityv1alpha1 "github.com/GizmoTickler/fos1/pkg/apis/security/v1alpha1"
)

// SuricataController reconciles SuricataInstance objects
type SuricataController struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// Reconcile handles SuricataInstance reconciliation
func (r *SuricataController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := klog.FromContext(ctx).WithValues("suricatainstance", req.NamespacedName)

	// Fetch the SuricataInstance
	instance := &securityv1alpha1.SuricataInstance{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return
			return ctrl.Result{}, nil
		}
		// Error reading the object
		return ctrl.Result{}, err
	}

	// Initialize status if needed
	if instance.Status.Phase == "" {
		instance.Status.Phase = "Pending"
		if err := r.Status().Update(ctx, instance); err != nil {
			log.Error(err, "Failed to update SuricataInstance status")
			return ctrl.Result{}, err
		}
	}

	// Handle ConfigMap for Suricata configuration
	configMap, err := r.reconcileConfigMap(ctx, instance)
	if err != nil {
		log.Error(err, "Failed to reconcile ConfigMap")
		r.updateStatusCondition(ctx, instance, "ConfigMapReady", "False", "ConfigMapError", err.Error())
		return ctrl.Result{}, err
	}
	r.updateStatusCondition(ctx, instance, "ConfigMapReady", "True", "ConfigMapCreated", "ConfigMap created successfully")

	// Handle Deployment
	deployment, err := r.reconcileDeployment(ctx, instance, configMap)
	if err != nil {
		log.Error(err, "Failed to reconcile Deployment")
		r.updateStatusCondition(ctx, instance, "DeploymentReady", "False", "DeploymentError", err.Error())
		return ctrl.Result{}, err
	}
	r.updateStatusCondition(ctx, instance, "DeploymentReady", "True", "DeploymentCreated", "Deployment created successfully")

	// Handle Service
	service, err := r.reconcileService(ctx, instance)
	if err != nil {
		log.Error(err, "Failed to reconcile Service")
		r.updateStatusCondition(ctx, instance, "ServiceReady", "False", "ServiceError", err.Error())
		return ctrl.Result{}, err
	}
	r.updateStatusCondition(ctx, instance, "ServiceReady", "True", "ServiceCreated", "Service created successfully")

	// Update status based on deployment
	if deployment.Status.ReadyReplicas > 0 {
		instance.Status.Phase = "Running"
		r.updateStatusCondition(ctx, instance, "Ready", "True", "Running", "Suricata is running")
	} else {
		instance.Status.Phase = "Pending"
		r.updateStatusCondition(ctx, instance, "Ready", "False", "NotRunning", "Suricata is not running")
	}

	// Update status
	if err := r.Status().Update(ctx, instance); err != nil {
		log.Error(err, "Failed to update SuricataInstance status")
		return ctrl.Result{}, err
	}

	// Requeue to update status periodically
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// reconcileConfigMap ensures the ConfigMap for Suricata configuration exists
func (r *SuricataController) reconcileConfigMap(ctx context.Context, instance *securityv1alpha1.SuricataInstance) (*corev1.ConfigMap, error) {
	log := klog.FromContext(ctx)

	// Generate Suricata configuration
	suricataConfig, err := generateSuricataConfig(instance)
	if err != nil {
		return nil, err
	}

	// Create ConfigMap object
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-config", instance.Name),
			Namespace: instance.Namespace,
		},
		Data: map[string]string{
			"suricata.yaml": suricataConfig,
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(instance, configMap, r.Scheme); err != nil {
		return nil, err
	}

	// Check if ConfigMap exists
	found := &corev1.ConfigMap{}
	err = r.Get(ctx, types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Create ConfigMap
		log.Info("Creating ConfigMap", "ConfigMap.Namespace", configMap.Namespace, "ConfigMap.Name", configMap.Name)
		err = r.Create(ctx, configMap)
		if err != nil {
			return nil, err
		}
		return configMap, nil
	} else if err != nil {
		return nil, err
	}

	// Update ConfigMap if needed
	if !reflect.DeepEqual(found.Data, configMap.Data) {
		found.Data = configMap.Data
		log.Info("Updating ConfigMap", "ConfigMap.Namespace", found.Namespace, "ConfigMap.Name", found.Name)
		err = r.Update(ctx, found)
		if err != nil {
			return nil, err
		}
	}

	return found, nil
}

// reconcileDeployment ensures the Deployment for Suricata exists
func (r *SuricataController) reconcileDeployment(ctx context.Context, instance *securityv1alpha1.SuricataInstance, configMap *corev1.ConfigMap) (*appsv1.Deployment, error) {
	log := klog.FromContext(ctx)

	// Define container resources
	resources := corev1.ResourceRequirements{}
	if instance.Spec.Resources != nil {
		resources = *instance.Spec.Resources
	}

	// Define container security context
	securityContext := &corev1.SecurityContext{
		Privileged:               &[]bool{true}[0],
		AllowPrivilegeEscalation: &[]bool{true}[0],
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{"NET_ADMIN", "NET_RAW", "SYS_NICE"},
		},
	}

	// Create Deployment object
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &[]int32{1}[0],
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": instance.Name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": instance.Name,
					},
				},
				Spec: corev1.PodSpec{
					HostNetwork: instance.Spec.HostNetwork,
					Containers: []corev1.Container{
						{
							Name:            "suricata",
							Image:           "jasonish/suricata:latest",
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command: []string{
								"/usr/bin/suricata",
								"-c", "/etc/suricata/suricata.yaml",
								"--set", fmt.Sprintf("vars.address-groups.HOME_NET=%s", getHomeNet(instance)),
							},
							SecurityContext: securityContext,
							Resources:       resources,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/etc/suricata",
								},
								{
									Name:      "logs",
									MountPath: "/var/log/suricata",
								},
								{
									Name:      "run",
									MountPath: "/var/run/suricata",
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "api",
									ContainerPort: 9999,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"pgrep", "suricata",
										},
									},
								},
								InitialDelaySeconds: 30,
								PeriodSeconds:       10,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"pgrep", "suricata",
										},
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       10,
							},
						},
					},
					Volumes: []corev1.Volume{
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
						{
							Name: "logs",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "run",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
					NodeSelector: instance.Spec.NodeSelector,
				},
			},
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(instance, deployment, r.Scheme); err != nil {
		return nil, err
	}

	// Check if Deployment exists
	found := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Create Deployment
		log.Info("Creating Deployment", "Deployment.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
		err = r.Create(ctx, deployment)
		if err != nil {
			return nil, err
		}
		return deployment, nil
	} else if err != nil {
		return nil, err
	}

	// Update Deployment if needed
	if !reflect.DeepEqual(found.Spec.Template.Spec.Containers[0].Image, deployment.Spec.Template.Spec.Containers[0].Image) ||
		!reflect.DeepEqual(found.Spec.Template.Spec.Containers[0].Command, deployment.Spec.Template.Spec.Containers[0].Command) ||
		!reflect.DeepEqual(found.Spec.Template.Spec.Containers[0].Resources, deployment.Spec.Template.Spec.Containers[0].Resources) ||
		!reflect.DeepEqual(found.Spec.Template.Spec.NodeSelector, deployment.Spec.Template.Spec.NodeSelector) {
		found.Spec.Template.Spec.Containers[0].Image = deployment.Spec.Template.Spec.Containers[0].Image
		found.Spec.Template.Spec.Containers[0].Command = deployment.Spec.Template.Spec.Containers[0].Command
		found.Spec.Template.Spec.Containers[0].Resources = deployment.Spec.Template.Spec.Containers[0].Resources
		found.Spec.Template.Spec.NodeSelector = deployment.Spec.Template.Spec.NodeSelector
		log.Info("Updating Deployment", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
		err = r.Update(ctx, found)
		if err != nil {
			return nil, err
		}
	}

	return found, nil
}

// reconcileService ensures the Service for Suricata exists
func (r *SuricataController) reconcileService(ctx context.Context, instance *securityv1alpha1.SuricataInstance) (*corev1.Service, error) {
	log := klog.FromContext(ctx)

	// Create Service object
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": instance.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "api",
					Port:       9999,
					TargetPort: intstr.FromString("api"),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(instance, service, r.Scheme); err != nil {
		return nil, err
	}

	// Check if Service exists
	found := &corev1.Service{}
	err := r.Get(ctx, types.NamespacedName{Name: service.Name, Namespace: service.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Create Service
		log.Info("Creating Service", "Service.Namespace", service.Namespace, "Service.Name", service.Name)
		err = r.Create(ctx, service)
		if err != nil {
			return nil, err
		}
		return service, nil
	} else if err != nil {
		return nil, err
	}

	// Update Service if needed
	if !reflect.DeepEqual(found.Spec.Ports, service.Spec.Ports) {
		found.Spec.Ports = service.Spec.Ports
		log.Info("Updating Service", "Service.Namespace", found.Namespace, "Service.Name", found.Name)
		err = r.Update(ctx, found)
		if err != nil {
			return nil, err
		}
	}

	return found, nil
}

// updateStatusCondition updates a condition in the SuricataInstance status
func (r *SuricataController) updateStatusCondition(ctx context.Context, instance *securityv1alpha1.SuricataInstance, conditionType, status, reason, message string) {
	// Find existing condition
	for i, condition := range instance.Status.Conditions {
		if condition.Type == conditionType {
			// Update existing condition
			if condition.Status != status || condition.Reason != reason || condition.Message != message {
				instance.Status.Conditions[i].Status = status
				instance.Status.Conditions[i].Reason = reason
				instance.Status.Conditions[i].Message = message
				instance.Status.Conditions[i].LastTransitionTime = metav1.Now()
			}
			return
		}
	}

	// Add new condition
	instance.Status.Conditions = append(instance.Status.Conditions, securityv1alpha1.SuricataInstanceCondition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// getHomeNet returns the HOME_NET value for Suricata configuration
func getHomeNet(instance *securityv1alpha1.SuricataInstance) string {
	// Default HOME_NET
	return "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
}

// generateSuricataConfig generates Suricata configuration YAML
func generateSuricataConfig(instance *securityv1alpha1.SuricataInstance) (string, error) {
	// This is a simplified version, in a real implementation you would generate a complete Suricata configuration
	config := `%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"

default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules

af-packet:
`

	// Add interfaces
	for _, iface := range instance.Spec.Interfaces {
		config += fmt.Sprintf("  - interface: %s\n", iface.Name)
		config += fmt.Sprintf("    threads: %d\n", iface.ThreadCount)
		config += fmt.Sprintf("    promisc: %t\n", iface.Promiscuous)
		config += fmt.Sprintf("    checksum-checks: %s\n", getBoolString(iface.Checksum, "yes", "no"))
		if iface.BPFFilter != "" {
			config += fmt.Sprintf("    bpf-filter: %s\n", iface.BPFFilter)
		}
	}

	// Add detection engine settings
	config += `
detect-engine:
  - profile: medium
  - custom-values:
      toclient-src-groups: 2
      toclient-dst-groups: 2
      toclient-sp-groups: 2
      toclient-dp-groups: 3
      toserver-src-groups: 2
      toserver-dst-groups: 4
      toserver-sp-groups: 2
      toserver-dp-groups: 25
  - sgh-mpm-context: auto
  - inspection-recursion-limit: 3000

app-layer:
  protocols:
    tls:
      enabled: yes
    http:
      enabled: yes
    ssh:
      enabled: yes
    smtp:
      enabled: yes
    dns:
      enabled: yes
    ftp:
      enabled: yes

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - ssh
        - flow
`

	// Add stats settings
	config += fmt.Sprintf(`
stats:
  enabled: yes
  interval: %s
`, instance.Spec.StatsInterval)

	return config, nil
}

// getBoolString returns a string representation of a boolean
func getBoolString(value bool, trueStr, falseStr string) string {
	if value {
		return trueStr
	}
	return falseStr
}

// SetupWithManager sets up the controller with the Manager
func (r *SuricataController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.SuricataInstance{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}
