package zeek

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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/varuntirumala1/fos1/pkg/apis/security/v1alpha1"
)

// ZeekController reconciles ZeekInstance objects
type ZeekController struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// Reconcile handles ZeekInstance reconciliation
func (r *ZeekController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := klog.FromContext(ctx).WithValues("zeekinstance", req.NamespacedName)

	// Fetch the ZeekInstance
	instance := &securityv1alpha1.ZeekInstance{}
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
			log.Error(err, "Failed to update ZeekInstance status")
			return ctrl.Result{}, err
		}
	}

	// Handle ConfigMap for Zeek configuration
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
		r.updateStatusCondition(ctx, instance, "Ready", "True", "Running", "Zeek is running")
	} else {
		instance.Status.Phase = "Pending"
		r.updateStatusCondition(ctx, instance, "Ready", "False", "NotRunning", "Zeek is not running")
	}

	// Update status
	if err := r.Status().Update(ctx, instance); err != nil {
		log.Error(err, "Failed to update ZeekInstance status")
		return ctrl.Result{}, err
	}

	// Requeue to update status periodically
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// reconcileConfigMap ensures the ConfigMap for Zeek configuration exists
func (r *ZeekController) reconcileConfigMap(ctx context.Context, instance *securityv1alpha1.ZeekInstance) (*corev1.ConfigMap, error) {
	log := klog.FromContext(ctx)

	// Generate Zeek configuration
	zeekConfig, err := generateZeekConfig(instance)
	if err != nil {
		return nil, err
	}

	// Generate local.zeek script
	localZeek, err := generateLocalZeek(instance)
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
			"zeekctl.cfg": zeekConfig,
			"local.zeek":  localZeek,
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

// reconcileDeployment ensures the Deployment for Zeek exists
func (r *ZeekController) reconcileDeployment(ctx context.Context, instance *securityv1alpha1.ZeekInstance, configMap *corev1.ConfigMap) (*appsv1.Deployment, error) {
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
							Name:            "zeek",
							Image:           "zeek/zeek:latest",
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command: []string{
								"/bin/bash",
								"-c",
								"cp /etc/zeek/zeekctl.cfg /usr/local/zeek/etc/zeekctl.cfg && " +
									"cp /etc/zeek/local.zeek /usr/local/zeek/share/zeek/site/local.zeek && " +
									"cd /usr/local/zeek && " +
									"./bin/zeekctl deploy && " +
									"tail -f /usr/local/zeek/logs/current/stderr.log",
							},
							SecurityContext: securityContext,
							Resources:       resources,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/etc/zeek",
								},
								{
									Name:      "logs",
									MountPath: "/usr/local/zeek/logs",
								},
								{
									Name:      "spool",
									MountPath: "/usr/local/zeek/spool",
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "api",
									ContainerPort: 9977,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"pgrep", "zeek",
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
											"pgrep", "zeek",
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
							Name: "spool",
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

// reconcileService ensures the Service for Zeek exists
func (r *ZeekController) reconcileService(ctx context.Context, instance *securityv1alpha1.ZeekInstance) (*corev1.Service, error) {
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
					Port:       9977,
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

// updateStatusCondition updates a condition in the ZeekInstance status
func (r *ZeekController) updateStatusCondition(ctx context.Context, instance *securityv1alpha1.ZeekInstance, conditionType, status, reason, message string) {
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
	instance.Status.Conditions = append(instance.Status.Conditions, securityv1alpha1.ZeekInstanceCondition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// generateZeekConfig generates Zeek configuration
func generateZeekConfig(instance *securityv1alpha1.ZeekInstance) (string, error) {
	// This is a simplified version, in a real implementation you would generate a complete Zeek configuration
	config := `# Zeek Control Configuration
# This file was automatically generated by the Zeek controller

[manager]
type=manager
host=localhost

[logger]
type=logger
host=localhost

[proxy]
type=proxy
host=localhost
`

	// Add interfaces
	for i, iface := range instance.Spec.Interfaces {
		config += fmt.Sprintf("\n[worker-%d]\n", i+1)
		config += "type=worker\n"
		config += "host=localhost\n"
		config += fmt.Sprintf("interface=%s\n", iface.Name)
		if iface.BPFFilter != "" {
			config += fmt.Sprintf("filter=%s\n", iface.BPFFilter)
		}
	}

	// Add cluster settings
	if instance.Spec.ClusterMode {
		config += "\n[cluster]\n"
		config += "enabled=yes\n"
		if instance.Spec.NodeName != "" {
			config += fmt.Sprintf("node=%s\n", instance.Spec.NodeName)
		}
	}

	// Add log rotation settings
	config += "\n[log]\n"
	config += fmt.Sprintf("rotation_interval=%s\n", instance.Spec.LogRotationInterval)

	return config, nil
}

// generateLocalZeek generates the local.zeek script
func generateLocalZeek(instance *securityv1alpha1.ZeekInstance) (string, error) {
	// This is a simplified version, in a real implementation you would generate a complete local.zeek script
	script := `##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!

# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults

# Load the scan detection script.
@load misc/scan

# Log some information about web applications being used.
@load misc/app-stats

# Detect traceroute being run on the network.
@load misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
@load frameworks/software/vulnerable

# Detect software being downloaded.
@load frameworks/software/download

# Detect long connections.
@load misc/long-connections

# Collect metrics for the connection.
@load protocols/conn/metrics

# Collect statistics for the HTTP analyzer.
@load protocols/http/metrics

# Detect file transfers.
@load protocols/ftp/detect

# Detect SQL injection attacks.
@load protocols/http/detect-sqli

# Detect SSH brute-forcing.
@load protocols/ssh/detect-bruteforcing

# Detect SSL/TLS certificates that are about to expire.
@load protocols/ssl/expiring-certs

# Detect DNS tunneling.
@load protocols/dns/detect-tunnels

# Enable logging of connection summaries.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# Enable logging of files.
@load frameworks/files/hash-all-files
@load frameworks/files/detect-MHR

# Enable logging of SMTP connections.
@load protocols/smtp/detect-suspicious-attachments

# Enable JSON logging.
@load policy/tuning/json-logs
`

	// Add custom scripts
	for _, script := range instance.Spec.Scripts {
		if script.Enabled {
			script := fmt.Sprintf("\n# Load custom script: %s\n", script.Name)
			if script.Path != "" {
				script += fmt.Sprintf("@load %s\n", script.Path)
			} else {
				script += fmt.Sprintf("@load %s\n", script.Name)
			}

			// Add script configuration
			if len(script.Config) > 0 {
				script += "redef "
				for key, value := range script.Config {
					script += fmt.Sprintf("%s = %s;\n", key, value)
				}
			}
		}
	}

	return script, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *ZeekController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ZeekInstance{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}
