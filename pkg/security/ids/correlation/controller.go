package correlation

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

// EventCorrelationController reconciles EventCorrelation objects
type EventCorrelationController struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// Reconcile handles EventCorrelation reconciliation
func (r *EventCorrelationController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := klog.FromContext(ctx).WithValues("eventcorrelation", req.NamespacedName)

	// Fetch the EventCorrelation
	instance := &securityv1alpha1.EventCorrelation{}
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
			log.Error(err, "Failed to update EventCorrelation status")
			return ctrl.Result{}, err
		}
	}

	// Skip reconciliation if disabled
	if !instance.Spec.Enabled {
		instance.Status.Phase = "Disabled"
		r.updateStatusCondition(ctx, instance, "Ready", "False", "Disabled", "Event correlation is disabled")
		if err := r.Status().Update(ctx, instance); err != nil {
			log.Error(err, "Failed to update EventCorrelation status")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Handle ConfigMap for correlation rules
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
		r.updateStatusCondition(ctx, instance, "Ready", "True", "Running", "Event correlation is running")
	} else {
		instance.Status.Phase = "Pending"
		r.updateStatusCondition(ctx, instance, "Ready", "False", "NotRunning", "Event correlation is not running")
	}

	// Update status
	if err := r.Status().Update(ctx, instance); err != nil {
		log.Error(err, "Failed to update EventCorrelation status")
		return ctrl.Result{}, err
	}

	// Requeue to update status periodically
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// reconcileConfigMap ensures the ConfigMap for correlation rules exists
func (r *EventCorrelationController) reconcileConfigMap(ctx context.Context, instance *securityv1alpha1.EventCorrelation) (*corev1.ConfigMap, error) {
	log := klog.FromContext(ctx)

	// Generate correlation rules configuration
	rulesConfig, err := generateRulesConfig(instance)
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
			"rules.json": rulesConfig,
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

// reconcileDeployment ensures the Deployment for event correlation exists
func (r *EventCorrelationController) reconcileDeployment(ctx context.Context, instance *securityv1alpha1.EventCorrelation, configMap *corev1.ConfigMap) (*appsv1.Deployment, error) {
	log := klog.FromContext(ctx)

	// Define container resources
	resources := corev1.ResourceRequirements{}
	if instance.Spec.Resources != nil {
		resources = *instance.Spec.Resources
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
					Containers: []corev1.Container{
						{
							Name:            "correlator",
							Image:           "fos1/event-correlator:latest", // This would be your custom event correlation image
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command: []string{
								"/usr/bin/event-correlator",
								"--config", "/etc/correlator/rules.json",
								"--max-events", fmt.Sprintf("%d", instance.Spec.MaxEventsInMemory),
								"--max-age", instance.Spec.MaxEventAge,
								"--output-format", instance.Spec.OutputFormat,
							},
							Resources: resources,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/etc/correlator",
								},
								{
									Name:      "logs",
									MountPath: "/var/log/correlator",
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "api",
									ContainerPort: 8080,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/health",
										Port: intstr.FromInt(8080),
									},
								},
								InitialDelaySeconds: 30,
								PeriodSeconds:       10,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/ready",
										Port: intstr.FromInt(8080),
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

// reconcileService ensures the Service for event correlation exists
func (r *EventCorrelationController) reconcileService(ctx context.Context, instance *securityv1alpha1.EventCorrelation) (*corev1.Service, error) {
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
					Port:       8080,
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

// updateStatusCondition updates a condition in the EventCorrelation status
func (r *EventCorrelationController) updateStatusCondition(ctx context.Context, instance *securityv1alpha1.EventCorrelation, conditionType, status, reason, message string) {
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
	instance.Status.Conditions = append(instance.Status.Conditions, securityv1alpha1.EventCorrelationCondition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// generateRulesConfig generates the correlation rules configuration
func generateRulesConfig(instance *securityv1alpha1.EventCorrelation) (string, error) {
	// This is a simplified version, in a real implementation you would generate a complete JSON configuration
	config := `{
  "rules": [`

	// Add rules
	for i, rule := range instance.Spec.Rules {
		if i > 0 {
			config += ","
		}
		config += fmt.Sprintf(`
    {
      "name": "%s",
      "description": "%s",
      "threshold": %d,
      "timeWindow": "%s",
      "severity": "%s",
      "action": "%s",
      "conditions": [`,
			rule.Name, rule.Description, rule.Threshold, rule.TimeWindow, rule.Severity, rule.Action)

		// Add conditions
		for j, condition := range rule.Conditions {
			if j > 0 {
				config += ","
			}
			config += fmt.Sprintf(`
        {
          "field": "%s",
          "operator": "%s",
          "value": "%s"
        }`,
				condition.Field, condition.Operator, condition.Value)
		}

		config += `
      ]
    }`
	}

	config += `
  ]
}`

	return config, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *EventCorrelationController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.EventCorrelation{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}
