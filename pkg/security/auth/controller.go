package auth

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

// AuthController reconciles AuthProvider objects
type AuthController struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Manager  Manager
}

// Reconcile handles AuthProvider reconciliation
func (r *AuthController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := klog.FromContext(ctx).WithValues("authprovider", req.NamespacedName)

	// Fetch the AuthProvider
	instance := &securityv1alpha1.AuthProvider{}
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
			log.Error(err, "Failed to update AuthProvider status")
			return ctrl.Result{}, err
		}
	}

	// Handle ConfigMap for authentication configuration
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
		r.updateStatusCondition(ctx, instance, "Ready", "True", "Running", "Authentication provider is running")
	} else {
		instance.Status.Phase = "Pending"
		r.updateStatusCondition(ctx, instance, "Ready", "False", "NotRunning", "Authentication provider is not running")
	}

	// Update status
	if err := r.Status().Update(ctx, instance); err != nil {
		log.Error(err, "Failed to update AuthProvider status")
		return ctrl.Result{}, err
	}

	// Add the provider to the authentication manager
	if r.Manager != nil && instance.Status.Phase == "Running" {
		// Convert the CRD to a provider info
		providerInfo := convertToProviderInfo(instance)

		// Add the provider to the manager
		if err := r.Manager.AddProvider(providerInfo); err != nil {
			log.Error(err, "Failed to add provider to authentication manager")
			r.updateStatusCondition(ctx, instance, "ProviderReady", "False", "ProviderError", err.Error())
			return ctrl.Result{}, err
		}
		r.updateStatusCondition(ctx, instance, "ProviderReady", "True", "ProviderAdded", "Provider added to authentication manager")
	}

	// Requeue to update status periodically
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// reconcileConfigMap ensures the ConfigMap for authentication configuration exists
func (r *AuthController) reconcileConfigMap(ctx context.Context, instance *securityv1alpha1.AuthProvider) (*corev1.ConfigMap, error) {
	log := klog.FromContext(ctx)

	// Generate authentication configuration
	authConfig, err := generateAuthConfig(instance)
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
			"auth.yaml": authConfig,
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

// reconcileDeployment ensures the Deployment for authentication exists
func (r *AuthController) reconcileDeployment(ctx context.Context, instance *securityv1alpha1.AuthProvider, configMap *corev1.ConfigMap) (*appsv1.Deployment, error) {
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
							Name:            "auth",
							Image:           "fos1/auth-service:latest", // This would be your custom authentication service image
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command: []string{
								"/usr/bin/auth-service",
								"--config", "/etc/auth/auth.yaml",
							},
							Resources: resources,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/etc/auth",
								},
								{
									Name:      "data",
									MountPath: "/var/lib/auth",
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
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
							Name: "data",
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

// reconcileService ensures the Service for authentication exists
func (r *AuthController) reconcileService(ctx context.Context, instance *securityv1alpha1.AuthProvider) (*corev1.Service, error) {
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
					Name:       "http",
					Port:       8080,
					TargetPort: intstr.FromString("http"),
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

// updateStatusCondition updates a condition in the AuthProvider status
func (r *AuthController) updateStatusCondition(ctx context.Context, instance *securityv1alpha1.AuthProvider, conditionType, status, reason, message string) {
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
	instance.Status.Conditions = append(instance.Status.Conditions, securityv1alpha1.AuthProviderCondition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// generateAuthConfig generates authentication configuration
func generateAuthConfig(instance *securityv1alpha1.AuthProvider) (string, error) {
	// This is a simplified implementation
	// In a real implementation, you would generate a complete authentication configuration
	config := fmt.Sprintf(`# Authentication configuration for %s
type: %s
name: %s
enabled: %t
`, instance.Name, instance.Spec.Type, instance.Name, instance.Spec.Enabled)

	// Add provider-specific configuration
	switch instance.Spec.Type {
	case "local":
		if instance.Spec.Local != nil {
			config += fmt.Sprintf(`
local:
  password_policy:
    min_length: %d
    require_uppercase: %t
    require_lowercase: %t
    require_numbers: %t
    require_special: %t
    max_age: %d
    history_count: %d
  mfa_enabled: %t
  mfa_methods:
`, instance.Spec.Local.PasswordPolicy.MinLength,
				instance.Spec.Local.PasswordPolicy.RequireUppercase,
				instance.Spec.Local.PasswordPolicy.RequireLowercase,
				instance.Spec.Local.PasswordPolicy.RequireNumbers,
				instance.Spec.Local.PasswordPolicy.RequireSpecial,
				instance.Spec.Local.PasswordPolicy.MaxAge,
				instance.Spec.Local.PasswordPolicy.HistoryCount,
				instance.Spec.Local.MFAEnabled)

			for _, method := range instance.Spec.Local.MFAMethods {
				config += fmt.Sprintf("    - %s\n", method)
			}
		}
	case "ldap":
		if instance.Spec.LDAP != nil {
			config += fmt.Sprintf(`
ldap:
  url: %s
  bind_dn: %s
  bind_password: %s
  user_base_dn: %s
  user_filter: %s
  group_base_dn: %s
  group_filter: %s
  group_member_attribute: %s
  start_tls: %t
  insecure_skip_verify: %t
`, instance.Spec.LDAP.URL,
				instance.Spec.LDAP.BindDN,
				instance.Spec.LDAP.BindPassword,
				instance.Spec.LDAP.UserBaseDN,
				instance.Spec.LDAP.UserFilter,
				instance.Spec.LDAP.GroupBaseDN,
				instance.Spec.LDAP.GroupFilter,
				instance.Spec.LDAP.GroupMemberAttribute,
				instance.Spec.LDAP.StartTLS,
				instance.Spec.LDAP.InsecureSkipVerify)

			if len(instance.Spec.LDAP.UserAttributes) > 0 {
				config += "  user_attributes:\n"
				for ldapAttr, userAttr := range instance.Spec.LDAP.UserAttributes {
					config += fmt.Sprintf("    %s: %s\n", ldapAttr, userAttr)
				}
			}
		}
	case "oauth":
		if instance.Spec.OAuth != nil {
			config += fmt.Sprintf(`
oauth:
  provider_type: %s
  client_id: %s
  client_secret: %s
  authorization_url: %s
  token_url: %s
  user_info_url: %s
  redirect_url: %s
  user_id_attribute: %s
  scopes:
`, instance.Spec.OAuth.ProviderType,
				instance.Spec.OAuth.ClientID,
				instance.Spec.OAuth.ClientSecret,
				instance.Spec.OAuth.AuthorizationURL,
				instance.Spec.OAuth.TokenURL,
				instance.Spec.OAuth.UserInfoURL,
				instance.Spec.OAuth.RedirectURL,
				instance.Spec.OAuth.UserIDAttribute)

			for _, scope := range instance.Spec.OAuth.Scopes {
				config += fmt.Sprintf("    - %s\n", scope)
			}

			if len(instance.Spec.OAuth.UserAttributes) > 0 {
				config += "  user_attributes:\n"
				for oauthAttr, userAttr := range instance.Spec.OAuth.UserAttributes {
					config += fmt.Sprintf("    %s: %s\n", oauthAttr, userAttr)
				}
			}
		}
	}

	return config, nil
}

// convertToProviderInfo converts an AuthProvider CRD to a ProviderInfo
func convertToProviderInfo(instance *securityv1alpha1.AuthProvider) *ProviderInfo {
	providerInfo := &ProviderInfo{
		Name:      instance.Name,
		Type:      instance.Spec.Type,
		Enabled:   instance.Spec.Enabled,
		Priority:  instance.Spec.Priority,
		CreatedAt: instance.CreationTimestamp.Time,
		UpdatedAt: metav1.Now().Time,
		Config:    ProviderConfig{},
	}

	// Set provider-specific configuration
	switch instance.Spec.Type {
	case "local":
		if instance.Spec.Local != nil {
			providerInfo.Config.Local = &LocalConfig{
				PasswordPolicy: PasswordPolicy{
					MinLength:        instance.Spec.Local.PasswordPolicy.MinLength,
					RequireUppercase: instance.Spec.Local.PasswordPolicy.RequireUppercase,
					RequireLowercase: instance.Spec.Local.PasswordPolicy.RequireLowercase,
					RequireNumbers:   instance.Spec.Local.PasswordPolicy.RequireNumbers,
					RequireSpecial:   instance.Spec.Local.PasswordPolicy.RequireSpecial,
					MaxAge:           instance.Spec.Local.PasswordPolicy.MaxAge,
					HistoryCount:     instance.Spec.Local.PasswordPolicy.HistoryCount,
				},
				MFAEnabled: instance.Spec.Local.MFAEnabled,
				MFAMethods: instance.Spec.Local.MFAMethods,
			}
		}
	case "ldap":
		if instance.Spec.LDAP != nil {
			providerInfo.Config.LDAP = &LDAPConfig{
				URL:                 instance.Spec.LDAP.URL,
				BindDN:              instance.Spec.LDAP.BindDN,
				BindPassword:        instance.Spec.LDAP.BindPassword,
				UserBaseDN:          instance.Spec.LDAP.UserBaseDN,
				UserFilter:          instance.Spec.LDAP.UserFilter,
				GroupBaseDN:         instance.Spec.LDAP.GroupBaseDN,
				GroupFilter:         instance.Spec.LDAP.GroupFilter,
				GroupMemberAttribute: instance.Spec.LDAP.GroupMemberAttribute,
				UserAttributes:      instance.Spec.LDAP.UserAttributes,
				StartTLS:            instance.Spec.LDAP.StartTLS,
				InsecureSkipVerify:  instance.Spec.LDAP.InsecureSkipVerify,
				CACert:              instance.Spec.LDAP.CACert,
			}
		}
	case "oauth":
		if instance.Spec.OAuth != nil {
			providerInfo.Config.OAuth = &OAuthConfig{
				ProviderType:    instance.Spec.OAuth.ProviderType,
				ClientID:        instance.Spec.OAuth.ClientID,
				ClientSecret:    instance.Spec.OAuth.ClientSecret,
				AuthorizationURL: instance.Spec.OAuth.AuthorizationURL,
				TokenURL:        instance.Spec.OAuth.TokenURL,
				UserInfoURL:     instance.Spec.OAuth.UserInfoURL,
				RedirectURL:     instance.Spec.OAuth.RedirectURL,
				Scopes:          instance.Spec.OAuth.Scopes,
				UserIDAttribute: instance.Spec.OAuth.UserIDAttribute,
				UserAttributes:  instance.Spec.OAuth.UserAttributes,
			}
		}
	}

	return providerInfo
}

// SetupWithManager sets up the controller with the Manager
func (r *AuthController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.AuthProvider{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}
