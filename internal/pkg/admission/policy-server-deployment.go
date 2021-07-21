package admission

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

const (
	certsVolumeName             = "certs"
	policiesConfigContainerPath = "/config"
	policiesFilename            = "policies.yml"
	policiesVolumeName          = "policies"
	secretsContainerPath        = "/pki"
)

// reconcilePolicyServerDeployment reconciles the Deployment that runs the PolicyServer
// component
func (r *Reconciler) reconcilePolicyServerDeployment(ctx context.Context) error {
	cfg, err := r.policyServerConfigMapNotCached(ctx)
	if err != nil {
		return err
	}
	if err != nil {
		return fmt.Errorf("cannot get policy-server ConfigMap version: %w", err)
	}

	err = r.Client.Create(ctx, r.deployment(ctx, cfg))
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("error reconciling policy-server deployment: %w", err)
	}

	return r.updatePolicyServerDeployment(ctx, cfg)
}

// isPolicyServerReady returns true when the PolicyServer deployment is running only
// fresh replicas that are reflecting its Spec.
// This works using the same code of `kubectl rollout status <deployment>`
func (r *Reconciler) isPolicyServerReady(ctx context.Context) (bool, error) {
	deployment := &appsv1.Deployment{}
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      constants.PolicyServerDeploymentName,
	}, deployment)
	if err != nil {
		return false, fmt.Errorf("cannot retrieve existing policy-server Deployment: %w", err)
	}

	// nolint
	// This code takes inspiration from how `kubectl rollout status deployment <name>`
	// works. The source code can be found here:
	// https://github.com/kubernetes/kubectl/blob/ddb56dde55b6b8de6eba1efbd1d435bed7b40ff4/pkg/polymorphichelpers/rollout_status.go#L75-L91
	if deployment.Generation <= deployment.Status.ObservedGeneration {
		cond := getProgressingDeploymentCondition(deployment.Status)
		if cond != nil && cond.Reason == "ProgressDeadlineExceeded" {
			return false, fmt.Errorf("deployment %q exceeded its progress deadline", deployment.Name)
		}
		if deployment.Spec.Replicas != nil && deployment.Status.UpdatedReplicas < *deployment.Spec.Replicas {
			return false,
				&PolicyServerNotReadyError{
					Message: fmt.Sprintf("Waiting for deployment %q rollout to finish: %d out of %d new replicas have been updated",
						deployment.Name, deployment.Status.UpdatedReplicas, *deployment.Spec.Replicas)}
		}
		if deployment.Status.Replicas > deployment.Status.UpdatedReplicas {
			return false, &PolicyServerNotReadyError{
				Message: fmt.Sprintf("Waiting for deployment %q rollout to finish: %d old replicas are pending termination",
					deployment.Name, deployment.Status.Replicas-deployment.Status.UpdatedReplicas)}
		}
		if deployment.Status.AvailableReplicas < deployment.Status.UpdatedReplicas {
			return false, &PolicyServerNotReadyError{
				Message: fmt.Sprintf("Waiting for deployment %q rollout to finish: %d of %d updated replicas are available",
					deployment.Name, deployment.Status.AvailableReplicas, deployment.Status.UpdatedReplicas)}
		}
		// deployment successfully rolled out
		return true, nil
	}
	return false, &PolicyServerNotReadyError{
		Message: "Waiting for deployment spec update to be observed"}
}

// GetDeploymentCondition returns the condition with the provided type.
func getProgressingDeploymentCondition(status appsv1.DeploymentStatus) *appsv1.DeploymentCondition {
	for i := range status.Conditions {
		c := status.Conditions[i]
		if c.Type == appsv1.DeploymentProgressing {
			return &c
		}
	}
	return nil
}

func (r *Reconciler) updatePolicyServerDeployment(ctx context.Context, cfg *corev1.ConfigMap) error {
	deployment := &appsv1.Deployment{}
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      constants.PolicyServerDeploymentName,
	}, deployment)
	if err != nil {
		return fmt.Errorf("cannot retrieve existing policy-server Deployment: %w", err)
	}

	//nolint
	currentConfigVersion, found := deployment.Spec.Template.ObjectMeta.Annotations[constants.PolicyServerDeploymentConfigAnnotation]
	if !found || currentConfigVersion != cfg.GetResourceVersion() {
		// the current deployment is using an older version of the configuration

		currentDeploymentVersion := deployment.GetResourceVersion()
		newDeployment := buildDeploymentFromConfigMap(r.DeploymentsNamespace, r.DeploymentsServiceAccountName, cfg)
		newDeployment.SetResourceVersion(currentDeploymentVersion)
		r.Log.Info("deployment updated")

		return r.Client.Update(ctx, newDeployment)
	}
	return nil
}

type PolicyServerDeploymentSettings struct {
	Replicas    int32
	Image       string
	EnvVars     map[string]string
	Annotations map[string]string
}

func policyServerDeploymentSettings(cfg *corev1.ConfigMap) PolicyServerDeploymentSettings {
	settings := PolicyServerDeploymentSettings{
		Replicas:    int32(constants.PolicyServerReplicaSize),
		Image:       constants.PolicyServerImage,
		EnvVars:     make(map[string]string),
		Annotations: make(map[string]string),
	}

	buf, found := cfg.Data[constants.PolicyServerReplicaSizeKey]
	if found {
		repSize, err := strconv.ParseInt(buf, 10, 32)
		if err == nil {
			settings.Replicas = int32(repSize)
		}
	}

	buf, found = cfg.Data[constants.PolicyServerImageKey]
	if found {
		settings.Image = buf
	}

	relevantEnvVarPrefixes := []string{
		"KUBEWARDEN_", "OTEL_",
	}
	for k, v := range cfg.Data {
		relevant := false
		for _, prefix := range relevantEnvVarPrefixes {
			if strings.HasPrefix(k, prefix) {
				relevant = true
				break
			}
		}
		if relevant {
			settings.EnvVars[k] = v
		}
	}

	// setup distributed tracing
	buf, found = cfg.Data[constants.PolicyServerJaegerSidecar]
	if found {
		settings.Annotations[constants.PolicyServerJaegerSidecar] = buf
		settings.EnvVars[constants.PolicyServerLogFormat] = "jaeger"
	}

	buf, found = cfg.Data[constants.PolicyServerOpenTelemetrySidecar]
	if found {
		settings.Annotations[constants.PolicyServerOpenTelemetrySidecar] = buf
		settings.EnvVars[constants.PolicyServerLogFormat] = "otlp"
	}

	return settings
}

func buildDeploymentFromConfigMap(namespace, serviceAccountName string, cfg *corev1.ConfigMap) *appsv1.Deployment {
	settings := policyServerDeploymentSettings(cfg)

	admissionContainer := corev1.Container{
		Name:  constants.PolicyServerDeploymentName,
		Image: settings.Image,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      certsVolumeName,
				ReadOnly:  true,
				MountPath: secretsContainerPath,
			},
			{
				Name:      policiesVolumeName,
				ReadOnly:  true,
				MountPath: policiesConfigContainerPath,
			},
		},
		Env: buildDeploymentPolicyServerContainerEnvVars(settings),
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   constants.PolicyServerReadinessProbe,
					Port:   intstr.FromInt(constants.PolicyServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
		},
	}

	templateAnnotations := map[string]string{
		constants.PolicyServerDeploymentConfigAnnotation: cfg.GetResourceVersion(),
	}
	for k, v := range settings.Annotations {
		templateAnnotations[k] = v
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerDeploymentName,
			Namespace: namespace,
			Labels:    constants.PolicyServerLabels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &settings.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: constants.PolicyServerLabels,
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      constants.PolicyServerLabels,
					Annotations: templateAnnotations,
				},
				Spec: corev1.PodSpec{
					Containers:         []corev1.Container{admissionContainer},
					ServiceAccountName: serviceAccountName,
					Volumes: []corev1.Volume{
						{
							Name: certsVolumeName,
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: constants.PolicyServerSecretName,
								},
							},
						},
						{
							Name: policiesVolumeName,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: constants.PolicyServerConfigMapName,
									},
									Items: []corev1.KeyToPath{
										{
											Key:  constants.PolicyServerConfigPoliciesEntry,
											Path: policiesFilename,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func buildDeploymentPolicyServerContainerEnvVars(settings PolicyServerDeploymentSettings) []corev1.EnvVar {
	envVars := []corev1.EnvVar{
		{
			Name:  "KUBEWARDEN_CERT_FILE",
			Value: filepath.Join(secretsContainerPath, constants.PolicyServerTLSCert),
		},
		{
			Name:  "KUBEWARDEN_KEY_FILE",
			Value: filepath.Join(secretsContainerPath, constants.PolicyServerTLSKey),
		},
		{
			Name:  "KUBEWARDEN_PORT",
			Value: fmt.Sprintf("%d", constants.PolicyServerPort),
		},
		{
			Name:  "KUBEWARDEN_POLICIES_DOWNLOAD_DIR",
			Value: "/tmp/",
		},
		{
			Name:  "KUBEWARDEN_POLICIES",
			Value: filepath.Join(policiesConfigContainerPath, policiesFilename),
		},
	}
	for k, v := range settings.EnvVars {
		envVars = append(envVars, corev1.EnvVar{
			Name:  k,
			Value: v,
		})
	}

	return envVars
}

func (r *Reconciler) deployment(ctx context.Context, cfg *corev1.ConfigMap) *appsv1.Deployment {
	return buildDeploymentFromConfigMap(r.DeploymentsNamespace, r.DeploymentsServiceAccountName, cfg)
}
