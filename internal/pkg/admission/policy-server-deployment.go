package admission

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"time"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

// reconcilePolicyServerDeployment reconciles the Deployment that runs the PolicyServer
// component
func (r *Reconciler) reconcilePolicyServerDeployment(ctx context.Context, policyServer *policiesv1alpha2.PolicyServer) error {
	configMapVersion, err := r.policyServerConfigMapVersion(ctx, policyServer)
	if err != nil {
		return fmt.Errorf("cannot get policy-server ConfigMap version: %w", err)
	}

	deployment := r.deployment(configMapVersion, policyServer)
	err = r.Client.Create(ctx, deployment)
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("error reconciling policy-server deployment: %w", err)
	}

	return r.updatePolicyServerDeployment(ctx, policyServer, deployment)
}

// isPolicyServerReady returns true when the PolicyServer deployment is running only
// fresh replicas that are reflecting its Spec.
// This works using the same code of `kubectl rollout status <deployment>`
func (r *Reconciler) isPolicyServerReady(ctx context.Context, policyServer *policiesv1alpha2.PolicyServer) (bool, error) {
	deployment := &appsv1.Deployment{}
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      policyServer.NameWithPrefix(),
	}, deployment)
	if err != nil {
		return false, fmt.Errorf("cannot retrieve existing policy-server Deployment: %w", err)
	}

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

func (r *Reconciler) updatePolicyServerDeployment(ctx context.Context, policyServer *policiesv1alpha2.PolicyServer, newDeployment *appsv1.Deployment) error {
	originalDeployment := &appsv1.Deployment{}
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      policyServer.NameWithPrefix(),
	}, originalDeployment)
	if err != nil {
		return fmt.Errorf("cannot retrieve existing policy-server Deployment: %w", err)
	}

	if shouldUpdatePolicyServerDeployment(originalDeployment, newDeployment) {
		patch := originalDeployment.DeepCopy()
		patch.Spec.Replicas = newDeployment.Spec.Replicas
		patch.Spec.Template = newDeployment.Spec.Template
		patch.Spec.Template.Annotations[constants.PolicyServerDeploymentRestartAnnotation] = time.Now().Format(time.RFC3339)
		err = r.Client.Patch(ctx, patch, client.MergeFrom(originalDeployment))
		if err != nil {
			return fmt.Errorf("cannot patch policy-server Deployment: %w", err)
		}
		r.Log.Info("deployment patched")
	}

	return nil
}

func shouldUpdatePolicyServerDeployment(originalDeployment *appsv1.Deployment, newDeployment *appsv1.Deployment) bool {
	return *originalDeployment.Spec.Replicas != *newDeployment.Spec.Replicas ||
		originalDeployment.Spec.Template.Spec.Containers[0].Image != newDeployment.Spec.Template.Spec.Containers[0].Image ||
		originalDeployment.Spec.Template.Spec.ServiceAccountName != newDeployment.Spec.Template.Spec.ServiceAccountName ||
		!reflect.DeepEqual(originalDeployment.Spec.Template.Spec.Containers[0].Env, newDeployment.Spec.Template.Spec.Containers[0].Env) ||
		!haveEqualAnnotationsWithoutRestart(originalDeployment, newDeployment)
}

func haveEqualAnnotationsWithoutRestart(originalDeployment *appsv1.Deployment, newDeployment *appsv1.Deployment) bool {
	if originalDeployment.Spec.Template.Annotations == nil && newDeployment.Spec.Template.Annotations == nil {
		return true
	}
	annotationsWithoutRestart := make(map[string]string)
	for k, v := range originalDeployment.Spec.Template.Annotations {
		if k != constants.PolicyServerDeploymentRestartAnnotation {
			annotationsWithoutRestart[k] = v
		}
	}
	return reflect.DeepEqual(annotationsWithoutRestart, newDeployment.Spec.Template.Annotations)
}

func (r *Reconciler) deployment(configMapVersion string, policyServer *policiesv1alpha2.PolicyServer) *appsv1.Deployment {
	const (
		certsVolumeName             = "certs"
		policiesConfigContainerPath = "/config"
		policiesFilename            = "policies.yml"
		policiesVolumeName          = "policies"
		secretsContainerPath        = "/pki"
	)

	admissionContainer := corev1.Container{
		Name:  policyServer.NameWithPrefix(),
		Image: policyServer.Spec.Image,
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
		Env: append([]corev1.EnvVar{
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
		}, policyServer.Spec.Env...),
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

	templateAnnotations := policyServer.Spec.Annotations
	if templateAnnotations == nil {
		templateAnnotations = make(map[string]string)
	}
	templateAnnotations[constants.PolicyServerDeploymentConfigAnnotation] = configMapVersion

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
			Labels: map[string]string{
				constants.AppLabelKey: policyServer.AppLabel(),
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &policyServer.Spec.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					constants.AppLabelKey: policyServer.AppLabel(),
				},
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						constants.AppLabelKey: policyServer.AppLabel(),
					},
					Annotations: templateAnnotations,
				},
				Spec: corev1.PodSpec{
					Containers:         []corev1.Container{admissionContainer},
					ServiceAccountName: policyServer.Spec.ServiceAccountName,
					Volumes: []corev1.Volume{
						{
							Name: certsVolumeName,
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: policyServer.NameWithPrefix(),
								},
							},
						},
						{
							Name: policiesVolumeName,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: policyServer.NameWithPrefix(),
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
