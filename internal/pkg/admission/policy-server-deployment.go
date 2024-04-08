package admission

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/policyserver"
)

const (
	certsVolumeName                  = "certs"
	policiesConfigContainerPath      = "/config"
	policiesFilename                 = "policies.yml"
	sourcesFilename                  = "sources.yml"
	verificationFilename             = "verification.yml"
	policiesVolumeName               = "policies"
	sourcesVolumeName                = "sources"
	verificationConfigVolumeName     = "verification"
	secretsContainerPath             = "/pki"
	imagePullSecretVolumeName        = "imagepullsecret"
	dockerConfigJSONPolicyServerPath = "/home/kubewarden/.docker"
	policyStoreVolume                = "policy-store"
	policyStoreVolumePath            = "/tmp"
	sigstoreCacheDirPath             = "/tmp/sigstore-data"
)

// reconcilePolicyServerDeployment reconciles the Deployment that runs the PolicyServer
// component
func (r *Reconciler) reconcilePolicyServerDeployment(ctx context.Context, policyServer *policiesv1.PolicyServer) error {
	configMapVersion, err := r.policyServerConfigMapVersion(ctx, policyServer)
	if err != nil {
		return fmt.Errorf("cannot get policy-server ConfigMap version: %w", err)
	}

	if policyServer.Spec.ImagePullSecret != "" {
		err = policyserver.ValidateImagePullSecret(ctx, r.Client, policyServer.Spec.ImagePullSecret, r.DeploymentsNamespace)
		if err != nil {
			r.Log.Error(err, "error while validating policy-server imagePullSecret")
		}
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

func (r *Reconciler) updatePolicyServerDeployment(ctx context.Context, policyServer *policiesv1.PolicyServer, newDeployment *appsv1.Deployment) error {
	originalDeployment := &appsv1.Deployment{}
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      policyServer.NameWithPrefix(),
	}, originalDeployment)
	if err != nil {
		return fmt.Errorf("cannot retrieve existing policy-server Deployment: %w", err)
	}

	shouldUpdate, err := shouldUpdatePolicyServerDeployment(policyServer, originalDeployment, newDeployment)
	if err != nil {
		return fmt.Errorf("cannot check if it is necessary to update the policy server deployment: %w", err)
	}
	if shouldUpdate {
		patch := originalDeployment.DeepCopy()
		patch.Spec.Replicas = newDeployment.Spec.Replicas
		patch.Spec.Template = newDeployment.Spec.Template
		patch.ObjectMeta.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation] = newDeployment.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation]
		err = r.Client.Patch(ctx, patch, client.MergeFrom(originalDeployment))
		if err != nil {
			return fmt.Errorf("cannot patch policy-server Deployment: %w", err)
		}
		r.Log.Info("deployment patched")
	}

	return nil
}

func getPolicyServerImageFromDeployment(policyServer *policiesv1.PolicyServer, deployment *appsv1.Deployment) (string, error) {
	for containerIndex := range deployment.Spec.Template.Spec.Containers {
		container := &deployment.Spec.Template.Spec.Containers[containerIndex]
		if container.Name == policyServer.NameWithPrefix() {
			return container.Image, nil
		}
	}
	return "", fmt.Errorf("cannot find policy server container")
}

func isPolicyServerImageChanged(policyServer *policiesv1.PolicyServer, originalDeployment *appsv1.Deployment, newDeployment *appsv1.Deployment) (bool, error) {
	var oldImage, newImage string
	var err error
	if oldImage, err = getPolicyServerImageFromDeployment(policyServer, originalDeployment); err != nil {
		return false, err
	}
	if newImage, err = getPolicyServerImageFromDeployment(policyServer, newDeployment); err != nil {
		return false, err
	}
	return oldImage != newImage, nil
}

func shouldUpdatePolicyServerDeployment(policyServer *policiesv1.PolicyServer, originalDeployment *appsv1.Deployment, newDeployment *appsv1.Deployment) (bool, error) {
	containerImageChanged, err := isPolicyServerImageChanged(policyServer, originalDeployment, newDeployment)
	if err != nil {
		return false, err
	}
	return *originalDeployment.Spec.Replicas != *newDeployment.Spec.Replicas ||
		containerImageChanged ||
		originalDeployment.Spec.Template.Spec.ServiceAccountName != newDeployment.Spec.Template.Spec.ServiceAccountName ||
		originalDeployment.Spec.Template.Spec.SecurityContext != newDeployment.Spec.Template.Spec.SecurityContext ||
		originalDeployment.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation] != newDeployment.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation] ||
		!reflect.DeepEqual(originalDeployment.Spec.Template.Spec.Containers[0].Env, newDeployment.Spec.Template.Spec.Containers[0].Env) ||
		!reflect.DeepEqual(originalDeployment.Spec.Template.Spec.Containers[0].Resources, newDeployment.Spec.Template.Spec.Containers[0].Resources) ||
		!reflect.DeepEqual(originalDeployment.Spec.Template.Spec.Affinity, newDeployment.Spec.Template.Spec.Affinity) ||
		!haveEqualAnnotationsWithoutRestart(originalDeployment, newDeployment), nil
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

func (r *Reconciler) adaptDeploymentSettingsForPolicyServer(policyServerDeployment *appsv1.Deployment, policyServer *policiesv1.PolicyServer) {
	if policyServer.Spec.VerificationConfig != "" {
		policyServerDeployment.Spec.Template.Spec.Volumes = append(
			policyServerDeployment.Spec.Template.Spec.Volumes,
			corev1.Volume{
				Name: verificationConfigVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: policyServer.Spec.VerificationConfig,
						},
						Items: []corev1.KeyToPath{
							{
								Key:  constants.PolicyServerVerificationConfigEntry,
								Path: verificationFilename,
							},
						},
					},
				},
			},
		)
	}
	if policyServer.Spec.ImagePullSecret != "" {
		policyServerDeployment.Spec.Template.Spec.Volumes = append(
			policyServerDeployment.Spec.Template.Spec.Volumes,
			corev1.Volume{
				Name: imagePullSecretVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: policyServer.Spec.ImagePullSecret,
						Items: []corev1.KeyToPath{
							{
								Key:  ".dockerconfigjson",
								Path: "config.json",
							},
						},
					},
				},
			},
		)
	}
	if len(policyServer.Spec.InsecureSources) > 0 || len(policyServer.Spec.SourceAuthorities) > 0 {
		policyServerDeployment.Spec.Template.Spec.Volumes = append(
			policyServerDeployment.Spec.Template.Spec.Volumes,
			corev1.Volume{
				Name: sourcesVolumeName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: policyServer.NameWithPrefix(),
						},
					},
				},
			},
		)
	}
	if emptyAffinity := (corev1.Affinity{}); policyServer.Spec.Affinity != emptyAffinity {
		policyServerDeployment.Spec.Template.Spec.Affinity = &policyServer.Spec.Affinity
	}
}

func envVarsContainVariable(envVars []corev1.EnvVar, envVarName string) int {
	for i, envvar := range envVars {
		if envvar.Name == envVarName {
			return i
		}
	}
	return -1
}

func (r *Reconciler) deployment(configMapVersion string, policyServer *policiesv1.PolicyServer) *appsv1.Deployment {
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
			{
				Name:      policyStoreVolume,
				MountPath: policyStoreVolumePath,
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
				Value: strconv.Itoa(constants.PolicyServerPort),
			},
			{
				Name:  "KUBEWARDEN_POLICIES_DOWNLOAD_DIR",
				Value: policyStoreVolumePath,
			},
			{
				Name:  "KUBEWARDEN_POLICIES",
				Value: filepath.Join(policiesConfigContainerPath, policiesFilename),
			},
			{
				Name:  "KUBEWARDEN_SIGSTORE_CACHE_DIR",
				Value: sigstoreCacheDirPath,
			},
		}, policyServer.Spec.Env...),
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   constants.PolicyServerReadinessProbe,
					Port:   intstr.FromInt(constants.PolicyServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
		},
		Resources: corev1.ResourceRequirements{
			Requests: policyServer.Spec.Requests,
			Limits:   policyServer.Spec.Limits,
		},
	}
	if r.AlwaysAcceptAdmissionReviewsInDeploymentsNamespace {
		admissionContainer.Env = append(admissionContainer.Env, corev1.EnvVar{
			Name:  "KUBEWARDEN_ALWAYS_ACCEPT_ADMISSION_REVIEWS_ON_NAMESPACE",
			Value: r.DeploymentsNamespace,
		})
	}
	if policyServer.Spec.VerificationConfig != "" {
		admissionContainer.VolumeMounts = append(admissionContainer.VolumeMounts,
			corev1.VolumeMount{
				Name:      verificationConfigVolumeName,
				ReadOnly:  true,
				MountPath: constants.PolicyServerVerificationConfigContainerPath,
			},
		)
		admissionContainer.Env = append(admissionContainer.Env,
			corev1.EnvVar{
				Name:  "KUBEWARDEN_VERIFICATION_CONFIG_PATH",
				Value: filepath.Join(constants.PolicyServerVerificationConfigContainerPath, verificationFilename),
			},
		)
	}
	if policyServer.Spec.ImagePullSecret != "" {
		admissionContainer.VolumeMounts = append(admissionContainer.VolumeMounts,
			corev1.VolumeMount{
				Name:      imagePullSecretVolumeName,
				ReadOnly:  true,
				MountPath: dockerConfigJSONPolicyServerPath,
			},
		)
		admissionContainer.Env = append(admissionContainer.Env,
			corev1.EnvVar{
				Name:  "KUBEWARDEN_DOCKER_CONFIG_JSON_PATH",
				Value: dockerConfigJSONPolicyServerPath,
			},
		)
	}
	if len(policyServer.Spec.InsecureSources) > 0 || len(policyServer.Spec.SourceAuthorities) > 0 {
		admissionContainer.VolumeMounts = append(admissionContainer.VolumeMounts,
			corev1.VolumeMount{
				Name:      sourcesVolumeName,
				ReadOnly:  true,
				MountPath: constants.PolicyServerSourcesConfigContainerPath,
			},
		)
		admissionContainer.Env = append(admissionContainer.Env,
			corev1.EnvVar{
				Name:  "KUBEWARDEN_SOURCES_PATH",
				Value: filepath.Join(constants.PolicyServerSourcesConfigContainerPath, sourcesFilename),
			},
		)
	}

	podSecurityContext := &corev1.PodSecurityContext{}
	if policyServer.Spec.SecurityContexts.Pod != nil {
		podSecurityContext = policyServer.Spec.SecurityContexts.Pod
	}
	if policyServer.Spec.SecurityContexts.Container != nil {
		admissionContainer.SecurityContext = policyServer.Spec.SecurityContexts.Container
	} else {
		admissionContainer.SecurityContext = defaultContainerSecurityContext()
	}

	templateAnnotations := policyServer.Spec.Annotations
	if templateAnnotations == nil {
		templateAnnotations = make(map[string]string)
	}

	if r.MetricsEnabled {
		templateAnnotations[constants.OptelInjectAnnotation] = "true" //nolint:goconst

		envvar := corev1.EnvVar{Name: constants.PolicyServerEnableMetricsEnvVar, Value: "true"}
		if index := envVarsContainVariable(admissionContainer.Env, constants.PolicyServerEnableMetricsEnvVar); index >= 0 {
			admissionContainer.Env[index] = envvar
		} else {
			admissionContainer.Env = append(admissionContainer.Env, envvar)
		}
	}

	if r.TracingEnabled {
		templateAnnotations[constants.OptelInjectAnnotation] = "true"

		logFmtEnvVar := corev1.EnvVar{Name: constants.PolicyServerLogFmtEnvVar, Value: "otlp"}
		if index := envVarsContainVariable(admissionContainer.Env, constants.PolicyServerLogFmtEnvVar); index >= 0 {
			admissionContainer.Env[index] = logFmtEnvVar
		} else {
			admissionContainer.Env = append(admissionContainer.Env, logFmtEnvVar)
		}
	}

	policyServerDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
			Annotations: map[string]string{
				constants.PolicyServerDeploymentConfigVersionAnnotation: configMapVersion,
			},
			Labels: map[string]string{
				constants.AppLabelKey:          policyServer.AppLabel(),
				constants.PolicyServerLabelKey: policyServer.Name,
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
						constants.PolicyServerDeploymentPodSpecConfigVersionLabel: configMapVersion,
						constants.PolicyServerLabelKey:                            policyServer.Name,
					},
					Annotations: templateAnnotations,
				},
				Spec: corev1.PodSpec{
					SecurityContext:    podSecurityContext,
					Containers:         []corev1.Container{admissionContainer},
					ServiceAccountName: policyServer.Spec.ServiceAccountName,
					Volumes: []corev1.Volume{
						{
							Name: policyStoreVolume,
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
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

	r.adaptDeploymentSettingsForPolicyServer(policyServerDeployment, policyServer)

	return policyServerDeployment
}

func defaultContainerSecurityContext() *corev1.SecurityContext {
	enableReadOnlyFilesystem := true
	privileged := false
	runAsNonRoot := true
	allowPrivilegeEscalation := false
	capabilities := corev1.Capabilities{
		Add:  []corev1.Capability{},
		Drop: []corev1.Capability{"all"},
	}
	admissionContainerSecurityContext := corev1.SecurityContext{
		ReadOnlyRootFilesystem:   &enableReadOnlyFilesystem,
		Privileged:               &privileged,
		AllowPrivilegeEscalation: &allowPrivilegeEscalation,
		Capabilities:             &capabilities,
		RunAsNonRoot:             &runAsNonRoot,
	}
	return &admissionContainerSecurityContext
}
