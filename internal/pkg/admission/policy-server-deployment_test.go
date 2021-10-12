package admission

import (
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestShouldUpdatePolicyServerDeployment(t *testing.T) {
	deployment := createDeployment(1, "sa", "", "image", []corev1.EnvVar{{Name: "env1"}}, map[string]string{})
	var tests = []struct {
		name     string
		original *appsv1.Deployment
		new      *appsv1.Deployment
		expect   bool
	}{
		{"equal deployments", deployment, createDeployment(1, "sa", "", "image", []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), false},
		{"different replicas", deployment, createDeployment(2, "sa", "", "image", []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), true},
		{"different image", deployment, createDeployment(1, "sa", "", "test", []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), true},
		{"different serviceAccount", deployment, createDeployment(1, "serviceAccount", "", "image", []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), true},
		{"new imagePullSecret", deployment, createDeployment(1, "sa", "regcred", "image", []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), true},
		{"different imagePullSecret", createDeployment(1, "sa", "regcred", "image", nil, map[string]string{}), createDeployment(1, "sa", "regcred2", "image", nil, map[string]string{}), false},
		{"different env", deployment, createDeployment(1, "sa", "", "image", []corev1.EnvVar{{Name: "env1"}, {Name: "env2"}}, map[string]string{}), true},
		{"different annotation", deployment, createDeployment(1, "sa", "", "image", []corev1.EnvVar{{Name: "env1"}}, map[string]string{"key": "val"}), true},
		{"same nil env", createDeployment(1, "sa", "", "image", nil, map[string]string{}), createDeployment(1, "sa", "", "image", nil, map[string]string{}), false},
		{"same nil annotation", createDeployment(1, "sa", "", "image", []corev1.EnvVar{{Name: "env1"}}, nil), createDeployment(1, "sa", "", "image", []corev1.EnvVar{{Name: "env1"}}, nil), false},
	}

	for _, test := range tests {
		tt := test // ensure tt is correctly scoped when used in function literal
		t.Run(tt.name, func(t *testing.T) {
			got := shouldUpdatePolicyServerDeployment(tt.original, tt.new)
			if got != tt.expect {
				t.Errorf("got %t, want %t", got, tt.expect)
			}
		})
	}
}

func createDeployment(replicasInt int, serviceAccount, imagePullSecret, image string, env []corev1.EnvVar, annotations map[string]string) *appsv1.Deployment {
	replicas := int32(replicasInt)
	const (
		imagePullSecretVolumeName        = "imagepullsecret"
		dockerConfigJSONPolicyServerPath = "/home/kubewarden/.docker"
	)
	container := corev1.Container{
		Image: image,
		Env:   env,
	}
	if imagePullSecret != "" {
		container.VolumeMounts = append(container.VolumeMounts,
			corev1.VolumeMount{
				Name:      imagePullSecretVolumeName,
				ReadOnly:  true,
				MountPath: dockerConfigJSONPolicyServerPath,
			},
		)
		container.Env = append(container.Env,
			corev1.EnvVar{
				Name:  "KUBEWARDEN_DOCKER_CONFIG_JSON_PATH",
				Value: filepath.Join(dockerConfigJSONPolicyServerPath, ".dockerconfigjson"),
			},
		)
	}

	policyServerDeployment := &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: nil,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Annotations: annotations},
				Spec: corev1.PodSpec{
					Containers:         []corev1.Container{container},
					ServiceAccountName: serviceAccount,
				},
			},
			Strategy:                appsv1.DeploymentStrategy{},
			MinReadySeconds:         0,
			RevisionHistoryLimit:    nil,
			Paused:                  false,
			ProgressDeadlineSeconds: nil,
		},
		Status: appsv1.DeploymentStatus{},
	}
	if imagePullSecret != "" {
		policyServerDeployment.Spec.Template.Spec.Volumes = append(
			policyServerDeployment.Spec.Template.Spec.Volumes,
			corev1.Volume{
				Name: imagePullSecretVolumeName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: imagePullSecret,
					},
				},
			},
		)
	}

	return policyServerDeployment
}
