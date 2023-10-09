package admission

import (
	"path/filepath"
	"testing"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	policyServerName          = "testing"
	policyServerContainerName = "policy-server-testing"
	invalidPolicyServerName   = "invalid"
	dropCapabilityAll         = "all"
)

func TestShouldUpdatePolicyServerDeployment(t *testing.T) {
	deployment := createDeployment(1, "sa", "", "image", nil, []corev1.EnvVar{{Name: "env1"}}, map[string]string{})
	tests := []struct {
		name     string
		original *appsv1.Deployment
		new      *appsv1.Deployment
		expect   bool
	}{
		{"equal deployments", deployment, createDeployment(1, "sa", "", "image", nil, []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), false},
		{"different replicas", deployment, createDeployment(2, "sa", "", "image", nil, []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), true},
		{"different image", deployment, createDeployment(1, "sa", "", "test", nil, []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), true},
		{"different serviceAccount", deployment, createDeployment(1, "serviceAccount", "", "image", nil, []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), true},
		{"new imagePullSecret", deployment, createDeployment(1, "sa", "regcred", "image", nil, []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), true},
		{"different imagePullSecret", createDeployment(1, "sa", "regcred", "image", nil, nil, map[string]string{}), createDeployment(1, "sa", "regcred2", "image", nil, nil, map[string]string{}), false},
		{"new insecureSources", deployment, createDeployment(1, "sa", "regcred", "image", []string{"localhost:5000"}, []corev1.EnvVar{{Name: "env1"}}, map[string]string{}), true},
		{"different insecureSources", createDeployment(1, "sa", "regcred", "image", []string{"localhost:4000"}, nil, map[string]string{}), createDeployment(1, "sa", "regcred2", "image", []string{"localhost:9999"}, nil, map[string]string{}), false},
		{"different env", deployment, createDeployment(1, "sa", "", "image", nil, []corev1.EnvVar{{Name: "env1"}, {Name: "env2"}}, map[string]string{}), true},
		{"different annotation", deployment, createDeployment(1, "sa", "", "image", nil, []corev1.EnvVar{{Name: "env1"}}, map[string]string{"key": "val"}), true},
		{"same nil env", createDeployment(1, "sa", "", "image", nil, nil, map[string]string{}), createDeployment(1, "sa", "", "image", nil, nil, map[string]string{}), false},
		{"same nil annotation", createDeployment(1, "sa", "", "image", nil, []corev1.EnvVar{{Name: "env1"}}, nil), createDeployment(1, "sa", "", "image", nil, []corev1.EnvVar{{Name: "env1"}}, nil), false},
	}

	policyServer := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
		},
	}
	policyServer.Name = policyServerName
	for _, test := range tests {
		tt := test // ensure tt is correctly scoped when used in function literal
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shouldUpdatePolicyServerDeployment(policyServer, tt.original, tt.new)
			if got != tt.expect {
				t.Errorf("got %t, want %t", got, tt.expect)
			}
		})
	}
}

func createDeployment(replicasInt int, serviceAccount, imagePullSecret, image string,
	insecureSources []string,
	env []corev1.EnvVar, annotations map[string]string,
) *appsv1.Deployment {
	replicas := int32(replicasInt)
	const (
		imagePullSecretVolumeName        = "imagepullsecret"
		dockerConfigJSONPolicyServerPath = "/home/kubewarden/.docker"
		sourcesVolumeName                = "sources"
		sourcesConfigContainerPath       = "/sources"
		sourcesFilename                  = "sources.yml"
	)
	container := corev1.Container{
		Image: image,
		Env:   env,
		Name:  policyServerContainerName,
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
	if len(insecureSources) > 0 {
		container.VolumeMounts = append(container.VolumeMounts,
			corev1.VolumeMount{
				Name:      sourcesVolumeName,
				ReadOnly:  true,
				MountPath: sourcesConfigContainerPath,
			},
		)
		container.Env = append(container.Env,
			corev1.EnvVar{
				Name:  "KUBEWARDEN_SOURCES_PATH",
				Value: filepath.Join(sourcesConfigContainerPath, sourcesFilename),
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

func insertContainer(deployment *appsv1.Deployment) {
	container := corev1.Container{
		Name:  "container0",
		Image: "container0image:latest",
	}
	containers := []corev1.Container{container}
	containers = append(containers, deployment.Spec.Template.Spec.Containers...)
	deployment.Spec.Template.Spec.Containers = containers
}

func TestGetPolicyServeImageFromDeployment(t *testing.T) {
	policyServer := policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
		},
	}
	policyServer.Name = policyServerName
	deployment := createDeployment(1, "sa", "", "image", nil, []corev1.EnvVar{}, map[string]string{})
	image, err := getPolicyServerImageFromDeployment(&policyServer, deployment)
	if err != nil || image != "image" {
		t.Errorf("The function cannot find the right container image for the policy server container. Expected: 'image', Got: %s", image)
	}
	deployment.Spec.Template.Spec.Containers[0].Name = "policy-server-default"
	image, err = getPolicyServerImageFromDeployment(&policyServer, deployment)
	if err == nil || image != "" {
		t.Error("The function should not be able to find the container image. Because there is no container with the policy server name")
	}
}

func TestIfPolicyServerImageChanged(t *testing.T) {
	policyServer := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
		},
	}
	policyServer.Name = policyServerName
	oldDeployment := createDeployment(1, "sa", "", "image", nil, []corev1.EnvVar{}, map[string]string{})
	newDeployment := createDeployment(1, "sa", "", "image", nil, []corev1.EnvVar{}, map[string]string{})
	oldDeployment.Spec.Template.Spec.Containers[0].Name = policyServerContainerName
	newDeployment.Spec.Template.Spec.Containers[0].Name = policyServerContainerName

	changed, err := isPolicyServerImageChanged(policyServer, oldDeployment, newDeployment)
	if changed || err != nil {
		t.Errorf("Function should not detect change in the container image. changed: %v, err: %v", changed, err)
		return
	}
	insertContainer(oldDeployment)
	changed, err = isPolicyServerImageChanged(policyServer, oldDeployment, newDeployment)
	if changed || err != nil {
		t.Errorf("Function should not detect change in the container image. changed: %v, err: %v", changed, err)
		return
	}
	insertContainer(newDeployment)
	changed, err = isPolicyServerImageChanged(policyServer, oldDeployment, newDeployment)
	if changed || err != nil {
		t.Errorf("Function should not detect change in the container image. changed: %v, err: %v", changed, err)
		return
	}
	newDeployment.Spec.Template.Spec.Containers[1].Image = "image2"
	changed, err = isPolicyServerImageChanged(policyServer, oldDeployment, newDeployment)
	if changed == false || err != nil {
		t.Errorf("Function should detect change in the container image. changed: %v, err: %s", changed, err)
		return
	}

	policyServer.Name = invalidPolicyServerName
	_, err = isPolicyServerImageChanged(policyServer, oldDeployment, newDeployment)
	if err == nil {
		t.Errorf("Function should fail to find the container image.  err: %v", err)
	}
}

func TestPolicyServerWithContainerSecurityContext(t *testing.T) {
	reconciler := Reconciler{
		Client:               nil,
		DeploymentsNamespace: "kubewarden",
	}
	readOnlFileSystem := false
	privileged := true
	runAsRoot := false
	allowPrivilegeEscalation := true
	capabilities := corev1.Capabilities{
		Drop: []corev1.Capability{corev1.Capability(dropCapabilityAll)},
	}
	containerSecurity := corev1.SecurityContext{
		ReadOnlyRootFilesystem:   &readOnlFileSystem,
		Privileged:               &privileged,
		RunAsNonRoot:             &runAsRoot,
		AllowPrivilegeEscalation: &allowPrivilegeEscalation,
		Capabilities:             &capabilities,
	}
	policyServer := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
			SecurityContexts: policiesv1.PolicyServerSecurity{
				Container: &containerSecurity,
			},
		},
	}
	deployment := reconciler.deployment("v1", policyServer)

	if deployment.Spec.Template.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem == nil ||
		*deployment.Spec.Template.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem != readOnlFileSystem {
		t.Error("Policy server container ReadOnlyRootFilesystem diverge from the expected value")
	}
	if deployment.Spec.Template.Spec.Containers[0].SecurityContext.Privileged == nil ||
		*deployment.Spec.Template.Spec.Containers[0].SecurityContext.Privileged != privileged {
		t.Error("Policy server container Privileged diverge from the expected value")
	}
	if deployment.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot == nil ||
		*deployment.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot != runAsRoot {
		t.Error("Policy server container RunAsNonRoot diverges from the expected value")
	}
	if deployment.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation == nil ||
		*deployment.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation != allowPrivilegeEscalation {
		t.Error("Policy server container AllowPrivilegeEscalation diverge from the expected value")
	}
	if deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities == nil ||
		len(deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Add) > 0 ||
		len(deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Drop) != 1 ||
		deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Drop[0] != dropCapabilityAll {
		t.Error("Policy server container Capabilities diverge from the expected value")
	}
}

func TestPolicyServerWithPodSecurityContext(t *testing.T) {
	reconciler := Reconciler{
		Client:               nil,
		DeploymentsNamespace: "kubewarden",
	}
	var user, group int64
	user = 1000
	group = 2000
	podSecurity := corev1.PodSecurityContext{
		RunAsUser:  &user,
		RunAsGroup: &group,
	}
	policyServer := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
			SecurityContexts: policiesv1.PolicyServerSecurity{
				Pod: &podSecurity,
			},
		},
	}
	deployment := reconciler.deployment("v1", policyServer)

	if deployment.Spec.Template.Spec.SecurityContext == nil {
		t.Error("Pod securityContext should be defined ")
	}

	if deployment.Spec.Template.Spec.SecurityContext != nil {
		if *deployment.Spec.Template.Spec.SecurityContext.RunAsUser != user {
			t.Error("Pod RunAsUser diverges from the expected value")
		}
		if *deployment.Spec.Template.Spec.SecurityContext.RunAsGroup != group {
			t.Error("Pod RunAsGroup diverges from the expected value")
		}
	}
}

func TestPolicyServerWithoutSecurityContext(t *testing.T) {
	reconciler := Reconciler{
		Client:               nil,
		DeploymentsNamespace: "kubewarden",
	}
	policyServer := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image:            "image",
			SecurityContexts: policiesv1.PolicyServerSecurity{},
		},
	}
	deployment := reconciler.deployment("v1", policyServer)
	containerDefaultSecurityContext := defaultContainerSecurityContext()

	if *deployment.Spec.Template.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem != *containerDefaultSecurityContext.ReadOnlyRootFilesystem {
		t.Error("Policy server container ReadOnlyRootFilesystem diverge from the expected value")
	}
	if *deployment.Spec.Template.Spec.Containers[0].SecurityContext.Privileged != *containerDefaultSecurityContext.Privileged {
		t.Error("Policy server container Privileged diverge from the expected value")
	}
	if *deployment.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot != *containerDefaultSecurityContext.RunAsNonRoot {
		t.Error("Policy server container RunAsNonRoot diverges from the expected value")
	}
	if *deployment.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation != *containerDefaultSecurityContext.AllowPrivilegeEscalation {
		t.Error("Policy server container AllowPrivilegeEscalation diverge from the expected value")
	}
	if deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities == containerDefaultSecurityContext.Capabilities {
		t.Error("Policy server container should have capabilities defined")
	}
}

func TestPolicyServerWithPodAndContainerSecurityContext(t *testing.T) {
	reconciler := Reconciler{
		Client:               nil,
		DeploymentsNamespace: "kubewarden",
	}
	readOnlFileSystem := false
	privileged := true
	runAsRoot := false
	allowPrivilegeEscalation := true
	capabilities := corev1.Capabilities{
		Drop: []corev1.Capability{corev1.Capability(dropCapabilityAll)},
	}
	var user, group int64
	user = 1000
	group = 2000
	podSecurity := corev1.PodSecurityContext{
		RunAsUser:  &user,
		RunAsGroup: &group,
	}
	containerSecurity := corev1.SecurityContext{
		ReadOnlyRootFilesystem:   &readOnlFileSystem,
		Privileged:               &privileged,
		RunAsNonRoot:             &runAsRoot,
		AllowPrivilegeEscalation: &allowPrivilegeEscalation,
		Capabilities:             &capabilities,
	}
	policyServer := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
			SecurityContexts: policiesv1.PolicyServerSecurity{
				Container: &containerSecurity,
				Pod:       &podSecurity,
			},
		},
	}
	deployment := reconciler.deployment("v1", policyServer)

	if *deployment.Spec.Template.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem != readOnlFileSystem {
		t.Error("Policy server container ReadOnlyRootFilesystem diverge from the expected value")
	}
	if *deployment.Spec.Template.Spec.Containers[0].SecurityContext.Privileged != privileged {
		t.Error("Policy server container Privileged diverge from the expected value")
	}
	if *deployment.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot != runAsRoot {
		t.Error("Policy server container RunAsNonRoot diverges from the expected value")
	}
	if *deployment.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation != allowPrivilegeEscalation {
		t.Error("Policy server container AllowPrivilegeEscalation diverge from the expected value")
	}
	if deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities == nil {
		t.Error("Policy server container should have capabilities defined")
	} else {
		if len(deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Add) > 0 {
			t.Error("Policy server container should not have 'Add' capabilities defined")
		}
		if len(deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Drop) != 1 ||
			deployment.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities.Drop[0] != dropCapabilityAll {
			t.Error("Policy server container Capabilities should have only one 'All' drop capability")
		}
	}

	if deployment.Spec.Template.Spec.SecurityContext == nil {
		t.Error("Pod securityContext should be defined ")
		return
	}

	if *deployment.Spec.Template.Spec.SecurityContext.RunAsUser != user {
		t.Error("Pod RunAsUser diverges from the expected value")
	}
	if *deployment.Spec.Template.Spec.SecurityContext.RunAsGroup != group {
		t.Error("Pod RunAsGroup diverges from the expected value")
	}
}

func TestDefaultContainerSecurityContext(t *testing.T) {
	securityContext := defaultContainerSecurityContext()

	if *securityContext.ReadOnlyRootFilesystem != true {
		t.Error("Policy server container ReadOnlyRootFilesystem diverge from the expected value")
	}
	if *securityContext.Privileged != false {
		t.Error("Policy server container Privileged diverge from the expected value")
	}
	if *securityContext.RunAsNonRoot != true {
		t.Error("Policy server container RunAsNonRoot diverges from the expected value")
	}
	if *securityContext.AllowPrivilegeEscalation != false {
		t.Error("Policy server container AllowPrivilegeEscalation diverge from the expected value")
	}
	if securityContext.Capabilities == nil {
		t.Error("Policy server container should have capabilities defined")
	} else {
		if len(securityContext.Capabilities.Add) > 0 {
			t.Error("Policy server container should not have 'Add' capabilities defined")
		}
		if len(securityContext.Capabilities.Drop) != 1 ||
			securityContext.Capabilities.Drop[0] != dropCapabilityAll {
			t.Error("Policy server container Capabilities should have only one 'All' drop capability")
		}
	}
}

func TestMetricAndLogFmtEnvVarsDetection(t *testing.T) {
	for _, envVarName := range []string{constants.PolicyServerEnableMetricsEnvVar} {
		env := []corev1.EnvVar{{Name: "env1"}, {Name: "env2"}, {Name: envVarName}, {Name: "env3"}}
		envIndex := envVarsContainVariable(env, envVarName)
		if envIndex != 2 {
			t.Error("Function must find a metrics environment at position {}. Found at {}.", 2, envIndex)
		}

		env = []corev1.EnvVar{{Name: "env1"}, {Name: "env2"}, {Name: "env3"}}
		envIndex = envVarsContainVariable(env, envVarName)
		if envIndex != -1 {
			t.Error("Function must the metrics environment variable at position {}. Found at {}.", -1, envIndex)
		}
	}
}

func TestPolicyServerDeploymentMetricConfigurationWithValueDefinedByUser(t *testing.T) {
	reconciler := Reconciler{
		Client:               nil,
		DeploymentsNamespace: "kubewarden",
		MetricsEnabled:       true,
	}
	policyServer := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
			Env:   []corev1.EnvVar{{Name: constants.PolicyServerEnableMetricsEnvVar, Value: "0"}},
		},
	}
	deployment := reconciler.deployment("v1", policyServer)
	hasMetricEnvvar := false
	for _, envvar := range deployment.Spec.Template.Spec.Containers[0].Env {
		if envvar.Name == constants.PolicyServerEnableMetricsEnvVar {
			hasMetricEnvvar = true
			if envvar.Value != "1" {
				t.Error("Present but not reconciled {} value", constants.PolicyServerEnableMetricsEnvVar)
			}
		}
	}
	if !hasMetricEnvvar {
		t.Error("Missing {} environment variable", constants.PolicyServerEnableMetricsEnvVar)
	}

	value, hasAnnotation := deployment.Spec.Template.Annotations["sidecar.opentelemetry.io/inject"]
	if !hasAnnotation {
		t.Error("Missing OTEL annotation")
	}
	if value != "true" {
		t.Error("OTEL annotation invalid value")
	}
}

func TestPolicyServerDeploymentMetricConfigurationWithNoValueDefinedByUSer(t *testing.T) {
	reconciler := Reconciler{
		Client:               nil,
		DeploymentsNamespace: "kubewarden",
		MetricsEnabled:       false,
	}
	policyServer := &policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image: "image",
			Env:   []corev1.EnvVar{},
		},
	}
	deployment := reconciler.deployment("v1", policyServer)
	hasMetricEnvvar := false
	for _, envvar := range deployment.Spec.Template.Spec.Containers[0].Env {
		if envvar.Name == constants.PolicyServerEnableMetricsEnvVar {
			hasMetricEnvvar = true
		}
	}
	if hasMetricEnvvar {
		t.Error("{} should not be set", constants.PolicyServerEnableMetricsEnvVar)
	}

	_, hasAnnotation := deployment.Spec.Template.Annotations["sidecar.opentelemetry.io/inject"]
	if hasAnnotation {
		t.Error("OTEL annotation should not be set")
	}
}
