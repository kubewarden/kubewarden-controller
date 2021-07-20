package admission

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

func createConfigMapFromYaml(yaml string) (*corev1.ConfigMap, error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode

	obj, _, err := decode([]byte(yaml), nil, nil)
	if err != nil {
		return nil, err
	}

	return obj.(*corev1.ConfigMap), nil
}

func TestPolicyServerDeploymentSettings(t *testing.T) {
	rawCfg := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: policy-server
data:
  replicas: "4"
  image: registry.testing.org/policy-server:testing
  logLevel: debug
`
	cfg, err := createConfigMapFromYaml(rawCfg)
	if err != nil {
		t.Errorf("unexpected error creating the ConfigMap: %v", err)
	}

	settings := policyServerDeploymentSettings(cfg)

	if settings.Image != "registry.testing.org/policy-server:testing" {
		t.Errorf("unexpected value for image: %v", settings.Image)
	}

	if settings.Replicas != 4 {
		t.Errorf("unexpected value for replicas: %v", settings.Replicas)
	}

	if len(settings.EnvVars) != 1 {
		t.Errorf("unexpected number of entries inside of envVars: %v", len(settings.EnvVars))
	}

	value, found := settings.EnvVars["KUBEWARDEN_LOG_LEVEL"]
	if !found {
		t.Errorf("did not find KUBEWARDEN_LOG_LEVEL")
	}
	if value != "debug" {
		t.Errorf("unexpected log level: %v", settings.EnvVars["KUBEWARDEN_LOG_LEVEL"])
	}
}

func TestBuildDeployment(t *testing.T) {
	rawCfg := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: policy-server
data:
  replicas: "4"
  image: registry.testing.org/policy-server:testing
  logLevel: debug
`
	cfg, err := createConfigMapFromYaml(rawCfg)
	if err != nil {
		t.Errorf("unexpected error creating the ConfigMap: %v", err)
	}

	deployment := buildDeploymentFromConfigMap("testing", "testingSA", cfg)

	if *deployment.Spec.Replicas != 4 {
		t.Fatalf("unexpected number of replicas %v", *deployment.Spec.Replicas)
	}

	if len(deployment.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("unexpected number of containers defined %v", len(deployment.Spec.Template.Spec.Containers))
	}

	container := deployment.Spec.Template.Spec.Containers[0]

	if container.Image != "registry.testing.org/policy-server:testing" {
		t.Fatalf("unexpected image used %v", container.Image)
	}

	found := false
	var logEnvVar corev1.EnvVar

	for _, env := range container.Env {
		if env.Name == "KUBEWARDEN_LOG_LEVEL" {
			found = true
			logEnvVar = env
			break
		}
	}
	if !found {
		t.Fatalf("cound not find KUBEWARDEN_LOG_LEVEL env variable among %#v", container.Env)
	}
	if logEnvVar.Value != "debug" {
		t.Fatalf("unexpected log level: %#v", logEnvVar.Value)
	}
}
