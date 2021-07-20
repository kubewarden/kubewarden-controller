package admission

import (
	"testing"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
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
  KUBEWARDEN_LOG_LEVEL: debug
  OTEL_EXPORTER_JAEGER_AGENT_HOST: localhost
  sidecar.jaegertracing.io/inject: kubewarden
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

	expectedEnvVars := map[string]string{
		"KUBEWARDEN_LOG_LEVEL":            "debug",
		"OTEL_EXPORTER_JAEGER_AGENT_HOST": "localhost",
	}

	for expectedKey, expectedValue := range expectedEnvVars {
		value, found := settings.EnvVars[expectedKey]
		if !found {
			t.Errorf("did not find %s", expectedKey)
		}
		if value != expectedValue {
			t.Errorf("unexpected value for key %s, expected %s - got %s",
				expectedKey,
				expectedValue,
				settings.EnvVars[expectedKey])
		}
	}

	// check tracing values
	value, found := settings.Annotations[constants.PolicyServerJaegerSidecar]
	if !found {
		t.Errorf("didn't find the jaeger sidecar annotation")
	}
	if value != "kubewarden" {
		t.Errorf("unexpected value for the jaeger sidecar: %v", value)
	}

	value, found = settings.EnvVars[constants.PolicyServerLogFormat]
	if !found {
		t.Errorf("didn't find the KUBEWARDEN_LOG_FMT env variable")
	}
	if value != "jaeger" {
		t.Errorf("unexpected value for the log format")
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
  KUBEWARDEN_LOG_LEVEL: debug
  sidecar.opentelemetry.io/inject: kubewarden
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

	expectedEnvVars := map[string]string{
		"KUBEWARDEN_LOG_LEVEL": "debug",
		"KUBEWARDEN_LOG_FMT":   "otlp",
	}

	for k, expectedV := range expectedEnvVars {
		actualV, found := findEnvVar(k, container.Env)
		if !found {
			t.Errorf("Cannot find env variable %s", k)
		}
		if actualV != expectedV {
			t.Errorf("Wrong value for env variable %s, expected %s - got %s",
				k, expectedV, actualV)
		}
	}

	annotations := deployment.Spec.Template.ObjectMeta.Annotations
	sidecar, found := annotations[constants.PolicyServerOpenTelemetrySidecar]
	if !found {
		t.Errorf("Couldn't find otel sidecar annotation")
	}
	if sidecar != "kubewarden" {
		t.Errorf("Wrong value for the otel sidecar: %s", sidecar)
	}
}

func findEnvVar(key string, envVars []corev1.EnvVar) (string, bool) {
	for _, env := range envVars {
		if env.Name == key {
			return env.Value, true
		}
	}

	return "", false
}
