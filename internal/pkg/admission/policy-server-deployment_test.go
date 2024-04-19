package admission

import (
	"testing"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	corev1 "k8s.io/api/core/v1"
)

const (
	dropCapabilityAll = "all"
)

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
	for _, envVarName := range []string{constants.PolicyServerEnableMetricsEnvVar, constants.PolicyServerLogFmtEnvVar} {
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
