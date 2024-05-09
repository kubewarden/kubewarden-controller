package admission

import (
	"testing"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
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

func TestDeploymentMetricsConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		metricsEnabled bool
		tracingEnabled bool
	}{
		{"with metrics enabled", true, false},
		{"with tracing enabled", false, true},
		{"with metrics and tracing enabled", true, true},
		{"with metrics and tracing disabled", false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reconciler := newReconciler(nil, test.metricsEnabled, test.tracingEnabled)
			deployment := &appsv1.Deployment{}
			policyServer := &policiesv1.PolicyServer{}
			err := reconciler.updatePolicyServerDeployment(policyServer, deployment, "")
			require.NoError(t, err)
			if test.metricsEnabled || test.tracingEnabled {
				require.Contains(t, deployment.Spec.Template.GetAnnotations(), constants.OptelInjectAnnotation, "Deployment pod spec should have OpenTelemetry annotations")
				require.Equal(t, "true", deployment.Spec.Template.GetAnnotations()[constants.OptelInjectAnnotation], "Deployment pod spec should have OpenTelemetry annotations value equal to 'true'")
			}
			if !test.metricsEnabled && !test.tracingEnabled {
				require.NotContains(t, deployment.Spec.Template.GetAnnotations(), constants.OptelInjectAnnotation, "Deployment pod spec should not have OpenTelemetry annotations")
			}

			if test.metricsEnabled {
				require.Contains(t, deployment.Spec.Template.Spec.Containers[0].Env,
					corev1.EnvVar{Name: constants.PolicyServerEnableMetricsEnvVar, Value: "true"}, "Policy server container should have metrics environment variable")
			} else {
				require.NotContains(t, deployment.Spec.Template.Spec.Containers[0].Env,
					corev1.EnvVar{Name: constants.PolicyServerEnableMetricsEnvVar, Value: "true"}, "Policy server container should not have metrics environment variable")
			}

			if test.tracingEnabled {
				require.Contains(t, deployment.Spec.Template.Spec.Containers[0].Env,
					corev1.EnvVar{Name: constants.PolicyServerLogFmtEnvVar, Value: "otlp"}, "Policy server container should have tracing environment variable")
			} else {
				require.NotContains(t, deployment.Spec.Template.Spec.Containers[0].Env,
					corev1.EnvVar{Name: constants.PolicyServerLogFmtEnvVar, Value: "otlp"}, "Policy server container should not have tracing environment variable")
			}
		})
	}
}

func TestPolicyServerDeploymentOwnerReference(t *testing.T) {
	reconciler := newReconciler(nil, false, false)
	policyServer := policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			UID:  "test-uid",
		},
	}
	gvk, err := apiutil.GVKForObject(&policyServer, reconciler.Client.Scheme())
	require.NoError(t, err)
	deployment := &appsv1.Deployment{}

	err = reconciler.updatePolicyServerDeployment(&policyServer, deployment, "")

	require.NoError(t, err)
	require.Equal(t, policyServer.GetName(), deployment.OwnerReferences[0].Name)
	require.Equal(t, policyServer.GetUID(), deployment.OwnerReferences[0].UID)
	require.Equal(t, gvk.GroupVersion().String(), deployment.OwnerReferences[0].APIVersion)
	require.Equal(t, gvk.Kind, deployment.OwnerReferences[0].Kind)
}
