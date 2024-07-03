package policies

import (
	"context"
	"net/url"
	"testing"

	"github.com/kubewarden/audit-scanner/internal/testutils"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestGetPoliciesForANamespace(t *testing.T) {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
	}

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app": "kubewarden-policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}

	// a ClusterAdmissionPolicy
	clusterAdmissionPolicy1 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods", "namespaces"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Build()

	// a ClusterAdmissionPolicy with a namespaceSelector that does not match the namespace
	clusterAdmissionPolicy2 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy2").
		NamespaceSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods", "namespaces"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Build()

	// a ClusterAdmissionPolicy with status pending, it should be skipped
	clusterAdmissionPolicy3 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy3").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods", "namespaces"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusPending).
		Build()

	// a ClusterAdmissionPolicy targeting namespaces, it should not be considered as it is targeting cluster-wide resources
	// it should not count as a skipped policy
	clusterAdmissionPolicy4 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy4").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		BackgroundAudit(false).
		Build()

	// an AdmissionPolicy
	admissionPolicy1 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy5").
		Namespace("test").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Build()

	// an AdmissionPolicy with background audit set to false, it should be skipped
	admissionPolicy2 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy6").
		Namespace("test").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		BackgroundAudit(false).
		Build()

	// an AdmissionPolicy in another namespace, it should not be considered
	admissionPolicy3 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy7").
		Namespace("prod").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Build()

	// an AdmissionPolicy in targeting wildcard resources, it should be skipped
	admissionPolicy4 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy8").
		Namespace("test").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"*"},
			APIVersions: []string{"*"},
			Resources:   []string{"*"},
		}).
		Build()

	// an AdmissionPolicy with unknown GVR, it should be errored and skipped
	admissionPolicy5 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy9").
		Namespace("test").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"foo"},
		}).
		Build()

	client, err := testutils.NewFakeClient(
		namespace,
		policyServer,
		policyServerService,
		clusterAdmissionPolicy1,
		clusterAdmissionPolicy2,
		clusterAdmissionPolicy3,
		clusterAdmissionPolicy4,
		admissionPolicy1,
		admissionPolicy2,
		admissionPolicy3,
		admissionPolicy4,
		admissionPolicy5,
	)
	require.NoError(t, err)

	policiesClient, err := NewClient(client, "kubewarden", "")
	require.NoError(t, err)

	policies, err := policiesClient.GetPoliciesForANamespace(context.Background(), "test")
	require.NoError(t, err)

	expectedPolicies := &Policies{
		PoliciesByGVR: map[schema.GroupVersionResource][]*Policy{
			{
				Group:    "",
				Version:  "v1",
				Resource: "pods",
			}: {
				{
					Policy:       clusterAdmissionPolicy1,
					PolicyServer: &url.URL{Scheme: "https", Host: "policy-server-default.kubewarden.svc:443", Path: "/audit/clusterwide-policy1"},
				},
				{
					Policy:       admissionPolicy1,
					PolicyServer: &url.URL{Scheme: "https", Host: "policy-server-default.kubewarden.svc:443", Path: "/audit/namespaced-test-policy5"},
				},
			},
			{
				Group:    "apps",
				Version:  "v1",
				Resource: "deployments",
			}: {
				{
					Policy:       clusterAdmissionPolicy1,
					PolicyServer: &url.URL{Scheme: "https", Host: "policy-server-default.kubewarden.svc:443", Path: "/audit/clusterwide-policy1"},
				},
				{
					Policy:       admissionPolicy1,
					PolicyServer: &url.URL{Scheme: "https", Host: "policy-server-default.kubewarden.svc:443", Path: "/audit/namespaced-test-policy5"},
				},
			},
		},
		PolicyNum:  2,
		SkippedNum: 3,
		ErroredNum: 1,
	}

	assert.Equal(t, expectedPolicies, policies)
}

func TestGetClusterWidePolicies(t *testing.T) {
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
	}

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app": "kubewarden-policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}

	// a ClusterAdmissionPolicy
	clusterAdmissionPolicy1 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Build()

	// a ClusterAdmissionPolicy with a namespaceSelector
	clusterAdmissionPolicy2 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy2").
		NamespaceSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Build()

	// a ClusterAdmissionPolicy with an objectSelector
	clusterAdmissionPolicy3 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy3").
		ObjectSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Build()

	// a ClusterAdmissionPolicy with background audit set to false, it should be skipped
	clusterAdmissionPolicy4 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy4").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		BackgroundAudit(false).
		Build()

	// a ClusterAdmissionPolicy targeting pods, it should not be considered as it is targeting namespaced resources
	clusterAdmissionPolicy5 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy5").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Build()

	// a ClusterAdmissionPolicy with no CREATE operation, it should be skipped
	clusterAdmissionPolicy6 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy6").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}, admissionregistrationv1.Update, admissionregistrationv1.Delete).
		Build()

	// an AdmissionPolicy, it should not be considered
	admissionPolicy1 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy7").
		Namespace("test").
		Build()

	// a ClusterAdmissionPolicy targeting unknown GVR, it should be errored and skipped
	clusterAdmissionPolicy7 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy8").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"foo"},
		}).
		Build()

	client, err := testutils.NewFakeClient(
		namespace,
		policyServer,
		policyServerService,
		clusterAdmissionPolicy1,
		clusterAdmissionPolicy2,
		clusterAdmissionPolicy3,
		clusterAdmissionPolicy4,
		clusterAdmissionPolicy5,
		clusterAdmissionPolicy6,
		admissionPolicy1,
		clusterAdmissionPolicy7,
	)
	require.NoError(t, err)

	policiesClient, err := NewClient(client, "kubewarden", "")
	require.NoError(t, err)

	policies, err := policiesClient.GetClusterWidePolicies(context.Background())
	require.NoError(t, err)

	expectedPolicies := &Policies{
		PoliciesByGVR: map[schema.GroupVersionResource][]*Policy{
			{
				Group:    "",
				Version:  "v1",
				Resource: "namespaces",
			}: {
				{
					Policy:       clusterAdmissionPolicy1,
					PolicyServer: &url.URL{Scheme: "https", Host: "policy-server-default.kubewarden.svc:443", Path: "/audit/clusterwide-policy1"},
				},
				{
					Policy:       clusterAdmissionPolicy2,
					PolicyServer: &url.URL{Scheme: "https", Host: "policy-server-default.kubewarden.svc:443", Path: "/audit/clusterwide-policy2"},
				},
				{
					Policy:       clusterAdmissionPolicy3,
					PolicyServer: &url.URL{Scheme: "https", Host: "policy-server-default.kubewarden.svc:443", Path: "/audit/clusterwide-policy3"},
				},
			},
		},
		PolicyNum:  3,
		SkippedNum: 2,
		ErroredNum: 1,
	}

	assert.Equal(t, expectedPolicies, policies)
}
