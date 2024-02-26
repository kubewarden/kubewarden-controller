package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubewarden/audit-scanner/internal/k8s"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/report"
	reportMocks "github.com/kubewarden/audit-scanner/internal/report/mocks"
	"github.com/kubewarden/audit-scanner/internal/testutils"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	dynamicFake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

func newMockPolicyServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)

		admissionReview := admissionv1.AdmissionReview{
			Response: &admissionv1.AdmissionResponse{
				Allowed: true,
			},
		}
		response, err := json.Marshal(admissionReview)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}

		_, err = writer.Write(response)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}
	}))
}

func TestScanAllNamespaces(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

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

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
		},
	}

	namespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
		},
	}

	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "namespace1",
		},
	}

	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "namespace2",
		},
	}

	deployment1 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment1",
			Namespace: "namespace1",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	deployment2 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment2",
			Namespace: "namespace2",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	// an AdmissionPolicy targeting pods in namespace1
	admissionPolicy1 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy1").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting deployments in namespace2
	admissionPolicy2 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy2").
		Namespace("namespace2").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy with an object selector that matches deployment1 in namespace1
	admissionPolicy3 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy3").
		Namespace("namespace1").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy with an object selector that does not match any deployment in namespace2
	admissionPolicy4 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy4").
		Namespace("namespace2").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "prod"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting pods and deployments in all namespaces
	clusterAdmissionPolicy := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy5").
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
		Status(policiesv1.PolicyStatusActive).
		Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		scheme.Scheme,
		deployment1,
		deployment2,
		pod1,
		pod2)
	clientset := fake.NewSimpleClientset(
		namespace1,
		namespace2,
	)
	client := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		admissionPolicy1,
		admissionPolicy2,
		admissionPolicy3,
		admissionPolicy4,
		clusterAdmissionPolicy,
	)

	k8sClient, err := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil)
	require.NoError(t, err)

	policiesClient, err := policies.NewClient(client, "kubewarden", mockPolicyServer.URL)
	require.NoError(t, err)

	mockPolicyReportStore := reportMocks.NewPolicyReportStore(t)

	mockPolicyReportStore.EXPECT().GetPolicyReport("namespace1").Return(report.PolicyReport{}, nil).Once()
	mockPolicyReportStore.On("SavePolicyReport", mock.AnythingOfType("*report.PolicyReport")).
		Return(func(policyReport *report.PolicyReport) error {
			assert.Equal(t, "namespace1", policyReport.Namespace)
			assert.Equal(t, 4, policyReport.Summary.Pass)

			return nil
		}).Once()

	mockPolicyReportStore.EXPECT().GetPolicyReport("namespace2").Return(report.PolicyReport{}, nil).Once()
	mockPolicyReportStore.On("SavePolicyReport", mock.AnythingOfType("*report.PolicyReport")).
		Return(func(policyReport *report.PolicyReport) error {
			assert.Equal(t, "namespace2", policyReport.Namespace)
			assert.Equal(t, 3, policyReport.Summary.Pass)

			return nil
		}).Once()

	scanner, err := NewScanner(policiesClient, k8sClient, mockPolicyReportStore, false, true, "")
	require.NoError(t, err)

	err = scanner.ScanAllNamespaces(context.Background())
	require.NoError(t, err)
}

func TestScanClusterWideResources(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

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

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
		},
	}

	namespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	// a ClusterAdmissionPolicy targeting namespaces
	clusterAdmissionPolicy1 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting namespaces with an object selector that matches namespace2
	clusterAdmissionPolicy2 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy2").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting namespaces with an object selector that does not match any namespace
	clusterAdmissionPolicy3 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy3").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "prod"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		scheme.Scheme,
		namespace1,
		namespace2,
	)
	clientset := fake.NewSimpleClientset(
		namespace1,
		namespace2,
	)
	client := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		clusterAdmissionPolicy1,
		clusterAdmissionPolicy2,
		clusterAdmissionPolicy3,
	)

	k8sClient, err := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil)
	require.NoError(t, err)

	policiesClient, err := policies.NewClient(client, "kubewarden", mockPolicyServer.URL)
	require.NoError(t, err)

	mockPolicyReportStore := reportMocks.NewPolicyReportStore(t)
	mockPolicyReportStore.EXPECT().GetClusterPolicyReport("clusterwide").Return(report.ClusterPolicyReport{}, nil).Once()
	mockPolicyReportStore.On("SaveClusterPolicyReport", mock.AnythingOfType("*report.ClusterPolicyReport")).
		Return(func(policyReport *report.ClusterPolicyReport) error {
			assert.Equal(t, 3, policyReport.Summary.Pass)

			return nil
		}).Once()

	scanner, err := NewScanner(policiesClient, k8sClient, mockPolicyReportStore, false, true, "")
	require.NoError(t, err)

	err = scanner.ScanClusterWideResources(context.Background())
	require.NoError(t, err)
}
