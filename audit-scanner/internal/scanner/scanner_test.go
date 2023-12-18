package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kubewarden/audit-scanner/internal/constants"
	"github.com/kubewarden/audit-scanner/internal/report"
	"github.com/kubewarden/audit-scanner/internal/resources"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	admv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var defaultHTTPTestingServerFunc = func(response http.ResponseWriter, req *http.Request) {
	_, err := io.Copy(response, req.Body)
	if err != nil {
		fmt.Fprintf(response, "Cannot write the response")
	}
}

var defaultHTTPTestingServerHandler = http.HandlerFunc(defaultHTTPTestingServerFunc)

type ResourcesFetcherMock struct {
	auditURL string
}

func (r ResourcesFetcherMock) GetResourcesForPolicies(_ context.Context, _ []policiesv1.Policy, _ string) ([]resources.AuditableResources, error) {
	return []resources.AuditableResources{}, nil
}

func (r ResourcesFetcherMock) GetPolicyServerURLRunningPolicy(_ context.Context, _ policiesv1.Policy) (*url.URL, error) {
	return url.Parse(r.auditURL)
}

func (r ResourcesFetcherMock) GetClusterWideResourcesForPolicies(_ context.Context, _ []policiesv1.Policy) ([]resources.AuditableResources, error) {
	return []resources.AuditableResources{}, nil
}

func TestSendRequestToPolicyServer(t *testing.T) {
	server := httptest.NewServer(defaultHTTPTestingServerHandler)
	defer func() { server.Close() }()

	admRequest := admv1.AdmissionRequest{
		UID:  "uid",
		Name: "name",
		Kind: metav1.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "pod",
		},
		Resource: metav1.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "pod",
		},
		Operation: admv1.Create,
		Namespace: "namespace",
	}
	admReview := admv1.AdmissionReview{
		Request:  &admRequest,
		Response: nil,
	}
	url, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response, err := sendAdmissionReviewToPolicyServer(url, &admReview, server.Client())
	if err != nil && response == nil {
		t.Fatal(err)
	}
	admissionRequest := response.Request

	if admissionRequest.Kind.Group != "" {
		t.Errorf("Group diverge")
	}
	if admissionRequest.Kind.Kind != "pod" {
		t.Errorf("Kind diverge")
	}
	if admissionRequest.Kind.Version != "v1" {
		t.Errorf("Version diverge")
	}
}

func TestEvaluationClusterReportCache(t *testing.T) {
	serverCalled := false
	admReview := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{},
		Response: &admv1.AdmissionResponse{
			Allowed: true,
			UID:     "asdf-rwegc-qwasd-hwertreg",
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, req *http.Request) {
		serverCalled = true
		payload, _ := json.Marshal(admReview)
		_, err := response.Write(payload)
		if err != nil {
			panic("Unexpected error on testing HTTP server!")
		}
	}))
	defer func() { server.Close() }()

	policy := policiesv1.ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-admission-policy",
		},
	}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindClusterAdmissionPolicy,
	})
	policy.SetResourceVersion("1")
	resource := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Namespace",
			"metadata": map[string]interface{}{
				"name":            "testingns",
				"resourceVersion": "2",
			},
			"spec":   map[string]interface{}{},
			"status": map[string]interface{}{},
		},
	}

	auditableResource := resources.AuditableResources{
		Policies: []policiesv1.Policy{&policy},
		// It can be any kubernetes resource
		Resources: []unstructured.Unstructured{resource},
	}

	resourcesFetcher := ResourcesFetcherMock{
		auditURL: server.URL,
	}
	clusterReport := report.NewClusterPolicyReport("")
	previousClusterReport := report.NewClusterPolicyReport("")
	previousClusterReport.AddResult(previousClusterReport.CreateResult(&policy, resource, &admReview, nil))

	auditClusterResource(&auditableResource, resourcesFetcher, server.Client(), &clusterReport, &previousClusterReport)

	if serverCalled {
		t.Errorf("Policy server should not be contacted")
	}
}

func TestEvaluationNamespaceReportCache(t *testing.T) {
	serverCalled := false
	admReview := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{},
		Response: &admv1.AdmissionResponse{
			Allowed: true,
			UID:     "asdf-rwegc-qwasd-hwertreg",
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, req *http.Request) {
		serverCalled = true
		payload, _ := json.Marshal(admReview)
		_, err := response.Write(payload)
		if err != nil {
			panic("Unexpected error on testing HTTP server!")
		}
	}))
	defer func() { server.Close() }()

	policy := policiesv1.AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admission-policy",
		},
	}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindAdmissionPolicy,
	})
	policy.SetResourceVersion("1")
	resource := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":            "testingpod",
				"resourceVersion": "2",
			},
			"spec":   map[string]interface{}{},
			"status": map[string]interface{}{},
		},
	}

	auditableResource := resources.AuditableResources{
		Policies: []policiesv1.Policy{&policy},
		// It can be any kubernetes resource
		Resources: []unstructured.Unstructured{resource},
	}

	resourcesFetcher := ResourcesFetcherMock{
		auditURL: server.URL,
	}
	namespace := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "mynamespace",
		},
	}
	previousReport := report.NewPolicyReport(namespace)
	previousReport.AddResult(previousReport.CreateResult(&policy, resource, &admReview, nil))
	report := report.NewPolicyReport(namespace)

	auditResource(&auditableResource, resourcesFetcher, server.Client(), &report, &previousReport)

	if serverCalled {
		t.Errorf("Policy server should not be contacted")
	}
}
