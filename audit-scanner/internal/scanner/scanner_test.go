package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const auditURL = "http://localhost:9876/audit/"

func startServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/audit/", func(response http.ResponseWriter, req *http.Request) {
		_, err := io.Copy(response, req.Body)
		if err != nil {
			fmt.Fprintf(response, "Cannot write the response")
		}
	})
	mux.HandleFunc("/", func(response http.ResponseWriter, req *http.Request) {
		// The "/" pattern matches everything, so we need to check
		// that we're at the root here.
		if req.URL.Path != "/" {
			http.NotFound(response, req)
			return
		}
		fmt.Fprintf(response, "Welcome to the home page!")
	})
	err := http.ListenAndServe("localhost:9876", mux) //nolint
	if err != nil {
		fmt.Println(err)
	}
}

func TestSendRequestToPolicyServer(t *testing.T) {
	go startServer()

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
	url, err := url.Parse(auditURL)
	if err != nil {
		t.Fatal(err)
	}
	response, err := sendAdmissionReviewToPolicyServer(url, &admReview, &http.Client{})
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
