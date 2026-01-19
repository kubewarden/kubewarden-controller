package scanner

import (
	"testing"

	"github.com/google/uuid"
	admv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

const (
	resourceName      = "testing-name"
	resourceNamespace = "testing-namespace"
)

func generateUnstructuredPodObject() unstructured.Unstructured {
	groupVersionKind := schema.GroupVersionKind{
		Group:   "core",
		Version: "v1",
		Kind:    "Pod",
	}
	uid := types.UID(uuid.New().String())
	obj := unstructured.Unstructured{}
	obj.SetGroupVersionKind(groupVersionKind)
	obj.SetUID(uid)
	obj.SetName(resourceName)
	obj.SetNamespace(resourceNamespace)
	return obj
}

func TestObjectInAdmissionRequest(t *testing.T) {
	obj := generateUnstructuredPodObject()
	admissionRequest := newAdmissionRequest(obj)

	admReqObj := admissionRequest.Object.Object
	if admReqObj.GetObjectKind().GroupVersionKind().Group != obj.GroupVersionKind().Group {
		t.Errorf("Object group diverge")
	}
	if admReqObj.GetObjectKind().GroupVersionKind().Version != obj.GroupVersionKind().Version {
		t.Errorf("Object version diverge")
	}
	if admReqObj.GetObjectKind().GroupVersionKind().Kind != obj.GroupVersionKind().Kind {
		t.Errorf("Object Kind diverge")
	}
}

func TestBasicInfoInAdmissionRequest(t *testing.T) {
	obj := generateUnstructuredPodObject()
	admissionRequest := newAdmissionRequest(obj)

	if admissionRequest.Kind.Group != obj.GroupVersionKind().Group {
		t.Errorf("Group diverge")
	}
	if admissionRequest.Kind.Kind != obj.GroupVersionKind().Kind {
		t.Errorf("Kind diverge")
	}
	if admissionRequest.Kind.Version != obj.GroupVersionKind().Version {
		t.Errorf("Version diverge")
	}
	if admissionRequest.UID != obj.GetUID() {
		t.Errorf("UID diverge")
	}
	if admissionRequest.Name != resourceName {
		t.Errorf("Name diverge")
	}
	if admissionRequest.Resource.Group != obj.GroupVersionKind().Group {
		t.Errorf("Resource Group diverge")
	}
	if admissionRequest.Resource.Resource != obj.GroupVersionKind().Kind {
		t.Errorf("Resource diverge")
	}
	if admissionRequest.Resource.Version != obj.GroupVersionKind().Version {
		t.Errorf("Resource version diverge")
	}
	if admissionRequest.Namespace != resourceNamespace {
		t.Errorf("Namespace diverge")
	}
	if admissionRequest.Operation != admv1.Create {
		t.Errorf("Operation diverge")
	}
}

func TestGetAdmissionReview(t *testing.T) {
	obj := generateUnstructuredPodObject()
	admissionReview := newAdmissionReview(obj)

	if admissionReview.Response != nil {
		t.Fatalf("Response should not be set")
	}

	admissionRequest := admissionReview.Request

	if admissionRequest.Kind.Group != obj.GroupVersionKind().Group {
		t.Errorf("Group diverge")
	}
	if admissionRequest.Kind.Kind != obj.GroupVersionKind().Kind {
		t.Errorf("Kind diverge")
	}
	if admissionRequest.Kind.Version != obj.GroupVersionKind().Version {
		t.Errorf("Version diverge")
	}
	if admissionRequest.UID != obj.GetUID() {
		t.Errorf("UID diverge")
	}
	if admissionRequest.Name != resourceName {
		t.Errorf("Name diverge")
	}
	if admissionRequest.Resource.Group != obj.GroupVersionKind().Group {
		t.Errorf("Resource Group diverge")
	}
	if admissionRequest.Resource.Resource != obj.GroupVersionKind().Kind {
		t.Errorf("Resource diverge")
	}
	if admissionRequest.Resource.Version != obj.GroupVersionKind().Version {
		t.Errorf("Resource version diverge")
	}
	if admissionRequest.Namespace != resourceNamespace {
		t.Errorf("Namespace diverge")
	}
	if admissionRequest.Operation != admv1.Create {
		t.Errorf("Operation diverge")
	}
}
