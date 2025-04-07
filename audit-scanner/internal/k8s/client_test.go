package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicFake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

const pageSize = 100

func TestGetResources(t *testing.T) {
	var pods []runtime.Object
	for i := range pageSize + 5 {
		pods = append(pods, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pod-%d", i), Namespace: "default"}})
	}

	dynamicClient := dynamicFake.NewSimpleDynamicClient(scheme.Scheme, pods...)
	clientset := fake.NewSimpleClientset()

	logger := slog.Default()
	k8sClient, err := NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)
	require.NoError(t, err)

	pager, err := k8sClient.GetResources(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	}, "default")
	require.NoError(t, err)

	list, _, err := pager.List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)

	unstructuredList, ok := list.(*unstructured.UnstructuredList)
	require.True(t, ok, "expected unstructured list")

	assert.Len(t, unstructuredList.Items, pageSize+5)
	assert.Equal(t, "PodList", unstructuredList.GetObjectKind().GroupVersionKind().Kind)
}
