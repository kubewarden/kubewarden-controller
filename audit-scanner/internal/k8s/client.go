package k8s

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/pager"
)

const pageSize = 100

// A client to get resources and namespaces from a Kubernetes cluster
type Client struct {
	// dynamicClient is used to get resource lists
	dynamicClient dynamic.Interface
	// client is used to get namespaces
	clientset kubernetes.Interface
	// list of skipped namespaces from audit, by name. It includes kubewardenNamespace
	skippedNs []string
}

// NewClient returns a new client
func NewClient(dynamicClient dynamic.Interface, clientset kubernetes.Interface, kubewardenNamespace string, skippedNs []string) (*Client, error) {
	skippedNs = append(skippedNs, kubewardenNamespace)

	return &Client{
		dynamicClient,
		clientset,
		skippedNs,
	}, nil
}

func (f *Client) GetResources(gvr schema.GroupVersionResource, nsName string) (*pager.ListPager, error) {
	page := 0

	listPager := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		var resources *unstructured.UnstructuredList
		page++

		resources, err := f.listResources(ctx, gvr, nsName, opts)
		if apimachineryerrors.IsNotFound(err) {
			log.Warn().
				Dict("dict", zerolog.Dict().
					Str("resource GVK", gvr.String()).
					Str("ns", nsName),
				).Msg("API resource not found")
		}
		if apimachineryerrors.IsForbidden(err) {
			// ServiceAccount lacks permissions, GVK may not exist, or policies may be misconfigured
			log.Warn().
				Dict("dict", zerolog.Dict().
					Str("resource GVK", gvr.String()).
					Str("ns", nsName),
				).Msg("API resource forbidden, unknown GVK or ServiceAccount lacks permissions")
		}
		if err != nil {
			return nil, err
		}

		return resources, nil
	})

	listPager.PageSize = pageSize

	return listPager, nil
}

func (f *Client) listResources(ctx context.Context,
	gvr schema.GroupVersionResource,
	nsName string,
	opts metav1.ListOptions,
) (
	*unstructured.UnstructuredList, error,
) {
	resourceID := schema.GroupVersionResource{
		Group:    gvr.Group,
		Version:  gvr.Version,
		Resource: gvr.Resource,
	}

	return f.dynamicClient.Resource(resourceID).Namespace(nsName).List(ctx, opts)
}

// GetAuditedNamespaces gets all namespaces besides the ones in skippedNs
func (f *Client) GetAuditedNamespaces(ctx context.Context) (*corev1.NamespaceList, error) {
	// This function cannot be tested with fake client, as filtering is done server-side
	skipNsFields := fields.Everything()
	for _, nsName := range f.skippedNs {
		skipNsFields = fields.AndSelectors(skipNsFields, fields.OneTermNotEqualSelector("metadata.name", nsName))
		log.Debug().Str("ns", nsName).Msg("skipping ns")
	}

	namespaceList, err := f.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{FieldSelector: skipNsFields.String()})
	if err != nil {
		return nil, fmt.Errorf("can't list namespaces: %w", err)
	}
	return namespaceList, nil
}

func (f *Client) GetNamespace(ctx context.Context, nsName string) (*corev1.Namespace, error) {
	return f.clientset.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
}
