package k8s

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/pager"
)

// Client retrieves resources and namespaces from a Kubernetes cluster.
type Client struct {
	// dynamicClient is used to get resource lists
	dynamicClient dynamic.Interface
	// client is used to get namespaces
	clientset kubernetes.Interface
	// list of skipped namespaces from audit, by name. It includes kubewardenNamespace
	skippedNs []string
	// pageSize is the number of resources to fetch when paginating
	pageSize int64
	// logger is used to log the messages
	logger *slog.Logger
}

// NewClient returns a new client.
func NewClient(dynamicClient dynamic.Interface, clientset kubernetes.Interface, kubewardenNamespace string, skippedNs []string, pageSize int64, logger *slog.Logger) *Client {
	skippedNs = append(skippedNs, kubewardenNamespace)

	return &Client{
		dynamicClient,
		clientset,
		skippedNs,
		pageSize,
		logger.With("component", "k8sclient"),
	}
}

func (f *Client) GetResources(gvr schema.GroupVersionResource, nsName string) *pager.ListPager {
	listPager := pager.New(func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		list, err := f.listResources(ctx, gvr, nsName, opts)
		return list, err
	})

	listPager.PageSize = f.pageSize
	return listPager
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

	list, err := f.dynamicClient.Resource(resourceID).Namespace(nsName).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("can't list resources %s in namespace %s: %w", gvr.String(), nsName, err)
	}
	return list, nil
}

// GetAuditedNamespaces gets all namespaces besides the ones in skippedNs.
func (f *Client) GetAuditedNamespaces(ctx context.Context) (*corev1.NamespaceList, error) {
	// This function cannot be tested with fake client, as filtering is done server-side
	skipNsFields := fields.Everything()
	for _, nsName := range f.skippedNs {
		skipNsFields = fields.AndSelectors(skipNsFields, fields.OneTermNotEqualSelector("metadata.name", nsName))
		f.logger.DebugContext(ctx, "skipping ns", slog.String("ns", nsName))
	}

	namespaceList, err := f.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{FieldSelector: skipNsFields.String()})
	if err != nil {
		return nil, fmt.Errorf("can't list namespaces: %w", err)
	}
	return namespaceList, nil
}

func (f *Client) GetNamespace(ctx context.Context, nsName string) (*corev1.Namespace, error) {
	namespace, err := f.clientset.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("can't get namespace %s: %w", nsName, err)
	}
	return namespace, nil
}
