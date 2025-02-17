package featuregates

import (
	"encoding/json"
	"fmt"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"

	"k8s.io/apimachinery/pkg/runtime"
)

// CheckAdmissionWebhookMatchConditions returns true if the feature gate
// AdmissionWebhookMatchConditions is activated. It does this by fetching the
// OpenAPIV3 schema from the discovery client and checking for the feature
// gate. This feature is stable since Kubernetes v1.30.
func CheckAdmissionWebhookMatchConditions(config *rest.Config) (bool, error) {
	// Obtain openAPIV3 client from discoveryClient
	apiClient := discovery.NewDiscoveryClientForConfigOrDie(config).OpenAPIV3()
	paths, err := apiClient.Paths()
	if err != nil {
		return false, fmt.Errorf("failed to fetch OpenAPI spec: %w", err)
	}

	// Check for the feature gate AdmissionWebhookMatchConditions by looking at
	// the path `apis/admissionregistration.k8s.io/v1`, under
	// `components.schemas.io.k8s.api.admissionregistration.v1.ValidatingWebhook`.
	resourcePath := "apis/admissionregistration.k8s.io/v1"
	groupVersion, exists := paths[resourcePath]
	if !exists {
		return false, fmt.Errorf("couldn't find resource for \"%v\"", resourcePath)
	}
	openAPISchemaBytes, err := groupVersion.Schema(runtime.ContentTypeJSON)
	if err != nil {
		return false, fmt.Errorf("failed to fetch openapi schema for %s: %w", resourcePath, err)
	}
	var parsedV3Schema map[string]interface{}
	if err = json.Unmarshal(openAPISchemaBytes, &parsedV3Schema); err != nil {
		return false, fmt.Errorf("failed to unmarshal openapi schema for %s: %w", resourcePath, err)
	}
	components, ok := parsedV3Schema["components"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("couldn't find components in openapi schema for %s", resourcePath)
	}
	schemas, ok := components["schemas"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("couldn't find schemas in openapi schema for %s", resourcePath)
	}
	validatingWebhook, ok := schemas["io.k8s.api.admissionregistration.v1.ValidatingWebhook"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("couldn't find schema for io.k8s.api.admissionregistration.v1.ValidatingWebhook in openapi schema for %s", resourcePath)
	}
	properties, ok := validatingWebhook["properties"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("couldn't find properties in schema for io.k8s.api.admissionregistration.v1.ValidatingWebhook in openapi schema for %s", resourcePath)
	}
	_, exists = properties["matchConditions"]

	return exists, nil
}
