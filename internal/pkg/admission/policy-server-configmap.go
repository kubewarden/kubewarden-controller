package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	chimerav1alpha1 "github.com/chimera-kube/chimera-controller/api/v1alpha1"
	"github.com/chimera-kube/chimera-controller/internal/pkg/constants"
)

type policyServerConfigMapOperation int

const (
	AddPolicy = iota
	RemovePolicy
)

type policyServerConfigEntry struct {
	URL      string               `json:"url"`
	Settings runtime.RawExtension `json:"settings"`
}

// Reconciles the ConfigMap that holds the configuration of the Policy Server
func (r *AdmissionReconciler) reconcilePolicyServerConfigMap(
	ctx context.Context,
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
	operation policyServerConfigMapOperation,
) error {
	cfg := &corev1.ConfigMap{}
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      constants.PolicyServerConfigMapName,
	}, cfg)
	if err != nil {
		if apierrors.IsNotFound(err) {
			if operation == RemovePolicy {
				return nil
			}
			return r.createPolicyServerConfigMap(ctx, admissionPolicy)
		}
		return fmt.Errorf("cannot lookup policies ConfigMap: %w", err)
	}

	return r.reconcilePolicyServerConfigMapPolicies(ctx, cfg, admissionPolicy, operation)
}

func (r *AdmissionReconciler) createPolicyServerConfigMap(
	ctx context.Context,
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
) error {
	policies := map[string]policyServerConfigEntry{
		admissionPolicy.Name: {
			URL:      admissionPolicy.Spec.Module,
			Settings: admissionPolicy.Spec.Settings,
		},
	}
	policiesJSON, err := json.Marshal(policies)
	if err != nil {
		return fmt.Errorf("cannot marshal policies to JSON: %w", err)
	}

	data := map[string]string{
		constants.PolicyServerConfigPoliciesEntry: string(policiesJSON),
	}

	cfg := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.PolicyServerConfigMapName,
			Namespace: r.DeploymentsNamespace,
		},
		Data: data,
	}

	return r.Client.Create(ctx, cfg)
}

// Reconcile the policies section of the Policy Server configmap
func (r *AdmissionReconciler) reconcilePolicyServerConfigMapPolicies(
	ctx context.Context,
	cfg *corev1.ConfigMap,
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
	operation policyServerConfigMapOperation,
) error {
	// extract the policy settings from the ConfigMap
	currentPoliciesJSON, found := cfg.Data[constants.PolicyServerConfigPoliciesEntry]
	if !found {
		currentPoliciesJSON = "{}"
	}
	currentPolicies := make(map[string]policyServerConfigEntry)
	err := json.Unmarshal([]byte(currentPoliciesJSON), &currentPolicies)
	if err != nil {
		return fmt.Errorf("cannot unmarshal policy settings from ConfigMap: %w", err)
	}

	var newPoliciesJSON string
	var update bool

	switch operation {
	case AddPolicy:
		newPoliciesJSON, update, err = r.addPolicyToPolicyServerConfigMap(
			currentPolicies, admissionPolicy)
	case RemovePolicy:
		newPoliciesJSON, update, err = r.removePolicyFromPolicyServerConfigMap(
			currentPolicies, admissionPolicy)
	default:
		err = fmt.Errorf("unknown operation type")
	}

	if err != nil {
		return err
	}
	if !update {
		return nil
	}

	cfg.Data[constants.PolicyServerConfigPoliciesEntry] = newPoliciesJSON

	err = r.Client.Update(ctx, cfg)
	if err != nil {
		return fmt.Errorf("cannot update policies ConfigMap: %w", err)
	}

	return nil
}

func (r *AdmissionReconciler) addPolicyToPolicyServerConfigMap(
	currentPolicies map[string]policyServerConfigEntry,
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
) (string, bool, error) {
	var updatePolicies bool
	currentPolicy, found := currentPolicies[admissionPolicy.Name]

	expectedPolicy := policyServerConfigEntry{
		URL:      admissionPolicy.Spec.Module,
		Settings: admissionPolicy.Spec.Settings,
	}

	if !found {
		updatePolicies = true
	} else {
		// check if the policy we're reconciling is already part of the configuration
		currentPolicyJSON, err := json.Marshal(currentPolicy)
		if err != nil {
			return "", false, fmt.Errorf("cannot marshal current policy: %w", err)
		}
		expectedPolicyJSON, err := json.Marshal(expectedPolicy)
		if err != nil {
			return "", false, fmt.Errorf("cannot marshal expected policy: %w", err)
		}
		updatePolicies = !bytes.Equal(currentPolicyJSON, expectedPolicyJSON)
	}

	if !updatePolicies {
		return "", false, nil
	}

	currentPolicies[admissionPolicy.Name] = expectedPolicy

	// marshal back the updated policies
	newPoliciesJSON, err := json.Marshal(currentPolicies)
	if err != nil {
		return "", false, fmt.Errorf("cannot marshal policies to JSON: %w", err)
	}
	return string(newPoliciesJSON), true, nil
}

func (r *AdmissionReconciler) removePolicyFromPolicyServerConfigMap(
	currentPolicies map[string]policyServerConfigEntry,
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
) (string, bool, error) {
	_, found := currentPolicies[admissionPolicy.Name]

	if !found {
		return "", false, nil
	}

	delete(currentPolicies, admissionPolicy.Name)

	// marshal back the updated policies
	newPoliciesJSON, err := json.Marshal(currentPolicies)
	if err != nil {
		return "", false, fmt.Errorf("cannot marshal policies to JSON: %w", err)
	}
	return string(newPoliciesJSON), true, nil
}

func (r *AdmissionReconciler) policyServerConfigMapVersion(_ context.Context) (string, error) {
	// By using Unstructured data we force the client to fetch fresh, uncached
	// data from the API server
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{
		Kind:    "ConfigMap",
		Version: "v1",
	})
	err := r.Client.Get(context.Background(), client.ObjectKey{
		Namespace: r.DeploymentsNamespace,
		Name:      constants.PolicyServerConfigMapName,
	}, u)

	if err != nil {
		return "", fmt.Errorf("cannot retrieve existing policies ConfigMap: %w", err)
	}

	return u.GetResourceVersion(), nil
}
