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
	Url      string               `json:"url"`
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
		} else {
			return fmt.Errorf("Cannot lookup policies ConfigMap: %v", err)
		}
	}

	return r.reconcilePolicyServerConfigMapPolicies(ctx, cfg, admissionPolicy, operation)
}

func (r *AdmissionReconciler) createPolicyServerConfigMap(
	ctx context.Context,
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
) error {
	policies := map[string]policyServerConfigEntry{
		admissionPolicy.Name: {
			Url:      admissionPolicy.Spec.Module,
			Settings: admissionPolicy.Spec.Settings,
		},
	}
	policies_json, err := json.Marshal(policies)
	if err != nil {
		return fmt.Errorf("Cannot marshal policies to JSON: %v", err)
	}

	data := map[string]string{
		constants.PolicyServerConfigPoliciesEntry: string(policies_json),
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
	current_policies_json, found := cfg.Data[constants.PolicyServerConfigPoliciesEntry]
	if !found {
		current_policies_json = "{}"
	}
	current_policies := make(map[string]policyServerConfigEntry)
	err := json.Unmarshal([]byte(current_policies_json), &current_policies)
	if err != nil {
		return fmt.Errorf("Cannot unmarshal policy settings from ConfigMap: %v", err)
	}

	var new_policies_json string
	var update bool

	switch operation {
	case AddPolicy:
		new_policies_json, update, err = r.addPolicyToPolicyServerConfigMap(
			current_policies, admissionPolicy)
	case RemovePolicy:
		new_policies_json, update, err = r.removePolicyFromPolicyServerConfigMap(
			current_policies, admissionPolicy)
	default:
		err = fmt.Errorf("Unknown operation type")
	}

	if err != nil {
		return err
	}
	if !update {
		return nil
	}

	cfg.Data[constants.PolicyServerConfigPoliciesEntry] = new_policies_json

	err = r.Client.Update(ctx, cfg)
	if err != nil {
		return fmt.Errorf("Cannot update policies ConfigMap: %v", err)
	}

	return nil
}

func (r *AdmissionReconciler) addPolicyToPolicyServerConfigMap(
	current_policies map[string]policyServerConfigEntry,
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
) (string, bool, error) {
	update_policies := false
	current_policy, found := current_policies[admissionPolicy.Name]

	expected_policy := policyServerConfigEntry{
		Url:      admissionPolicy.Spec.Module,
		Settings: admissionPolicy.Spec.Settings,
	}

	if !found {
		update_policies = true
	} else {
		// check if the policy we're reconciling is already part of the configuration
		current_policy_json, err := json.Marshal(current_policy)
		if err != nil {
			return "", false, fmt.Errorf("Cannot marshal current policy: %v", err)
		}
		expected_policy_json, err := json.Marshal(expected_policy)
		if err != nil {
			return "", false, fmt.Errorf("Cannot marshal expected policy: %v", err)
		}
		update_policies = bytes.Compare(current_policy_json, expected_policy_json) != 0
	}

	if !update_policies {
		return "", false, nil
	}

	current_policies[admissionPolicy.Name] = expected_policy

	// marshal back the updated policies
	new_policies_json, err := json.Marshal(current_policies)
	if err != nil {
		return "", false, fmt.Errorf("Cannot marshal policies to JSON: %v", err)
	}
	return string(new_policies_json), true, nil
}

func (r *AdmissionReconciler) removePolicyFromPolicyServerConfigMap(
	current_policies map[string]policyServerConfigEntry,
	admissionPolicy *chimerav1alpha1.AdmissionPolicy,
) (string, bool, error) {
	_, found := current_policies[admissionPolicy.Name]

	if !found {
		return "", false, nil
	}

	delete(current_policies, admissionPolicy.Name)

	// marshal back the updated policies
	new_policies_json, err := json.Marshal(current_policies)
	if err != nil {
		return "", false, fmt.Errorf("Cannot marshal policies to JSON: %v", err)
	}
	return string(new_policies_json), true, nil
}

func (r *AdmissionReconciler) policyServerConfigMapVersion(ctx context.Context) (string, error) {
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
		return "", fmt.Errorf("Cannot retrieve existing policies ConfigMap: %v", err)
	}

	return u.GetResourceVersion(), nil
}
