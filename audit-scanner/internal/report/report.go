package report

import (
	"encoding/json"
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"

	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	admv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type PolicyReport struct {
	v1alpha2.PolicyReport
}
type ClusterPolicyReport struct {
	v1alpha2.ClusterPolicyReport
}

const (
	// Status specifies state of a policy result
	StatusPass  = "pass"
	StatusFail  = "fail"
	StatusWarn  = "warn"
	StatusError = "error"
	StatusSkip  = "skip"

	// Severity specifies severity of a policy result
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"

	// Category specifies the category of a policy result
	TypeMutating     = "mutating"
	TypeValidating   = "validating"
	TypeContextAware = "context-aware"
	ValueTypeTrue    = "true"

	LabelAppManagedBy = "app.kubernetes.io/managed-by"
	LabelApp          = "kubewarden"
)

func NewClusterPolicyReport(name string) ClusterPolicyReport {
	labels := map[string]string{}
	labels[LabelAppManagedBy] = LabelApp
	return ClusterPolicyReport{
		ClusterPolicyReport: v1alpha2.ClusterPolicyReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:              getClusterReportName(name),
				CreationTimestamp: metav1.Now(),
				Labels:            labels,
			},
			Summary: v1alpha2.PolicyReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
			Results: []*v1alpha2.PolicyReportResult{},
		},
	}
}

func NewPolicyReport(namespace *v1.Namespace) PolicyReport {
	labels := map[string]string{}
	labels[LabelAppManagedBy] = LabelApp
	return PolicyReport{
		PolicyReport: v1alpha2.PolicyReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:              getNamespacedReportName(namespace.Name),
				Namespace:         namespace.Name,
				CreationTimestamp: metav1.Now(),
				Labels:            labels,
			},
			Scope: &v1.ObjectReference{
				Kind:            namespace.Kind,
				Namespace:       "",
				Name:            namespace.Name,
				UID:             namespace.UID,
				APIVersion:      namespace.APIVersion,
				ResourceVersion: namespace.ResourceVersion,
			},
			Summary: v1alpha2.PolicyReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
			Results: []*v1alpha2.PolicyReportResult{},
		},
	}
}

func getClusterReportName(name string) string {
	return PrefixNameClusterPolicyReport + name
}

func getNamespacedReportName(namespace string) string {
	return PrefixNamePolicyReport + namespace
}

func (r *PolicyReport) AddResult(result *v1alpha2.PolicyReportResult) {
	switch result.Result {
	case StatusFail:
		r.Summary.Fail++
	case StatusError:
		r.Summary.Error++
	case StatusPass:
		r.Summary.Pass++
	}
	r.Results = append(r.Results, result)
}

// GetSummaryJSON gets the report.Summary formatted in JSON. Useful for logging
func (r *PolicyReport) GetSummaryJSON() (string, error) {
	marshaled, err := json.Marshal(r.Summary)
	if err != nil {
		return "error marshalling summary", err
	}
	return string(marshaled), nil
}

// GetSummaryJSON gets the report.Summary formatted in JSON. Useful for logging
func (r *ClusterPolicyReport) GetSummaryJSON() (string, error) {
	marshaled, err := json.Marshal(r.Summary)
	if err != nil {
		return "error marshalling summary", err
	}
	return string(marshaled), nil
}

// GetReusablePolicyReportResult tries to find a PolicyReportResult that
// can be reused.
//
// The result can be reused if both these conditions are
// satisfied:
//   - The subject of the PolicyReportResult (the object that was inspected)
//     has not been changed since the report was created
//   - The policy that evaluated the subject (now given by the user as
//     parameter) has not been changed since the report was created
func (r *PolicyReport) GetReusablePolicyReportResult(policy policiesv1.Policy, resource unstructured.Unstructured) *v1alpha2.PolicyReportResult {
	return findReusableResult(r.Results, policy, resource)
}

func (r *PolicyReport) CreateResult(
	policy policiesv1.Policy, resource unstructured.Unstructured,
	auditResponse *admv1.AdmissionReview, responseErr error,
) *v1alpha2.PolicyReportResult {
	result := newPolicyReportResult(policy, resource, auditResponse, responseErr)
	log.Debug().
		Str("report name", r.Name).
		Dict("result", zerolog.Dict().
			Str("policy", policy.GetName()).
			Str("resource", resource.GetName()).
			Bool("allowed", auditResponse.Response.Allowed).
			Str("result", string(result.Result)),
		).Msg("added result to report")
	return result
}

func (r *ClusterPolicyReport) CreateResult(
	policy policiesv1.Policy, resource unstructured.Unstructured,
	auditResponse *admv1.AdmissionReview, responseErr error,
) *v1alpha2.PolicyReportResult {
	result := newPolicyReportResult(policy, resource, auditResponse, responseErr)
	log.Debug().Str("report name", r.Name).Dict("result", zerolog.Dict().
		Str("policy", policy.GetName()).Str("resource", resource.GetName()).
		Bool("allowed", auditResponse.Response.Allowed).
		Str("result", string(result.Result)),
	).Msg("added result to report")
	return result
}

func (r *ClusterPolicyReport) AddResult(result *v1alpha2.PolicyReportResult) {
	switch result.Result {
	case StatusFail:
		r.Summary.Fail++
	case StatusError:
		r.Summary.Error++
	case StatusPass:
		r.Summary.Pass++
	}
	r.Results = append(r.Results, result)
}

// GetReusablePolicyReportResult tries to find a PolicyReportResult that
// can be reused.
//
// The result can be reused if both these conditions are
// satisfied:
//   - The subject of the PolicyReportResult (the object that was inspected)
//     has not been changed since the report was created
//   - The policy that evaluated the subject (now given by the user as
//     parameter) has not been changed since the report was created
func (r *ClusterPolicyReport) GetReusablePolicyReportResult(policy policiesv1.Policy, resource unstructured.Unstructured) *v1alpha2.PolicyReportResult {
	return findReusableResult(r.Results, policy, resource)
}

// isReportGeneratedByPolicy checks if the given PolicyReportResult
// has been generated by the given policy.
// The comparison uses the policy UID and its revision and checks them
// with the metadata stored inside of the given PolicyReportResult
func isReportGeneratedByPolicy(result *v1alpha2.PolicyReportResult, policy policiesv1.Policy) (bool, error) {
	policyName, err := getPolicyName(policy)
	if err != nil {
		return false, err
	}
	policyResourceVersion, hasPolicyResourceVersion := result.Properties[PropertyPolicyResourceVersion]
	policyUID, hasPolicyUID := result.Properties[PropertyPolicyUID]
	return result.Policy == policyName &&
		hasPolicyResourceVersion && policyResourceVersion == policy.GetResourceVersion() &&
		hasPolicyUID && types.UID(policyUID) == policy.GetUID(), nil
}

// findReusableResult returns the PolicyReportResult that refers to the same policy and
// resource from the given parameters.
// A policy is considered the same if it has the same UID and resourceVersion.
// Check more in the isReportGeneratedByPolicy function
// A resource is considered the same if its resource object reference matches with some resource from the report
func findReusableResult(results []*v1alpha2.PolicyReportResult, policy policiesv1.Policy, resource unstructured.Unstructured) *v1alpha2.PolicyReportResult {
	resourceObjReference := getResourceObjectReference(resource)

	for _, result := range results {
		isSamePolicy, err := isReportGeneratedByPolicy(result, policy)
		if err != nil {
			log.Error().Err(err).
				Dict("policy", zerolog.Dict().
					Str("resultPolicy", result.Policy).
					Str("uid", string(policy.GetUID())).
					Str("name", policy.GetName())).
				Msg("cannot check if PolicyReportResult has been generated by the given policy")
			continue
		}
		if isSamePolicy {
			for _, objReference := range result.Subjects {
				if resourceObjReference == *objReference {
					return result
				}
			}
		}
	}
	return nil
}

func getPolicyName(policy policiesv1.Policy) (string, error) {
	switch policy.GetObjectKind().GroupVersionKind() {
	case schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindClusterAdmissionPolicy,
	}:
		return "cap-" + policy.GetName(), nil
	case schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindAdmissionPolicy,
	}:
		return "ap-" + policy.GetName(), nil
	default:
		// this should never happens
		log.Fatal().Msg("cannot generate policy name")
		return "", fmt.Errorf("cannot generate policy name")
	}
}

func getResourceObjectReference(resource unstructured.Unstructured) v1.ObjectReference {
	return v1.ObjectReference{
		Kind:            resource.GetKind(),
		Namespace:       resource.GetNamespace(),
		Name:            resource.GetName(),
		UID:             resource.GetUID(),
		APIVersion:      resource.GetAPIVersion(),
		ResourceVersion: resource.GetResourceVersion(),
	}
}

//nolint:funlen
func newPolicyReportResult(
	policy policiesv1.Policy, resource unstructured.Unstructured,
	auditResponse *admv1.AdmissionReview, responseErr error,
) *v1alpha2.PolicyReportResult {
	var result v1alpha2.PolicyResult
	var description string
	if responseErr != nil {
		result = StatusError
		description = auditResponse.Response.Result.Message
	} else {
		if auditResponse.Response.Allowed {
			result = StatusPass
		} else {
			result = StatusFail
			description = auditResponse.Response.Result.Message
		}
	}

	name, _ := getPolicyName(policy)

	time := metav1.Now()
	timestamp := *time.ProtoTime()

	var severity v1alpha2.PolicyResultSeverity
	var scored bool
	if policy.GetPolicyMode() == policiesv1.PolicyMode(policiesv1.PolicyModeStatusMonitor) {
		scored = true
		severity = SeverityInfo
	} else {
		if sev, present := policy.GetSeverity(); present {
			scored = true
			switch sev {
			case SeverityCritical:
				severity = SeverityCritical
			case SeverityHigh:
				severity = SeverityHigh
			case SeverityMedium:
				severity = SeverityMedium
			case SeverityLow:
				severity = SeverityLow
			default:
				// this should never happen
				log.Error().
					Dict("result", zerolog.Dict().
						Str("policy", policy.GetName()).
						Str("resource", resource.GetName()).
						Bool("allowed", auditResponse.Response.Allowed).
						Str("severity", sev),
					).Msg("severity unknown")
			}
		}
	}

	var category string
	if cat, present := policy.GetCategory(); present {
		category = cat
	}

	properties := map[string]string{}
	if policy.IsMutating() {
		properties[TypeMutating] = ValueTypeTrue
	} else {
		properties[TypeValidating] = ValueTypeTrue
	}
	if policy.IsContextAware() {
		properties[TypeContextAware] = ValueTypeTrue
	}
	// The policy resource version and the policy UID are used to check if the
	// same result can be reused in the next scan
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
	properties[PropertyPolicyResourceVersion] = policy.GetResourceVersion()
	properties[PropertyPolicyUID] = string(policy.GetUID())

	rule := policy.GetName()

	resourceObjectReference := getResourceObjectReference(resource)

	return &v1alpha2.PolicyReportResult{
		Source:   PolicyReportSource,
		Policy:   name,     // either cap-policy_name or ap-policy_name
		Rule:     rule,     // policy name
		Category: category, // either validating, or mutating and validating
		Severity: severity, // either info for monitor or empty
		// Timestamp shouldn't be used in go structs, and only gives seconds
		// https://github.com/kubernetes/apimachinery/blob/v0.27.2/pkg/apis/meta/v1/time_proto.go#LL48C9-L48C9
		Timestamp:       timestamp, // time the result was computed
		Result:          result,    // pass, fail, error
		Scored:          scored,
		Subjects:        []*v1.ObjectReference{&resourceObjectReference}, // reference to object evaluated
		SubjectSelector: &metav1.LabelSelector{},
		Description:     description, // output message of the policy
		Properties:      properties,
	}
}
