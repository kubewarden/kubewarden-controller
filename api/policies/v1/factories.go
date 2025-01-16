//go:build testing

package v1

import (
	"fmt"
	"math/rand"
	"os"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

const (
	integrationTestsFinalizer   = "integration-tests-safety-net-finalizer"
	defaultKubewardenRepository = "ghcr.io/kubewarden/policy-server"
	maxNameSuffixLength         = 8
)

type AdmissionPolicyFactory struct {
	name         string
	namespace    string
	policyServer string
	mutating     bool
	rules        []admissionregistrationv1.RuleWithOperations
	module       string
	matchConds   []admissionregistrationv1.MatchCondition
	mode         PolicyMode
}

func NewAdmissionPolicyFactory() *AdmissionPolicyFactory {
	return &AdmissionPolicyFactory{
		name:         newName("admission-policy"),
		namespace:    "default",
		policyServer: "",
		mutating:     false,
		rules: []admissionregistrationv1.RuleWithOperations{
			{
				Operations: []admissionregistrationv1.OperationType{
					admissionregistrationv1.Create,
					admissionregistrationv1.Update,
				},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"Pods"},
				},
			},
		},
		module: "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
		matchConds: []admissionregistrationv1.MatchCondition{
			{Name: "noop", Expression: "true"},
		},
		mode: "protect",
	}
}

func (f *AdmissionPolicyFactory) WithName(name string) *AdmissionPolicyFactory {
	f.name = name
	return f
}

func (f *AdmissionPolicyFactory) WithNamespace(namespace string) *AdmissionPolicyFactory {
	f.namespace = namespace
	return f
}

func (f *AdmissionPolicyFactory) WithPolicyServer(policyServer string) *AdmissionPolicyFactory {
	f.policyServer = policyServer
	return f
}

func (f *AdmissionPolicyFactory) WithMutating(mutating bool) *AdmissionPolicyFactory {
	f.mutating = mutating
	return f
}

func (f *AdmissionPolicyFactory) WithRules(rules []admissionregistrationv1.RuleWithOperations) *AdmissionPolicyFactory {
	f.rules = rules
	return f
}

func (f *AdmissionPolicyFactory) WithMatchConditions(matchConditions []admissionregistrationv1.MatchCondition) *AdmissionPolicyFactory {
	f.matchConds = matchConditions
	return f
}

func (f *AdmissionPolicyFactory) WithMode(mode PolicyMode) *AdmissionPolicyFactory {
	f.mode = mode
	return f
}

func (f *AdmissionPolicyFactory) Build() *AdmissionPolicy {
	policy := AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      f.name,
			Namespace: f.namespace,
			Finalizers: []string{
				// On a real cluster the Kubewarden finalizer is added by our mutating
				// webhook. This is not running now, hence we have to manually add the finalizer
				constants.KubewardenFinalizer,
				// By adding this finalizer automatically, we ensure that when
				// testing removal of finalizers on deleted objects, that they will
				// exist at all times
				integrationTestsFinalizer,
			},
		},
		Spec: AdmissionPolicySpec{
			PolicySpec: PolicySpec{
				PolicyServer:    f.policyServer,
				Module:          f.module,
				Rules:           f.rules,
				Mutating:        f.mutating,
				MatchConditions: f.matchConds,
				Mode:            f.mode,
			},
		},
	}
	return &policy
}

type ClusterAdmissionPolicyFactory struct {
	name                  string
	policyServer          string
	mutating              bool
	rules                 []admissionregistrationv1.RuleWithOperations
	module                string
	contextAwareResources []ContextAwareResource
	matchConds            []admissionregistrationv1.MatchCondition
	mode                  PolicyMode
}

func NewClusterAdmissionPolicyFactory() *ClusterAdmissionPolicyFactory {
	return &ClusterAdmissionPolicyFactory{
		name:         newName("cluster-admission"),
		policyServer: "",
		mutating:     false,
		rules: []admissionregistrationv1.RuleWithOperations{
			{
				Operations: []admissionregistrationv1.OperationType{
					admissionregistrationv1.Create,
					admissionregistrationv1.Update,
				},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"Pods"},
				},
			},
		},
		module:                "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
		contextAwareResources: []ContextAwareResource{},
		matchConds: []admissionregistrationv1.MatchCondition{
			{Name: "noop", Expression: "true"},
		},
		mode: "protect",
	}
}

func (f *ClusterAdmissionPolicyFactory) WithName(name string) *ClusterAdmissionPolicyFactory {
	f.name = name
	return f
}

func (f *ClusterAdmissionPolicyFactory) WithPolicyServer(policyServer string) *ClusterAdmissionPolicyFactory {
	f.policyServer = policyServer
	return f
}

func (f *ClusterAdmissionPolicyFactory) WithMutating(mutating bool) *ClusterAdmissionPolicyFactory {
	f.mutating = mutating
	return f
}

func (f *ClusterAdmissionPolicyFactory) WithContextAwareResources(resources []ContextAwareResource) *ClusterAdmissionPolicyFactory {
	f.contextAwareResources = resources
	return f
}

func (f *ClusterAdmissionPolicyFactory) WithRules(rules []admissionregistrationv1.RuleWithOperations) *ClusterAdmissionPolicyFactory {
	f.rules = rules
	return f
}

func (f *ClusterAdmissionPolicyFactory) WithMatchConditions(matchConditions []admissionregistrationv1.MatchCondition) *ClusterAdmissionPolicyFactory {
	f.matchConds = matchConditions
	return f
}

func (f *ClusterAdmissionPolicyFactory) WithMode(mode PolicyMode) *ClusterAdmissionPolicyFactory {
	f.mode = mode
	return f
}

func (f *ClusterAdmissionPolicyFactory) Build() *ClusterAdmissionPolicy {
	clusterAdmissionPolicy := ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: f.name,
			Finalizers: []string{
				// On a real cluster the Kubewarden finalizer is added by our mutating
				// webhook. This is not running now, hence we have to manually add the finalizer
				constants.KubewardenFinalizer,
				// By adding this finalizer automatically, we ensure that when
				// testing removal of finalizers on deleted objects, that they will
				// exist at all times
				integrationTestsFinalizer,
			},
		},
		Spec: ClusterAdmissionPolicySpec{
			ContextAwareResources: f.contextAwareResources,
			PolicySpec: PolicySpec{
				PolicyServer:    f.policyServer,
				Module:          f.module,
				Rules:           f.rules,
				Mutating:        f.mutating,
				MatchConditions: f.matchConds,
				Mode:            f.mode,
			},
		},
	}
	return &clusterAdmissionPolicy
}

type AdmissionPolicyGroupFactory struct {
	name          string
	namespace     string
	policyServer  string
	rules         []admissionregistrationv1.RuleWithOperations
	expression    string
	policyMembers PolicyGroupMembers
	matchConds    []admissionregistrationv1.MatchCondition
	mode          PolicyMode
}

func NewAdmissionPolicyGroupFactory() *AdmissionPolicyGroupFactory {
	return &AdmissionPolicyGroupFactory{
		name:         newName("admissing-policy-group"),
		namespace:    "default",
		policyServer: "",
		rules: []admissionregistrationv1.RuleWithOperations{
			{
				Operations: []admissionregistrationv1.OperationType{
					admissionregistrationv1.Create,
					admissionregistrationv1.Update,
				},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"Pods"},
				},
			},
		},
		expression: "pod_privileged()",
		policyMembers: PolicyGroupMembers{
			"pod_privileged": {
				Module: "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
			},
		},
		matchConds: []admissionregistrationv1.MatchCondition{
			{Name: "noop", Expression: "true"},
		},
		mode: "protect",
	}
}

func (f *AdmissionPolicyGroupFactory) WithName(name string) *AdmissionPolicyGroupFactory {
	f.name = name
	return f
}

func (f *AdmissionPolicyGroupFactory) WithNamespace(namespace string) *AdmissionPolicyGroupFactory {
	f.namespace = namespace
	return f
}

func (f *AdmissionPolicyGroupFactory) WithPolicyServer(policyServer string) *AdmissionPolicyGroupFactory {
	f.policyServer = policyServer
	return f
}

func (f *AdmissionPolicyGroupFactory) WithRules(rules []admissionregistrationv1.RuleWithOperations) *AdmissionPolicyGroupFactory {
	f.rules = rules
	return f
}

func (f *AdmissionPolicyGroupFactory) WithMatchConditions(matchContions []admissionregistrationv1.MatchCondition) *AdmissionPolicyGroupFactory {
	f.matchConds = matchContions
	return f
}

func (f *AdmissionPolicyGroupFactory) WithMode(mode PolicyMode) *AdmissionPolicyGroupFactory {
	f.mode = mode
	return f
}

func (f *AdmissionPolicyGroupFactory) Build() *AdmissionPolicyGroup {
	return &AdmissionPolicyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      f.name,
			Namespace: f.namespace,
			Finalizers: []string{
				// On a real cluster the Kubewarden finalizer is added by our mutating
				// webhook. This is not running now, hence we have to manually add the finalizer
				constants.KubewardenFinalizer,
				// By adding this finalizer automatically, we ensure that when
				// testing removal of finalizers on deleted objects, that they will
				// exist at all times
				integrationTestsFinalizer,
			},
		},
		Spec: AdmissionPolicyGroupSpec{
			PolicyGroupSpec: PolicyGroupSpec{
				GroupSpec: GroupSpec{
					PolicyServer:    f.policyServer,
					Expression:      f.expression,
					Rules:           f.rules,
					MatchConditions: f.matchConds,
					Mode:            f.mode,
				},
				Policies: f.policyMembers,
			},
		},
	}
}

type ClusterAdmissionPolicyGroupFactory struct {
	name          string
	policyServer  string
	rules         []admissionregistrationv1.RuleWithOperations
	expression    string
	policyMembers PolicyGroupMembersWithContext
	matchConds    []admissionregistrationv1.MatchCondition
	mode          PolicyMode
}

func NewClusterAdmissionPolicyGroupFactory() *ClusterAdmissionPolicyGroupFactory {
	return &ClusterAdmissionPolicyGroupFactory{
		name:         newName("cluster-admission-policy-group"),
		policyServer: "",
		rules: []admissionregistrationv1.RuleWithOperations{
			{
				Operations: []admissionregistrationv1.OperationType{
					admissionregistrationv1.Create,
					admissionregistrationv1.Update,
				},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{"Pods"},
				},
			},
		},
		expression: "pod_privileged() && user_group_psp()",
		policyMembers: PolicyGroupMembersWithContext{
			"pod_privileged": {
				PolicyGroupMember: PolicyGroupMember{
					Module: "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
				},
			},
			"user_group_psp": {
				PolicyGroupMember: PolicyGroupMember{
					Module: "registry://ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
				},
			},
		},
		matchConds: []admissionregistrationv1.MatchCondition{
			{Name: "noop", Expression: "true"},
		},
		mode: "protect",
	}
}

func (f *ClusterAdmissionPolicyGroupFactory) WithName(name string) *ClusterAdmissionPolicyGroupFactory {
	f.name = name
	return f
}

func (f *ClusterAdmissionPolicyGroupFactory) WithPolicyServer(policyServer string) *ClusterAdmissionPolicyGroupFactory {
	f.policyServer = policyServer
	return f
}

func (f *ClusterAdmissionPolicyGroupFactory) WithMembers(members PolicyGroupMembersWithContext) *ClusterAdmissionPolicyGroupFactory {
	f.policyMembers = members
	return f
}

func (f *ClusterAdmissionPolicyGroupFactory) WithRules(rules []admissionregistrationv1.RuleWithOperations) *ClusterAdmissionPolicyGroupFactory {
	f.rules = rules
	return f
}

func (f *ClusterAdmissionPolicyGroupFactory) WithMatchConditions(matchConditions []admissionregistrationv1.MatchCondition) *ClusterAdmissionPolicyGroupFactory {
	f.matchConds = matchConditions
	return f
}

func (f *ClusterAdmissionPolicyGroupFactory) WithMode(mode PolicyMode) *ClusterAdmissionPolicyGroupFactory {
	f.mode = mode
	return f
}

func (f *ClusterAdmissionPolicyGroupFactory) Build() *ClusterAdmissionPolicyGroup {
	clusterAdmissionPolicy := ClusterAdmissionPolicyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: f.name,
			Finalizers: []string{
				// On a real cluster the Kubewarden finalizer is added by our mutating
				// webhook. This is not running now, hence we have to manually add the finalizer
				constants.KubewardenFinalizer,
				// By adding this finalizer automatically, we ensure that when
				// testing removal of finalizers on deleted objects, that they will
				// exist at all times
				integrationTestsFinalizer,
			},
		},
		Spec: ClusterAdmissionPolicyGroupSpec{
			ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
				GroupSpec: GroupSpec{
					PolicyServer:    f.policyServer,
					Expression:      f.expression,
					Rules:           f.rules,
					MatchConditions: f.matchConds,
					Mode:            f.mode,
				},
				Policies: f.policyMembers,
			},
		},
	}
	return &clusterAdmissionPolicy
}

type PolicyServerBuilder struct {
	name            string
	minAvailable    *intstr.IntOrString
	maxUnavailable  *intstr.IntOrString
	imagePullSecret string
	limits          corev1.ResourceList
	requests        corev1.ResourceList
}

func NewPolicyServerFactory() *PolicyServerBuilder {
	return &PolicyServerBuilder{
		name: newName("policy-server"),
	}
}

func (f *PolicyServerBuilder) WithName(name string) *PolicyServerBuilder {
	f.name = name
	return f
}

func (f *PolicyServerBuilder) WithMinAvailable(minAvailable *intstr.IntOrString) *PolicyServerBuilder {
	f.minAvailable = minAvailable
	return f
}

func (f *PolicyServerBuilder) WithMaxUnavailable(maxUnavailable *intstr.IntOrString) *PolicyServerBuilder {
	f.maxUnavailable = maxUnavailable
	return f
}

func (f *PolicyServerBuilder) WithImagePullSecret(secret string) *PolicyServerBuilder {
	f.imagePullSecret = secret
	return f
}

func (f *PolicyServerBuilder) WithLimits(limits corev1.ResourceList) *PolicyServerBuilder {
	f.limits = limits
	return f
}

func (f *PolicyServerBuilder) WithRequests(requests corev1.ResourceList) *PolicyServerBuilder {
	f.requests = requests
	return f
}

func (f *PolicyServerBuilder) Build() *PolicyServer {
	policyServer := PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: f.name,
			Finalizers: []string{
				// On a real cluster the Kubewarden finalizer is added by our mutating
				// webhook. This is not running now, hence we have to manually add the finalizer
				constants.KubewardenFinalizer,
				// By adding this finalizer automatically, we ensure that when
				// testing removal of finalizers on deleted objects, that they will
				// exist at all times
				integrationTestsFinalizer,
			},
		},
		Spec: PolicyServerSpec{
			Image:           policyServerRepository() + ":" + policyServerVersion(),
			Replicas:        1,
			MinAvailable:    f.minAvailable,
			MaxUnavailable:  f.maxUnavailable,
			ImagePullSecret: f.imagePullSecret,
			Limits:          f.limits,
			Requests:        f.requests,
		},
	}

	return &policyServer
}

func policyServerRepository() string {
	repository, ok := os.LookupEnv("POLICY_SERVER_REPOSITORY")
	if !ok {
		return defaultKubewardenRepository
	}
	return repository
}

func policyServerVersion() string {
	version, ok := os.LookupEnv("POLICY_SERVER_VERSION")
	if !ok {
		return "latest"
	}

	return version
}

func randStringRunes(n int) string {
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	b := make([]rune, n)
	for i := range b {
		//nolint:gosec // this is a test code.
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return string(b)
}

func newName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, randStringRunes(maxNameSuffixLength))
}
