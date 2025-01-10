//go:build testing

package v1

import (
	"fmt"
	"math/rand"
	"os"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

func (fac *AdmissionPolicyFactory) WithName(name string) *AdmissionPolicyFactory {
	fac.name = name
	return fac
}

func (fac *AdmissionPolicyFactory) WithNamespace(namespace string) *AdmissionPolicyFactory {
	fac.namespace = namespace
	return fac
}

func (fac *AdmissionPolicyFactory) WithPolicyServer(policyServer string) *AdmissionPolicyFactory {
	fac.policyServer = policyServer
	return fac
}

func (fac *AdmissionPolicyFactory) WithMutating(mutating bool) *AdmissionPolicyFactory {
	fac.mutating = mutating
	return fac
}

func (fac *AdmissionPolicyFactory) WithRules(rules []admissionregistrationv1.RuleWithOperations) *AdmissionPolicyFactory {
	fac.rules = rules
	return fac
}

func (fac *AdmissionPolicyFactory) WithMatchConditions(matchConditions []admissionregistrationv1.MatchCondition) *AdmissionPolicyFactory {
	fac.matchConds = matchConditions
	return fac
}

func (fac *AdmissionPolicyFactory) WithMode(mode PolicyMode) *AdmissionPolicyFactory {
	fac.mode = mode
	return fac
}

func (fac *AdmissionPolicyFactory) Build() *AdmissionPolicy {
	policy := AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fac.name,
			Namespace: fac.namespace,
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
				PolicyServer:    fac.policyServer,
				Module:          fac.module,
				Rules:           fac.rules,
				Mutating:        fac.mutating,
				MatchConditions: fac.matchConds,
				Mode:            fac.mode,
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

func (fac *ClusterAdmissionPolicyFactory) WithName(name string) *ClusterAdmissionPolicyFactory {
	fac.name = name
	return fac
}

func (fac *ClusterAdmissionPolicyFactory) WithPolicyServer(policyServer string) *ClusterAdmissionPolicyFactory {
	fac.policyServer = policyServer
	return fac
}

func (fac *ClusterAdmissionPolicyFactory) WithMutating(mutating bool) *ClusterAdmissionPolicyFactory {
	fac.mutating = mutating
	return fac
}

func (fac *ClusterAdmissionPolicyFactory) WithContextAwareResources(resources []ContextAwareResource) *ClusterAdmissionPolicyFactory {
	fac.contextAwareResources = resources
	return fac
}

func (fac *ClusterAdmissionPolicyFactory) WithRules(rules []admissionregistrationv1.RuleWithOperations) *ClusterAdmissionPolicyFactory {
	fac.rules = rules
	return fac
}

func (fac *ClusterAdmissionPolicyFactory) WithMatchConditions(matchConditions []admissionregistrationv1.MatchCondition) *ClusterAdmissionPolicyFactory {
	fac.matchConds = matchConditions
	return fac
}

func (fac *ClusterAdmissionPolicyFactory) WithMode(mode PolicyMode) *ClusterAdmissionPolicyFactory {
	fac.mode = mode
	return fac
}

func (fac *ClusterAdmissionPolicyFactory) Build() *ClusterAdmissionPolicy {
	clusterAdmissionPolicy := ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: fac.name,
			Finalizers: []string{
				// On a real cluster the Kubewarden finalizer is added by our mutating
				// webhook. This is not running now, hence we have to manually add the finalizer
				constants.KubewardenFinalizer,
				// By adding this finalizer automatically, we ensure that when
				// testing removal of finalizers on deleted objects, that they will
				// exist at all times
				integrationTestsFinalizer,
			}},
		Spec: ClusterAdmissionPolicySpec{
			ContextAwareResources: fac.contextAwareResources,
			PolicySpec: PolicySpec{
				PolicyServer:    fac.policyServer,
				Module:          fac.module,
				Rules:           fac.rules,
				Mutating:        fac.mutating,
				MatchConditions: fac.matchConds,
				Mode:            fac.mode,
			},
		},
	}
	return &clusterAdmissionPolicy
}

type PolicyServerBuilder struct {
	name string
}

func NewPolicyServerFactory() *PolicyServerBuilder {
	return &PolicyServerBuilder{
		name: newName("policy-server"),
	}
}

func (fac *PolicyServerBuilder) WithName(name string) *PolicyServerBuilder {
	fac.name = name
	return fac
}

func (fac *PolicyServerBuilder) Build() *PolicyServer {
	policyServer := PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: fac.name,
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
			Image:    policyServerRepository() + ":" + policyServerVersion(),
			Replicas: 1,
		},
	}
	return &policyServer
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

func (fac *AdmissionPolicyGroupFactory) WithName(name string) *AdmissionPolicyGroupFactory {
	fac.name = name
	return fac
}

func (fac *AdmissionPolicyGroupFactory) WithNamespace(namespace string) *AdmissionPolicyGroupFactory {
	fac.namespace = namespace
	return fac
}

func (fac *AdmissionPolicyGroupFactory) WithPolicyServer(policyServer string) *AdmissionPolicyGroupFactory {
	fac.policyServer = policyServer
	return fac
}

func (fac *AdmissionPolicyGroupFactory) WithRules(rules []admissionregistrationv1.RuleWithOperations) *AdmissionPolicyGroupFactory {
	fac.rules = rules
	return fac
}

func (fac *AdmissionPolicyGroupFactory) WithMatchConditions(matchContions []admissionregistrationv1.MatchCondition) *AdmissionPolicyGroupFactory {
	fac.matchConds = matchContions
	return fac
}

func (fac *AdmissionPolicyGroupFactory) WithMode(mode PolicyMode) *AdmissionPolicyGroupFactory {
	fac.mode = mode
	return fac
}

func (fac *AdmissionPolicyGroupFactory) Build() *AdmissionPolicyGroup {
	return &AdmissionPolicyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fac.name,
			Namespace: fac.namespace,
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
				PolicyServer:    fac.policyServer,
				Policies:        fac.policyMembers,
				Expression:      fac.expression,
				Rules:           fac.rules,
				MatchConditions: fac.matchConds,
				Mode:            fac.mode,
			},
		},
	}
}

type ClusterAdmissionPolicyGroupFactory struct {
	name          string
	policyServer  string
	rules         []admissionregistrationv1.RuleWithOperations
	expression    string
	policyMembers PolicyGroupMembers
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
		policyMembers: PolicyGroupMembers{
			"pod_privileged": {
				Module: "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
			},
			"user_group_psp": {
				Module: "registry://ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
			},
		},
		matchConds: []admissionregistrationv1.MatchCondition{
			{Name: "noop", Expression: "true"},
		},
		mode: "protect",
	}
}

func (fac *ClusterAdmissionPolicyGroupFactory) WithName(name string) *ClusterAdmissionPolicyGroupFactory {
	fac.name = name
	return fac
}

func (fac *ClusterAdmissionPolicyGroupFactory) WithPolicyServer(policyServer string) *ClusterAdmissionPolicyGroupFactory {
	fac.policyServer = policyServer
	return fac
}

func (fac *ClusterAdmissionPolicyGroupFactory) WithMembers(members PolicyGroupMembers) *ClusterAdmissionPolicyGroupFactory {
	fac.policyMembers = members
	return fac
}

func (fac *ClusterAdmissionPolicyGroupFactory) WithRules(rules []admissionregistrationv1.RuleWithOperations) *ClusterAdmissionPolicyGroupFactory {
	fac.rules = rules
	return fac
}

func (fac *ClusterAdmissionPolicyGroupFactory) WithMatchConditions(matchConditions []admissionregistrationv1.MatchCondition) *ClusterAdmissionPolicyGroupFactory {
	fac.matchConds = matchConditions
	return fac
}

func (fac *ClusterAdmissionPolicyGroupFactory) WithMode(mode PolicyMode) *ClusterAdmissionPolicyGroupFactory {
	fac.mode = mode
	return fac
}

func (fac *ClusterAdmissionPolicyGroupFactory) Build() *ClusterAdmissionPolicyGroup {
	clusterAdmissionPolicy := ClusterAdmissionPolicyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: fac.name,
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
			PolicyGroupSpec: PolicyGroupSpec{
				PolicyServer:    fac.policyServer,
				Policies:        fac.policyMembers,
				Expression:      fac.expression,
				Rules:           fac.rules,
				MatchConditions: fac.matchConds,
				Mode:            fac.mode,
			},
		},
	}
	return &clusterAdmissionPolicy
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
