package controller

import (
	"os"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

type admissionPolicyFactory struct {
	name         string
	namespace    string
	policyServer string
	mutating     bool
	rules        []admissionregistrationv1.RuleWithOperations
	module       string
}

func newAdmissionPolicyFactory() *admissionPolicyFactory {
	return &admissionPolicyFactory{
		name:         newName("validating-policy"),
		namespace:    "",
		policyServer: "",
		mutating:     false,
		rules:        []admissionregistrationv1.RuleWithOperations{},
		module:       "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
	}
}

func (fac *admissionPolicyFactory) withName(name string) *admissionPolicyFactory {
	fac.name = name
	return fac
}

func (fac *admissionPolicyFactory) withNamespace(namespace string) *admissionPolicyFactory {
	fac.namespace = namespace
	return fac
}

func (fac *admissionPolicyFactory) withPolicyServer(policyServer string) *admissionPolicyFactory {
	fac.policyServer = policyServer
	return fac
}

func (fac *admissionPolicyFactory) withMutating(mutating bool) *admissionPolicyFactory {
	fac.mutating = mutating
	return fac
}

func (fac *admissionPolicyFactory) build() *policiesv1.AdmissionPolicy {
	policy := policiesv1.AdmissionPolicy{
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
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				PolicyServer: fac.policyServer,
				Module:       fac.module,
				Rules:        fac.rules,
				Mutating:     fac.mutating,
				MatchConditions: []admissionregistrationv1.MatchCondition{
					{
						Name:       "noop",
						Expression: "true",
					},
				},
			},
		},
	}
	return &policy
}

type clusterAdmissionPolicyFactory struct {
	name         string
	policyServer string
	mutating     bool
	rules        []admissionregistrationv1.RuleWithOperations
	module       string
}

func newClusterAdmissionPolicyFactory() *clusterAdmissionPolicyFactory {
	return &clusterAdmissionPolicyFactory{
		name:         newName("validating-cluster-policy"),
		policyServer: "",
		mutating:     false,
		rules:        []admissionregistrationv1.RuleWithOperations{},
		module:       "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
	}
}

func (fac *clusterAdmissionPolicyFactory) withName(name string) *clusterAdmissionPolicyFactory {
	fac.name = name
	return fac
}

func (fac *clusterAdmissionPolicyFactory) withPolicyServer(policyServer string) *clusterAdmissionPolicyFactory {
	fac.policyServer = policyServer
	return fac
}

func (fac *clusterAdmissionPolicyFactory) withMutating(mutating bool) *clusterAdmissionPolicyFactory {
	fac.mutating = mutating
	return fac
}

func (fac *clusterAdmissionPolicyFactory) build() *policiesv1.ClusterAdmissionPolicy {
	clusterAdmissionPolicy := policiesv1.ClusterAdmissionPolicy{
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
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				PolicyServer: fac.policyServer,
				Module:       fac.module,
				Rules:        fac.rules,
				Mutating:     fac.mutating,
				MatchConditions: []admissionregistrationv1.MatchCondition{
					{Name: "noop", Expression: "true"},
				},
			},
		},
	}
	return &clusterAdmissionPolicy
}

type policyServerBuilder struct {
	name string
}

func newPolicyServerFactory() *policyServerBuilder {
	return &policyServerBuilder{
		name: newName("policy-server"),
	}
}

func (fac *policyServerBuilder) withName(name string) *policyServerBuilder {
	fac.name = name
	return fac
}

func (fac *policyServerBuilder) build() *policiesv1.PolicyServer {
	policyServer := policiesv1.PolicyServer{
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
		Spec: policiesv1.PolicyServerSpec{
			Image:    policyServerRepository() + ":" + policyServerVersion(),
			Replicas: 1,
		},
	}
	return &policyServer
}

type admissionPolicyGroupFactory struct {
	name         string
	namespace    string
	policyServer string
}

func newAdmissionPolicyGroupFactory() *admissionPolicyGroupFactory {
	return &admissionPolicyGroupFactory{
		name:         newName("validating-policygroup"),
		namespace:    "",
		policyServer: "",
	}
}

func (fac *admissionPolicyGroupFactory) withName(name string) *admissionPolicyGroupFactory {
	fac.name = name
	return fac
}

func (fac *admissionPolicyGroupFactory) withNamespace(namespace string) *admissionPolicyGroupFactory {
	fac.namespace = namespace
	return fac
}

func (fac *admissionPolicyGroupFactory) withPolicyServer(policyServer string) *admissionPolicyGroupFactory {
	fac.policyServer = policyServer
	return fac
}

func (fac *admissionPolicyGroupFactory) build() *policiesv1.AdmissionPolicyGroup {
	admissionPolicy := policiesv1.AdmissionPolicyGroup{
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
		Spec: policiesv1.AdmissionPolicyGroupSpec{
			PolicyGroupSpec: policiesv1.PolicyGroupSpec{
				PolicyServer: fac.policyServer,
				Policies: policiesv1.PolicyGroupMembers{
					"pod-privileged": {
						Module: "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
					},
				},
				Rules: []admissionregistrationv1.RuleWithOperations{},
				MatchConditions: []admissionregistrationv1.MatchCondition{
					{Name: "noop", Expression: "true"},
				},
			},
		},
	}
	return &admissionPolicy
}

type clusterAdmissionPolicyGroupFactory struct {
	name         string
	policyServer string
}

func newClusterAdmissionPolicyGroupFactory() *clusterAdmissionPolicyGroupFactory {
	return &clusterAdmissionPolicyGroupFactory{
		name:         newName("validating-policygroup"),
		policyServer: "",
	}
}

func (fac *clusterAdmissionPolicyGroupFactory) withName(name string) *clusterAdmissionPolicyGroupFactory {
	fac.name = name
	return fac
}

func (fac *clusterAdmissionPolicyGroupFactory) withPolicyServer(policyServer string) *clusterAdmissionPolicyGroupFactory {
	fac.policyServer = policyServer
	return fac
}

func (fac *clusterAdmissionPolicyGroupFactory) build() *policiesv1.ClusterAdmissionPolicyGroup {
	clusterAdmissionPolicy := policiesv1.ClusterAdmissionPolicyGroup{
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
		Spec: policiesv1.ClusterAdmissionPolicyGroupSpec{
			PolicyGroupSpec: policiesv1.PolicyGroupSpec{
				Rules:        []admissionregistrationv1.RuleWithOperations{},
				PolicyServer: fac.policyServer,
				MatchConditions: []admissionregistrationv1.MatchCondition{
					{Name: "noop", Expression: "true"},
				},
				Policies: policiesv1.PolicyGroupMembers{
					"pod-privileged": {
						Module: "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
					},
					"user-group-psp": {
						Module: "registry://ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
					},
				},
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
