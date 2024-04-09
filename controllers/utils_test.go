/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"

	. "github.com/onsi/gomega"         //nolint:revive
	. "github.com/onsi/gomega/gstruct" //nolint:revive
	"github.com/onsi/gomega/types"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	timeout                   = 180 * time.Second
	pollInterval              = 250 * time.Millisecond
	IntegrationTestsFinalizer = "integration-tests-safety-net-finalizer"
)

var (
	templatePolicyServer = policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image:    "ghcr.io/kubewarden/policy-server:" + policyServerVersion(),
			Replicas: 1,
		},
	}
	templateClusterAdmissionPolicy = policiesv1.ClusterAdmissionPolicy{
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				Module: "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
				Rules:  []admissionregistrationv1.RuleWithOperations{},
			},
		},
	}
	templateAdmissionPolicy = policiesv1.AdmissionPolicy{
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				Module: "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
				Rules:  []admissionregistrationv1.RuleWithOperations{},
			},
		},
	}
)

func policyServerVersion() string {
	version, ok := os.LookupEnv("POLICY_SERVER_VERSION")
	if !ok {
		return "latest"
	}

	return version
}

func policyServerFactory(name string) *policiesv1.PolicyServer {
	policyServer := templatePolicyServer.DeepCopy()
	policyServer.Name = name
	policyServer.Finalizers = []string{
		// On a real cluster the Kubewarden finalizer is added by our mutating
		// webhook. This is not running now, hence we have to manually add the finalizer
		constants.KubewardenFinalizer,
		// By adding this finalizer automatically, we ensure that when
		// testing removal of finalizers on deleted objects, that they will
		// exist at all times
		IntegrationTestsFinalizer,
	}
	return policyServer
}

func admissionPolicyFactory(name, policyNamespace, policyServerName string, mutating bool) *policiesv1.AdmissionPolicy {
	admissionPolicy := templateAdmissionPolicy.DeepCopy()
	admissionPolicy.Name = name
	admissionPolicy.Namespace = policyNamespace
	admissionPolicy.Spec.PolicyServer = policyServerName
	admissionPolicy.Spec.PolicySpec.Mutating = mutating
	admissionPolicy.Finalizers = []string{
		// On a real cluster the Kubewarden finalizer is added by our mutating
		// webhook. This is not running now, hence we have to manually add the finalizer
		constants.KubewardenFinalizer,
		// By adding this finalizer automatically, we ensure that when
		// testing removal of finalizers on deleted objects, that they will
		// exist at all times
		IntegrationTestsFinalizer,
	}
	return admissionPolicy
}

func clusterAdmissionPolicyFactory(name, policyServerName string, mutating bool) *policiesv1.ClusterAdmissionPolicy {
	clusterAdmissionPolicy := templateClusterAdmissionPolicy.DeepCopy()
	clusterAdmissionPolicy.Name = name
	clusterAdmissionPolicy.Spec.PolicyServer = policyServerName
	clusterAdmissionPolicy.Spec.PolicySpec.Mutating = mutating
	clusterAdmissionPolicy.Finalizers = []string{
		// On a real cluster the Kubewarden finalizer is added by our mutating
		// webhook. This is not running now, hence we have to manually add the finalizer
		constants.KubewardenFinalizer,
		// By adding this finalizer automatically, we ensure that when
		// testing removal of finalizers on deleted objects, that they will
		// exist at all times
		IntegrationTestsFinalizer,
	}
	return clusterAdmissionPolicy
}

func getTestAdmissionPolicy(namespace, name string) (*policiesv1.AdmissionPolicy, error) {
	admissionPolicy := policiesv1.AdmissionPolicy{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &admissionPolicy); err != nil {
		return nil, errors.Join(errors.New("could not find AdmissionPolicy"), err)
	}
	return &admissionPolicy, nil
}

func getTestClusterAdmissionPolicy(name string) (*policiesv1.ClusterAdmissionPolicy, error) {
	clusterAdmissionPolicy := policiesv1.ClusterAdmissionPolicy{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Name: name}, &clusterAdmissionPolicy); err != nil {
		return nil, errors.Join(errors.New("could not find ClusterAdmissionPolicy"), err)
	}
	return &clusterAdmissionPolicy, nil
}

func getTestPolicyServer(name string) (*policiesv1.PolicyServer, error) {
	policyServer := policiesv1.PolicyServer{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Name: name}, &policyServer); err != nil {
		return nil, errors.Join(errors.New("could not find PolicyServer"), err)
	}
	return &policyServer, nil
}

func getTestPolicyServerService(policyServerName string) (*corev1.Service, error) {
	policyServer := policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyServerName,
		},
	}
	serviceName := policyServer.NameWithPrefix()

	service := corev1.Service{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Name: serviceName, Namespace: DeploymentsNamespace}, &service); err != nil {
		return nil, errors.Join(errors.New("could not find Service owned by PolicyServer"), err)
	}
	return &service, nil
}

func getTestPolicyServerDeployment(policyServerName string) (*appsv1.Deployment, error) {
	policyServer := policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyServerName,
		},
	}
	deploymentName := policyServer.NameWithPrefix()

	deployment := appsv1.Deployment{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Name: deploymentName, Namespace: DeploymentsNamespace}, &deployment); err != nil {
		return nil, errors.Join(errors.New("could not find Deployment owned by PolicyServer"), err)
	}
	return &deployment, nil
}

func getTestPolicyServerPod(policyServerName string) (*corev1.Pod, error) {
	podList := corev1.PodList{}
	if err := reconciler.APIReader.List(ctx, &podList, client.MatchingLabels{
		constants.PolicyServerLabelKey: policyServerName,
	}); err != nil {
		return nil, errors.Join(errors.New("could not list Pods owned by PolicyServer"), err)
	}

	if len(podList.Items) == 0 {
		return nil, errors.New("could not find Pod owned by PolicyServer")
	}

	return &podList.Items[0], nil
}

func getTestValidatingWebhookConfiguration(name string) (*admissionregistrationv1.ValidatingWebhookConfiguration, error) {
	validatingWebhookConfiguration := admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Name: name}, &validatingWebhookConfiguration); err != nil {
		return nil, errors.Join(errors.New("could not find ValidatingWebhookConfiguration"), err)
	}
	return &validatingWebhookConfiguration, nil
}

func getTestMutatingWebhookConfiguration(name string) (*admissionregistrationv1.MutatingWebhookConfiguration, error) {
	mutatingWebhookConfiguration := admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Name: name}, &mutatingWebhookConfiguration); err != nil {
		return nil, errors.Join(errors.New("could not find ValidatingWebhookConfiguration"), err)
	}
	return &mutatingWebhookConfiguration, nil
}

func getTestCASecret() (*corev1.Secret, error) {
	secret := corev1.Secret{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Name: constants.PolicyServerCARootSecretName, Namespace: DeploymentsNamespace}, &secret); err != nil {
		return nil, errors.Join(errors.New("could not find CA secret"), err)
	}

	return &secret, nil
}

func alreadyExists() types.GomegaMatcher { //nolint:ireturn
	return WithTransform(
		func(err error) bool {
			return err != nil && apierrors.IsAlreadyExists(err)
		},
		BeTrue(),
	)
}

func haveSucceededOrAlreadyExisted() types.GomegaMatcher { //nolint:ireturn
	return SatisfyAny(
		BeNil(),
		alreadyExists(),
	)
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz1234567890")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))] //nolint:gosec
	}

	return string(b)
}

func newName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, randStringRunes(8))
}

func getPolicyServerPodDisruptionBudget(policyServerName string) (*k8spoliciesv1.PodDisruptionBudget, error) {
	policyServer := policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: policyServerName,
		},
	}
	podDisruptionBudgetName := policyServer.NameWithPrefix()
	pdb := &k8spoliciesv1.PodDisruptionBudget{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Name: podDisruptionBudgetName, Namespace: DeploymentsNamespace}, pdb); err != nil {
		return nil, errors.Join(errors.New("could not find PodDisruptionBudget"), err)
	}
	return pdb, nil
}

func policyServerPodDisruptionBudgetMatcher(policyServer *policiesv1.PolicyServer, minAvailable *intstr.IntOrString, maxUnavailable *intstr.IntOrString) types.GomegaMatcher { //nolint:ireturn
	maxUnavailableMatcher := BeNil()
	minAvailableMatcher := BeNil()
	if minAvailable != nil {
		minAvailableMatcher = PointTo(Equal(*minAvailable))
	}
	if maxUnavailable != nil {
		maxUnavailableMatcher = PointTo(Equal(*maxUnavailable))
	}
	return SatisfyAll(
		Not(BeNil()),
		PointTo(MatchFields(IgnoreExtras, Fields{
			"ObjectMeta": MatchFields(IgnoreExtras, Fields{
				"OwnerReferences": ContainElement(MatchFields(IgnoreExtras, Fields{
					"Name": Equal(policyServer.GetName()),
					"Kind": Equal("PolicyServer"),
				})),
			}),
			"Spec": MatchFields(IgnoreExtras, Fields{
				"MaxUnavailable": maxUnavailableMatcher,
				"MinAvailable":   minAvailableMatcher,
				"Selector": PointTo(MatchAllFields(Fields{
					"MatchLabels": MatchAllKeys(Keys{
						constants.AppLabelKey:          Equal(policyServer.AppLabel()),
						constants.PolicyServerLabelKey: Equal(policyServer.GetName()),
					}),
					"MatchExpressions": Ignore(),
				})),
			}),
		}),
		),
	)
}
