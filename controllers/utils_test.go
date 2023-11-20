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

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"

	. "github.com/onsi/gomega" //nolint:revive
	"github.com/onsi/gomega/types"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	timeout      = 120 * time.Second
	pollInterval = 250 * time.Millisecond
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

	// By adding this finalizer automatically, we ensure that when
	// testing removal of finalizers on deleted objects, that they will
	// exist at all times
	policyServer.Finalizers = []string{"integration-tests-safety-net-finalizer"}
	return policyServer
}

func admissionPolicyFactory(name, policyNamespace, policyServerName string, mutating bool) *policiesv1.AdmissionPolicy {
	admissionPolicy := templateAdmissionPolicy.DeepCopy()
	admissionPolicy.Name = name
	admissionPolicy.Namespace = policyNamespace
	admissionPolicy.Spec.PolicyServer = policyServerName
	admissionPolicy.Spec.PolicySpec.Mutating = mutating
	// By adding this finalizer automatically, we ensure that when
	// testing removal of finalizers on deleted objects, that they will
	// exist at all times
	admissionPolicy.Finalizers = []string{"integration-tests-safety-net-finalizer"}
	return admissionPolicy
}

func clusterAdmissionPolicyFactory(name, policyServerName string, mutating bool) *policiesv1.ClusterAdmissionPolicy {
	clusterAdmissionPolicy := templateClusterAdmissionPolicy.DeepCopy()
	clusterAdmissionPolicy.Name = name
	clusterAdmissionPolicy.Spec.PolicyServer = policyServerName
	clusterAdmissionPolicy.Spec.PolicySpec.Mutating = mutating
	// By adding this finalizer automatically, we ensure that when
	// testing removal of finalizers on deleted objects, that they will
	// exist at all times
	clusterAdmissionPolicy.Finalizers = []string{"integration-tests-safety-net-finalizer"}
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
