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

	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/onsi/gomega/types"

	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	someNamespace = corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "some-namespace",
		},
	}
	templatePolicyServer = policiesv1.PolicyServer{
		Spec: policiesv1.PolicyServerSpec{
			Image:    "some-registry/some-policy-server:latest",
			Replicas: 1,
		},
	}
	templateClusterAdmissionPolicy = policiesv1.ClusterAdmissionPolicy{
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				Module: "registry://some-registry/some/module:latest",
				Rules:  []admissionregistrationv1.RuleWithOperations{},
			},
		},
	}
	templateAdmissionPolicy = policiesv1.AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: someNamespace.Name,
		},
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				Module: "registry://some-registry/some/module:latest",
				Rules:  []admissionregistrationv1.RuleWithOperations{},
			},
		},
	}
)

func AlreadyExists() types.GomegaMatcher { //nolint:ireturn
	return WithTransform(
		func(err error) bool {
			return err != nil && apierrors.IsAlreadyExists(err)
		},
		BeTrue(),
	)
}

func HaveSucceededOrAlreadyExisted() types.GomegaMatcher { //nolint:ireturn
	return SatisfyAny(
		BeNil(),
		AlreadyExists(),
	)
}

func policyServer(name string) *policiesv1.PolicyServer {
	policyServer := templatePolicyServer.DeepCopy()
	policyServer.Name = name
	// By adding this finalizer automatically, we ensure that when
	// testing removal of finalizers on deleted objects, that they will
	// exist at all times
	policyServer.Finalizers = []string{"integration-tests-safety-net-finalizer"}
	return policyServer
}

func admissionPolicyWithPolicyServerName(name, policyServerName string) *policiesv1.AdmissionPolicy {
	admissionPolicy := templateAdmissionPolicy.DeepCopy()
	admissionPolicy.Name = name
	admissionPolicy.Namespace = someNamespace.Name
	admissionPolicy.Spec.PolicyServer = policyServerName
	// By adding this finalizer automatically, we ensure that when
	// testing removal of finalizers on deleted objects, that they will
	// exist at all times
	admissionPolicy.Finalizers = []string{"integration-tests-safety-net-finalizer"}
	return admissionPolicy
}

func getFreshAdmissionPolicy(namespace, name string) (*policiesv1.AdmissionPolicy, error) {
	newAdmissionPolicy := policiesv1.AdmissionPolicy{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &newAdmissionPolicy); err != nil {
		return nil, errors.Join(errors.New("could not find admission policy"), err)
	}
	return &newAdmissionPolicy, nil
}

func clusterAdmissionPolicyWithPolicyServerName(name, policyServerName string) *policiesv1.ClusterAdmissionPolicy {
	clusterAdmissionPolicy := templateClusterAdmissionPolicy.DeepCopy()
	clusterAdmissionPolicy.Name = name
	clusterAdmissionPolicy.Spec.PolicyServer = policyServerName
	// By adding this finalizer automatically, we ensure that when
	// testing removal of finalizers on deleted objects, that they will
	// exist at all times
	clusterAdmissionPolicy.Finalizers = []string{"integration-tests-safety-net-finalizer"}
	return clusterAdmissionPolicy
}

func getFreshClusterAdmissionPolicy(name string) (*policiesv1.ClusterAdmissionPolicy, error) {
	newClusterAdmissionPolicy := policiesv1.ClusterAdmissionPolicy{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Name: name}, &newClusterAdmissionPolicy); err != nil {
		return nil, errors.Join(errors.New("could not find cluster admission policy"), err)
	}
	return &newClusterAdmissionPolicy, nil
}

func getFreshPolicyServer(name string) (*policiesv1.PolicyServer, error) {
	newPolicyServer := policiesv1.PolicyServer{}
	if err := reconciler.APIReader.Get(ctx, client.ObjectKey{Name: name}, &newPolicyServer); err != nil {
		return nil, errors.Join(errors.New("could not find policy server"), err)
	}
	return &newPolicyServer, nil
}
