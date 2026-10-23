package controller

import (
	"context"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
)

var _ = Describe("Reconcile requests for all the policies", func() {
	ctx := context.Background()

	It("should contain a request for each policy of each kind", func() {
		admissionPolicy := policiesv1.NewAdmissionPolicyFactory().Build()
		Expect(k8sClient.Create(ctx, admissionPolicy)).To(Succeed())
		admissionPolicyGroup := policiesv1.NewAdmissionPolicyGroupFactory().Build()
		Expect(k8sClient.Create(ctx, admissionPolicyGroup)).To(Succeed())
		clusterAdmissionPolicy := policiesv1.NewClusterAdmissionPolicyFactory().Build()
		Expect(k8sClient.Create(ctx, clusterAdmissionPolicy)).To(Succeed())
		clusterAdmissionPolicyGroup := policiesv1.NewClusterAdmissionPolicyGroupFactory().Build()
		Expect(k8sClient.Create(ctx, clusterAdmissionPolicyGroup)).To(Succeed())

		Expect(findAllAdmissionPolicies(ctx, k8sClient, logr.Discard())).To(ContainElement(reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(admissionPolicy),
		}))
		Expect(findAllAdmissionPolicyGroups(ctx, k8sClient, logr.Discard())).To(ContainElement(reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(admissionPolicyGroup),
		}))
		Expect(findAllClusterAdmissionPolicies(ctx, k8sClient, logr.Discard())).To(ContainElement(reconcile.Request{
			NamespacedName: client.ObjectKey{Name: clusterAdmissionPolicy.Name},
		}))
		Expect(findAllClusterAdmissionPolicyGroups(ctx, k8sClient, logr.Discard())).To(ContainElement(reconcile.Request{
			NamespacedName: client.ObjectKey{Name: clusterAdmissionPolicyGroup.Name},
		}))
	})
})
