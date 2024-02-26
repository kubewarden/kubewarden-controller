/*
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

package v1

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func admissionPolicyFactory() *AdmissionPolicy {
	return &AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing-policy",
			Namespace: "default",
		},
		Spec: AdmissionPolicySpec{
			PolicySpec: PolicySpec{
				PolicyServer: "",
				Settings: runtime.RawExtension{
					Raw: []byte("{}"),
				},
				Rules: getRules(nil),
				Mode:  "protect",
			},
		},
	}
}

func clusterAdmissionPolicyFactory(customRules []admissionregistrationv1.RuleWithOperations, policyServer string, policyMode PolicyMode) *ClusterAdmissionPolicy {
	return &ClusterAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testing-policy",
			Namespace: "default",
		},
		Spec: ClusterAdmissionPolicySpec{
			PolicySpec: PolicySpec{
				PolicyServer: policyServer,
				Settings: runtime.RawExtension{
					Raw: []byte("{}"),
				},
				Rules: getRules(customRules),
				Mode:  policyMode,
			},
		},
	}
}

func getRules(customRules []admissionregistrationv1.RuleWithOperations) []admissionregistrationv1.RuleWithOperations {
	rules := customRules

	if rules == nil {
		rules = append(rules, admissionregistrationv1.RuleWithOperations{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"*"},
				APIVersions: []string{"*"},
				Resources:   []string{"*/*"},
			},
		})
	}
	return rules
}
