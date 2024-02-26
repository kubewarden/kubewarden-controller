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
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidatePolicyServerName(t *testing.T) {
	name := make([]byte, 64)
	for i := range name {
		name[i] = 'a'
	}
	policyServer := &PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(name),
			Namespace: "default",
		},
		Spec: PolicyServerSpec{
			Image:    "image",
			Replicas: 1,
		},
	}
	policyServerValidator := policyServerValidator{
		k8sClient:            nil,
		deploymentsNamespace: "default",
	}
	err := policyServerValidator.validate(context.Background(), policyServer)
	require.ErrorContains(t, err, "the PolicyServer name cannot be longer than 63 characters")
}
