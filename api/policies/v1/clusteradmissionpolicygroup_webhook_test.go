//go:build testing

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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

func TestClusterClusterAdmissionPolicyDefault(t *testing.T) {
	policy := ClusterAdmissionPolicyGroup{}
	policy.Default()

	require.Equal(t, constants.DefaultPolicyServer, policy.GetPolicyServer())
	require.Contains(t, policy.GetFinalizers(), constants.KubewardenFinalizer)
}

func TestClusterClusterAdmissionPolicyValidateCreate(t *testing.T) {
	policy := NewClusterAdmissionPolicyGroupFactory().Build()
	warnings, err := policy.ValidateCreate()
	require.NoError(t, err)
	require.Empty(t, warnings)
}

func TestClusterClusterAdmissionPolicyValidateCreateWithNoMembers(t *testing.T) {
	policy := NewClusterAdmissionPolicyGroupFactory().Build()
	policy.Spec.Policies = nil
	warnings, err := policy.ValidateCreate()
	require.Error(t, err)
	require.Empty(t, warnings)
	require.Contains(t, err.Error(), "policy groups must have at least one policy member")
}

func TestClusterClusterAdmissionPolicyValidateUpdate(t *testing.T) {
	oldPolicy := NewClusterAdmissionPolicyGroupFactory().Build()
	newPolicy := NewClusterAdmissionPolicyGroupFactory().Build()
	warnings, err := newPolicy.ValidateUpdate(oldPolicy)
	require.NoError(t, err)
	require.Empty(t, warnings)
}

func TestClusterClusterAdmissionPolicyValidateUpdateWithInvalidOldPolicy(t *testing.T) {
	oldPolicy := NewAdmissionPolicyGroupFactory().Build()
	newPolicy := NewClusterAdmissionPolicyGroupFactory().Build()
	warnings, err := newPolicy.ValidateUpdate(oldPolicy)
	require.Empty(t, warnings)
	require.ErrorContains(t, err, "object is not of type ClusterAdmissionPolicyGroup")
}
