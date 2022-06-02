package naming

import (
	"fmt"

	"github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
)

func PolicyServerDeploymentNameForPolicyServer(policyServer *v1alpha2.PolicyServer) string {
	return PolicyServerDeploymentNameForPolicyServerName(policyServer.Name)
}

func PolicyServerDeploymentNameForPolicyServerName(policyServerName string) string {
	return fmt.Sprintf("policy-server-%s", policyServerName)
}
