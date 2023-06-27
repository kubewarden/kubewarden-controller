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
	"fmt"

	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var policyserverlog = logf.Log.WithName("policyserver-resource")

func (ps *PolicyServer) SetupWebhookWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewWebhookManagedBy(mgr).
		For(ps).
		Complete()
	if err != nil {
		return fmt.Errorf("failed enrolling webhook with manager: %w", err)
	}
	return nil
}

//+kubebuilder:webhook:path=/mutate-policies-kubewarden-io-v1-policyserver,mutating=true,failurePolicy=fail,sideEffects=None,groups=policies.kubewarden.io,resources=policyservers,verbs=create;update,versions=v1,name=mpolicyserver.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &PolicyServer{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (ps *PolicyServer) Default() {
	policyserverlog.Info("default", "name", ps.Name)
	if ps.ObjectMeta.DeletionTimestamp == nil {
		controllerutil.AddFinalizer(ps, constants.KubewardenFinalizer)
	}
}
