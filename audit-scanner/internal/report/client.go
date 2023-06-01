package report

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	polReport "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1beta1"
)

// Save instantiates the passed namespaced PolicyReport if it doesn't exist, or
// updated a new one if one is found
func Save(report *polReport.PolicyReport) error {
	config := ctrl.GetConfigOrDie()
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(
		polReport.SchemeGroupVersion,
		&polReport.PolicyReport{},
		&polReport.PolicyReportList{},
		&polReport.ClusterPolicyReportList{},
	)
	metav1.AddToGroupVersion(customScheme, polReport.SchemeGroupVersion)
	client, err := client.New(config, client.Options{Scheme: customScheme})
	if err != nil {
		return fmt.Errorf("failed when creating new client: %w", err)
	}

	// Check for existing Policy Reports
	result := &polReport.PolicyReport{}
	getErr := client.Get(context.TODO(), types.NamespacedName{
		Namespace: report.Namespace,
		Name:      report.Name,
	}, result)

	// Create new Policy Report if not found
	if errors.IsNotFound(getErr) {
		log.Info().Msg("creating policy report...")

		err = client.Create(context.TODO(), report)
		if err != nil {
			return fmt.Errorf("failed when creating PolicyReport: %w", err)
		}
	} else {
		// Update existing Policy Report
		log.Info().Msg("updating policy report...")
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			getObj := &polReport.PolicyReport{}
			err := client.Get(context.TODO(), types.NamespacedName{
				Namespace: report.Namespace,
				Name:      report.Name,
			}, getObj)
			if errors.IsNotFound(err) {
				// This should never happen
				log.Error().Err(err).Str("PolicyReport name", report.GetName())
				return nil
			}

			if err != nil {
				return fmt.Errorf("failed when getting PolicyReport: %w", err)
			}

			report.SetResourceVersion(getObj.GetResourceVersion())

			updateErr := client.Update(context.TODO(), report)
			// return unwrapped error for RetryOnConflict()
			return updateErr
		})
		if retryErr != nil {
			log.Error().Err(retryErr).Msg("PolcyReport update failed")
		}
		log.Info().Msg("updated policy report")
	}
	return nil
}
