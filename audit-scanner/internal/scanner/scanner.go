package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/kubewarden/audit-scanner/internal/constants"
	"github.com/kubewarden/audit-scanner/internal/k8s"
	reportLogger "github.com/kubewarden/audit-scanner/internal/log"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/report"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// Scanner verifies that existing resources don't violate any of the policies
type Scanner struct {
	policiesClient    *policies.Client
	k8sClient         *k8s.Client
	policyReportStore report.PolicyReportStore
	// http client used to make requests against the Policy Server
	httpClient http.Client
	outputScan bool
}

// NewScanner creates a new scanner
// If insecureClient is false, it will read the caCertFile and add it to the in-app
// cert trust store. This gets used by the httpClient when connection to
// PolicyServers endpoints.
func NewScanner(
	policiesClient *policies.Client,
	k8sClient *k8s.Client,
	policyReportStore report.PolicyReportStore,
	outputScan bool,
	insecureClient bool,
	caCertFile string,
) (*Scanner, error) {
	// Get the SystemCertPool to build an in-app cert pool from it
	// Continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if caCertFile != "" {
		certs, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %q with CA cert: %w", caCertFile, err)
		}
		// Append our cert to the in-app cert pool
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			return nil, errors.New("failed to append cert to in-app RootCAs trust store")
		}
		log.Debug().Str("ca-cert-file", caCertFile).
			Msg("appended cert file to in-app RootCAs trust store")
	}

	httpClient := *http.DefaultClient
	httpClient.Timeout = 10 * time.Second
	httpClient.Transport = http.DefaultTransport
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("failed to build httpClient: failed http.Transport type assertion")
	}
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    rootCAs, // our augmented in-app cert pool
		MinVersion: tls.VersionTLS12,
	}

	if insecureClient {
		transport.TLSClientConfig.InsecureSkipVerify = true
		log.Warn().Msg("connecting to PolicyServers endpoints without validating TLS connection")
	}

	return &Scanner{
		policiesClient:    policiesClient,
		k8sClient:         k8sClient,
		policyReportStore: policyReportStore,
		httpClient:        httpClient,
		outputScan:        outputScan,
	}, nil
}

// ScanNamespace scans resources for a given namespace.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanNamespace(ctx context.Context, nsName string) error { //nolint:funlen
	log.Info().Str("namespace", nsName).Msg("namespace scan started")

	namespace, err := s.k8sClient.GetNamespace(ctx, nsName)
	if err != nil {
		return err
	}
	policies, err := s.policiesClient.GetPoliciesForANamespace(ctx, nsName)
	if err != nil {
		return err
	}

	log.Info().
		Str("namespace", nsName).
		Dict("dict", zerolog.Dict().
			Int("policies to evaluate", policies.PolicyNum).
			Int("policies skipped", policies.SkippedNum),
		).Msg("policy count")

	// create PolicyReport
	namespacedsReport := report.NewPolicyReport(namespace)
	namespacedsReport.Summary.Skip = policies.SkippedNum

	// old policy report to be used as cache
	previousNamespacedReport, err := s.policyReportStore.GetPolicyReport(nsName)
	if errors.Is(err, constants.ErrResourceNotFound) {
		log.Info().Str("namespace", nsName).
			Msg("no pre-existing PolicyReport, will create one at end of the scan if needed")
	} else if err != nil {
		log.Err(err).Str("namespace", nsName).
			Msg("error when obtaining PolicyReport")
	}

	for gvr, objectFilters := range policies.PoliciesByGVRAndLabelSelector {
		for labelSelector, policies := range objectFilters {
			pager, err := s.k8sClient.GetResources(gvr, nsName, labelSelector)
			if err != nil {
				return err
			}

			err = pager.EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
				resource, ok := obj.(*unstructured.Unstructured)
				if !ok {
					return fmt.Errorf("failed to convert runtime.Object to *unstructured.Unstructured")
				}
				s.auditResource(ctx, policies, *resource, &namespacedsReport, &previousNamespacedReport)

				return nil
			})
			if err != nil {
				return err
			}
		}
	}

	if err := s.policyReportStore.SavePolicyReport(&namespacedsReport); err != nil {
		log.Error().Err(err).Msg("error adding PolicyReport to store")
	}
	log.Info().Str("namespace", nsName).Msg("namespace scan finished")
	if s.outputScan {
		reportLogger.PolicyReport(&namespacedsReport)
	}

	return nil
}

// ScanAllNamespaces scans resources for all namespaces, except the ones in the skipped list.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanAllNamespaces(ctx context.Context) error {
	log.Info().Msg("all-namespaces scan started")
	nsList, err := s.k8sClient.GetAuditedNamespaces(ctx)
	if err != nil {
		log.Error().Err(err).Msg("error scanning all namespaces")
	}

	for _, ns := range nsList.Items {
		if e := s.ScanNamespace(ctx, ns.Name); e != nil {
			log.Error().Err(e).Str("ns", ns.Name).Msg("error scanning namespace")
			err = errors.Join(err, e)
		}
	}
	log.Info().Msg("all-namespaces scan finished")
	return err
}

// ScanClusterWideResources scans all cluster wide resources.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanClusterWideResources(ctx context.Context) error {
	log.Info().Msg("clusterwide resources scan started")

	policies, err := s.policiesClient.GetClusterWidePolicies(ctx)
	if err != nil {
		return err
	}

	log.Info().
		Dict("dict", zerolog.Dict().
			Int("policies to evaluate", policies.PolicyNum).
			Int("policies skipped", policies.SkippedNum),
		).Msg("cluster admission policies count")

	// create PolicyReport
	clusterReport := report.NewClusterPolicyReport(constants.DefaultClusterwideReportName)
	clusterReport.Summary.Skip = policies.SkippedNum

	// old policy report to be used as cache
	previousClusterReport, err := s.policyReportStore.GetClusterPolicyReport(constants.DefaultClusterwideReportName)
	if err != nil {
		log.Info().Err(err).Msg("no-prexisting ClusterPolicyReport, will create one at the end of the scan")
	}

	for gvr, objectFilters := range policies.PoliciesByGVRAndLabelSelector {
		for labelSelector, policies := range objectFilters {
			pager, err := s.k8sClient.GetResources(gvr, "", labelSelector)
			if err != nil {
				return err
			}

			err = pager.EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
				resource, ok := obj.(*unstructured.Unstructured)
				if !ok {
					return fmt.Errorf("failed to convert runtime.Object to *unstructured.Unstructured")
				}

				s.auditClusterResource(ctx, policies, *resource, &clusterReport, &previousClusterReport)

				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	if err := s.policyReportStore.SaveClusterPolicyReport(&clusterReport); err != nil {
		log.Error().Err(err).Msg("error adding PolicyReport to store")
	}

	log.Info().Msg("clusterwide resources scan finished")

	if s.outputScan {
		reportLogger.ClusterPolicyReport(&clusterReport)
	}

	return nil
}

func (s *Scanner) auditClusterResource(ctx context.Context, policies []*policies.Policy, resource unstructured.Unstructured, clusterReport, previousClusterReport *report.ClusterPolicyReport) {
	for _, p := range policies {
		url := p.PolicyServer
		policy := p.Policy

		if result := previousClusterReport.GetReusablePolicyReportResult(policy, resource); result != nil {
			// We have a result from the same policy version for the same resource instance.
			// Skip the evaluation
			clusterReport.AddResult(result)
			log.Debug().Dict("skip-evaluation", zerolog.Dict().
				Str("policy", policy.GetName()).
				Str("policyResourceVersion", policy.GetResourceVersion()).
				Str("policyUID", string(policy.GetUID())).
				Str("resource", resource.GetName()).
				Str("resourceResourceVersion", resource.GetResourceVersion()),
			).Msg("Previous result found. Reusing result")
			continue
		}
		admissionRequest := newAdmissionReview(resource)
		auditResponse, responseErr := s.sendAdmissionReviewToPolicyServer(ctx, url, admissionRequest)
		if responseErr != nil {
			// log error, will end in ClusterPolicyReportResult too
			log.Error().Err(responseErr).Dict("response", zerolog.Dict().
				Str("admissionRequest name", admissionRequest.Request.Name).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()),
			).
				Msg("error sending AdmissionReview to PolicyServer")
		} else {
			log.Debug().Dict("response", zerolog.Dict().
				Str("uid", string(auditResponse.Response.UID)).
				Bool("allowed", auditResponse.Response.Allowed).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()),
			).
				Msg("audit review response")
			result := clusterReport.CreateResult(policy, resource, auditResponse, responseErr)
			clusterReport.AddResult(result)
		}
	}
}

func (s *Scanner) auditResource(ctx context.Context, policies []*policies.Policy, resource unstructured.Unstructured, nsReport, previousNsReport *report.PolicyReport) {
	for _, p := range policies {
		url := p.PolicyServer
		policy := p.Policy

		if result := previousNsReport.GetReusablePolicyReportResult(policy, resource); result != nil {
			// We have a result from the same policy version for the same resource instance.
			// Skip the evaluation
			nsReport.AddResult(result)
			log.Debug().Dict("skip-evaluation", zerolog.Dict().
				Str("policy", policy.GetName()).
				Str("policyResourceVersion", policy.GetResourceVersion()).
				Str("policyUID", string(policy.GetUID())).
				Str("resource", resource.GetName()).
				Str("resourceResourceVersion", resource.GetResourceVersion()),
			).Msg("Previous result found. Reusing result")
			continue
		}

		admissionRequest := newAdmissionReview(resource)
		auditResponse, responseErr := s.sendAdmissionReviewToPolicyServer(ctx, url, admissionRequest)
		if responseErr != nil {
			// log responseErr, will end in PolicyReportResult too
			log.Error().Err(responseErr).Dict("response", zerolog.Dict().
				Str("admissionRequest name", admissionRequest.Request.Name).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()),
			).
				Msg("error sending AdmissionReview to PolicyServer")
		} else {
			log.Debug().Dict("response", zerolog.Dict().
				Str("uid", string(auditResponse.Response.UID)).
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()).
				Bool("allowed", auditResponse.Response.Allowed),
			).
				Msg("audit review response")
			result := nsReport.CreateResult(policy, resource, auditResponse, responseErr)
			nsReport.AddResult(result)
		}
	}
}

func (s *Scanner) sendAdmissionReviewToPolicyServer(ctx context.Context, url *url.URL, admissionRequest *admissionv1.AdmissionReview) (*admissionv1.AdmissionReview, error) {
	payload, err := json.Marshal(admissionRequest)
	if err != nil {
		return nil, err
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bytes.NewBuffer(payload))
	req.Header.Add("Content-Type", "application/json")

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read body of response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d body: %s", res.StatusCode, body)
	}

	admissionReview := admissionv1.AdmissionReview{}
	err = json.Unmarshal(body, &admissionReview)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize the audit review response: %w", err)
	}
	return &admissionReview, nil
}
