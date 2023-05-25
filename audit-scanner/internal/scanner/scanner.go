package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/kubewarden/audit-scanner/internal/resources"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	admv1 "k8s.io/api/admission/v1"
)

// A PoliciesFetcher interacts with the kubernetes api to return Kubewarden policies
type PoliciesFetcher interface {
	// GetPoliciesForANamespace gets all auditable policies for a given namespace, and the number of skipped policies
	GetPoliciesForANamespace(namespace string) ([]policiesv1.Policy, int, error)
	// GetPoliciesForAllNamespaces gets all auditable policies for all namespaces, and the number of skipped policies
	GetPoliciesForAllNamespaces() ([]policiesv1.Policy, int, error)
}

type ResourcesFetcher interface {
	GetResourcesForPolicies(ctx context.Context, policies []policiesv1.Policy, namespace string) ([]resources.AuditableResources, error)
	// GetPolicyServerURLRunningPolicy gets the URL used to send API requests to the policy server
	GetPolicyServerURLRunningPolicy(ctx context.Context, policy policiesv1.Policy) (*url.URL, error)
}

// A Scanner verifies that existing resources don't violate any of the policies
type Scanner struct {
	policiesFetcher  PoliciesFetcher
	resourcesFetcher ResourcesFetcher
	// http client used to make requests against the Policy Server
	httpClient http.Client
}

// NewScanner creates a new scanner with the PoliciesFetcher provided
func NewScanner(policiesFetcher PoliciesFetcher, resourcesFetcher ResourcesFetcher) *Scanner {
	return &Scanner{policiesFetcher, resourcesFetcher, http.Client{}}
}

// ScanNamespace scans resources for a given namespace
func (s *Scanner) ScanNamespace(namespace string) error {
	log.Info().Str("namespace", namespace).Msg("scan started")

	policies, skippedNum, err := s.policiesFetcher.GetPoliciesForANamespace(namespace)
	if err != nil {
		return err
	}
	log.Debug().Str("namespace", namespace).Int("count", len(policies)).Msg("number of policies to evaluate")

	// TODO continue with the scanning and remove this code
	log.Debug().Str("namespace", namespace).Msg("The following policies were found for the namespace " + namespace)
	for _, policy := range policies {
		log.Debug().Str("policy name", policy.GetName()).Msg("Policy retrieved")
	}

	auditableResources, err := s.resourcesFetcher.GetResourcesForPolicies(context.Background(), policies, namespace)

	if err != nil {
		return err
	}

	// TODO this is for debugging, it should be remove in future steps!
	for _, resource := range auditableResources {
		log.Debug().Msg("Policies: ")
		for _, policy := range resource.Policies {
			url, err := s.resourcesFetcher.GetPolicyServerURLRunningPolicy(context.Background(), policy)
			if err != nil {
				log.Debug().Err(err).Msg("CANNOT GET POLICY SERVER URL")
				continue
			}
			log.Debug().Msgf("POLICY SERVER URL: %s", url.String())
		}
		for _, resource := range resource.Resources {
			log.Debug().Dict("resource", zerolog.Dict().
				Str("name", resource.GetName()).
				Str("kind", resource.GetKind()).
				Str("namespace", resource.GetNamespace()).
				Str("UID", string(resource.GetUID()))).
				Msg("auditable resource")
		}
	}

	// Iterate through all auditableResources. Each item contains a list of resources and the policies that would need
	// to evaluate them.
	for i := range auditableResources {
		auditResource(&auditableResources[i], &s.resourcesFetcher, &s.httpClient)
	}

	return nil
}

// auditResource sends the requests to the Policy Server to evaluate the auditable resources.
// It will iterate over the policies which should evaluate the resource, get the URL to the service of the policy
// server running the policy, creates the AdmissionReview payload and send the request to the policy server for evaluation
func auditResource(resource *resources.AuditableResources, resourcesFetcher *ResourcesFetcher, httpClient *http.Client) {
	for _, policy := range resource.Policies {
		url, err := (*resourcesFetcher).GetPolicyServerURLRunningPolicy(context.Background(), policy)
		if err != nil {
			// TODO what's the better thing to do here?
			log.Error().Err(err)
			continue
		}
		for _, resource := range resource.Resources {
			admissionRequest := resources.GenerateAdmissionReview(resource)
			auditResponse, err := sendAdmissionReviewToPolicyServer(url, admissionRequest, httpClient)
			if err != nil {
				// TODO what's the better thing to do here?
				log.Error().Err(err)
				continue
			}

			log.Debug().Dict("response", zerolog.Dict().
				Str("uid", string(auditResponse.Response.UID)).
				Bool("allowed", auditResponse.Response.Allowed)).
				Msg("audit review response")
		}
	}
}

func sendAdmissionReviewToPolicyServer(url *url.URL, admissionRequest *admv1.AdmissionReview, httpClient *http.Client) (*admv1.AdmissionReview, error) {
	payload, err := json.Marshal(admissionRequest)

	if err != nil {
		return nil, err
	}
	// TODO remove the following line and properly configure the certificates
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url.String(), bytes.NewBuffer(payload))
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read body of response: %w", err)
	}
	if res.StatusCode > 299 {
		return nil, fmt.Errorf("response failed with status code: %d and\nbody: %s", res.StatusCode, body)
	}
	admissionReview := admv1.AdmissionReview{}
	err = json.Unmarshal(body, &admissionReview)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize the audit review response: %w", err)
	}
	return &admissionReview, nil
}

// ScanAllNamespaces scans resources for all namespaces
func (s *Scanner) ScanAllNamespaces() error {
	return errors.New("scanning all namespaces is not implemented yet. Please pass the --namespace flag to scan a namespace")
}
