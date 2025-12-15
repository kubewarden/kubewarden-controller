//go:build testing

package testutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/audit-scanner/constants"
	"github.com/kubewarden/kubewarden-controller/internal/audit-scanner/scheme"
	openreports "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func NewFakeClient(objects ...runtime.Object) (client.Client, error) {
	groupVersion := []schema.GroupVersion{
		{Group: "", Version: "v1"},
		{Group: "apps", Version: "v1"},
	}
	restMapper := meta.NewDefaultRESTMapper(groupVersion)
	restMapper.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}, meta.RESTScopeNamespace)
	restMapper.Add(schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}, meta.RESTScopeNamespace)
	restMapper.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}, meta.RESTScopeRoot)
	restMapper.Add(schema.GroupVersionKind{Group: admissionregistrationv1.GroupName, Version: "v1", Kind: "ValidatingWebhookConfiguration"}, meta.RESTScopeRoot)

	auditScheme, err := scheme.NewScheme()
	if err != nil {
		return nil, err
	}
	return fake.NewClientBuilder().WithRESTMapper(restMapper).WithScheme(auditScheme).WithRuntimeObjects(objects...).Build(), nil
}

type PolicyReportFactory struct {
	name      string
	namespace string
	labels    map[string]string
}

func NewPolicyReportFactory() *PolicyReportFactory {
	return &PolicyReportFactory{
		labels: map[string]string{},
	}
}

func (factory *PolicyReportFactory) Name(name string) *PolicyReportFactory {
	factory.name = name

	return factory
}

func (factory *PolicyReportFactory) RunUID(runUID string) *PolicyReportFactory {
	factory.labels[constants.AuditScannerRunUIDLabel] = runUID

	return factory
}

func (factory *PolicyReportFactory) Namespace(namespace string) *PolicyReportFactory {
	factory.namespace = namespace

	return factory
}

func (factory *PolicyReportFactory) WithAppLabel() *PolicyReportFactory {
	factory.labels["app.kubernetes.io/managed-by"] = "kubewarden"

	return factory
}

func (factory *PolicyReportFactory) Build() *wgpolicy.PolicyReport {
	return &wgpolicy.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      factory.name,
			Namespace: factory.namespace,
			Labels:    factory.labels,
		},
	}
}

func (factory *PolicyReportFactory) BuildOpenReports() *openreports.Report {
	return &openreports.Report{
		ObjectMeta: metav1.ObjectMeta{
			Name:      factory.name,
			Namespace: factory.namespace,
			Labels:    factory.labels,
		},
	}
}

type ClusterPolicyReportFactory struct {
	name   string
	labels map[string]string
}

func NewClusterPolicyReportFactory() *ClusterPolicyReportFactory {
	return &ClusterPolicyReportFactory{
		labels: map[string]string{},
	}
}

func (factory *ClusterPolicyReportFactory) Name(name string) *ClusterPolicyReportFactory {
	factory.name = name
	return factory
}

func (factory *ClusterPolicyReportFactory) RunUID(runUID string) *ClusterPolicyReportFactory {
	factory.labels[constants.AuditScannerRunUIDLabel] = runUID

	return factory
}

func (factory *ClusterPolicyReportFactory) WithAppLabel() *ClusterPolicyReportFactory {
	factory.labels["app.kubernetes.io/managed-by"] = "kubewarden"

	return factory
}

func (factory *ClusterPolicyReportFactory) Build() *wgpolicy.ClusterPolicyReport {
	return &wgpolicy.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:   factory.name,
			Labels: factory.labels,
		},
	}
}

func (factory *ClusterPolicyReportFactory) BuildOpenReports() *openreports.ClusterReport {
	return &openreports.ClusterReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:   factory.name,
			Labels: factory.labels,
		},
	}
}

type AdmissionPolicyFactory struct {
	name            string
	namespace       string
	objectSelector  *metav1.LabelSelector
	rules           []admissionregistrationv1.RuleWithOperations
	backgroundAudit bool
	status          policiesv1.PolicyStatusEnum
}

func NewAdmissionPolicyFactory() *AdmissionPolicyFactory {
	return &AdmissionPolicyFactory{
		backgroundAudit: true,
		status:          policiesv1.PolicyStatusActive,
	}
}

func (factory *AdmissionPolicyFactory) Name(name string) *AdmissionPolicyFactory {
	factory.name = name

	return factory
}

func (factory *AdmissionPolicyFactory) Namespace(namespace string) *AdmissionPolicyFactory {
	factory.namespace = namespace

	return factory
}

func (factory *AdmissionPolicyFactory) ObjectSelector(selector *metav1.LabelSelector) *AdmissionPolicyFactory {
	factory.objectSelector = selector

	return factory
}

func (factory *AdmissionPolicyFactory) Rule(rule admissionregistrationv1.Rule, operations ...admissionregistrationv1.OperationType) *AdmissionPolicyFactory {
	if len(operations) == 0 {
		operations = []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
	}

	factory.rules = append(factory.rules, admissionregistrationv1.RuleWithOperations{
		Operations: operations, Rule: rule,
	})

	return factory
}

func (factory *AdmissionPolicyFactory) BackgroundAudit(backgroundAudit bool) *AdmissionPolicyFactory {
	factory.backgroundAudit = backgroundAudit

	return factory
}

func (factory *AdmissionPolicyFactory) Status(status policiesv1.PolicyStatusEnum) *AdmissionPolicyFactory {
	factory.status = status

	return factory
}

func (factory *AdmissionPolicyFactory) Build() *policiesv1.AdmissionPolicy {
	policy := &policiesv1.AdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      factory.name,
			Namespace: factory.namespace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       constants.KubewardenKindAdmissionPolicy,
			APIVersion: constants.KubewardenPoliciesVersion,
		},
		Spec: policiesv1.AdmissionPolicySpec{
			PolicySpec: policiesv1.PolicySpec{
				ObjectSelector:  factory.objectSelector,
				PolicyServer:    "default",
				Rules:           factory.rules,
				BackgroundAudit: factory.backgroundAudit,
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: factory.status,
		},
	}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindAdmissionPolicy,
	})

	return policy
}

type AdmissionPolicyGroupFactory struct {
	name            string
	namespace       string
	objectSelector  *metav1.LabelSelector
	rules           []admissionregistrationv1.RuleWithOperations
	backgroundAudit bool
	status          policiesv1.PolicyStatusEnum
}

func NewAdmissionPolicyGroupFactory() *AdmissionPolicyGroupFactory {
	return &AdmissionPolicyGroupFactory{
		backgroundAudit: true,
		status:          policiesv1.PolicyStatusActive,
	}
}

func (factory *AdmissionPolicyGroupFactory) Name(name string) *AdmissionPolicyGroupFactory {
	factory.name = name

	return factory
}

func (factory *AdmissionPolicyGroupFactory) Namespace(namespace string) *AdmissionPolicyGroupFactory {
	factory.namespace = namespace

	return factory
}

func (factory *AdmissionPolicyGroupFactory) ObjectSelector(selector *metav1.LabelSelector) *AdmissionPolicyGroupFactory {
	factory.objectSelector = selector

	return factory
}

func (factory *AdmissionPolicyGroupFactory) Rule(rule admissionregistrationv1.Rule, operations ...admissionregistrationv1.OperationType) *AdmissionPolicyGroupFactory {
	if len(operations) == 0 {
		operations = []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
	}

	factory.rules = append(factory.rules, admissionregistrationv1.RuleWithOperations{
		Operations: operations, Rule: rule,
	})

	return factory
}

func (factory *AdmissionPolicyGroupFactory) BackgroundAudit(backgroundAudit bool) *AdmissionPolicyGroupFactory {
	factory.backgroundAudit = backgroundAudit

	return factory
}

func (factory *AdmissionPolicyGroupFactory) Status(status policiesv1.PolicyStatusEnum) *AdmissionPolicyGroupFactory {
	factory.status = status

	return factory
}

func (factory *AdmissionPolicyGroupFactory) Build() *policiesv1.AdmissionPolicyGroup {
	policy := &policiesv1.AdmissionPolicyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      factory.name,
			Namespace: factory.namespace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       constants.KubewardenKindAdmissionPolicyGroup,
			APIVersion: constants.KubewardenPoliciesVersion,
		},
		Spec: policiesv1.AdmissionPolicyGroupSpec{
			PolicyGroupSpec: policiesv1.PolicyGroupSpec{
				GroupSpec: policiesv1.GroupSpec{
					ObjectSelector:  factory.objectSelector,
					PolicyServer:    "default",
					Rules:           factory.rules,
					BackgroundAudit: factory.backgroundAudit,
				},
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: factory.status,
		},
	}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindAdmissionPolicyGroup,
	})

	return policy
}

type ClusterAdmissionPolicyFactory struct {
	name              string
	namespaceSelector *metav1.LabelSelector
	objectSelector    *metav1.LabelSelector
	rules             []admissionregistrationv1.RuleWithOperations
	backgroundAudit   bool
	status            policiesv1.PolicyStatusEnum
}

func NewClusterAdmissionPolicyFactory() *ClusterAdmissionPolicyFactory {
	return &ClusterAdmissionPolicyFactory{
		backgroundAudit: true,
		status:          policiesv1.PolicyStatusActive,
	}
}

func (factory *ClusterAdmissionPolicyFactory) Name(name string) *ClusterAdmissionPolicyFactory {
	factory.name = name

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) NamespaceSelector(selector *metav1.LabelSelector) *ClusterAdmissionPolicyFactory {
	factory.namespaceSelector = selector

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) ObjectSelector(selector *metav1.LabelSelector) *ClusterAdmissionPolicyFactory {
	factory.objectSelector = selector

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) Rule(rule admissionregistrationv1.Rule, operations ...admissionregistrationv1.OperationType) *ClusterAdmissionPolicyFactory {
	if len(operations) == 0 {
		operations = []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
	}

	factory.rules = append(factory.rules, admissionregistrationv1.RuleWithOperations{
		Operations: operations, Rule: rule,
	})

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) BackgroundAudit(backgroundAudit bool) *ClusterAdmissionPolicyFactory {
	factory.backgroundAudit = backgroundAudit

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) Status(status policiesv1.PolicyStatusEnum) *ClusterAdmissionPolicyFactory {
	factory.status = status

	return factory
}

func (factory *ClusterAdmissionPolicyFactory) Build() *policiesv1.ClusterAdmissionPolicy {
	policy := &policiesv1.ClusterAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       constants.KubewardenKindClusterAdmissionPolicy,
			APIVersion: constants.KubewardenPoliciesVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: factory.name,
		},
		Spec: policiesv1.ClusterAdmissionPolicySpec{
			NamespaceSelector: factory.namespaceSelector,
			PolicySpec: policiesv1.PolicySpec{
				ObjectSelector:  factory.objectSelector,
				PolicyServer:    "default",
				Rules:           factory.rules,
				BackgroundAudit: factory.backgroundAudit,
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: factory.status,
		},
	}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindClusterAdmissionPolicy,
	})

	return policy
}

type ClusterAdmissionPolicyGroupFactory struct {
	name              string
	namespaceSelector *metav1.LabelSelector
	objectSelector    *metav1.LabelSelector
	rules             []admissionregistrationv1.RuleWithOperations
	backgroundAudit   bool
	status            policiesv1.PolicyStatusEnum
}

func NewClusterAdmissionPolicyGroupFactory() *ClusterAdmissionPolicyGroupFactory {
	return &ClusterAdmissionPolicyGroupFactory{
		backgroundAudit: true,
		status:          policiesv1.PolicyStatusActive,
	}
}

func (factory *ClusterAdmissionPolicyGroupFactory) Name(name string) *ClusterAdmissionPolicyGroupFactory {
	factory.name = name

	return factory
}

func (factory *ClusterAdmissionPolicyGroupFactory) NamespaceSelector(selector *metav1.LabelSelector) *ClusterAdmissionPolicyGroupFactory {
	factory.namespaceSelector = selector

	return factory
}

func (factory *ClusterAdmissionPolicyGroupFactory) ObjectSelector(selector *metav1.LabelSelector) *ClusterAdmissionPolicyGroupFactory {
	factory.objectSelector = selector

	return factory
}

func (factory *ClusterAdmissionPolicyGroupFactory) Rule(rule admissionregistrationv1.Rule, operations ...admissionregistrationv1.OperationType) *ClusterAdmissionPolicyGroupFactory {
	if len(operations) == 0 {
		operations = []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
	}

	factory.rules = append(factory.rules, admissionregistrationv1.RuleWithOperations{
		Operations: operations, Rule: rule,
	})

	return factory
}

func (factory *ClusterAdmissionPolicyGroupFactory) BackgroundAudit(backgroundAudit bool) *ClusterAdmissionPolicyGroupFactory {
	factory.backgroundAudit = backgroundAudit

	return factory
}

func (factory *ClusterAdmissionPolicyGroupFactory) Status(status policiesv1.PolicyStatusEnum) *ClusterAdmissionPolicyGroupFactory {
	factory.status = status

	return factory
}

func (factory *ClusterAdmissionPolicyGroupFactory) Build() *policiesv1.ClusterAdmissionPolicyGroup {
	policy := &policiesv1.ClusterAdmissionPolicyGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       constants.KubewardenKindClusterAdmissionPolicyGroup,
			APIVersion: constants.KubewardenPoliciesVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: factory.name,
		},
		Spec: policiesv1.ClusterAdmissionPolicyGroupSpec{
			NamespaceSelector: factory.namespaceSelector,
			ClusterPolicyGroupSpec: policiesv1.ClusterPolicyGroupSpec{
				GroupSpec: policiesv1.GroupSpec{
					ObjectSelector:  factory.objectSelector,
					PolicyServer:    "default",
					Rules:           factory.rules,
					BackgroundAudit: factory.backgroundAudit,
				},
			},
		},
		Status: policiesv1.PolicyStatus{
			PolicyStatus: factory.status,
		},
	}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindClusterAdmissionPolicyGroup,
	})

	return policy
}

// GenerateTestCA generates a test CA root and key.
func GenerateTestCA() ([]byte, []byte, error) {
	key, keyPEM, err := generateKey()
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, keyPEM, err
}

// GenerateTestCert generates a test certificate and key signed by the given CA certificate and key.
func GenerateTestCert(caCertPEM, caKeyPEM []byte, commonName string) ([]byte, []byte, error) {
	key, keyPEM, err := generateKey()
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	block, _ = pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.IPAddresses = []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, keyPEM, nil
}

func generateKey() (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048) //nolint:mnd // This is a test helper
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return key, keyPEM, err
}

// WriteTempFile creates a temporary file with the given content and returns the file path.
func WriteTempFile(content []byte) (string, error) {
	tmpfile, err := os.CreateTemp("", "test-cert-*")
	if err != nil {
		return "", err
	}
	defer tmpfile.Close()

	if _, err := tmpfile.Write(content); err != nil {
		return "", err
	}

	return tmpfile.Name(), nil
}
