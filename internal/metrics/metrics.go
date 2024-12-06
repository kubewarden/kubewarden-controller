package metrics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	metricSDK "go.opentelemetry.io/otel/sdk/metric"

	"google.golang.org/grpc/credentials"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
)

const (
	meterName                      = "kubewarden"
	policyCounterMetricName        = "kubewarden_policy_total"
	policyCounterMetricDescription = "How many policies are installed in the cluster"
	timeBetweenExports             = 2 * time.Second
)

func loadTlsConfig(openTelemetryCertificate, openTelemetryClientCertificateKey, openTelemetryClientCertificate string) (*tls.Config, error) {
	serverCertificateBytes, err := os.ReadFile(openTelemetryCertificate)
	if err != nil {
		return nil, fmt.Errorf("cannot read OpenTelemetry server certificate: %w", err)
	}
	serverCertificatePool := x509.NewCertPool()
	if ok := serverCertificatePool.AppendCertsFromPEM(serverCertificateBytes); !ok {
		return nil, fmt.Errorf("cannot parse OpenTelemetry server certificate")
	}

	clientCertificateBytes, err := os.ReadFile(openTelemetryClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("cannot read OpenTelemetry client certificate: %w", err)
	}
	clientCertificateKeyBytes, err := os.ReadFile(openTelemetryClientCertificateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot read OpenTelemetry client certificate key: %w", err)
	}
	clientKeyPair, err := tls.X509KeyPair(clientCertificateBytes, clientCertificateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot load OpenTelemetry client key pair: %w", err)
	}
	return &tls.Config{RootCAs: serverCertificatePool, Certificates: []tls.Certificate{clientKeyPair}}, nil
}

func New(openTelemetryEndpoint, openTelemetryCertificate, openTelemetryClientCertificateKey, openTelemetryClientCertificate string) (func(context.Context) error, error) {
	ctx := context.Background()

	tlsConfig, err := loadTlsConfig(openTelemetryCertificate, openTelemetryClientCertificateKey, openTelemetryClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("cannot load TLS configuration: %w", err)
	}

	// Create the OTLP exporter to export metrics to the specified endpoint.
	// All the Otel exporter configuration is set by environment variables.
	// Keep the usage of the openTelemetryEndpoint to keep back compatibility.
	exporter, err := otlpmetricgrpc.New(
		ctx,
		otlpmetricgrpc.WithEndpoint(openTelemetryEndpoint),
		otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot start metric exporter: %w", err)
	}
	meterProvider := metricSDK.NewMeterProvider(metricSDK.WithReader(
		metricSDK.NewPeriodicReader(exporter, metricSDK.WithInterval(timeBetweenExports))))

	otel.SetMeterProvider(meterProvider)

	return meterProvider.Shutdown, nil
}

func RecordPolicyCount(ctx context.Context, policy policiesv1.Policy) error {
	failurePolicy := ""
	if policy.GetFailurePolicy() != nil {
		failurePolicy = string(*policy.GetFailurePolicy())
	}

	meter := otel.Meter(meterName)
	counter, err := meter.Int64Counter(policyCounterMetricName, metric.WithDescription(policyCounterMetricDescription))
	if err != nil {
		return fmt.Errorf("cannot create the instrument: %w", err)
	}

	commonLabels := []attribute.KeyValue{
		attribute.String("name", policy.GetUniqueName()),
		attribute.String("policy_server", policy.GetPolicyServer()),
		attribute.String("module", policy.GetModule()),
		attribute.Bool("mutating", policy.IsMutating()),
		attribute.String("namespace", policy.GetNamespace()),
		attribute.String("failure_policy", failurePolicy),
		attribute.String("policy_status", string(policy.GetStatus().PolicyStatus)),
	}
	counter.Add(ctx, 1, metric.WithAttributes(commonLabels...))

	return nil
}
