package metrics

import (
	"context"
	"fmt"
	"time"

	policiesv1 "github.com/kubewarden/kubewarden-controller/apis/policies/v1"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric/global"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/sdk/metric"
)

const (
	meterName                      = "kubewarden"
	policyCounterMetricName        = "kubewarden_policy_total"
	policyCounterMetricDescription = "How many policies are installed in the cluster"
)

func New(openTelemetryEndpoint string) (func(context.Context) error, error) {
	ctx := context.Background()

	exporter, err := otlpmetricgrpc.New(
		ctx,
		otlpmetricgrpc.WithInsecure(),
		otlpmetricgrpc.WithEndpoint(openTelemetryEndpoint),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot start metric exporter: %w", err)
	}
	meterProvider := metric.NewMeterProvider(metric.WithReader(
		metric.NewPeriodicReader(exporter, metric.WithInterval(2*time.Second))))

	global.SetMeterProvider(meterProvider)

	return meterProvider.Shutdown, nil
}

func RecordPolicyCount(policy policiesv1.Policy) error {
	failurePolicy := ""
	if policy.GetFailurePolicy() != nil {
		failurePolicy = string(*policy.GetFailurePolicy())
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
	meter := global.Meter(meterName)
	counter, err := meter.SyncInt64().Counter(policyCounterMetricName, instrument.WithDescription(policyCounterMetricDescription))
	if err != nil {
		return fmt.Errorf("cannot create the instrument: %w", err)
	}
	counter.Add(context.Background(), 1, commonLabels...)
	return nil
}
