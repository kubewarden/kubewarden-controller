package metrics

import (
	"context"
	"fmt"
	policiesv1 "github.com/kubewarden/kubewarden-controller/apis/policies/v1"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric/global"
	"go.opentelemetry.io/otel/metric/instrument"
	controller "go.opentelemetry.io/otel/sdk/metric/controller/basic"
	processor "go.opentelemetry.io/otel/sdk/metric/processor/basic"
	"go.opentelemetry.io/otel/sdk/metric/selector/simple"
)

const (
	meterName                      = "kubewarden"
	policyCounterMetricName        = "kubewarden_policy_total"
	policyCounterMetricDescription = "How many policies are installed in the cluster"
)

func New(openTelemetryEndpoint string) error {
	ctx := context.Background()

	client := otlpmetricgrpc.NewClient(
		otlpmetricgrpc.WithInsecure(),
		otlpmetricgrpc.WithEndpoint(openTelemetryEndpoint),
	)
	exporter, err := otlpmetric.New(ctx, client)
	if err != nil {
		return fmt.Errorf("cannot start metric exporter: %w", err)
	}
	controller := controller.New(
		processor.NewFactory(
			simple.NewWithHistogramDistribution(),
			exporter,
		),
		controller.WithExporter(exporter),
		controller.WithCollectPeriod(2*time.Second),
	)
	global.SetMeterProvider(controller)
	err = controller.Start(ctx)
	if err != nil {
		return fmt.Errorf("cannot start metric controller: %w", err)
	}
	return nil
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
