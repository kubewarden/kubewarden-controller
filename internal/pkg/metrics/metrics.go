package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/kubewarden/kubewarden-controller/apis/v1alpha2"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpgrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/global"
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

	driver := otlpgrpc.NewDriver(
		otlpgrpc.WithInsecure(),
		otlpgrpc.WithEndpoint(openTelemetryEndpoint),
	)
	exporter, err := otlp.NewExporter(ctx, driver)
	if err != nil {
		return fmt.Errorf("cannot start metric exporter: %w", err)
	}
	controller := controller.New(
		processor.New(
			simple.NewWithExactDistribution(),
			exporter,
		),
		controller.WithExporter(exporter),
		controller.WithCollectPeriod(2*time.Second),
	)
	global.SetMeterProvider(controller.MeterProvider())
	err = controller.Start(ctx)
	if err != nil {
		return fmt.Errorf("cannot start metric controller: %w", err)
	}
	return nil
}

func RecordPolicyCount(policy v1alpha2.Policy) {
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
	valueRecorder := metric.Must(meter).
		NewInt64Counter(
			policyCounterMetricName,
			metric.WithDescription(policyCounterMetricDescription),
		).Bind(commonLabels...)
	defer valueRecorder.Unbind()
	valueRecorder.Add(context.Background(), 1)
}
