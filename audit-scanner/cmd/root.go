package cmd

import (
	"context"
	"fmt"

	"github.com/kubewarden/audit-scanner/internal/k8s"
	logconfig "github.com/kubewarden/audit-scanner/internal/log"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/report"
	"github.com/kubewarden/audit-scanner/internal/scanner"
	"github.com/kubewarden/audit-scanner/internal/scheme"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const defaultKubewardenNamespace = "kubewarden"

// log level
var level logconfig.Level

// print result of scan as JSON to stdout
var outputScan bool

// list of namespaces to be skipped from scan
var skippedNs []string

// skip SSL cert validation when connecting to PolicyServers endpoints
var insecureSSL bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "audit-scanner",
	Short: "Reports evaluation of existing Kubernetes resources with your already deployed Kubewarden policies",
	Long: `Scans resources in your kubernetes cluster with your already deployed Kubewarden policies.
Each namespace will have a PolicyReport with the outcome of the scan for resources within this namespace.
There will be a ClusterPolicyReport with results for cluster-wide resources.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		level.SetZeroLogLevel()
		namespace, err := cmd.Flags().GetString("namespace")
		if err != nil {
			return err
		}
		kubewardenNamespace, err := cmd.Flags().GetString("kubewarden-namespace")
		if err != nil {
			return err
		}
		clusterWide, err := cmd.Flags().GetBool("cluster")
		if err != nil {
			return err
		}
		policyServerURL, err := cmd.Flags().GetString("policy-server-url")
		if err != nil {
			return err
		}
		caCertFile, err := cmd.Flags().GetString("extra-ca")
		if err != nil {
			return err
		}

		config := ctrl.GetConfigOrDie()
		dynamicClient := dynamic.NewForConfigOrDie(config)
		clientset := kubernetes.NewForConfigOrDie(config)

		client, err := client.New(config, client.Options{Scheme: scheme.NewScheme()})
		if err != nil {
			return err
		}
		policiesClient, err := policies.NewClient(client, kubewardenNamespace, policyServerURL)
		if err != nil {
			return err
		}
		k8sClient, err := k8s.NewClient(dynamicClient, clientset, kubewardenNamespace, skippedNs)
		if err != nil {
			return err
		}
		policyReportStore := report.NewPolicyReportStore(client)

		scanner, err := scanner.NewScanner(policiesClient, k8sClient, policyReportStore, outputScan, insecureSSL, caCertFile)
		if err != nil {
			return err
		}

		return startScanner(namespace, clusterWide, scanner)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	// make sure we always get json formatted errors, even for flag errors
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true

	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Error on cmd.Execute()")
	}
}

func startScanner(namespace string, clusterWide bool, scanner *scanner.Scanner) error {
	if clusterWide && namespace != "" {
		log.Fatal().Msg("Cannot scan cluster wide and only a namespace at the same time")
	}

	ctx := context.Background()
	if clusterWide {
		// only scan clusterwide
		return scanner.ScanClusterWideResources(ctx)
	}
	if namespace != "" {
		// only scan namespace
		return scanner.ScanNamespace(ctx, namespace)
	}

	// neither clusterWide flag nor namespace was provided, default
	// behaviour of scanning cluster wide and all ns
	if err := scanner.ScanClusterWideResources(ctx); err != nil {
		return err
	}
	return scanner.ScanAllNamespaces(ctx)
}

func init() {
	rootCmd.Flags().StringP("namespace", "n", "", "namespace to be evaluated")
	rootCmd.Flags().BoolP("cluster", "c", false, "scan cluster wide resources")
	rootCmd.Flags().StringP("kubewarden-namespace", "k", defaultKubewardenNamespace, "namespace where the Kubewarden components (e.g. PolicyServer) are installed (required)")
	rootCmd.Flags().StringP("policy-server-url", "u", "", "URI to the PolicyServers the Audit Scanner will query. Example: https://localhost:3000. Useful for out-of-cluster debugging")
	rootCmd.Flags().VarP(&level, "loglevel", "l", fmt.Sprintf("level of the logs. Supported values are: %v", logconfig.SupportedValues))
	rootCmd.Flags().BoolVarP(&outputScan, "output-scan", "o", false, "print result of scan in JSON to stdout")
	rootCmd.Flags().StringSliceVarP(&skippedNs, "ignore-namespaces", "i", nil, "comma separated list of namespace names to be skipped from scan. This flag can be repeated")
	rootCmd.Flags().BoolVar(&insecureSSL, "insecure-ssl", false, "skip SSL cert validation when connecting to PolicyServers endpoints. Useful for development")
	rootCmd.Flags().StringP("extra-ca", "f", "", "File path to CA cert in PEM format of PolicyServer endpoints")
}
