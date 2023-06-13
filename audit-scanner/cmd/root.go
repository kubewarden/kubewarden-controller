package cmd

import (
	"fmt"

	logconfig "github.com/kubewarden/audit-scanner/internal/log"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/resources"
	"github.com/kubewarden/audit-scanner/internal/scanner"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const defaultKubewardenNamespace = "kubewarden"

// A Scanner verifies that existing resources don't violate any of the policies
type Scanner interface {
	// ScanNamespace scans a given namespace
	ScanNamespace(namespace string) error
	// ScanAllNamespaces scan all namespaces
	ScanAllNamespaces() error
	// Scan only cluster wide resources
	ScanClusterWideResources() error
}

var level logconfig.Level

// print result of scan as JSON to stdout
var printJSON bool

// rootCmd represents the base command when called without any subcommands
var (
	rootCmd = &cobra.Command{
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
			policiesFetcher, err := policies.NewFetcher(kubewardenNamespace)
			if err != nil {
				return err
			}
			resourcesFetcher, err := resources.NewFetcher(kubewardenNamespace, policyServerURL)
			if err != nil {
				return err
			}
			scanner, err := scanner.NewScanner(policiesFetcher, resourcesFetcher, printJSON)
			if err != nil {
				return err
			}

			return startScanner(namespace, clusterWide, scanner)
		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Error on cmd.Execute()")
	}
}
func startScanner(namespace string, clusterWide bool, scanner Scanner) error {
	if clusterWide {
		if err := scanner.ScanClusterWideResources(); err != nil {
			return err
		}
	}

	if namespace != "" {
		if err := scanner.ScanNamespace(namespace); err != nil {
			return err
		}
	} else if !clusterWide {
		// FIXME ScanAllNamespaces is not implemented. Therefore, if we are
		// scanning cluster wide resource do not trigger this scan. It will failed anyway
		if err := scanner.ScanAllNamespaces(); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	rootCmd.Flags().StringP("namespace", "n", "", "namespace to be evaluated")
	rootCmd.Flags().BoolP("cluster", "c", false, "Scan cluster wide resources")
	rootCmd.Flags().StringP("kubewarden-namespace", "k", defaultKubewardenNamespace, "namespace where the Kubewarden components (e.g. Policy Server) are installed (required)")
	rootCmd.Flags().StringP("policy-server-url", "u", "", "Full URL to the PolicyServers, for example https://localhost:3000. Audit scanner will query the needed HTTP path. Useful for out-of-cluster debugging")
	rootCmd.Flags().VarP(&level, "loglevel", "l", fmt.Sprintf("level of the logs. Supported values are: %v", logconfig.SupportedValues))
	rootCmd.Flags().BoolVarP(&printJSON, "print", "p", false, "print result of scan in JSON to stdout")
}
