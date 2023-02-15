package cmd

import (
	"fmt"
	"os"

	logconfig "github.com/kubewarden/audit-scanner/internal/log"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/resources"
	"github.com/kubewarden/audit-scanner/internal/scanner"
	"github.com/spf13/cobra"
)

const defaultKubewardenNamespace = "kubewarden"

// A Scanner verifies that existing resources don't violate any of the policies
type Scanner interface {
	// ScanNamespace scans a given namespace
	ScanNamespace(namespace string) error
	// ScanAllNamespaces scan all namespaces
	ScanAllNamespaces() error
}

var level logconfig.Level

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
			policiesFetcher, err := policies.NewFetcher()
			if err != nil {
				return err
			}
			resourcesFetcher, err := resources.NewFetcher(kubewardenNamespace)
			if err != nil {
				return err
			}
			scanner := scanner.NewScanner(policiesFetcher, resourcesFetcher)

			return startScanner(namespace, scanner)
		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func startScanner(namespace string, scanner Scanner) error {
	if namespace != "" {
		if err := scanner.ScanNamespace(namespace); err != nil {
			return err
		}
	} else {
		if err := scanner.ScanAllNamespaces(); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	rootCmd.Flags().StringP("namespace", "n", "", "namespace to be evaluated")
	rootCmd.Flags().StringP("kubewarden-namespace", "k", defaultKubewardenNamespace, "namespace where the Kubewarden components (e.g. Policy Server) are installed (required)")
	rootCmd.Flags().VarP(&level, "loglevel", "l", fmt.Sprintf("level of the logs. Supported values are: %v", logconfig.SupportedValues))
}
