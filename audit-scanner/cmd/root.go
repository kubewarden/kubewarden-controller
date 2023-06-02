package cmd

import (
	"fmt"
	"os"

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
			policyServerFQDN, err := cmd.Flags().GetString("policy-server-fqdn")
			if err != nil {
				return err
			}
			policiesFetcher, err := policies.NewFetcher()
			if err != nil {
				return err
			}
			resourcesFetcher, err := resources.NewFetcher(kubewardenNamespace, policyServerFQDN)
			if err != nil {
				return err
			}
			scanner, err := scanner.NewScanner(policiesFetcher, resourcesFetcher)
			if err != nil {
				return err
			}

			err = startScanner(namespace, scanner)
			if err != nil {
				return err
			}
			return nil
		},
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Error on cmd.Execute()")
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
	rootCmd.Flags().StringP("policy-server-fqdn", "p", "", "FQDN of the PolicyServers. If non-empty, they will be queried on port 3000. Useful for out-of-cluster debugging")
	rootCmd.Flags().VarP(&level, "loglevel", "l", fmt.Sprintf("level of the logs. Supported values are: %v", logconfig.SupportedValues))
}
