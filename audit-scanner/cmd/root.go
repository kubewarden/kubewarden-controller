package cmd

import (
	"os"

	"github.com/kubewarden/audit-scanner/internal/scanner"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var (
	namespace string
	rootCmd   = &cobra.Command{
		Use:   "audit-scanner",
		Short: "Reports evaluation of existing Kubernetes resources with your already deployed Kubewarden policies",
		Long: `Scans resources in your kubernetes cluster with your already deployed Kubewarden policies.
Each namespace will have a PolicyReport with the outcome of the scan for resources within this namespace.
There will be a ClusterPolicyReport with results for cluster-wide resources.`,

		Run: func(cmd *cobra.Command, args []string) {
			scanner.Scan(namespace)
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

func init() {
	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "namespace to be evaluated")
}
