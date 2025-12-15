package main

import (
	"github.com/kubewarden/audit-scanner/cmd"
)

func main() {
	rootCmd := cmd.NewRootCommand()
	cmd.Execute(rootCmd)
}
