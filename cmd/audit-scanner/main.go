package main

import (
	"github.com/kubewarden/kubewarden-controller/internal/audit-scanner/cmd"
)

func main() {
	rootCmd := cmd.NewRootCommand()
	cmd.Execute(rootCmd)
}
