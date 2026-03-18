package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "lightti",
	Short: "LightTI — lightweight threat intelligence enrichment",
	Long:  "LightTI enriches IPs, domains, URLs, and file hashes across multiple threat intelligence sources.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "An error while executing: %v\n", err)
		os.Exit(1)
	}
}