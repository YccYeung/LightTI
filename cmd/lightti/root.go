package main

import (
	"github.com/spf13/cobra"
	"fmt"
	"os"
)

var rootCmd = &cobra.Command {
	Use:   "TODO",
	Short: "TODO",
	Long: "TODO",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO
	}, 
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "An error while executing")
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(enrich)
}