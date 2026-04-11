package main

import (
	"fmt"
	// "os"	
	// "context"

	// "github.com/YccYeung/LightTI/internal/llm"

	"github.com/spf13/cobra"
)

var	(
	command	string
)

var analyze = &cobra.Command{
	Use:   "analyze",
	Short: "TODO",
	Long:  "TODO",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO")
	},
}

func init() {
	analyze.Flags().StringVar(&command, "command", "", "Command to analyze")

	rootCmd.AddCommand(analyze)
}