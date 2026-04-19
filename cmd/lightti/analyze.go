package main

import (
	"fmt"
	"os"	
	// "context"

	"github.com/YccYeung/LightTI/internal/command"
	"github.com/YccYeung/LightTI/internal/llm"

	"github.com/spf13/cobra"
	"github.com/joho/godotenv"
)

var	(
	commandInput	string
)

var analyze = &cobra.Command{
	Use:   "analyze",
	Short: "TODO",
	Long:  "TODO",
	Run: func(cmd *cobra.Command, args []string) {
		_ = godotenv.Load()
		var commandResult command.CommandResult
		processedCommand := command.CommandParser(commandInput)
		lolBasResult, gtfoBinsResult := command.LookupBinary(processedCommand.Executable, processedCommand.OS)
		
		commandResult.RawCommand = commandInput
		commandResult.ParsedCommand = *processedCommand
		commandResult.LOLBasResult = lolBasResult
		commandResult.GTFOBinsResult = gtfoBinsResult

		// Get llm provider 
		provider := llm.NewProvider()
		result, err := provider.CommandLLMAnalysis(commandResult)
		if err != nil {
			fmt.Fprintf(os.Stderr, "LLM analysis for Command '%s' failed: %v\n", commandResult.RawCommand, err)
			return
		}
		fmt.Println("\n=== Command Analysis Summary ===")
		fmt.Println(result)
	},
}

func init() {
	analyze.Flags().StringVar(&commandInput, "command", "", "Command to analyze")

	rootCmd.AddCommand(analyze)
}