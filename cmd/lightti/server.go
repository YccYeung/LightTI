package main

import (
	"os"
	"context"
	"fmt"

	"github.com/YccYeung/LightTI/internal/store"
	"github.com/YccYeung/LightTI/internal/api"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var server = &cobra.Command{
	Use:   "server",
	Short: "Start the LightTI server",
	Long:  "Start the LightTI server to handle API requests, connect to the database, and provide various functionalities using the configured environment variables.",
	Run: func(cmd *cobra.Command, args []string) {
		// Load Api key values from environment variables
		godotenv.Load()

		dbURL := os.Getenv("DATABASE_URL")
		vtApiKey := os.Getenv("VT_API_KEY")
		abuseIpApiKey := os.Getenv("ABUSE_IP_DB_API_KEY")
		model := os.Getenv("OLLAMA_MODEL")
		llmURL := os.Getenv("OLLAMA_URL")
		
		// Connect with PostgreSQL database
		ctx := context.Background()
		s, err := store.New(ctx, dbURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to connect to database: %v\n", err)
			return
		}

		h := api.NewHandler(s, vtApiKey, abuseIpApiKey, model, llmURL)

		r := api.SetupRouter(h)
		r.Run(":8080")
	},	
}

func init() {
	rootCmd.AddCommand(server)
}