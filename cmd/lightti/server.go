package main

import (
	"os"
	"context"
	"fmt"
	"log"

	"github.com/YccYeung/LightTI/internal/store"
	"github.com/YccYeung/LightTI/internal/api"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

// server sub-command: initialises the store, wires up the API handler, and starts the HTTP server.
var server = &cobra.Command{
	Use:   "server",
	Short: "Start the LightTI server",
	Long:  "Start the LightTI server to handle API requests, connect to the database, and provide various functionalities using the configured environment variables.",
	Run: func(cmd *cobra.Command, args []string) {
		// Load .env file so os.Getenv calls below can read API keys.
		_ = godotenv.Load()

		dbURL := os.Getenv("DATABASE_URL")
		vtApiKey := os.Getenv("VT_API_KEY")
		abuseIpApiKey := os.Getenv("ABUSE_IP_DB_API_KEY")
		model := os.Getenv("OLLAMA_MODEL")
		llmURL := os.Getenv("OLLAMA_URL")
		
		// Initialise the database store.
		ctx := context.Background()
		s, err := store.New(ctx, dbURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to connect to database: %v\n", err)
			return
		}
		// Wire API keys, LLM config, and store into the handler.
		h := api.NewHandler(s, vtApiKey, abuseIpApiKey, model, llmURL)
		// Register routes and start listening on port 8080.
		r := api.SetupRouter(h)
		if err := r.Run(":8080"); err != nil {
			log.Fatal(err)
		}
	},	
}

func init() {
	rootCmd.AddCommand(server)
}